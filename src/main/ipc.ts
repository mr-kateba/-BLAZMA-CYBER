import { app, dialog, ipcMain, safeStorage, shell, type BrowserWindow, type IpcMainInvokeEvent } from 'electron';
import { rmSync, mkdirSync } from 'node:fs';
import type { ClearTarget, Result } from '../shared/api';
import { identifyHash } from '../core/hash-id';
import { NetworkGate, OfflineModeError } from '../core/network-gate';
import { isIP } from '../core/validation';
import { AnalysisError, analyzeFile, hashFile, hashText } from './services/file-analysis';
import { verifySignature } from './services/windows-security';
import { getSystemSnapshot } from './services/system-info';
import { getWindowsFacts } from './services/windows-security';
import { HistoryService } from './services/history';
import { SecretStore, isApiKeyService } from './services/secrets';
import { SettingsService } from './services/settings';
import { logger, setLogLevel } from './services/logger';
import { dataDir, subDir } from './services/paths';

const MAX_TEXT = 1024 * 1024;
const TASK_ID_RE = /^[a-zA-Z0-9-]{1,64}$/;

function fail(error: string, detail?: string): Result<never> {
  return detail ? { ok: false, error, detail } : { ok: false, error };
}

function errorCode(e: unknown): string {
  if (e instanceof AnalysisError) return e.code;
  if (e instanceof OfflineModeError) return 'offline_mode';
  return 'internal_error';
}

export function registerIpc(getWindow: () => BrowserWindow | null, isTrustedSender: (e: IpcMainInvokeEvent) => boolean) {
  const settings = new SettingsService();
  setLogLevel(settings.get().logLevel);
  const history = new HistoryService(() => settings.get().keepHistory);
  const secrets = new SecretStore();
  const gate = new NetworkGate(
    () => settings.get().offlineMode,
    (entry) => {
      history.network.add(entry);
      logger.info('network_request', { module: entry.module, service: entry.service, host: entry.host, outcome: entry.outcome });
    },
  );
  const tasks = new Map<string, AbortController>();

  /** Wraps every handler: rejects untrusted senders and never lets an exception cross IPC. */
  const handle = (channel: string, fn: (...args: any[]) => unknown) => {
    ipcMain.handle(channel, async (event, ...args) => {
      if (!isTrustedSender(event)) {
        logger.security('ipc_untrusted_sender', { channel, url: event.senderFrame?.url });
        throw new Error('untrusted_sender');
      }
      try {
        return await fn(...args);
      } catch (e) {
        logger.error('ipc_handler_error', { channel, message: e instanceof Error ? e.message : String(e) });
        return fail(errorCode(e));
      }
    });
  };

  const progress = (taskId: string) => (p: object) => getWindow()?.webContents.send('files:progress', { taskId, ...p });

  const runTask = async <T>(taskId: unknown, work: (signal: AbortSignal) => Promise<T>): Promise<Result<T>> => {
    if (typeof taskId !== 'string' || !TASK_ID_RE.test(taskId)) return fail('invalid_task');
    const ctrl = new AbortController();
    tasks.set(taskId, ctrl);
    try {
      return { ok: true, data: await work(ctrl.signal) };
    } catch (e) {
      const code = errorCode(e);
      if (code === 'internal_error') logger.error('task_failed', { message: e instanceof Error ? e.message : String(e) });
      return fail(code);
    } finally {
      tasks.delete(taskId);
    }
  };

  handle('app:info', () => ({
    version: app.getVersion(),
    platform: process.platform,
    dataDir: dataDir(),
    electron: process.versions.electron,
    secureStorageAvailable: safeStorage.isEncryptionAvailable(),
  }));
  handle('app:openDataFolder', async () => {
    const err = await shell.openPath(dataDir());
    return err ? fail('open_failed') : { ok: true, data: true };
  });

  handle('settings:get', () => settings.get());
  handle('settings:update', (patch: unknown) => {
    const before = settings.get();
    const next = settings.update(patch);
    setLogLevel(next.logLevel);
    if (before.offlineMode !== next.offlineMode) logger.security('offline_mode_changed', { offlineMode: next.offlineMode });
    return { ok: true, data: next };
  });

  handle('system:snapshot', async () => ({ ok: true, data: await getSystemSnapshot() }));
  handle('system:security', async () => ({ ok: true, data: (await getWindowsFacts()).security }));

  handle('files:pick', async () => {
    const win = getWindow();
    const r = win ? await dialog.showOpenDialog(win, { properties: ['openFile'] }) : await dialog.showOpenDialog({ properties: ['openFile'] });
    return r.canceled ? null : (r.filePaths[0] ?? null);
  });
  handle('files:analyze', (path: unknown, taskId: unknown) =>
    runTask(taskId, async (signal) => {
      const res = await analyzeFile(path, signal, progress(taskId as string), verifySignature);
      history.record({ kind: 'file_analysis', subject: res.name, summaryKey: `verdict.${res.assessment.verdict}` });
      logger.info('file_analyzed', { type: res.type.id, size: res.sizeBytes, verdict: res.assessment.verdict });
      return res;
    }),
  );
  handle('files:hash', (path: unknown, taskId: unknown) =>
    runTask(taskId, async (signal) => {
      const res = await hashFile(path, signal, progress(taskId as string));
      history.record({ kind: 'hash_file', subject: String(path).split(/[\\/]/).pop() ?? '', summaryKey: 'activity.summary.hashed' });
      return res;
    }),
  );
  handle('files:cancel', (taskId: unknown) => {
    if (typeof taskId === 'string') tasks.get(taskId)?.abort();
  });

  handle('hashlab:hashText', (text: unknown) => {
    if (typeof text !== 'string' || text.length > MAX_TEXT) return fail('invalid_input');
    // Text content is never stored in history: only the fact that a hash was computed.
    history.record({ kind: 'hash_text', subject: '—', summaryKey: 'activity.summary.hashed_text' });
    return { ok: true, data: hashText(text) };
  });
  handle('hashlab:identify', (value: unknown) => {
    if (typeof value !== 'string' || value.length > 4096) return fail('invalid_input');
    return { ok: true, data: identifyHash(value) };
  });

  handle('privacy:networkActivity', () => history.network.list());
  handle('privacy:clear', (target: unknown) => {
    const t = target as ClearTarget;
    switch (t) {
      case 'activity':
        history.activity.clear();
        break;
      case 'network_activity':
        history.network.clear();
        break;
      case 'logs': {
        const dir = subDir('logs');
        rmSync(dir, { recursive: true, force: true });
        mkdirSync(dir, { recursive: true, mode: 0o700 });
        break;
      }
      case 'temp': {
        const dir = subDir('temp');
        rmSync(dir, { recursive: true, force: true });
        mkdirSync(dir, { recursive: true, mode: 0o700 });
        break;
      }
      default:
        return fail('invalid_input');
    }
    logger.security('data_cleared', { target: t });
    return { ok: true, data: true };
  });
  handle('privacy:publicIp', async () => {
    // Explicit, user-initiated request only. Goes through the gate (blocked in Offline Mode, logged).
    const res = await gate.request({
      module: 'dashboard',
      service: 'ipify',
      url: 'https://api.ipify.org?format=json',
      dataKind: 'privacy.data.connection_only',
      timeoutMs: 10000,
    });
    if (!res.ok) return fail('api_error', String(res.status));
    const body = (await res.json()) as { ip?: unknown };
    if (typeof body.ip !== 'string' || !isIP(body.ip)) return fail('invalid_response');
    return { ok: true, data: { ip: body.ip, service: 'api.ipify.org' } };
  });

  handle('activity:recent', (limit: unknown) => history.activity.list(typeof limit === 'number' ? Math.min(Math.max(1, limit), 200) : 20));

  handle('secrets:status', () => secrets.status());
  handle('secrets:set', (service: unknown, value: unknown) => {
    if (!isApiKeyService(service) || typeof value !== 'string') return fail('invalid_input');
    const v = value.trim();
    if (v.length < 8 || v.length > 512 || /\s/.test(v)) return fail('invalid_api_key_format');
    if (!secrets.available()) return fail('secure_storage_unavailable');
    secrets.set(service, v);
    logger.security('api_key_saved', { service });
    return { ok: true, data: true };
  });
  handle('secrets:remove', (service: unknown) => {
    if (!isApiKeyService(service)) return fail('invalid_input');
    secrets.remove(service);
    logger.security('api_key_removed', { service });
    return { ok: true, data: true };
  });

  return { settings };
}
