import { app, dialog, ipcMain, Notification, safeStorage, shell, type BrowserWindow, type IpcMainInvokeEvent } from 'electron';
import { rmSync, mkdirSync } from 'node:fs';
import type { ClearTarget, Result } from '../shared/api';
import { identifyHash } from '../core/hash-id';
import { NetworkGate, OfflineModeError } from '../core/network-gate';
import { isIP } from '../core/validation';
import { AnalysisError, analyzeFile, hashFile, hashText, type AnalysisEngines } from './services/file-analysis';
import { verifySignature } from './services/windows-security';
import { QuarantineError, QuarantineService } from './services/quarantine';
import { DefenderError, findMpCmdRun, getThreatHistory, runDefenderScan } from './services/defender';
import { YaraError, YaraService } from './services/yara';
import { IntelError, IntelService } from './services/intel';
import { OsintService } from './services/osint';
import { bundledEngine, bundledRulePack } from './services/bundled';
import { runCapa, runDie } from './services/static-engines';
import { analyzeEmailFile, analyzeEmailText, EmailError, extractAttachment } from './services/email';
import { openTerminal, TerminalError } from './services/terminal';
import { systemFetch } from './services/net-fetch';
import { checkPwnedPassword, PwnedError } from './services/pwned';
import { deviceSecurity, DeviceSecurityError, openSettingsPage } from './services/device-security';
import { tamperChecks } from './services/tamper';
import { auditExtensions } from './services/extensions';
import { EventHuntError, parseOptions, parseSource, runEventHunt } from './services/event-hunt';
import { DownloadsWatcher } from './services/downloads-watch';
import { createTranslator, type Dict } from '../core/i18n';
import enDict from '../../locales/en.json';
import arDict from '../../locales/ar.json';
import { externalLinkHost } from '../core/intel';
import * as forensics from './services/forensics';
import { NetToolsError, NetToolsService } from './services/nettools';
import { RecoveryError, RecoveryService, detectFileEncryption } from './services/recovery';
import { CaseError, CaseService } from './services/cases';
import { ReportError, ReportService } from './services/reports';
import { HuntService } from './services/hunt';
import type { RecoveryEngineKind } from '../shared/api';
import type { DefenderScanKind } from '../shared/api';
import { validateAbsolutePath } from '../core/validation';
import { basename } from 'node:path';
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
  if (e instanceof AnalysisError || e instanceof QuarantineError || e instanceof DefenderError || e instanceof YaraError || e instanceof IntelError || e instanceof forensics.ForensicsError || e instanceof NetToolsError || e instanceof RecoveryError || e instanceof CaseError || e instanceof ReportError || e instanceof TerminalError || e instanceof DeviceSecurityError || e instanceof EmailError || e instanceof PwnedError || e instanceof EventHuntError) return e.code;
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
    systemFetch,
  );
  const tasks = new Map<string, AbortController>();
  const quarantine = new QuarantineService();
  const intel = new IntelService({ gate, secret: (svc) => secrets.get(svc) });
  const osint = new OsintService({ intel, gate, openExternal: (url) => shell.openExternal(url) });
  const net = new NetToolsService(gate);
  const cases = new CaseService();
  const reports = new ReportService();
  const recovery = new RecoveryService((kind) => (kind === 'john' ? settings.get().johnPath : settings.get().hashcatPath));
  const engineKind = (v: unknown): RecoveryEngineKind => { if (v !== 'john' && v !== 'hashcat') throw new RecoveryError('invalid_input'); return v; };
  const yara = new YaraService(() => settings.get().yaraPath, {
    exe: () => bundledEngine('yara-x')?.path ?? null,
    packs: () => {
      const p = bundledRulePack('reversinglabs.yar');
      return p ? [{ id: 'pack-reversinglabs', name: 'ReversingLabs — 1240 rules (MIT)', path: p }] : [];
    },
  });
  const hunt = new HuntService(cases, history, quarantine, yara);

  /** Engines used by File Analyzer, according to settings and platform. */
  const analysisEngines = (): AnalysisEngines => {
    const cfg = settings.get();
    const capaExe = bundledEngine('capa')?.path;
    const dieExe = bundledEngine('die')?.path;
    return {
      verifySignature,
      // Enabled but not shipped in this build (e.g. a Linux dev build): say so, don't pretend it's off.
      capa: !cfg.capaOnAnalyze ? undefined : capaExe ? (path, signal) => runCapa(capaExe, path, signal) : async () => ({ ran: false, reason: 'engine_not_bundled' }),
      die: !cfg.dieOnAnalyze ? undefined : dieExe ? (path, signal) => runDie(dieExe, path, signal) : async () => ({ ran: false, reason: 'engine_not_bundled' }),
      defender: cfg.defenderOnAnalyze
        ? async (path, signal) => {
            if (process.platform !== 'win32') return { ran: false, reason: 'unsupported_platform' };
            if (!findMpCmdRun()) return { ran: false, reason: 'defender_unavailable' };
            const r = await runDefenderScan('path', path, signal);
            return { ran: true, threats: r.threats };
          }
        : undefined,
      yara: cfg.yaraOnAnalyze
        ? async (path, signal) => {
            const r = await yara.scan(path, { recursive: false, signal, timeoutMs: 5 * 60_000 });
            return { ran: true, matches: r.files.flatMap((f) => f.matches), rulesUsed: r.rulesUsed };
          }
        : undefined,
    };
  };
  // Opt-in Downloads watcher: static analysis only, while the app is open.
  const downloads = new DownloadsWatcher({
    folder: () => app.getPath('downloads'),
    analyze: async (path, signal) => {
      const res = await analyzeFile(path, signal, () => {}, analysisEngines());
      history.record({ kind: 'file_analysis', subject: res.name, summaryKey: `verdict.${res.assessment.verdict}` });
      logger.info('download_analyzed', { type: res.type.id, size: res.sizeBytes, verdict: res.assessment.verdict });
      return res;
    },
    onChange: (s) => getWindow()?.webContents.send('downloads:state', s),
    onFlagged: (ev) => {
      if (!settings.get().notifications || !Notification.isSupported()) return;
      const lang = settings.get().language ?? 'en';
      const t = createTranslator((lang === 'ar' ? arDict : enDict) as Dict, enDict as Dict);
      const n = new Notification({ title: t(`downloads.notify.${ev.verdict}`), body: t('downloads.notify.body', { name: ev.name }) });
      n.on('click', () => {
        const w = getWindow();
        if (!w) return;
        if (w.isMinimized()) w.restore();
        w.focus();
        w.webContents.send('downloads:open', ev);
      });
      n.show();
    },
  });
  if (settings.get().watchDownloads) downloads.setEnabled(true);
  app.on('before-quit', () => downloads.stop());

  const idArg = (v: unknown): string => {
    if (typeof v !== 'string' || !/^[a-z0-9-]{1,64}$/.test(v)) throw new QuarantineError('invalid_input');
    return v;
  };

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
  handle('app:openLink', async (url: unknown) => {
    const host = externalLinkHost(url);
    if (!host) return fail('invalid_input');
    await gate.run({ module: 'reputation', service: 'browser:link', host, dataKind: 'privacy.data.indicator' }, () => shell.openExternal(url as string));
    return { ok: true, data: true };
  });
  handle('app:bundledEngines', () =>
    (['yara-x', 'capa', 'die', 'hayabusa'] as const).flatMap((id) => {
      const e = bundledEngine(id);
      return e ? [{ id, name: e.name, version: e.version, license: e.license }] : [];
    }),
  );
  handle('app:openTerminal', async () => {
    const kind = await openTerminal();
    logger.info('terminal_opened', { kind });
    return { ok: true, data: kind };
  });
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
    if (before.watchDownloads !== next.watchDownloads) downloads.setEnabled(next.watchDownloads);
    return { ok: true, data: next };
  });

  handle('system:snapshot', async () => ({ ok: true, data: await getSystemSnapshot() }));
  handle('system:security', async () => ({ ok: true, data: (await getWindowsFacts()).security }));
  handle('downloads:state', () => ({ ok: true, data: downloads.state() }));
  handle('extensions:audit', async () => ({ ok: true, data: await auditExtensions() }));
  handle('device:tamper', async () => ({ ok: true, data: await tamperChecks() }));
  handle('device:security', async (force: unknown) => {
    const r = await deviceSecurity(force === true);
    logger.info('device_security', { score: r.score, evaluated: r.evaluated, unknown: r.unknown });
    return { ok: true, data: r };
  });
  handle('device:openSettings', async (link: unknown) => {
    await openSettingsPage(link);
    return { ok: true, data: true };
  });

  handle('files:pick', async () => {
    const win = getWindow();
    const r = win ? await dialog.showOpenDialog(win, { properties: ['openFile'] }) : await dialog.showOpenDialog({ properties: ['openFile'] });
    return r.canceled ? null : (r.filePaths[0] ?? null);
  });
  handle('files:analyze', (path: unknown, taskId: unknown) =>
    runTask(taskId, async (signal) => {
      const res = await analyzeFile(path, signal, progress(taskId as string), analysisEngines());
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
  handle('files:pickFolder', async () => {
    const win = getWindow();
    const opts = { properties: ['openDirectory' as const] };
    const r = win ? await dialog.showOpenDialog(win, opts) : await dialog.showOpenDialog(opts);
    return r.canceled ? null : (r.filePaths[0] ?? null);
  });
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
  handle('privacy:clear', async (target: unknown) => {
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
      case 'intel_cache':
        intel.clearCache();
        break;
      case 'reports':
        await reports.clearAll();
        break;
      case 'cases':
        cases.clearAll();
        break;
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

  // ---- Quarantine ----
  handle('quarantine:list', () => ({ ok: true, data: quarantine.list() }));
  handle('quarantine:add', async (path: unknown, reason: unknown) => {
    const why = typeof reason === 'string' ? reason.slice(0, 200) : 'manual';
    const entry = await quarantine.quarantine(path, why);
    history.record({ kind: 'quarantine', subject: entry.originalName, summaryKey: 'activity.summary.quarantined' });
    logger.security('file_quarantined', { id: entry.id, sha256: entry.sha256, type: entry.typeId });
    return { ok: true, data: entry };
  });
  handle('quarantine:restore', async (id: unknown) => {
    const r = await quarantine.restore(idArg(id));
    history.record({ kind: 'restore', subject: basename(r.path), summaryKey: 'activity.summary.restored' });
    logger.security('file_restored', { id });
    return { ok: true, data: r };
  });
  handle('quarantine:restoreTo', async (id: unknown) => {
    const entry = quarantine.get(idArg(id));
    if (!entry) return fail('quarantine_not_found');
    const win = getWindow();
    const opts = { defaultPath: entry.originalName };
    const pick = win ? await dialog.showSaveDialog(win, opts) : await dialog.showSaveDialog(opts);
    if (pick.canceled || !pick.filePath) return { ok: true, data: null };
    const r = await quarantine.restore(entry.id, pick.filePath);
    history.record({ kind: 'restore', subject: basename(r.path), summaryKey: 'activity.summary.restored' });
    logger.security('file_restored', { id: entry.id, customTarget: true });
    return { ok: true, data: r };
  });
  handle('quarantine:remove', async (id: unknown) => {
    await quarantine.remove(idArg(id));
    logger.security('quarantine_deleted', { id });
    return { ok: true, data: true };
  });
  handle('quarantine:rescan', (id: unknown, taskId: unknown) =>
    runTask(taskId, (signal) =>
      quarantine.withDecoded(idArg(id), async (tmp) => {
        const res = await analyzeFile(tmp, signal, progress(taskId as string), analysisEngines());
        const entry = quarantine.get(id as string);
        // Present the result under the item's original identity, not the temp path.
        return { ...res, path: entry?.originalPath ?? res.path, name: entry?.originalName ?? res.name };
      }),
    ),
  );

  // ---- Microsoft Defender ----
  handle('defender:scan', (kind: unknown, target: unknown, taskId: unknown) => {
    if (kind !== 'quick' && kind !== 'full' && kind !== 'path') return fail('invalid_input');
    let path: string | null = null;
    if (kind === 'path') {
      const v = validateAbsolutePath(target);
      if (!v.ok) return fail(v.reason);
      path = v.path;
    }
    return runTask(taskId, async (signal) => {
      const r = await runDefenderScan(kind as DefenderScanKind, path, signal);
      history.record({ kind: 'defender_scan', subject: path ? basename(path) : kind, summaryKey: `defender.status.${r.status}` });
      logger.info('defender_scan', { kind, status: r.status, threats: r.threats.length });
      return r;
    });
  });
  handle('defender:history', async () => ({ ok: true, data: await getThreatHistory() }));

  // ---- YARA-X ----
  handle('yara:engine', () => yara.engine());
  handle('yara:pickEngine', async () => {
    const win = getWindow();
    const opts = { properties: ['openFile' as const], filters: process.platform === 'win32' ? [{ name: 'yr.exe', extensions: ['exe'] }] : [] };
    const pick = win ? await dialog.showOpenDialog(win, opts) : await dialog.showOpenDialog(opts);
    if (pick.canceled || !pick.filePaths[0]) return { ok: true, data: null };
    const previous = settings.get().yaraPath;
    settings.update({ yaraPath: pick.filePaths[0] });
    const info = await yara.engine();
    if (!info.available) {
      settings.update({ yaraPath: previous });
      return fail('yara_invalid_engine');
    }
    logger.security('yara_engine_configured', { version: info.version });
    return { ok: true, data: info };
  });
  handle('yara:clearEngine', async () => {
    settings.update({ yaraPath: null });
    return { ok: true, data: await yara.engine() };
  });
  handle('yara:rules', async () => ({ ok: true, data: await yara.listRules() }));
  handle('yara:validate', async () => ({ ok: true, data: await yara.validateAll() }));
  handle('yara:setEnabled', async (id: unknown, enabled: unknown) => ({ ok: true, data: await yara.setEnabled(id, enabled) }));
  handle('yara:source', async (id: unknown) => ({ ok: true, data: await yara.getSource(id) }));
  handle('yara:save', async (name: unknown, source: unknown) => ({ ok: true, data: await yara.saveCustom(name, source) }));
  handle('yara:importFile', async () => {
    const win = getWindow();
    const opts = { properties: ['openFile' as const], filters: [{ name: 'YARA', extensions: ['yar', 'yara'] }] };
    const pick = win ? await dialog.showOpenDialog(win, opts) : await dialog.showOpenDialog(opts);
    if (pick.canceled || !pick.filePaths[0]) return { ok: true, data: null };
    return { ok: true, data: await yara.importFile(pick.filePaths[0]) };
  });
  handle('yara:remove', async (id: unknown) => ({ ok: true, data: await yara.remove(id) }));
  handle('yara:scan', (target: unknown, recursive: unknown, taskId: unknown) => {
    const v = validateAbsolutePath(target);
    if (!v.ok) return fail(v.reason);
    return runTask(taskId, async (signal) => {
      const r = await yara.scan(v.path, { recursive: recursive === true, signal });
      history.record({ kind: 'yara_scan', subject: basename(v.path), summaryKey: 'activity.summary.yara_scanned' });
      logger.info('yara_scan', { files: r.files.length, matched: r.matchedFiles, rules: r.rulesUsed });
      return r;
    });
  });

  // ---- Intelligence ----
  handle('intel:ip', async (ip: unknown, options: unknown) => {
    const o = (options ?? {}) as Record<string, unknown>;
    const r = await intel.ip(ip, {
      reverseDns: o.reverseDns === true, rdap: o.rdap === true, asn: o.asn === true, geo: o.geo === true, tor: o.tor === true,
      reputation: Array.isArray(o.reputation) ? o.reputation.filter((x) => x === 'virustotal' || x === 'abuseipdb' || x === 'shodan') : [],
    });
    history.record({ kind: 'ip_lookup', subject: r.ip, summaryKey: 'activity.summary.looked_up' });
    return { ok: true, data: r };
  });
  handle('intel:domain', async (domain: unknown, options: unknown) => {
    const o = (options ?? {}) as Record<string, unknown>;
    const r = await intel.domain(domain, {
      dns: o.dns === true, rdap: o.rdap === true, tls: o.tls === true, infrastructure: o.infrastructure === true,
      reputation: Array.isArray(o.reputation) ? o.reputation.filter((x) => x === 'virustotal') : [],
    });
    history.record({ kind: 'domain_lookup', subject: r.domain, summaryKey: 'activity.summary.looked_up' });
    return { ok: true, data: r };
  });
  handle('intel:reputation', async (kind: unknown, value: unknown, services: unknown) => {
    const r = await intel.reputation(kind, value, services);
    history.record({ kind: 'reputation_lookup', subject: String(value).trim().slice(0, 80), summaryKey: 'activity.summary.looked_up' });
    return { ok: true, data: r };
  });

  // ---- Email check (local only) ----
  handle('email:pick', async () => {
    const win = getWindow();
    const opts = { properties: ['openFile' as const], filters: [{ name: 'Email', extensions: ['eml', 'txt'] }, { name: '*', extensions: ['*'] }] };
    const r = win ? await dialog.showOpenDialog(win, opts) : await dialog.showOpenDialog(opts);
    return r.canceled ? null : (r.filePaths[0] ?? null);
  });
  const recordEmail = (r: { subject: string | null; level: string }) =>
    history.record({ kind: 'email_check', subject: (r.subject ?? '').slice(0, 80), summaryKey: `email.level.${r.level}` });
  handle('email:analyzeFile', async (path: unknown) => {
    const r = await analyzeEmailFile(path);
    recordEmail(r);
    return { ok: true, data: r };
  });
  handle('email:analyzeText', async (source: unknown) => {
    const r = analyzeEmailText(source);
    recordEmail(r);
    return { ok: true, data: r };
  });
  handle('email:extractAttachment', async (token: unknown, index: unknown) => ({ ok: true, data: await extractAttachment(token, index) }));

  // ---- Password leak check (k-anonymity; the password is never logged or recorded in history) ----
  handle('password:checkPwned', async (password: unknown) => ({ ok: true, data: await checkPwnedPassword(gate, password) }));

  // ---- OSINT ----
  handle('osint:lookup', async (type: unknown, value: unknown, options: unknown) => {
    const o = (options ?? {}) as Record<string, unknown>;
    const r = await osint.lookup(type, value, { ct: o.ct === true, wayback: o.wayback === true, github: o.github === true, emailDns: o.emailDns === true });
    history.record({ kind: 'osint_lookup', subject: r.value.slice(0, 80), summaryKey: 'activity.summary.looked_up' });
    return { ok: true, data: r };
  });
  handle('osint:openPivot', async (type: unknown, value: unknown, pivotId: unknown) => {
    await osint.openPivot(type, value, pivotId);
    return { ok: true, data: undefined };
  });

  // ---- Forensics (read-only) ----
  const COLLECTORS = {
    processes: forensics.processes, connections: forensics.connections, services: forensics.services, drivers: forensics.drivers,
    startup: forensics.startup, tasks: forensics.tasks, users: forensics.users, software: forensics.software, usb: forensics.usb,
  } as const;
  handle('forensics:collect', async (module: unknown) => {
    if (typeof module !== 'string' || !(module in COLLECTORS)) return fail('invalid_input');
    const r = await COLLECTORS[module as keyof typeof COLLECTORS]();
    history.record({ kind: 'forensics', subject: module, summaryKey: 'activity.summary.collected' });
    return { ok: true, data: r };
  });
  handle('forensics:events', async (log: unknown, levels: unknown, max: unknown) => ({ ok: true, data: await forensics.events(log, levels, max) }));
  handle('forensics:signatures', (paths: unknown, taskId: unknown) => runTask(taskId, () => forensics.signatures(paths)));
  handle('forensics:psHistory', async () => {
    // Sensitive: may contain secrets typed on the command line. Returned to the UI only; never logged.
    logger.security('ps_history_viewed');
    return { ok: true, data: await forensics.powershellHistory() };
  });

  // ---- Network Toolkit ----
  handle('net:ping', (target: unknown, count: unknown, taskId: unknown) => runTask(taskId, (signal) => net.ping(target, count, signal)));
  handle('net:traceroute', (target: unknown, taskId: unknown) => runTask(taskId, (signal) => net.traceroute(target, signal)));
  handle('net:dns', async (name: unknown) => ({ ok: true, data: await net.dnsLookup(name) }));
  handle('net:reverse', async (ip: unknown) => ({ ok: true, data: await net.reverseLookup(ip) }));
  handle('net:portCheck', (target: unknown, ports: unknown, taskId: unknown) =>
    runTask(taskId, async (signal) => {
      const r = await net.portCheck(target, ports, signal, progress(taskId as string));
      history.record({ kind: 'port_check', subject: r.address, summaryKey: 'activity.summary.port_checked' });
      logger.security('port_check', { target: r.address, ports: r.results.length, open: r.results.filter((x) => x.state === 'open').length });
      return r;
    }),
  );
  handle('net:adapters', async () => ({ ok: true, data: await net.adapters() }));
  handle('net:routes', async () => ({ ok: true, data: await net.routes() }));
  handle('net:neighbors', async () => ({ ok: true, data: await net.neighbors() }));
  handle('net:subnets', () => ({ ok: true, data: net.localSubnets() }));
  handle('net:discover', (cidr: unknown, taskId: unknown) =>
    runTask(taskId, async (signal) => {
      const r = await net.discover(cidr, signal, progress(taskId as string));
      history.record({ kind: 'discovery', subject: r.subnet, summaryKey: 'activity.summary.discovered' });
      logger.security('network_discovery', { subnet: r.subnet, alive: r.alive.length });
      return r;
    }),
  );

  // ---- Investigations: cases, reports, threat hunting ----
  const caseOk = (c: unknown) => ({ ok: true as const, data: c });
  handle('cases:list', () => caseOk(cases.list()));
  handle('cases:get', (id: unknown) => caseOk(cases.get(id)));
  handle('cases:create', (name: unknown, desc: unknown, tags: unknown) => {
    const c = cases.create(name, desc, tags);
    logger.info('case_created', { id: c.id });
    return caseOk(c);
  });
  handle('cases:update', (id: unknown, patch: unknown) => caseOk(cases.update(id, patch)));
  handle('cases:remove', (id: unknown) => {
    cases.remove(id);
    logger.security('case_deleted', { id });
    return { ok: true, data: true };
  });
  handle('cases:addEvidence', (id: unknown, ev: unknown) => caseOk(cases.addEvidence(id, ev)));
  handle('cases:removeEvidence', (id: unknown, evId: unknown) => caseOk(cases.removeEvidence(id, evId)));
  handle('cases:addNote', (id: unknown, text: unknown) => caseOk(cases.addNote(id, text)));
  handle('cases:updateNote', (id: unknown, noteId: unknown, text: unknown) => caseOk(cases.updateNote(id, noteId, text)));
  handle('cases:removeNote', (id: unknown, noteId: unknown) => caseOk(cases.removeNote(id, noteId)));
  handle('cases:addEvent', (id: unknown, title: unknown, detail: unknown, time: unknown) => caseOk(cases.addEvent(id, title, detail, time)));

  handle('reports:generate', async (caseId: unknown, options: unknown) => {
    const rec = await reports.generate(cases.get(caseId), options);
    logger.info('report_generated', { caseId: rec.caseId, format: rec.format, language: rec.language });
    return { ok: true, data: rec };
  });
  handle('reports:list', () => ({ ok: true, data: reports.list() }));
  handle('reports:open', async (id: unknown) => {
    await reports.open(id);
    return { ok: true, data: true };
  });
  handle('reports:reveal', (id: unknown) => {
    reports.reveal(id);
    return { ok: true, data: true };
  });
  handle('reports:remove', async (id: unknown) => {
    await reports.remove(id);
    return { ok: true, data: true };
  });

  handle('hunt:search', (query: unknown, taskId: unknown) => runTask(taskId, () => hunt.search(query)));
  handle('hunt:persistence', async () => ({ ok: true, data: await hunt.persistence() }));
  handle('hunt:eventEngine', () => {
    const e = bundledEngine('hayabusa');
    return { available: !!e, version: e?.version ?? null };
  });
  handle('hunt:pickEvents', async (kind: unknown) => {
    const win = getWindow();
    const opts = kind === 'dir'
      ? { properties: ['openDirectory' as const] }
      : { properties: ['openFile' as const], filters: [{ name: 'Windows event log', extensions: ['evtx'] }] };
    const r = win ? await dialog.showOpenDialog(win, opts) : await dialog.showOpenDialog(opts);
    return r.canceled ? null : (r.filePaths[0] ?? null);
  });
  handle('hunt:events', async (source: unknown, options: unknown, taskId: unknown) => {
    const exe = bundledEngine('hayabusa')?.path;
    if (!exe) return fail('engine_not_bundled');
    const src = await parseSource(source);
    const opts = parseOptions(options);
    return runTask(taskId, async (signal) => {
      const r = await runEventHunt(exe, src, opts, signal);
      history.record({ kind: 'event_hunt', subject: src.kind === 'live' ? 'Windows' : basename(src.path), summaryKey: 'activity.summary.event_hunt' });
      logger.info('event_hunt', { source: src.kind, total: r.total, critical: r.byLevel.critical, high: r.byLevel.high, ms: r.durationMs });
      return r;
    });
  });

  // ---- Password Recovery (authorized, local; results never logged) ----
  handle('recovery:detect', async (path: unknown) => ({ ok: true, data: await detectFileEncryption(path) }));
  handle('recovery:engine', (kind: unknown) => recovery.engine(engineKind(kind)));
  handle('recovery:pickEngine', async (kind: unknown) => {
    const k = engineKind(kind);
    const win = getWindow();
    const opts = { properties: ['openFile' as const] };
    const pick = win ? await dialog.showOpenDialog(win, opts) : await dialog.showOpenDialog(opts);
    if (pick.canceled || !pick.filePaths[0]) return { ok: true, data: null };
    const prev = k === 'john' ? settings.get().johnPath : settings.get().hashcatPath;
    settings.update(k === 'john' ? { johnPath: pick.filePaths[0] } : { hashcatPath: pick.filePaths[0] });
    const info = await recovery.engine(k);
    if (!info.available) {
      settings.update(k === 'john' ? { johnPath: prev } : { hashcatPath: prev });
      return fail('engine_check_failed');
    }
    logger.security('recovery_engine_configured', { engine: k, version: info.version });
    return { ok: true, data: info };
  });
  handle('recovery:clearEngine', (kind: unknown) => {
    const k = engineKind(kind);
    settings.update(k === 'john' ? { johnPath: null } : { hashcatPath: null });
    return { ok: true, data: true };
  });
  handle('recovery:pickWordlist', async () => {
    const win = getWindow();
    const opts = { properties: ['openFile' as const] };
    const pick = win ? await dialog.showOpenDialog(win, opts) : await dialog.showOpenDialog(opts);
    return pick.canceled ? null : (pick.filePaths[0] ?? null);
  });
  handle('recovery:start', async (kind: unknown, target: unknown, mode: unknown, authorized: unknown) => {
    const info = await recovery.start(engineKind(kind), target, mode, authorized === true, (id, ev) => {
      // Progress/done events go to the window only. The recovered password is NOT logged here.
      getWindow()?.webContents.send('recovery:event', { id, ...ev });
    });
    // Log only that a session started, its engine and mode — never the target contents or any result.
    logger.security('recovery_started', { id: info.id, engine: kind, mode: (mode as { type?: string })?.type });
    return { ok: true, data: info };
  });
  handle('recovery:stop', (id: unknown) => recovery.stop(id));
  handle('recovery:setPaused', (id: unknown, paused: unknown) => recovery.setPaused(id, paused === true));

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
