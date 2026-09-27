import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from 'react';
import { AlertTriangle, CircleCheck, CircleX, Info } from 'lucide-react';
import type { Settings } from '../../shared/api';
import type { PageId } from '../nav';
import { useI18n } from '../i18n/I18nProvider';
import { useEscape } from './useEscape';

type ToastTone = 'green' | 'red' | 'amber' | 'blue';

interface ConfirmOptions {
  title: string;
  body: string;
  confirmLabel: string;
  danger?: boolean;
  /** Optional checkbox the user must tick before confirming (e.g. authorization statement). */
  requireCheck?: string;
}

interface AppCtx {
  settings: Settings;
  updateSettings: (patch: Partial<Settings>) => Promise<void>;
  page: PageId;
  navigate: (p: PageId) => void;
  toast: (tone: ToastTone, text: string) => void;
  confirm: (o: ConfirmOptions) => Promise<boolean>;
  /** Opens the File Analyzer and starts analyzing `path` (e.g. from the process list). */
  analyzeFile: (path: string) => void;
  /** Consumed once by the File Analyzer on mount. */
  takePendingFile: () => string | null;
  /** Opens a tool with a value pre-filled (from the smart search); the user still starts it. */
  openWith: (page: PageId, value: string, mode?: string) => void;
  /** The value the target page starts with (idempotent; cleared by the next navigation). */
  prefillFor: (page: PageId) => { value: string; mode?: string } | null;
  /** Changes on every openWith so an already-open page restarts with the new value. */
  viewSeq: number;
}

const Ctx = createContext<AppCtx | null>(null);

export function useApp(): AppCtx {
  const v = useContext(Ctx);
  if (!v) throw new Error('useApp outside provider');
  return v;
}

const TOAST_ICON = { green: CircleCheck, red: CircleX, amber: AlertTriangle, blue: Info };
const TOAST_TONE = { green: 'var(--green)', red: 'var(--red)', amber: 'var(--amber)', blue: 'var(--primary)' };

export function AppProvider({ settings, setSettings, initialPage, children }: {
  settings: Settings; setSettings: (s: Settings) => void; initialPage: PageId; children: ReactNode;
}) {
  const { t } = useI18n();
  const [page, setPage] = useState<PageId>(initialPage);
  const [toasts, setToasts] = useState<Array<{ id: number; tone: ToastTone; text: string }>>([]);
  const [dialog, setDialog] = useState<(ConfirmOptions & { resolve: (v: boolean) => void }) | null>(null);
  const pending = useRef<string | null>(null);
  const analyzeFile = useCallback((path: string) => {
    pending.current = path;
    setPage('file-analyzer');
  }, []);
  const takePendingFile = useCallback(() => {
    const p = pending.current;
    pending.current = null;
    return p;
  }, []);
  const prefill = useRef<{ page: PageId; value: string; mode?: string } | null>(null);
  const [viewSeq, setViewSeq] = useState(0);
  const openWith = useCallback((p: PageId, value: string, mode?: string) => {
    prefill.current = { page: p, value, mode };
    setViewSeq((n) => n + 1);
    setPage(p);
  }, []);
  const prefillFor = useCallback((p: PageId) => {
    const x = prefill.current;
    return x && x.page === p ? { value: x.value, mode: x.mode } : null;
  }, []);

  const toast = useCallback(
    (tone: ToastTone, text: string) => {
      if (!settings.notifications && tone !== 'red') return;
      const id = Date.now() + Math.random();
      setToasts((x) => [...x.slice(-3), { id, tone, text }]);
      setTimeout(() => setToasts((x) => x.filter((y) => y.id !== id)), 3800);
    },
    [settings.notifications],
  );

  const updateSettings = useCallback(
    async (patch: Partial<Settings>) => {
      const r = await window.blazma.settings.update(patch);
      if (r.ok) setSettings(r.data);
      else toast('red', t(`errors.${r.error}`));
    },
    [setSettings, toast, t],
  );

  // "Terminal" is an action, not a page: it opens the regular Windows terminal in its own window.
  const navigate = useCallback(
    (p: PageId) => {
      if (p !== 'terminal') {
        prefill.current = null;
        return setPage(p);
      }
      void window.blazma.app.openTerminal().then((r) => {
        if (r.ok) toast('green', t(`terminal.opened.${r.data}`));
        else toast('red', t(`errors.${r.error}`));
      });
    },
    [setPage, toast, t],
  );

  const [checked, setChecked] = useState(false);
  const confirm = useCallback((o: ConfirmOptions) => new Promise<boolean>((resolve) => { setChecked(false); setDialog({ ...o, resolve }); }), []);
  const close = (v: boolean) => {
    dialog?.resolve(v);
    setDialog(null);
  };
  useEscape(!!dialog, () => close(false));

  return (
    <Ctx.Provider value={{ settings, updateSettings, page, navigate, toast, confirm, analyzeFile, takePendingFile, openWith, prefillFor, viewSeq }}>
      {children}
      <div className="toasts" aria-live="polite">
        {toasts.map((x) => {
          const Icon = TOAST_ICON[x.tone];
          return (
            <div key={x.id} className="toast" style={{ '--tone': TOAST_TONE[x.tone] } as React.CSSProperties}>
              <Icon size={18} />
              <span>{x.text}</span>
            </div>
          );
        })}
      </div>
      {dialog && (
        <div className="overlay" onClick={() => close(false)}>
          <div className="dialog" role="alertdialog" aria-modal="true" aria-labelledby="confirm-title" aria-describedby="confirm-body" onClick={(e) => e.stopPropagation()}>
            <h3 id="confirm-title">{dialog.title}</h3>
            <p id="confirm-body" className="muted" style={{ margin: 0 }}>{dialog.body}</p>
            {dialog.requireCheck && (
              <label className="row" style={{ marginTop: 14, alignItems: 'flex-start', cursor: 'pointer' }}>
                <input type="checkbox" checked={checked} onChange={(e) => setChecked(e.target.checked)} style={{ marginTop: 4 }} />
                <span>{dialog.requireCheck}</span>
              </label>
            )}
            <div className="dialog-actions">
              <button className="btn ghost" onClick={() => close(false)} autoFocus>
                {t('common.cancel')}
              </button>
              <button className={`btn ${dialog.danger ? 'danger' : 'primary'}`} disabled={!!dialog.requireCheck && !checked} onClick={() => close(true)}>
                {dialog.confirmLabel}
              </button>
            </div>
          </div>
        </div>
      )}
    </Ctx.Provider>
  );
}
