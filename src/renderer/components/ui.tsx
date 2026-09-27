import { useEffect, useRef, useState, type CSSProperties, type ReactNode } from 'react';
import { AlertTriangle, Check, CircleHelp, Copy, Inbox, Info, UploadCloud } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { useI18n } from '../i18n/I18nProvider';
import { useApp } from './AppContext';

export type Tone = 'blue' | 'cyan' | 'green' | 'amber' | 'red' | 'purple' | 'gray';
const TONE_VAR: Record<Tone, string> = {
  blue: 'var(--primary)', cyan: 'var(--cyan)', green: 'var(--green)', amber: 'var(--amber)', red: 'var(--red)', purple: 'var(--purple)', gray: '#7d8db0',
};

export function Card({ title, subtitle, icon, tone = 'blue', actions, children, className = '', style, explain }: {
  title?: ReactNode; subtitle?: ReactNode; icon?: LucideIcon; tone?: Tone; actions?: ReactNode; children?: ReactNode; className?: string; style?: CSSProperties;
  /** Glossary term (explain.<term>) shown as a "What does this mean?" button next to the title. */
  explain?: string;
}) {
  const Icon = icon;
  return (
    <section className={`card ${className}`} style={style}>
      {(title || actions) && (
        <header className="card-head">
          {Icon && <IconTile icon={Icon} tone={tone} small />}
          <div style={{ flex: 1, minWidth: 0 }}>
            {title && <h3 className="card-title">{title}{explain && <Explain term={explain} />}</h3>}
            {subtitle && <div className="card-sub">{subtitle}</div>}
          </div>
          {actions}
        </header>
      )}
      {children}
    </section>
  );
}

export function IconTile({ icon: Icon, tone = 'blue', small = false }: { icon: LucideIcon; tone?: Tone; small?: boolean }) {
  return (
    <span className={`icon-tile ${small ? 'sm' : ''}`} style={{ '--tile': TONE_VAR[tone] } as CSSProperties}>
      <Icon size={small ? 17 : 22} strokeWidth={1.8} />
    </span>
  );
}

export function Badge({ tone = 'blue', children, icon: Icon }: { tone?: Tone; children: ReactNode; icon?: LucideIcon }) {
  return (
    <span className={`badge tone-${tone}`}>
      {Icon && <Icon size={12} />}
      {children}
    </span>
  );
}

export function Dot({ tone }: { tone: Tone }) {
  return <span className="dot" style={{ color: TONE_VAR[tone] }} />;
}

export function Progress({ value, indeterminate = false }: { value?: number; indeterminate?: boolean }) {
  return (
    <div className={`progress ${indeterminate ? 'indeterminate' : ''}`} role="progressbar" aria-valuenow={value} aria-valuemin={0} aria-valuemax={100}>
      <span style={{ width: `${Math.max(0, Math.min(100, value ?? 0))}%` }} />
    </div>
  );
}

export function Skeleton({ w = '100%', h = 14, style }: { w?: number | string; h?: number; style?: CSSProperties }) {
  return <span className="skeleton" style={{ width: w, height: h, ...style }} />;
}

/** Wraps technical values (IP, hash, path, URL) so they stay LTR inside Arabic text. */
export function Ltr({ children, mono = false, breakAll = false, className = '' }: { children: ReactNode; mono?: boolean; breakAll?: boolean; className?: string }) {
  return (
    <bdi dir="ltr" className={`ltr ${mono ? 'mono' : ''} ${breakAll ? 'break' : ''} ${className}`}>
      {children}
    </bdi>
  );
}

export function EmptyState({ icon: Icon = Inbox, title, hint, children }: { icon?: LucideIcon; title: string; hint?: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <Icon className="empty-icon" size={34} strokeWidth={1.5} />
      <div className="empty-title">{title}</div>
      {hint && <div className="small">{hint}</div>}
      {children}
    </div>
  );
}

export function Notice({ tone = 'blue', icon: Icon = Info, children }: { tone?: Tone; icon?: LucideIcon; children: ReactNode }) {
  return (
    <div className={`notice tone-${tone}`}>
      <Icon size={16} />
      <div>{children}</div>
    </div>
  );
}

export function ErrorState({ code, onRetry }: { code: string; onRetry?: () => void }) {
  const { t } = useI18n();
  return (
    <div className="empty">
      <AlertTriangle className="empty-icon" size={30} color="var(--amber)" />
      <div className="empty-title">{t('errors.title')}</div>
      <div className="small">{t(`errors.${code}`)}</div>
      {onRetry && (
        <button className="btn sm" onClick={onRetry}>
          {t('common.retry')}
        </button>
      )}
    </div>
  );
}

export function CopyButton({ value }: { value: string }) {
  const { t } = useI18n();
  const { toast } = useApp();
  const [done, setDone] = useState(false);
  return (
    <button
      className="icon-btn"
      style={{ width: 28, height: 28 }}
      title={t('common.copy')}
      aria-label={t('common.copy')}
      onClick={async () => {
        await navigator.clipboard.writeText(value);
        setDone(true);
        toast('green', t('common.copied'));
        setTimeout(() => setDone(false), 1200);
      }}
    >
      {done ? <Check size={14} color="var(--green)" /> : <Copy size={14} />}
    </button>
  );
}

export function Toggle({ checked, onChange, label, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: string; disabled?: boolean }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      className="toggle"
      disabled={disabled}
      onClick={() => onChange(!checked)}
    />
  );
}

export function Tabs<T extends string>({ value, onChange, items }: { value: T; onChange: (v: T) => void; items: Array<{ id: T; label: string }> }) {
  return (
    <div className="tabs" role="tablist">
      {items.map((it) => (
        <button key={it.id} role="tab" aria-selected={value === it.id} className={value === it.id ? 'active' : ''} onClick={() => onChange(it.id)}>
          {it.label}
        </button>
      ))}
    </div>
  );
}

/** Circular gauge (SVG). Value 0..100 or null (loading). */
export function Gauge({ value, label, color, size = 118, unit = '%' }: { value: number | null; label: string; color: string; size?: number; unit?: string }) {
  const { dir } = useI18n();
  const r = (size - 14) / 2;
  const c = 2 * Math.PI * r;
  const v = value ?? 0;
  return (
    <div className="gauge" style={{ width: size, height: size }}>
      <svg width={size} height={size} style={{ transform: `rotate(-90deg) ${dir === 'rtl' ? 'scaleY(-1)' : ''}` }}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgba(100,130,190,0.14)" strokeWidth={9} />
        <circle
          className="arc"
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={9}
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={c * (1 - v / 100)}
          style={{ filter: `drop-shadow(0 0 6px ${color})` }}
        />
      </svg>
      <div className="gauge-center">
        <div>
          <div className="gauge-label">{label}</div>
          <div className="gauge-value">{value === null ? '—' : `${Math.round(v)}${unit}`}</div>
        </div>
      </div>
    </div>
  );
}

/** Minimal sparkline for a series of 0..100 values. Time flows toward the inline-end. */
export function Sparkline({ values, color, height = 40 }: { values: number[]; color: string; height?: number }) {
  const { dir } = useI18n();
  const w = 200;
  if (values.length < 2) return <Skeleton h={height} />;
  const step = w / (values.length - 1);
  const pts = values.map((v, i) => `${(i * step).toFixed(1)},${(height - (v / 100) * (height - 4) - 2).toFixed(1)}`);
  const id = `sg-${color.replace(/[^a-z0-9]/gi, '')}`;
  return (
    <svg viewBox={`0 0 ${w} ${height}`} preserveAspectRatio="none" style={{ width: '100%', height, transform: dir === 'rtl' ? 'scaleX(-1)' : undefined }} aria-hidden="true">
      <defs>
        <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor={color} stopOpacity="0.35" />
          <stop offset="1" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <polygon points={`0,${height} ${pts.join(' ')} ${w},${height}`} fill={`url(#${id})`} />
      <polyline points={pts.join(' ')} fill="none" stroke={color} strokeWidth="1.8" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

export interface Column<R> {
  key: string;
  label: string;
  render: (row: R) => ReactNode;
  width?: number | string;
}

export function DataTable<R>({ columns, rows, rowKey, maxHeight }: { columns: Column<R>[]; rows: R[]; rowKey: (r: R, i: number) => string; maxHeight?: number }) {
  return (
    <div className="table-wrap" style={{ maxHeight }}>
      <table className="data">
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key} style={{ width: c.width }}>
                {c.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={rowKey(r, i)}>
              {columns.map((c) => (
                <td key={c.key}>{c.render(r)}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Drag-and-drop file area. Paths are resolved through the preload (webUtils), never guessed. */
export function FileDrop({ onFile, title, hint, activeText, browseLabel, onBrowse }: {
  onFile: (path: string) => void; title: string; hint: string; activeText: string; browseLabel: string;
  /** Custom file dialog (e.g. one with a file-type filter); defaults to the generic picker. */
  onBrowse?: () => void;
}) {
  const [active, setActive] = useState(false);
  const depth = useRef(0);
  return (
    <div
      className={`dropzone ${active ? 'active' : ''}`}
      onDragEnter={(e) => {
        e.preventDefault();
        depth.current++;
        setActive(true);
      }}
      onDragOver={(e) => e.preventDefault()}
      onDragLeave={() => {
        depth.current = Math.max(0, depth.current - 1);
        if (depth.current === 0) setActive(false);
      }}
      onDrop={(e) => {
        e.preventDefault();
        depth.current = 0;
        setActive(false);
        const f = e.dataTransfer.files[0];
        if (f) {
          const p = window.blazma.files.pathForFile(f);
          if (p) onFile(p);
        }
      }}
    >
      <div className="drop-icon">
        <UploadCloud size={32} strokeWidth={1.6} />
      </div>
      <div style={{ fontSize: 17, fontWeight: 600 }}>{active ? activeText : title}</div>
      <div className="muted small">{hint}</div>
      <button
        className="btn primary"
        onClick={async () => {
          if (onBrowse) return onBrowse();
          const p = await window.blazma.files.pickFile();
          if (p) onFile(p);
        }}
      >
        {browseLabel}
      </button>
    </div>
  );
}

/** Polls an async loader on an interval; keeps the last good value while refreshing. */
export function usePoll<T>(loader: () => Promise<T>, intervalMs: number | null, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let alive = true;
    const run = async () => {
      try {
        const v = await loader();
        if (alive) {
          setData(v);
          setError(null);
        }
      } catch (e) {
        if (alive) setError(e instanceof Error ? e.message : 'internal_error');
      }
    };
    void run();
    const id = intervalMs ? setInterval(run, intervalMs) : null;
    return () => {
      alive = false;
      if (id) clearInterval(id);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [intervalMs, tick, ...deps]);
  return { data, error, reload: () => setTick((x) => x + 1) };
}

/** Case-insensitive client-side filter over selected fields. */
export function useFilter<R>(rows: R[] | null | undefined, fields: (r: R) => Array<string | number | null | undefined>) {
  const [q, setQ] = useState('');
  const filtered = !rows ? [] : !q.trim() ? rows : rows.filter((r) => fields(r).some((f) => f !== null && f !== undefined && String(f).toLowerCase().includes(q.trim().toLowerCase())));
  return { q, setQ, filtered };
}

export function FilterInput({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder: string }) {
  return (
    <input className="input" style={{ maxWidth: 280, height: 34 }} value={value} placeholder={placeholder} aria-label={placeholder} onChange={(e) => onChange(e.target.value)} />
  );
}

/** "What does this mean?": a small help button that explains a technical term in plain language. */
export function Explain({ term }: { term: string }) {
  const { t } = useI18n();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLSpanElement>(null);
  useEffect(() => {
    if (!open) return;
    const click = (e: MouseEvent) => {
      if (!ref.current?.contains(e.target as Node)) setOpen(false);
    };
    const key = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', click);
    window.addEventListener('keydown', key);
    return () => {
      document.removeEventListener('mousedown', click);
      window.removeEventListener('keydown', key);
    };
  }, [open]);
  const title = t(`explain.${term}.title`);
  return (
    <span className="explain" ref={ref}>
      <button type="button" className="explain-btn" aria-label={t('explain.ask', { term: title })} title={t('explain.ask', { term: title })} aria-expanded={open} onClick={() => setOpen((o) => !o)}>
        <CircleHelp size={14} />
      </button>
      {open && (
        <span className="explain-pop" role="note">
          <strong>{title}</strong>
          <span>{t(`explain.${term}.text`)}</span>
        </span>
      )}
    </span>
  );
}
