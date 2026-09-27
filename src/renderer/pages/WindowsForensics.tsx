import { useEffect, useMemo, useState } from 'react';
import { Eye, FileSearch, MonitorCog, RefreshCw, ShieldAlert, ShieldCheck, TerminalSquare, TriangleAlert } from 'lucide-react';
import type {
  ConnectionRow, DriverRow, EventLogName, EventRow, ForensicsModule, ForensicsResult, ProcessRow, ServiceRow, SignatureRow, SoftwareRow, StartupRow,
  TaskRow, UsbRow, UserRow,
} from '../../shared/api';
import { Badge, Card, DataTable, EmptyState, ErrorState, FilterInput, IconTile, Ltr, Notice, Progress, Skeleton, Tabs, Toggle, useFilter, type Column, type Tone } from '../components/ui';
import { useApp } from '../components/AppContext';
import { useI18n } from '../i18n/I18nProvider';
import { formatDateTime, newTaskId } from '../format';

type Tab = ForensicsModule | 'events' | 'history';
const TABS: Tab[] = ['processes', 'connections', 'services', 'drivers', 'startup', 'tasks', 'users', 'software', 'events', 'usb', 'history'];

function useCollector<T>(module: ForensicsModule) {
  const [state, setState] = useState<{ data?: ForensicsResult<T>; error?: string; loading: boolean }>({ loading: true });
  const load = async () => {
    setState((s) => ({ ...s, loading: true }));
    const r = await window.blazma.forensics.collect(module);
    setState(r.ok ? { data: r.data as ForensicsResult<T>, loading: false } : { error: r.error, loading: false });
  };
  useEffect(() => void load(), [module]); // eslint-disable-line react-hooks/exhaustive-deps
  return { ...state, reload: load };
}

function Meta({ data, count, total, onReload }: { data: ForensicsResult<unknown>; count: number; total: number; onReload: () => void }) {
  const { t, locale } = useI18n();
  return (
    <div className="row-wrap" style={{ alignItems: 'center' }}>
      <Badge tone="blue">{t('forensics.count', { shown: count, total })}</Badge>
      <Badge tone="gray">{t(`forensics.source.${data.source}`)}</Badge>
      {data.elevated === true && <Badge tone="amber">{t('forensics.elevated')}</Badge>}
      {data.elevated === false && <Badge tone="gray">{t('forensics.standardUser')}</Badge>}
      <span className="small dim">{t('common.checkedAt', { time: formatDateTime(locale, data.collectedAt) })}</span>
      <button className="icon-btn" style={{ width: 30, height: 30 }} aria-label={t('common.refresh')} title={t('common.refresh')} onClick={onReload}><RefreshCw size={14} /></button>
    </div>
  );
}

function Collected<T>({ module, columns, fields, extra, prefilter }: {
  module: ForensicsModule;
  columns: Column<T>[];
  fields: (r: T) => Array<string | number | null | undefined>;
  extra?: (rows: T[]) => React.ReactNode;
  prefilter?: (r: T) => boolean;
}) {
  const { t } = useI18n();
  const c = useCollector<T>(module);
  const base = useMemo(() => (c.data ? (prefilter ? c.data.rows.filter(prefilter) : c.data.rows) : []), [c.data, prefilter]);
  const f = useFilter(base, fields);
  if (c.loading && !c.data) return <Card><Skeleton h={160} /></Card>;
  if (c.error) return <Card><ErrorState code={c.error} onRetry={() => void c.reload()} /></Card>;
  const data = c.data!;
  return (
    <div className="col" style={{ gap: 12 }}>
      {data.partial && <Notice tone="amber" icon={TriangleAlert}>{t(data.partial)}</Notice>}
      <Card>
        <div className="row-wrap" style={{ justifyContent: 'space-between', marginBottom: 12 }}>
          <FilterInput value={f.q} onChange={f.setQ} placeholder={t('forensics.filter')} />
          <Meta data={data as ForensicsResult<unknown>} count={f.filtered.length} total={data.rows.length} onReload={() => void c.reload()} />
        </div>
        {extra?.(f.filtered)}
        {f.filtered.length === 0 ? <EmptyState title={t('forensics.empty')} /> : (
          <DataTable<T> maxHeight={560} rowKey={(_, i) => String(i)} rows={f.filtered.slice(0, 2000)} columns={columns} />
        )}
      </Card>
    </div>
  );
}

const SIG_TONE: Record<string, Tone> = { valid: 'green', not_signed: 'amber', hash_mismatch: 'red', not_trusted: 'red', unknown_error: 'gray', other: 'gray' };

function SignatureBadge({ s }: { s?: SignatureRow }) {
  const { t } = useI18n();
  if (!s) return <span className="dim small">—</span>;
  return (
    <span title={s.publisher ?? undefined}>
      <Badge tone={SIG_TONE[s.status] ?? 'gray'}>{t(`file.sig.${s.status}`, { raw: s.status })}</Badge>
      {s.publisher && <div className="tiny dim"><Ltr>{s.publisher}</Ltr></div>}
    </span>
  );
}

/** Batch Authenticode verification of unique paths shown in a table (Windows only). */
function useSignatures() {
  const [sigs, setSigs] = useState<Map<string, SignatureRow>>(new Map());
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const check = async (paths: string[]) => {
    setRunning(true);
    setError(null);
    const r = await window.blazma.forensics.signatures([...new Set(paths)], newTaskId());
    setRunning(false);
    if (r.ok) setSigs(new Map(r.data.map((x) => [x.path.toLowerCase(), x])));
    else setError(r.error);
  };
  return { sigs, running, error, check, get: (p: string | null) => (p ? sigs.get(p.toLowerCase()) : undefined) };
}

function SignatureBar({ paths, sig }: { paths: string[]; sig: ReturnType<typeof useSignatures> }) {
  const { t } = useI18n();
  const isWin = navigator.userAgent.includes('Windows');
  return (
    <div className="row-wrap" style={{ marginBottom: 12, alignItems: 'center' }}>
      <button className="btn sm" disabled={!isWin || sig.running || paths.length === 0} onClick={() => void sig.check(paths)}>
        <ShieldCheck size={13} /> {t('forensics.checkSignatures', { count: new Set(paths).size })}
      </button>
      {!isWin && <span className="small dim">{t('errors.unsupported_platform')}</span>}
      {sig.running && <div style={{ width: 160 }}><Progress indeterminate /></div>}
      {sig.error && <span className="small" style={{ color: 'var(--amber)' }}>{t(`errors.${sig.error}`)}</span>}
    </div>
  );
}

function Processes() {
  const { t, locale } = useI18n();
  const { analyzeFile } = useApp();
  const sig = useSignatures();
  const [conns, setConns] = useState<Map<number, number>>(new Map());
  useEffect(() => {
    void window.blazma.forensics.collect('connections').then((r) => {
      if (!r.ok) return;
      const m = new Map<number, number>();
      for (const c of (r.data as ForensicsResult<ConnectionRow>).rows) if (c.pid !== null && c.remoteAddress) m.set(c.pid, (m.get(c.pid) ?? 0) + 1);
      setConns(m);
    });
  }, []);
  return (
    <Collected<ProcessRow>
      module="processes"
      fields={(r) => [r.pid, r.name, r.path, r.user, r.commandLine]}
      extra={(rows) => <SignatureBar paths={rows.map((r) => r.path).filter((p): p is string => !!p)} sig={sig} />}
      columns={[
        { key: 'pid', label: 'PID', width: 70, render: (r) => <Ltr mono>{r.pid}</Ltr> },
        { key: 'n', label: t('forensics.col.name'), render: (r) => <div><Ltr>{r.name}</Ltr>{r.ppid !== null && <div className="tiny dim">PPID <Ltr mono>{r.ppid}</Ltr></div>}</div> },
        { key: 'p', label: t('forensics.col.path'), render: (r) => (r.path ? <Ltr mono breakAll className="small">{r.path}</Ltr> : <span className="dim small">{t('forensics.noAccess')}</span>) },
        { key: 'u', label: t('forensics.col.user'), render: (r) => <Ltr className="small">{r.user ?? '—'}</Ltr> },
        { key: 's', label: t('forensics.col.signature'), render: (r) => <SignatureBadge s={sig.get(r.path)} /> },
        { key: 'c', label: t('forensics.col.connections'), render: (r) => (conns.get(r.pid) ? <Badge tone="blue">{conns.get(r.pid)}</Badge> : <span className="dim">0</span>) },
        { key: 't', label: t('forensics.col.started'), render: (r) => <span className="small nowrap">{formatDateTime(locale, r.started)}</span> },
        { key: 'a', label: '', render: (r) => r.path && <button className="btn sm" title={t('forensics.analyzeHint')} onClick={() => analyzeFile(r.path!)}><FileSearch size={13} /> {t('forensics.analyze')}</button> },
      ]}
    />
  );
}

function Connections() {
  const { t } = useI18n();
  const [established, setEstablished] = useState(false);
  const pre = useMemo(() => (established ? (r: ConnectionRow) => r.state === 'ESTABLISHED' || r.state === 'Established' : undefined), [established]);
  return (
    <div className="col" style={{ gap: 12 }}>
      <div className="row"><Toggle checked={established} label={t('forensics.onlyEstablished')} onChange={setEstablished} /><span>{t('forensics.onlyEstablished')}</span></div>
      <Collected<ConnectionRow>
        module="connections"
        prefilter={pre}
        fields={(r) => [r.localAddress, r.localPort, r.remoteAddress, r.remotePort, r.state, r.process, r.pid]}
        columns={[
          { key: 'pr', label: t('forensics.col.protocol'), width: 70, render: (r) => <Badge tone={r.protocol === 'TCP' ? 'blue' : 'purple'}>{r.protocol}</Badge> },
          { key: 'l', label: t('forensics.col.local'), render: (r) => <Ltr mono className="small">{`${r.localAddress}:${r.localPort}`}</Ltr> },
          { key: 'r', label: t('forensics.col.remote'), render: (r) => (r.remoteAddress ? <Ltr mono className="small">{`${r.remoteAddress}:${r.remotePort}`}</Ltr> : <span className="dim">—</span>) },
          { key: 's', label: t('forensics.col.state'), render: (r) => (r.state ? <Badge tone={/listen/i.test(r.state) ? 'amber' : /establ/i.test(r.state) ? 'green' : 'gray'}>{r.state}</Badge> : '—') },
          { key: 'p', label: t('forensics.col.process'), render: (r) => (r.pid !== null ? <span><Ltr>{r.process ?? '?'}</Ltr> <span className="dim small">(<Ltr mono>{r.pid}</Ltr>)</span></span> : <span className="dim small">{t('forensics.noAccess')}</span>) },
        ]}
      />
    </div>
  );
}

function Services() {
  const { t } = useI18n();
  const sig = useSignatures();
  return (
    <Collected<ServiceRow>
      module="services"
      fields={(r) => [r.name, r.displayName, r.state, r.startMode, r.binaryPath, r.account]}
      extra={(rows) => <SignatureBar paths={rows.map((r) => r.binaryPath).filter((p): p is string => !!p)} sig={sig} />}
      columns={[
        { key: 'n', label: t('forensics.col.name'), render: (r) => <div><Ltr>{r.displayName ?? r.name}</Ltr><div className="tiny dim"><Ltr mono>{r.name}</Ltr></div></div> },
        { key: 's', label: t('forensics.col.state'), render: (r) => <Badge tone={r.state === 'Running' ? 'green' : 'gray'}>{r.state ?? '—'}</Badge> },
        { key: 'm', label: t('forensics.col.startup'), render: (r) => <span className="small">{r.startMode ?? '—'}</span> },
        {
          key: 'b', label: t('forensics.col.binary'),
          render: (r) => (
            <div>
              <Ltr mono breakAll className="small">{r.binaryPath ?? '—'}</Ltr>
              {r.unquotedPath && <div><Badge tone="red" icon={ShieldAlert}>{t('forensics.unquoted')}</Badge></div>}
            </div>
          ),
        },
        { key: 'a', label: t('forensics.col.account'), render: (r) => <Ltr className="small">{r.account ?? '—'}</Ltr> },
        { key: 'g', label: t('forensics.col.signature'), render: (r) => <SignatureBadge s={sig.get(r.binaryPath)} /> },
      ]}
    />
  );
}

function Drivers() {
  const { t } = useI18n();
  const sig = useSignatures();
  return (
    <Collected<DriverRow>
      module="drivers"
      fields={(r) => [r.name, r.displayName, r.state, r.path]}
      extra={(rows) => <SignatureBar paths={rows.map((r) => r.path).filter((p): p is string => !!p)} sig={sig} />}
      columns={[
        { key: 'n', label: t('forensics.col.name'), render: (r) => <div><Ltr>{r.displayName ?? r.name}</Ltr><div className="tiny dim"><Ltr mono>{r.name}</Ltr></div></div> },
        { key: 's', label: t('forensics.col.state'), render: (r) => <Badge tone={r.state === 'Running' ? 'green' : 'gray'}>{r.state ?? '—'}</Badge> },
        { key: 'm', label: t('forensics.col.startup'), render: (r) => <span className="small">{r.startMode ?? '—'}</span> },
        { key: 'p', label: t('forensics.col.path'), render: (r) => <Ltr mono breakAll className="small">{r.path ?? '—'}</Ltr> },
        { key: 'g', label: t('forensics.col.signature'), render: (r) => <SignatureBadge s={sig.get(r.path)} /> },
      ]}
    />
  );
}

function Startup() {
  const { t } = useI18n();
  return (
    <Collected<StartupRow>
      module="startup"
      fields={(r) => [r.name, r.command, r.location, r.user]}
      columns={[
        { key: 'n', label: t('forensics.col.name'), render: (r) => <Ltr>{r.name}</Ltr> },
        { key: 'c', label: t('forensics.col.command'), render: (r) => <Ltr mono breakAll className="small">{r.command}</Ltr> },
        { key: 'l', label: t('forensics.col.location'), render: (r) => <Ltr mono breakAll className="small">{r.location}</Ltr> },
        { key: 'u', label: t('forensics.col.user'), render: (r) => <Ltr className="small">{r.user ?? '—'}</Ltr> },
      ]}
    />
  );
}

function Tasks() {
  const { t } = useI18n();
  const [hideMs, setHideMs] = useState(true);
  const pre = useMemo(() => (hideMs ? (r: TaskRow) => !r.microsoft : undefined), [hideMs]);
  return (
    <div className="col" style={{ gap: 12 }}>
      <div className="row"><Toggle checked={hideMs} label={t('forensics.hideMicrosoft')} onChange={setHideMs} /><span>{t('forensics.hideMicrosoft')}</span></div>
      <Collected<TaskRow>
        module="tasks"
        prefilter={pre}
        fields={(r) => [r.name, r.path, r.author, ...r.actions]}
        columns={[
          { key: 'n', label: t('forensics.col.name'), render: (r) => <div><Ltr>{r.name}</Ltr><div className="tiny dim"><Ltr mono>{r.path}</Ltr></div></div> },
          { key: 's', label: t('forensics.col.state'), render: (r) => <Badge tone={r.state === 'Ready' || r.state === 'Running' ? 'green' : 'gray'}>{r.state ?? '—'}</Badge> },
          { key: 'a', label: t('forensics.col.actions'), render: (r) => <div className="col" style={{ gap: 2 }}>{r.actions.map((a, i) => <Ltr key={i} mono breakAll className="small">{a}</Ltr>)}</div> },
          { key: 'au', label: t('forensics.col.author'), render: (r) => <Ltr className="small">{r.author ?? '—'}</Ltr> },
        ]}
      />
    </div>
  );
}

function Users() {
  const { t, locale } = useI18n();
  return (
    <Collected<UserRow>
      module="users"
      fields={(r) => [r.name, r.description]}
      columns={[
        { key: 'n', label: t('forensics.col.name'), render: (r) => <span className="row"><Ltr>{r.name}</Ltr>{r.admin && <Badge tone="amber">{t('forensics.admin')}</Badge>}</span> },
        { key: 'e', label: t('forensics.col.enabled'), render: (r) => (r.enabled === null ? '—' : <Badge tone={r.enabled ? 'green' : 'gray'}>{t(r.enabled ? 'common.yes' : 'common.no')}</Badge>) },
        { key: 'l', label: t('forensics.col.lastLogon'), render: (r) => <span className="small">{formatDateTime(locale, r.lastLogon)}</span> },
        { key: 'd', label: t('forensics.col.description'), render: (r) => <span className="small">{r.description ?? ''}</span> },
      ]}
    />
  );
}

function Software() {
  const { t } = useI18n();
  return (
    <Collected<SoftwareRow>
      module="software"
      fields={(r) => [r.name, r.publisher, r.version]}
      columns={[
        { key: 'n', label: t('forensics.col.name'), render: (r) => <Ltr>{r.name}</Ltr> },
        { key: 'v', label: t('forensics.col.version'), render: (r) => <Ltr mono className="small">{r.version ?? '—'}</Ltr> },
        { key: 'p', label: t('forensics.col.publisher'), render: (r) => <Ltr className="small">{r.publisher ?? '—'}</Ltr> },
        { key: 'd', label: t('forensics.col.installed'), render: (r) => <Ltr className="small">{r.installDate ?? '—'}</Ltr> },
        { key: 's', label: t('forensics.col.scope'), render: (r) => <Badge tone={r.scope === 'user' ? 'purple' : 'blue'}>{t(`forensics.scope.${r.scope}`)}</Badge> },
      ]}
    />
  );
}

function Usb() {
  const { t } = useI18n();
  return (
    <Collected<UsbRow>
      module="usb"
      fields={(r) => [r.name, r.serial, r.vendorProduct]}
      columns={[
        { key: 'n', label: t('forensics.col.device'), render: (r) => <Ltr>{r.name}</Ltr> },
        { key: 's', label: t('forensics.col.serial'), render: (r) => <Ltr mono className="small">{r.serial ?? '—'}</Ltr> },
        { key: 'v', label: t('forensics.col.vendorProduct'), render: (r) => <Ltr mono breakAll className="small">{r.vendorProduct ?? '—'}</Ltr> },
      ]}
    />
  );
}

const LOGS: EventLogName[] = ['System', 'Application', 'Security', 'Windows PowerShell', 'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-Windows Defender/Operational'];
const LEVELS = [1, 2, 3, 4] as const;

function Events() {
  const { t, locale } = useI18n();
  const [log, setLog] = useState<EventLogName>('System');
  const [levels, setLevels] = useState<number[]>([1, 2, 3]);
  const [max, setMax] = useState(100);
  const [state, setState] = useState<{ loading?: boolean; data?: ForensicsResult<EventRow>; error?: string }>({});
  const f = useFilter(state.data?.rows, (r) => [r.id, r.provider, r.message, r.level]);
  const load = async () => {
    setState({ loading: true });
    const r = await window.blazma.forensics.events(log, levels, max);
    setState(r.ok ? { data: r.data } : { error: r.error });
  };
  return (
    <div className="col" style={{ gap: 12 }}>
      <Card>
        <div className="row-wrap" style={{ alignItems: 'flex-end', gap: 14 }}>
          <div className="field">
            <label>{t('forensics.eventLog')}</label>
            <select className="select" style={{ width: 320 }} value={log} onChange={(e) => setLog(e.target.value as EventLogName)}>
              {LOGS.map((l) => <option key={l} value={l}>{l}</option>)}
            </select>
          </div>
          <div className="field">
            <label>{t('forensics.levels')}</label>
            <div className="row-wrap">
              {LEVELS.map((lv) => (
                <button key={lv} type="button" className="opt" aria-pressed={levels.includes(lv)} onClick={() => setLevels((x) => (x.includes(lv) ? x.filter((y) => y !== lv) : [...x, lv]))}>
                  {t(`forensics.level.${lv}`)}
                </button>
              ))}
            </div>
          </div>
          <div className="field">
            <label>{t('forensics.maxEvents')}</label>
            <select className="select" style={{ width: 100 }} value={max} onChange={(e) => setMax(Number(e.target.value))}>
              {[50, 100, 250, 500].map((n) => <option key={n} value={n}>{n}</option>)}
            </select>
          </div>
          <button className="btn primary" disabled={state.loading} onClick={() => void load()}>{t('forensics.loadEvents')}</button>
        </div>
        {log === 'Security' && <div style={{ marginTop: 12 }}><Notice tone="amber" icon={ShieldAlert}>{t('forensics.securityLogNote')}</Notice></div>}
      </Card>
      {state.loading && <Card><Progress indeterminate /></Card>}
      {state.error && <Card><ErrorState code={state.error} /></Card>}
      {state.data && (
        <Card>
          <div className="row-wrap" style={{ justifyContent: 'space-between', marginBottom: 12 }}>
            <FilterInput value={f.q} onChange={f.setQ} placeholder={t('forensics.filter')} />
            <Meta data={state.data as ForensicsResult<unknown>} count={f.filtered.length} total={state.data.rows.length} onReload={() => void load()} />
          </div>
          {f.filtered.length === 0 ? <EmptyState title={t('forensics.noEvents')} /> : (
            <DataTable<EventRow>
              maxHeight={560}
              rowKey={(_, i) => String(i)}
              rows={f.filtered}
              columns={[
                { key: 't', label: t('forensics.col.time'), render: (r) => <span className="small nowrap">{formatDateTime(locale, r.time)}</span> },
                { key: 'l', label: t('forensics.col.level'), render: (r) => <Badge tone={/crit|err/i.test(r.level ?? '') ? 'red' : /warn/i.test(r.level ?? '') ? 'amber' : 'gray'}>{r.level ?? '—'}</Badge> },
                { key: 'i', label: 'ID', render: (r) => <Ltr mono>{r.id}</Ltr> },
                { key: 'p', label: t('forensics.col.provider'), render: (r) => <Ltr className="small">{r.provider ?? '—'}</Ltr> },
                { key: 'm', label: t('forensics.col.message'), render: (r) => <div className="small" dir="auto" style={{ whiteSpace: 'pre-wrap', maxHeight: 90, overflow: 'auto' }}>{r.message}</div> },
              ]}
            />
          )}
        </Card>
      )}
    </div>
  );
}

function History() {
  const { t } = useI18n();
  const { confirm } = useApp();
  const [state, setState] = useState<{ data?: { path: string; lines: string[]; total: number }; error?: string; loading?: boolean }>({});
  const f = useFilter(state.data?.lines, (l) => [l]);
  return (
    <Card title={t('forensics.psHistory')} explain="ps_history" icon={TerminalSquare} tone="purple">
      <Notice tone="amber" icon={TriangleAlert}>{t('forensics.psHistoryWarning')}</Notice>
      {!state.data && (
        <button
          className="btn primary"
          style={{ marginTop: 12 }}
          disabled={state.loading}
          onClick={async () => {
            if (!(await confirm({ title: t('forensics.psHistory'), body: t('forensics.psHistoryWarning'), confirmLabel: t('forensics.show') }))) return;
            setState({ loading: true });
            const r = await window.blazma.forensics.powershellHistory();
            setState(r.ok ? { data: r.data } : { error: r.error });
          }}
        >
          <Eye size={15} /> {t('forensics.show')}
        </button>
      )}
      {state.error && <div style={{ marginTop: 12 }}><ErrorState code={state.error} /></div>}
      {state.data && (
        <div style={{ marginTop: 12 }}>
          <div className="row-wrap" style={{ justifyContent: 'space-between', marginBottom: 10 }}>
            <FilterInput value={f.q} onChange={f.setQ} placeholder={t('forensics.filter')} />
            <span className="small dim">{t('forensics.historyCount', { shown: state.data.lines.length, total: state.data.total })} · <Ltr mono>{state.data.path}</Ltr></span>
          </div>
          <pre className="table-wrap mono small" dir="ltr" style={{ padding: 12, margin: 0, maxHeight: 520, whiteSpace: 'pre-wrap' }}>{f.filtered.join('\n')}</pre>
        </div>
      )}
    </Card>
  );
}

export function WindowsForensics() {
  const { t } = useI18n();
  const [tab, setTab] = useState<Tab>('processes');
  const winOnly: Tab[] = ['services', 'drivers', 'startup', 'tasks', 'users', 'software', 'events', 'usb'];
  const isWin = navigator.userAgent.includes('Windows');
  return (
    <div className="page">
      <div className="page-head">
        <IconTile icon={MonitorCog} tone="blue" />
        <div>
          <h1 className="page-title">{t('forensics.title')}</h1>
          <div className="page-sub">{t('forensics.subtitle')}</div>
        </div>
      </div>
      <div style={{ overflowX: 'auto' }}>
        <Tabs<Tab> value={tab} onChange={setTab} items={TABS.map((id) => ({ id, label: t(`forensics.tab.${id}`) }))} />
      </div>
      <div className="col" style={{ gap: 12 }}>
        <Notice tone="blue" icon={ShieldCheck}>{t('forensics.readOnlyNote')}</Notice>
        {!isWin && winOnly.includes(tab) ? (
          <Card><EmptyState icon={MonitorCog} title={t('forensics.windowsOnly')} hint={t('errors.unsupported_platform')} /></Card>
        ) : (
          <>
            {tab === 'processes' && <Processes />}
            {tab === 'connections' && <Connections />}
            {tab === 'services' && <Services />}
            {tab === 'drivers' && <Drivers />}
            {tab === 'startup' && <Startup />}
            {tab === 'tasks' && <Tasks />}
            {tab === 'users' && <Users />}
            {tab === 'software' && <Software />}
            {tab === 'events' && <Events />}
            {tab === 'usb' && <Usb />}
            {tab === 'history' && <History />}
          </>
        )}
      </div>
    </div>
  );
}
