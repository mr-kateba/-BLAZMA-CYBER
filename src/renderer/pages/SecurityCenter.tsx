import { useEffect, useState } from 'react';
import {
  CircleCheck, FileSearch, FolderSearch, History, RotateCcw, ScanSearch, ShieldAlert, ShieldCheck, ShieldHalf, Trash2, TriangleAlert, X, Zap, type LucideIcon,
} from 'lucide-react';
import type { DefenderScanKind, DefenderScanResult, DefenderThreat, FileAnalysis, QuarantineEntry, SecurityStatus, YaraEngineInfo } from '../../shared/api';
import { Badge, Card, DataTable, EmptyState, ErrorState, IconTile, Ltr, Notice, Progress, Skeleton, Tabs, usePoll, type Tone } from '../components/ui';
import { useApp } from '../components/AppContext';
import { useI18n } from '../i18n/I18nProvider';
import { formatBytes, formatDateTime, formatDuration, newTaskId } from '../format';
import { AnalysisResult } from './FileAnalyzer';

type Tab = 'overview' | 'scan' | 'quarantine' | 'history';

export function useElapsed(running: boolean): number {
  const [start, setStart] = useState<number | null>(null);
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    if (!running) {
      setStart(null);
      return;
    }
    setStart(Date.now());
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [running]);
  return start ? now - start : 0;
}

function Overview({ sec, yaraEngine, qCount }: { sec: SecurityStatus | null; yaraEngine: YaraEngineInfo | null; qCount: number | null }) {
  const { t, locale } = useI18n();
  const { navigate } = useApp();
  if (!sec) return <Card><Skeleton h={120} /></Card>;
  const d = sec.defender;
  const row = (label: string, value: React.ReactNode) => (<><dt>{label}</dt><dd>{value}</dd></>);
  const onOff = (v?: 'on' | 'off' | 'unknown') => v === 'on' ? <Badge tone="green">{t('common.on')}</Badge> : v === 'off' ? <Badge tone="red">{t('common.off')}</Badge> : <Badge tone="gray">{t('common.unknown')}</Badge>;
  return (
    <div className="grid g-3">
      <Card title={t('security.engine')} explain="defender" icon={ShieldHalf} tone={d.available ? 'green' : 'amber'} className="span-2">
        {!sec.platformSupported ? (
          <Notice tone="gray" icon={ShieldAlert}>{t('security.windowsOnly')}</Notice>
        ) : !d.available ? (
          <Notice tone="amber" icon={TriangleAlert}>{t(`errors.${d.reason ?? 'defender_unavailable'}`)}</Notice>
        ) : (
          <dl className="kv">
            {row(t('security.antivirus'), onOff(d.antivirusEnabled))}
            {row(t('security.realtime'), onOff(d.realTimeProtection))}
            {row(t('security.definitions'), d.signatureVersion ? <Ltr>{t('security.defAge', { version: d.signatureVersion, age: d.signatureAgeDays ?? '?' })}</Ltr> : '—')}
            {row(t('security.lastQuick'), formatDateTime(locale, d.lastQuickScan))}
            {row(t('security.lastFull'), formatDateTime(locale, d.lastFullScan))}
          </dl>
        )}
      </Card>
      <div className="col" style={{ gap: 16 }}>
        <Card title={t('security.yaraEngine')} explain="yara" icon={ScanSearch} tone={yaraEngine?.available ? 'green' : 'amber'}
          actions={<button className="btn sm" onClick={() => navigate('yara')}>{t('settings.configure')}</button>}>
          {!yaraEngine ? <Skeleton h={16} /> : yaraEngine.available
            ? <Badge tone="green">{t('yara.engineInstalled', { version: yaraEngine.version ?? '' })}</Badge>
            : <Badge tone="amber">{t('yara.engineMissing')}</Badge>}
        </Card>
        <Card title={t('security.quarantineItems')} explain="quarantine" icon={ShieldCheck} tone="cyan">
          <div className="stat-value">{qCount === null ? '—' : <Ltr>{qCount}</Ltr>}</div>
        </Card>
      </div>
    </div>
  );
}

function ScanTab({ sec }: { sec: SecurityStatus | null }) {
  const { t } = useI18n();
  const { toast } = useApp();
  const [run, setRun] = useState<{ taskId: string; kind: DefenderScanKind; target: string | null } | null>(null);
  const [result, setResult] = useState<DefenderScanResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const elapsed = useElapsed(run !== null);
  const usable = !!sec?.platformSupported && !!sec.defender.available;

  const start = async (kind: DefenderScanKind) => {
    let target: string | null = null;
    if (kind === 'path') return;
    const taskId = newTaskId();
    setErr(null);
    setResult(null);
    setRun({ taskId, kind, target });
    const r = await window.blazma.defender.scan(kind, target, taskId);
    setRun(null);
    if (r.ok) setResult(r.data);
    else if (r.error !== 'cancelled') setErr(r.error);
  };
  const startPath = async (folder: boolean) => {
    const target = folder ? await window.blazma.files.pickFolder() : await window.blazma.files.pickFile();
    if (!target) return;
    const taskId = newTaskId();
    setErr(null);
    setResult(null);
    setRun({ taskId, kind: 'path', target });
    const r = await window.blazma.defender.scan('path', target, taskId);
    setRun(null);
    if (r.ok) {
      setResult(r.data);
      if (r.data.status === 'threats_found') toast('red', t('security.resultThreats', { count: r.data.threats.length }));
    } else if (r.error !== 'cancelled') setErr(r.error);
  };

  const options: Array<{ id: string; icon: LucideIcon; tone: Tone; title: string; desc: string; go: () => void }> = [
    { id: 'quick', icon: Zap, tone: 'blue', title: t('security.quick'), desc: t('security.quickDesc'), go: () => void start('quick') },
    { id: 'full', icon: ShieldHalf, tone: 'purple', title: t('security.full'), desc: t('security.fullDesc'), go: () => void start('full') },
    { id: 'file', icon: FileSearch, tone: 'cyan', title: t('security.fileScan'), desc: t('security.fileDesc'), go: () => void startPath(false) },
    { id: 'folder', icon: FolderSearch, tone: 'green', title: t('security.folderScan'), desc: t('security.folderDesc'), go: () => void startPath(true) },
  ];

  if (!usable) {
    return <Card><Notice tone={sec?.platformSupported ? 'amber' : 'gray'} icon={ShieldAlert}>{sec?.platformSupported ? t(`errors.${sec.defender.reason ?? 'defender_unavailable'}`) : t('security.windowsOnly')}</Notice></Card>;
  }

  return (
    <div className="col" style={{ gap: 16 }}>
      {run ? (
        <Card>
          <div className="row" style={{ marginBottom: 12 }}>
            <IconTile icon={ShieldHalf} tone="cyan" small />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontWeight: 600 }}>{t('security.running')}</div>
              <div className="small dim">{run.target ? <Ltr mono>{run.target}</Ltr> : t(`security.${run.kind}`)}</div>
            </div>
            <button className="btn danger sm" onClick={() => void window.blazma.files.cancel(run.taskId)}><X size={14} /> {t('common.cancel')}</button>
          </div>
          <Progress indeterminate />
          <div className="small muted" style={{ marginTop: 8 }}>{t('security.elapsed', { time: formatDuration(t, elapsed) })}</div>
        </Card>
      ) : (
        <div className="grid g-4">
          {options.map((o) => (
            <button key={o.id} className="card tool" onClick={o.go}>
              <IconTile icon={o.icon} tone={o.tone} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div className="tool-title">{o.title}</div>
                <div className="tool-desc">{o.desc}</div>
              </div>
            </button>
          ))}
        </div>
      )}
      <Notice tone="blue">{t('security.reportOnlyNote')} {t('security.policyNote')}</Notice>
      {err && <Card><ErrorState code={err} /></Card>}
      {result && (
        <Card
          title={result.status === 'no_threats' ? t('security.resultClean') : t('security.resultThreats', { count: result.threats.length })}
          icon={result.status === 'no_threats' ? CircleCheck : ShieldAlert}
          tone={result.status === 'no_threats' ? 'green' : 'red'}
          subtitle={t('security.duration', { time: formatDuration(t, result.durationMs) })}
        >
          {result.target && <div className="small" style={{ marginBottom: 8 }}><Ltr mono breakAll>{result.target}</Ltr></div>}
          {result.threats.map((x) => <div key={x}><Badge tone="red">{x}</Badge></div>)}
        </Card>
      )}
    </div>
  );
}

function QuarantineTab({ onCount }: { onCount: (n: number) => void }) {
  const { t, locale } = useI18n();
  const { confirm, toast } = useApp();
  const [items, setItems] = useState<QuarantineEntry[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [rescan, setRescan] = useState<{ id: string; taskId: string; result?: FileAnalysis } | null>(null);

  const load = async () => {
    const r = await window.blazma.quarantine.list();
    if (r.ok) {
      setItems(r.data);
      onCount(r.data.length);
    } else setErr(r.error);
  };
  useEffect(() => void load(), []);

  const restore = async (e: QuarantineEntry, choose: boolean) => {
    if (!choose && !(await confirm({ title: t('security.q.restoreTitle'), body: t('security.q.restoreBody', { name: e.originalName, path: e.originalPath }), confirmLabel: t('security.q.restore') }))) return;
    const r = choose ? await window.blazma.quarantine.restoreTo(e.id) : await window.blazma.quarantine.restore(e.id);
    if (r.ok && r.data) toast('green', t('security.q.restored', { path: r.data.path }));
    else if (!r.ok) toast('red', t(`errors.${r.error}`));
    void load();
  };
  const remove = async (e: QuarantineEntry) => {
    if (!(await confirm({ title: t('security.q.deleteTitle'), body: t('security.q.deleteBody', { name: e.originalName }), confirmLabel: t('security.q.delete'), danger: true }))) return;
    const r = await window.blazma.quarantine.remove(e.id);
    if (r.ok) toast('green', t('security.q.deleted'));
    else toast('red', t(`errors.${r.error}`));
    void load();
  };
  const doRescan = async (e: QuarantineEntry) => {
    const taskId = newTaskId();
    setRescan({ id: e.id, taskId });
    const r = await window.blazma.quarantine.rescan(e.id, taskId);
    if (r.ok) setRescan({ id: e.id, taskId, result: r.data });
    else {
      setRescan(null);
      if (r.error !== 'cancelled') toast('red', t(`errors.${r.error}`));
    }
  };

  if (err) return <Card><ErrorState code={err} onRetry={() => void load()} /></Card>;
  if (!items) return <Card><Skeleton h={100} /></Card>;

  return (
    <div className="col" style={{ gap: 16 }}>
      <Notice tone="cyan" icon={ShieldCheck}>{t('security.q.protectNote')}</Notice>
      {rescan && !rescan.result && <Card><Progress indeterminate /><div className="small muted" style={{ marginTop: 8 }}>{t('file.analyzing')}</div></Card>}
      {rescan?.result && (
        <div>
          <h3 className="section-title" style={{ marginBottom: 10 }}>{t('security.q.rescanTitle')}</h3>
          <AnalysisResult r={rescan.result} onReset={() => setRescan(null)} inQuarantine />
        </div>
      )}
      <Card>
        {items.length === 0 ? (
          <EmptyState icon={ShieldCheck} title={t('security.q.empty')} hint={t('security.q.emptyHint')} />
        ) : (
          <DataTable<QuarantineEntry>
            rowKey={(r) => r.id}
            rows={items}
            columns={[
              { key: 'n', label: t('security.q.name'), render: (r) => <div><Ltr breakAll>{r.originalName}</Ltr><div className="tiny dim"><Ltr mono>{r.sha256.slice(0, 16)}…</Ltr></div></div> },
              { key: 'o', label: t('security.q.original'), render: (r) => <Ltr mono breakAll className="small">{r.originalPath}</Ltr> },
              { key: 't', label: t('security.q.type'), render: (r) => <span className="small"><Ltr>{r.typeDescription}</Ltr></span> },
              { key: 's', label: t('security.q.size'), render: (r) => <span className="nowrap">{formatBytes(t, r.sizeBytes)}</span> },
              { key: 'd', label: t('security.q.date'), render: (r) => <span className="small nowrap">{formatDateTime(locale, r.quarantinedAt)}</span> },
              {
                key: 'a', label: t('security.q.actions'),
                render: (r) => (
                  <div className="row-wrap" style={{ gap: 6 }}>
                    <button className="btn sm" onClick={() => void doRescan(r)} disabled={!!rescan && !rescan.result}><ScanSearch size={13} /> {t('security.q.rescan')}</button>
                    <button className="btn sm" onClick={() => void restore(r, false)}><RotateCcw size={13} /> {t('security.q.restore')}</button>
                    <button className="btn sm" onClick={() => void restore(r, true)}>{t('security.q.restoreTo')}</button>
                    <button className="btn danger sm" onClick={() => void remove(r)}><Trash2 size={13} /> {t('security.q.delete')}</button>
                  </div>
                ),
              },
            ]}
          />
        )}
      </Card>
    </div>
  );
}

function HistoryTab({ sec }: { sec: SecurityStatus | null }) {
  const { t, locale } = useI18n();
  const [state, setState] = useState<{ data?: DefenderThreat[]; error?: string } | null>(null);
  useEffect(() => {
    if (!sec?.platformSupported) return;
    void window.blazma.defender.history().then((r) => setState(r.ok ? { data: r.data } : { error: r.error }));
  }, [sec?.platformSupported]);
  if (!sec?.platformSupported) return <Card><Notice tone="gray" icon={ShieldAlert}>{t('security.windowsOnly')}</Notice></Card>;
  if (!state) return <Card><Skeleton h={100} /></Card>;
  if (state.error) return <Card><ErrorState code={state.error} /></Card>;
  return (
    <Card title={t('security.tab.history')} icon={History} tone="blue">
      {state.data!.length === 0 ? <EmptyState icon={ShieldCheck} title={t('security.h.empty')} /> : (
        <DataTable<DefenderThreat>
          rowKey={(r, i) => `${r.id}-${i}`}
          rows={state.data!}
          columns={[
            { key: 'n', label: t('security.h.name'), render: (r) => <Ltr>{r.name ?? r.id}</Ltr> },
            { key: 'd', label: t('security.h.detected'), render: (r) => <span className="small nowrap">{formatDateTime(locale, r.detected)}</span> },
            { key: 'r', label: t('security.h.resources'), render: (r) => <div className="small">{r.resources.slice(0, 3).map((x) => <div key={x}><Ltr mono breakAll>{x}</Ltr></div>)}</div> },
            { key: 'a', label: t('security.h.action'), render: (r) => <Badge tone={r.actionSuccess ? 'green' : 'amber'}>{t(r.actionSuccess ? 'security.h.actionOk' : 'security.h.actionFail')}</Badge> },
          ]}
        />
      )}
    </Card>
  );
}

export function SecurityCenter({ initialTab = 'overview' }: { initialTab?: Tab }) {
  const { t } = useI18n();
  const [tab, setTab] = useState<Tab>(initialTab);
  const [qCount, setQCount] = useState<number | null>(null);
  const sec = usePoll(async () => {
    const r = await window.blazma.system.security();
    if (!r.ok) throw new Error(r.error);
    return r.data;
  }, 60_000);
  const yaraEngine = usePoll(() => window.blazma.yara.engine(), null);
  useEffect(() => void window.blazma.quarantine.list().then((r) => r.ok && setQCount(r.data.length)), [tab]);

  return (
    <div className="page">
      <div className="page-head">
        <IconTile icon={ShieldHalf} tone="blue" />
        <div>
          <h1 className="page-title">{t('security.title')}</h1>
          <div className="page-sub">{t('security.subtitle')}</div>
        </div>
      </div>
      <Tabs<Tab> value={tab} onChange={setTab} items={(['overview', 'scan', 'quarantine', 'history'] as const).map((id) => ({ id, label: t(`security.tab.${id}`) }))} />
      {tab === 'overview' && <Overview sec={sec.data} yaraEngine={yaraEngine.data} qCount={qCount} />}
      {tab === 'scan' && <ScanTab sec={sec.data} />}
      {tab === 'quarantine' && <QuarantineTab onCount={setQCount} />}
      {tab === 'history' && <HistoryTab sec={sec.data} />}
    </div>
  );
}
