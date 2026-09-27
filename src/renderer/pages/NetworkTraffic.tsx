import { useEffect, useMemo, useState } from 'react';
import { Activity, AlertTriangle, CircleCheck, FolderOpen, Lock, LockOpen, Radio, ShieldAlert, Unlock, X } from 'lucide-react';
import type { CaptureEnvironment, CaptureInterface, FindingSeverity, TaskProgress, TrafficCaptureOptions, TrafficFinding, TrafficResult } from '../../shared/api';
import { Badge, Card, DataTable, EmptyState, ErrorState, FileDrop, FilterInput, IconTile, Ltr, Notice, Progress, Tabs, Toggle, useFilter, type Tone } from '../components/ui';
import { OptionPills } from '../components/intel';
import { AddToCase } from '../components/AddToCase';
import { DeviceMaker } from '../components/DeviceMaker';
import { useApp } from '../components/AppContext';
import { useI18n } from '../i18n/I18nProvider';
import { formatBytes, formatDateTime, formatDuration, formatNumber, newTaskId } from '../format';

const SEV_TONE: Record<FindingSeverity, Tone> = { high: 'red', medium: 'amber', low: 'blue', info: 'gray' };
const SECONDS = [15, 30, 60, 120, 300] as const;
type ResultTab = 'devices' | 'conversations' | 'external' | 'dns' | 'https' | 'cleartext';

function useTaskProgress(taskId: string | undefined) {
  const [p, setP] = useState<TaskProgress | null>(null);
  useEffect(() => {
    setP(null);
    if (!taskId) return;
    return window.blazma.files.onProgress((x) => x.taskId === taskId && setP(x));
  }, [taskId]);
  return p;
}

const iso = (ms: number | null) => (ms ? new Date(ms).toISOString() : null);

export function NetworkTraffic() {
  const { t, locale } = useI18n();
  const { confirm, toast } = useApp();
  const [env, setEnv] = useState<CaptureEnvironment | null>(null);
  const [ifaces, setIfaces] = useState<CaptureInterface[]>([]);
  const [opts, setOpts] = useState<TrafficCaptureOptions>({ seconds: 30, backend: 'pktmon', iface: null, keep: false });
  const [state, setState] = useState<{ running?: { taskId: string; live: boolean; seconds?: number }; result?: TrafficResult; error?: string }>({});
  const progress = useTaskProgress(state.running?.taskId);

  useEffect(() => {
    void window.blazma.traffic.environment().then((r) => {
      if (!r.ok) return;
      setEnv(r.data);
      if (r.data.dumpcap) {
        setOpts((o) => ({ ...o, backend: 'dumpcap' }));
        void window.blazma.traffic.interfaces().then((x) => {
          if (!x.ok) return;
          setIfaces(x.data);
          const first = x.data.find((i) => !i.loopback);
          if (first) setOpts((o) => ({ ...o, iface: first.id }));
        });
      }
    });
  }, []);

  const analyzeFile = async (path: string) => {
    const taskId = newTaskId();
    setState({ running: { taskId, live: false } });
    const r = await window.blazma.traffic.analyzeFile(path, taskId);
    setState(r.ok ? { result: r.data } : { error: r.error });
  };
  const pick = async () => {
    const p = await window.blazma.traffic.pickFile();
    if (p) void analyzeFile(p);
  };
  const capture = async () => {
    const ok = await confirm({
      title: t('traffic.confirmTitle'),
      body: t(opts.backend === 'pktmon' ? 'traffic.confirmBodyPktmon' : 'traffic.confirmBody', { seconds: opts.seconds }),
      confirmLabel: t('traffic.start'),
    });
    if (!ok) return;
    const taskId = newTaskId();
    setState({ running: { taskId, live: true, seconds: opts.seconds } });
    const r = await window.blazma.traffic.capture(opts, taskId);
    setState(r.ok ? { result: r.data } : { error: r.error });
    if (!r.ok && r.error === 'capture_elevation_cancelled') toast('amber', t('errors.capture_elevation_cancelled'));
  };

  const canCapture = !!env && env.platform === 'windows' && (opts.backend === 'dumpcap' ? env.dumpcap : env.pktmon);
  const r = state.result;

  return (
    <div className="page">
      <div className="page-head">
        <IconTile icon={Activity} tone="cyan" />
        <div>
          <h1 className="page-title">{t('traffic.title')}</h1>
          <div className="page-sub">{t('traffic.subtitle')}</div>
        </div>
      </div>

      <div className="col" style={{ gap: 16 }}>
        <Notice tone="blue" icon={ShieldAlert}>{t('traffic.observeOnly')}</Notice>

        {!state.running && !r && (
          <div className="grid g-2">
            <Card title={t('traffic.liveTitle')} subtitle={t('traffic.liveSub')} icon={Radio} tone="cyan" explain="packet_capture">
              <div className="col" style={{ gap: 12 }}>
                {env && env.platform !== 'windows' && <Notice tone="gray">{t('errors.unsupported_platform')}</Notice>}
                {env?.platform === 'windows' && (
                  <>
                    <div>
                      <div className="small dim" style={{ marginBottom: 6 }}>{t('traffic.backend')}</div>
                      <OptionPills
                        single
                        items={[
                          { id: 'dumpcap', label: t('traffic.backendDumpcap'), checked: opts.backend === 'dumpcap', disabled: !env.dumpcap, hint: env.dumpcap ? undefined : t('traffic.notInstalled') },
                          { id: 'pktmon', label: t('traffic.backendPktmon'), checked: opts.backend === 'pktmon', disabled: !env.pktmon },
                        ]}
                        onToggle={(id) => setOpts((o) => ({ ...o, backend: id as TrafficCaptureOptions['backend'] }))}
                      />
                      <div className="tiny dim" style={{ marginTop: 6 }}>{t(opts.backend === 'pktmon' ? 'traffic.pktmonNote' : 'traffic.dumpcapNote')}</div>
                    </div>
                    {opts.backend === 'dumpcap' && ifaces.length > 0 && (
                      <label className="col" style={{ gap: 6 }}>
                        <span className="small dim">{t('traffic.interface')}</span>
                        <select className="input" value={opts.iface ?? ''} onChange={(e) => setOpts((o) => ({ ...o, iface: e.target.value }))}>
                          {ifaces.map((i) => <option key={i.id} value={i.id}>{i.name}</option>)}
                        </select>
                      </label>
                    )}
                    <div>
                      <div className="small dim" style={{ marginBottom: 6 }}>{t('traffic.duration')}</div>
                      <OptionPills
                        single
                        items={SECONDS.map((s) => ({ id: String(s), label: s < 60 ? t('traffic.seconds', { n: s }) : t('traffic.minutes', { n: s / 60 }), checked: opts.seconds === s }))}
                        onToggle={(id) => setOpts((o) => ({ ...o, seconds: Number(id) as TrafficCaptureOptions['seconds'] }))}
                      />
                    </div>
                    <div className="row" style={{ gap: 10 }}>
                      <Toggle checked={opts.keep} onChange={(keep) => setOpts((o) => ({ ...o, keep }))} label={t('traffic.keep')} />
                      <span className="small">{t('traffic.keep')}</span>
                    </div>
                    {!env.dumpcap && <div className="tiny dim">{t('traffic.wiresharkTip')}</div>}
                    <div>
                      <button className="btn primary" disabled={!canCapture} onClick={() => void capture()}><Radio size={15} /> {t('traffic.start')}</button>
                    </div>
                  </>
                )}
              </div>
            </Card>
            <Card title={t('traffic.fileTitle')} subtitle={t('traffic.fileSub')} icon={FolderOpen} tone="purple">
              <FileDrop onFile={(p) => void analyzeFile(p)} onBrowse={() => void pick()} title={t('traffic.dropTitle')} hint={t('traffic.dropHint')} activeText={t('file.dropActive')} browseLabel={t('traffic.pickCapture')} />
            </Card>
          </div>
        )}

        {state.running && (
          <Card>
            {state.running.live ? (
              <Progress value={progress && progress.totalBytes ? (progress.processedBytes / progress.totalBytes) * 100 : 0} indeterminate={!progress} />
            ) : (
              <Progress value={progress && progress.totalBytes ? (progress.processedBytes / progress.totalBytes) * 100 : 0} indeterminate={!progress} />
            )}
            <div className="row" style={{ marginTop: 10, gap: 10 }}>
              <span className="small muted">
                {state.running.live
                  ? progress && progress.processedBytes >= (state.running.seconds ?? 0) ? t('traffic.analyzing') : t('traffic.capturing', { done: progress?.processedBytes ?? 0, total: state.running.seconds ?? 0 })
                  : t('traffic.reading', { done: formatBytes(t, progress?.processedBytes ?? 0), total: formatBytes(t, progress?.totalBytes ?? 0) })}
              </span>
              <span className="spacer" />
              {(!state.running.live || opts.backend === 'dumpcap') && (
                <button className="btn danger sm" onClick={() => void window.blazma.files.cancel(state.running!.taskId)}><X size={13} /> {state.running.live ? t('traffic.stopEarly') : t('common.cancel')}</button>
              )}
            </div>
            {state.running.live && opts.backend === 'pktmon' && <div className="tiny dim" style={{ marginTop: 8 }}>{t('traffic.pktmonRunning')}</div>}
          </Card>
        )}
        {state.error && <Card><ErrorState code={state.error} onRetry={() => setState({})} /></Card>}
        {r && <TrafficResultView result={r} env={env} onAgain={() => setState({})} />}
      </div>
    </div>
  );
}

function FindingRow({ f }: { f: TrafficFinding }) {
  const { t } = useI18n();
  const [open, setOpen] = useState(false);
  const vars = f.vars;
  return (
    <div className={`devsec-row tone-${SEV_TONE[f.severity]}`}>
      <button className="devsec-head" aria-expanded={open} onClick={() => setOpen(!open)}>
        <AlertTriangle size={18} className="devsec-icon" />
        <span className="devsec-title">{t(`traffic.finding.${f.id}.title`, vars)}</span>
        <span className="spacer" />
        <Badge tone={SEV_TONE[f.severity]}>{t(`traffic.severity.${f.severity}`)}</Badge>
      </button>
      <div className="small muted devsec-detail"><Ltr mono className="small">{Object.entries(vars).filter(([k]) => k !== 'answered').map(([k, v]) => `${k}: ${v}`).join(' · ')}</Ltr></div>
      {open && (
        <div className="devsec-body">
          <div><strong>{t('traffic.what')}</strong> {t(`traffic.finding.${f.id}.body`, vars)}</div>
          <div><strong>{t('traffic.next')}</strong> {t(`traffic.finding.${f.id}.next`, vars)}</div>
        </div>
      )}
    </div>
  );
}

function EncBadge({ v }: { v: boolean | null }) {
  const { t } = useI18n();
  if (v === null) return <span className="dim small">—</span>;
  return v ? <Badge tone="green" icon={Lock}>{t('traffic.encrypted')}</Badge> : <Badge tone="amber" icon={LockOpen}>{t('traffic.cleartext')}</Badge>;
}

function TrafficResultView({ result, env, onAgain }: { result: TrafficResult; env: CaptureEnvironment | null; onAgain: () => void }) {
  const { t, locale } = useI18n();
  const { toast } = useApp();
  const r = result.report;
  const [tab, setTab] = useState<ResultTab>('devices');
  const span = r.first && r.last ? r.last - r.first : null;
  const maxProto = Math.max(1, ...r.protocols.map((p) => p.bytes));
  const convs = useFilter(r.conversations, (c) => [c.client, c.server, c.protocol, c.name ?? '', String(c.port)]);
  const dns = useFilter(r.dns.names, (d) => [d.name]);
  const evidence = useMemo(() => [
    ...r.findings.map((f) => ({ kind: 'finding' as const, value: t(`traffic.finding.${f.id}.title`, f.vars), label: t(`traffic.severity.${f.severity}`), source: 'traffic', details: Object.fromEntries(Object.entries(f.vars).map(([k, v]) => [k, v])) })),
    ...r.external.slice(0, 20).map((e) => ({ kind: 'ip' as const, value: e.ip, label: e.names[0] ?? null, source: 'traffic', details: { bytes: e.bytes, packets: e.packets } })),
  ], [r, t]);

  const openWs = async () => {
    const x = await window.blazma.traffic.openInWireshark(result.source.keptPath!);
    if (!x.ok) toast('red', t(`errors.${x.error}`));
  };

  return (
    <>
      <Card
        title={t('traffic.resultTitle')}
        icon={Activity}
        tone={r.findings.some((f) => f.severity === 'high') ? 'red' : r.findings.length ? 'amber' : 'green'}
        subtitle={result.source.kind === 'live' ? t('traffic.sourceLive', { seconds: result.source.seconds ?? 0, backend: result.source.backend ?? '' }) : <Ltr>{result.source.name}</Ltr>}
        actions={<div className="row" style={{ gap: 8 }}>{evidence.length > 0 && <AddToCase items={evidence} />}<button className="btn sm" onClick={onAgain}>{t('traffic.again')}</button></div>}
      >
        <div className="tstats">
          <div className="tstat"><div className="tstat-l">{t('traffic.packets')}</div><div className="tstat-v"><Ltr>{formatNumber(locale, r.packets)}</Ltr></div></div>
          <div className="tstat"><div className="tstat-l">{t('traffic.volume')}</div><div className="tstat-v"><Ltr>{formatBytes(t, r.bytes)}</Ltr></div></div>
          <div className="tstat"><div className="tstat-l">{t('traffic.devices')}</div><div className="tstat-v"><Ltr>{r.devices.length}</Ltr></div></div>
          <div className="tstat"><div className="tstat-l">{t('traffic.encryptedShare')}</div><div className="tstat-v"><Ltr>{r.encryptedShare === null ? '—' : `${Math.round(r.encryptedShare * 100)}%`}</Ltr></div></div>
          <div className="tstat"><div className="tstat-l">{t('traffic.span')}</div><div className="tstat-v"><Ltr>{span === null ? '—' : formatDuration(t, span)}</Ltr></div></div>
        </div>
        <div className="tiny dim" style={{ marginTop: 10 }}>
          {r.first && <>{formatDateTime(locale, iso(r.first))} — {formatDateTime(locale, iso(r.last))} · </>}
          {t('traffic.processed', { time: formatDuration(t, result.durationMs) })}
          {r.unreadable > 0 && <> · {t('traffic.unreadable', { n: r.unreadable })}</>}
        </div>
        {r.truncated && <div style={{ marginTop: 10 }}><Notice tone="amber">{t('traffic.truncated')}</Notice></div>}
        {result.readError && <div style={{ marginTop: 10 }}><Notice tone="amber">{t('traffic.readError')}</Notice></div>}
        {result.source.keptPath && (
          <div className="row-wrap" style={{ gap: 8, marginTop: 12 }}>
            <span className="tiny dim">{t('traffic.keptAt')}</span><Ltr mono className="tiny" breakAll>{result.source.keptPath}</Ltr>
            {env?.wireshark && <button className="btn sm" onClick={() => void openWs()}>{t('traffic.openWireshark')}</button>}
            <button className="btn sm" onClick={() => void window.blazma.traffic.openCapturesFolder()}><FolderOpen size={13} /> {t('traffic.openFolder')}</button>
          </div>
        )}
      </Card>

      <Card title={t('traffic.findingsTitle')} subtitle={t('traffic.findingsSub')} icon={ShieldAlert} tone={r.findings.length ? 'amber' : 'green'}>
        {r.findings.length === 0 ? (
          <div className="row" style={{ gap: 10 }}><CircleCheck size={18} color="var(--green)" /><span className="small">{t('traffic.noFindings')}</span></div>
        ) : (
          <div className="col" style={{ gap: 8 }}>{r.findings.map((f, i) => <FindingRow key={`${f.id}-${i}`} f={f} />)}</div>
        )}
      </Card>

      <Card title={t('traffic.protocolsTitle')} icon={Unlock} tone="purple">
        <div className="col" style={{ gap: 8 }}>
          {r.protocols.slice(0, 14).map((p) => (
            <div key={p.name} className="proto-row">
              <span className="proto-name"><Ltr>{p.name}</Ltr></span>
              <span className="proto-bar"><span style={{ width: `${Math.max(2, (p.bytes / maxProto) * 100)}%` }} className={p.encrypted === false ? 'warn' : p.encrypted ? 'ok' : ''} /></span>
              <span className="proto-val small"><Ltr>{formatBytes(t, p.bytes)}</Ltr></span>
              <EncBadge v={p.encrypted} />
            </div>
          ))}
        </div>
      </Card>

      <Card>
        <Tabs<ResultTab>
          value={tab}
          onChange={setTab}
          items={([
            ['devices', r.devices.length], ['conversations', r.conversations.length], ['external', r.external.length],
            ['dns', r.dns.names.length], ['https', r.tls.length], ['cleartext', r.cleartext.length],
          ] as const).map(([id, n]) => ({ id, label: `${t(`traffic.tab.${id}`)} (${n})` }))}
        />
        {tab === 'devices' && (r.devices.length === 0 ? <EmptyState title={t('traffic.none')} /> : (
          <DataTable maxHeight={480} rowKey={(d) => d.mac} rows={r.devices} columns={[
            { key: 'm', label: t('net.maker.title'), render: (d) => <div><DeviceMaker maker={d.maker} />{d.names.length > 0 && <div className="tiny dim"><Ltr>{d.names.join(', ')}</Ltr></div>}</div> },
            { key: 'mac', label: 'MAC', render: (d) => <Ltr mono className="small">{d.mac}</Ltr> },
            { key: 'ip', label: t('traffic.col.addresses'), render: (d) => d.ips.length ? <Ltr mono className="small">{d.ips.join(', ')}</Ltr> : <span className="dim">—</span> },
            { key: 'o', label: t('traffic.col.sent'), render: (d) => <Ltr className="small">{formatBytes(t, d.bytesOut)}</Ltr> },
            { key: 'i', label: t('traffic.col.received'), render: (d) => <Ltr className="small">{formatBytes(t, d.bytesIn)}</Ltr> },
          ]} />
        ))}
        {tab === 'conversations' && (
          <>
            <div style={{ marginBottom: 10 }}><FilterInput value={convs.q} onChange={convs.setQ} placeholder={t('forensics.filter')} /></div>
            <DataTable maxHeight={480} rowKey={(c, i) => `${i}-${c.client}-${c.server}-${c.port}`} rows={convs.filtered} columns={[
              { key: 'c', label: t('traffic.col.client'), render: (c) => <Ltr mono className="small">{c.client}</Ltr> },
              { key: 's', label: t('traffic.col.server'), render: (c) => <div><Ltr mono className="small">{c.port ? `${c.server}:${c.port}` : c.server}</Ltr>{c.name && <div className="tiny dim"><Ltr>{c.name}</Ltr></div>}</div> },
              { key: 'p', label: t('traffic.col.protocol'), render: (c) => <Ltr className="small">{c.protocol}</Ltr> },
              { key: 'e', label: '', render: (c) => <EncBadge v={c.encrypted} /> },
              { key: 'b', label: t('traffic.col.bytes'), render: (c) => <Ltr className="small">{formatBytes(t, c.bytes)}</Ltr> },
            ]} />
          </>
        )}
        {tab === 'external' && (r.external.length === 0 ? <EmptyState title={t('traffic.none')} /> : (
          <DataTable maxHeight={480} rowKey={(e) => e.ip} rows={r.external} columns={[
            { key: 'ip', label: 'IP', render: (e) => <Ltr mono className="small">{e.ip}</Ltr> },
            { key: 'n', label: t('traffic.col.names'), render: (e) => e.names.length ? <Ltr className="small" breakAll>{e.names.slice(0, 3).join(', ')}</Ltr> : <span className="dim">—</span> },
            { key: 'b', label: t('traffic.col.bytes'), render: (e) => <Ltr className="small">{formatBytes(t, e.bytes)}</Ltr> },
            { key: 'p', label: t('traffic.packets'), render: (e) => <Ltr className="small">{e.packets}</Ltr> },
          ]} />
        ))}
        {tab === 'dns' && (
          <>
            <div className="row-wrap" style={{ gap: 10, marginBottom: 10 }}>
              <span className="small muted">{t('traffic.dnsSummary', { queries: r.dns.queries, failures: r.dns.failures })}</span>
              <span className="spacer" />
              <FilterInput value={dns.q} onChange={dns.setQ} placeholder={t('forensics.filter')} />
            </div>
            <DataTable maxHeight={480} rowKey={(d) => d.name} rows={dns.filtered} columns={[
              { key: 'n', label: t('traffic.col.name'), render: (d) => <Ltr mono className="small" breakAll>{d.name}</Ltr> },
              { key: 'c', label: t('traffic.col.count'), render: (d) => <Ltr className="small">{d.count}</Ltr> },
              { key: 't', label: t('traffic.col.types'), render: (d) => <Ltr className="small">{d.types.join(', ')}</Ltr> },
              { key: 'f', label: t('traffic.col.failed'), render: (d) => d.failed ? <Badge tone="amber">{d.failed}</Badge> : <span className="dim">0</span> },
            ]} />
          </>
        )}
        {tab === 'https' && (r.tls.length === 0 ? <EmptyState title={t('traffic.none')} /> : (
          <DataTable maxHeight={480} rowKey={(x) => x.name} rows={r.tls} columns={[
            { key: 'n', label: t('traffic.col.site'), render: (x) => <Ltr mono className="small" breakAll>{x.name}</Ltr> },
            { key: 'c', label: t('traffic.col.count'), render: (x) => <Ltr className="small">{x.count}</Ltr> },
            { key: 'v', label: t('traffic.col.version'), render: (x) => x.versions.length ? x.versions.map((v) => <Badge key={v} tone={/1\.[01]|SSL/.test(v) ? 'amber' : 'green'}>{v}</Badge>) : <span className="dim">—</span> },
          ]} />
        ))}
        {tab === 'cleartext' && (r.cleartext.length === 0 ? <EmptyState title={t('traffic.noCleartext')} /> : (
          <>
            <div className="tiny dim" style={{ marginBottom: 10 }}>{t('traffic.cleartextNote')}</div>
            <DataTable maxHeight={480} rowKey={(c, i) => `${i}-${c.protocol}-${c.server}`} rows={r.cleartext} columns={[
              { key: 'p', label: t('traffic.col.protocol'), render: (c) => <Badge tone="amber">{c.protocol}</Badge> },
              { key: 'c', label: t('traffic.col.client'), render: (c) => <Ltr mono className="small">{c.client}</Ltr> },
              { key: 's', label: t('traffic.col.server'), render: (c) => <div><Ltr mono className="small">{c.server}</Ltr>{c.host && <div className="tiny dim"><Ltr>{c.host}</Ltr></div>}</div> },
              { key: 'd', label: t('traffic.col.detail'), render: (c) => c.detail ? <Ltr mono className="tiny" breakAll>{c.detail}</Ltr> : <span className="dim">—</span> },
              { key: 'n', label: t('traffic.col.count'), render: (c) => <Ltr className="small">{c.count}</Ltr> },
            ]} />
          </>
        ))}
      </Card>
    </>
  );
}
