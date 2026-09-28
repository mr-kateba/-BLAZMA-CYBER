import { useEffect, useState } from 'react';
import { Activity, Network, Radar, Route, ScanSearch, Search, ShieldAlert, X } from 'lucide-react';
import type { AdapterRow, DiscoveryResult, DnsLookupResult, NeighborRow, PingResult, PortCheckResult, RouteRow, TaskProgress, TraceResult } from '../../shared/api';
import { COMMON_PORTS } from '../../core/netparse';
import { isHostname } from '../../core/validation';
import { Badge, Card, DataTable, EmptyState, ErrorState, IconTile, Ltr, Notice, Progress, Skeleton, Tabs, Toggle } from '../components/ui';
import { OfflineBanner } from '../components/intel';
import { useApp } from '../components/AppContext';
import { useI18n } from '../i18n/I18nProvider';
import { DeviceMaker } from '../components/DeviceMaker';
import { formatDuration, newTaskId } from '../format';

type Tab = 'ping' | 'trace' | 'dns' | 'ports' | 'adapters' | 'routes' | 'neighbors' | 'discovery';

function TargetForm({ value, onChange, onSubmit, busy, placeholder, extra }: { value: string; onChange: (v: string) => void; onSubmit: () => void; busy: boolean; placeholder: string; extra?: React.ReactNode }) {
  const { t } = useI18n();
  const valid = isHostname(value.trim().toLowerCase());
  return (
    <form className="lookup-bar" onSubmit={(e) => { e.preventDefault(); if (valid) onSubmit(); }}>
      <input className="input mono" dir="ltr" value={value} placeholder={placeholder} aria-label={placeholder} onChange={(e) => onChange(e.target.value)} />
      {extra}
      <button className="btn primary" type="submit" disabled={!valid || busy}><Search size={16} /> {t('net.run')}</button>
    </form>
  );
}

function useTaskProgress(taskId: string | null) {
  const [p, setP] = useState<TaskProgress | null>(null);
  useEffect(() => {
    setP(null);
    if (!taskId) return;
    return window.blazma.files.onProgress((x) => x.taskId === taskId && setP(x));
  }, [taskId]);
  return p;
}

function PingTab() {
  const { t } = useI18n();
  const [target, setTarget] = useState('');
  const [count, setCount] = useState(4);
  const [s, setS] = useState<{ busy?: boolean; r?: PingResult; e?: string }>({});
  return (
    <div className="col" style={{ gap: 12 }}>
      <Card>
        <TargetForm
          value={target} onChange={setTarget} busy={!!s.busy} placeholder={t('net.targetPlaceholder')}
          extra={<select className="select" style={{ width: 90 }} value={count} onChange={(e) => setCount(Number(e.target.value))} aria-label={t('net.count')}>{[1, 4, 10].map((n) => <option key={n} value={n}>{n}×</option>)}</select>}
          onSubmit={async () => { setS({ busy: true }); const r = await window.blazma.net.ping(target.trim(), count, newTaskId()); setS(r.ok ? { r: r.data } : { e: r.error }); }}
        />
      </Card>
      {s.busy && <Card><Progress indeterminate /></Card>}
      {s.e && <Card><ErrorState code={s.e} /></Card>}
      {s.r && (
        <Card title={<Ltr mono>{`${s.r.target} (${s.r.address})`}</Ltr>} icon={Activity} tone={s.r.received === s.r.sent ? 'green' : s.r.received ? 'amber' : 'red'}>
          <div className="row-wrap" style={{ marginBottom: 12 }}>
            <Badge tone={s.r.received ? 'green' : 'red'}>{t('net.received', { received: s.r.received, sent: s.r.sent })}</Badge>
            {s.r.avg !== null && <Badge tone="blue">{t('net.rttStats', { min: s.r.min!, avg: s.r.avg, max: s.r.max! })}</Badge>}
          </div>
          <div className="chip-list">{s.r.rtts.map((x, i) => <span key={i} className="chip"><Ltr mono>{x === null ? t('net.timeout') : `${x} ms`}</Ltr></span>)}</div>
        </Card>
      )}
    </div>
  );
}

function TraceTab() {
  const { t } = useI18n();
  const [target, setTarget] = useState('');
  const [s, setS] = useState<{ busy?: boolean; r?: TraceResult; e?: string; id?: string }>({});
  return (
    <div className="col" style={{ gap: 12 }}>
      <Card>
        <TargetForm value={target} onChange={setTarget} busy={!!s.busy} placeholder={t('net.targetPlaceholder')}
          onSubmit={async () => { const id = newTaskId(); setS({ busy: true, id }); const r = await window.blazma.net.traceroute(target.trim(), id); setS(r.ok ? { r: r.data } : { e: r.error }); }} />
      </Card>
      {s.busy && <Card><Progress indeterminate /><div className="row small muted" style={{ marginTop: 8 }}><span>{t('net.tracing')}</span><span className="spacer" /><button className="btn danger sm" onClick={() => s.id && void window.blazma.files.cancel(s.id)}><X size={13} /> {t('common.cancel')}</button></div></Card>}
      {s.e && <Card><ErrorState code={s.e} /></Card>}
      {s.r && (
        <Card title={<Ltr mono>{`${s.r.target} (${s.r.address})`}</Ltr>} icon={Route} tone={s.r.reached ? 'green' : 'amber'} subtitle={t(s.r.reached ? 'net.reached' : 'net.notReached')}>
          <DataTable
            rowKey={(h) => String(h.hop)}
            rows={s.r.hops}
            columns={[
              { key: 'h', label: t('net.hop'), width: 60, render: (h) => <Ltr mono>{h.hop}</Ltr> },
              { key: 'a', label: t('net.address'), render: (h) => (h.address ? <Ltr mono>{h.address}</Ltr> : <span className="dim">* {t('net.timeout')}</span>) },
              { key: 'r', label: 'RTT', render: (h) => (h.rttMs !== null ? <Ltr mono>{`${h.rttMs} ms`}</Ltr> : '—') },
            ]}
          />
        </Card>
      )}
    </div>
  );
}

function DnsTab() {
  const { t } = useI18n();
  const [name, setName] = useState('');
  const [s, setS] = useState<{ busy?: boolean; r?: DnsLookupResult; rev?: { address: string; names: string[] }; e?: string }>({});
  const run = async () => {
    setS({ busy: true });
    const v = name.trim();
    if (/^[\d.]+$|:/.test(v)) {
      const r = await window.blazma.net.reverse(v);
      setS(r.ok ? { rev: r.data } : { e: r.error });
    } else {
      const r = await window.blazma.net.dns(v);
      setS(r.ok ? { r: r.data } : { e: r.error });
    }
  };
  const rows = s.r ? (Object.entries(s.r.records) as Array<[string, string[]]>).flatMap(([type, vals]) => vals.map((v) => ({ type, v }))) : [];
  return (
    <div className="col" style={{ gap: 12 }}>
      <Card>
        <TargetForm value={name} onChange={setName} busy={!!s.busy} placeholder={t('net.dnsPlaceholder')} onSubmit={() => void run()} />
        <div className="tiny dim" style={{ marginTop: 8 }}>{t('net.dnsHint')}</div>
      </Card>
      {s.busy && <Card><Progress indeterminate /></Card>}
      {s.e && <Card><ErrorState code={s.e} /></Card>}
      {s.rev && (
        <Card title={<Ltr mono>{s.rev.address}</Ltr>} icon={Search} tone="blue">
          {s.rev.names.length ? s.rev.names.map((n) => <div key={n}><Ltr mono>{n}</Ltr></div>) : <span className="muted">{t('ipintel.noPtr')}</span>}
        </Card>
      )}
      {s.r && (
        <Card title={<Ltr mono>{s.r.name}</Ltr>} icon={Search} tone="blue" subtitle={s.r.server ? t('net.server', { server: s.r.server }) : undefined}>
          {rows.length === 0 ? <div className="muted">{t('domainintel.noRecords')}</div> : (
            <DataTable rowKey={(x, i) => `${x.type}-${i}`} rows={rows} columns={[
              { key: 't', label: t('domainintel.type'), width: 80, render: (x) => <Badge tone="blue">{x.type}</Badge> },
              { key: 'v', label: t('domainintel.value'), render: (x) => <Ltr mono breakAll className="small">{x.v}</Ltr> },
            ]} />
          )}
        </Card>
      )}
    </div>
  );
}

function PortsTab() {
  const { t } = useI18n();
  const { confirm } = useApp();
  const [target, setTarget] = useState('127.0.0.1');
  const [ports, setPorts] = useState(COMMON_PORTS);
  const [onlyOpen, setOnlyOpen] = useState(false);
  const [s, setS] = useState<{ busy?: boolean; r?: PortCheckResult; e?: string; id?: string }>({});
  const prog = useTaskProgress(s.busy ? s.id ?? null : null);
  const run = async () => {
    if (!(await confirm({ title: t('net.authTitle'), body: t('net.authBody', { target: target.trim() }), confirmLabel: t('net.run'), requireCheck: t('net.authCheck') }))) return;
    const id = newTaskId();
    setS({ busy: true, id });
    const r = await window.blazma.net.portCheck(target.trim(), ports, id);
    setS(r.ok ? { r: r.data } : { e: r.error });
  };
  const rows = s.r ? (onlyOpen ? s.r.results.filter((x) => x.state === 'open') : s.r.results) : [];
  return (
    <div className="col" style={{ gap: 12 }}>
      <Notice tone="amber" icon={ShieldAlert}>{t('net.authorizedOnly')}</Notice>
      <Card>
        <TargetForm value={target} onChange={setTarget} busy={!!s.busy} placeholder={t('net.targetPlaceholder')} onSubmit={() => void run()} />
        <div className="field" style={{ marginTop: 12 }}>
          <label>{t('net.ports')}</label>
          <input className="input mono" dir="ltr" value={ports} onChange={(e) => setPorts(e.target.value)} />
          <span className="tiny dim">{t('net.portsHint')}</span>
        </div>
      </Card>
      {s.busy && (
        <Card>
          <Progress value={prog ? (prog.processedBytes / prog.totalBytes) * 100 : undefined} indeterminate={!prog} />
          <div className="row small muted" style={{ marginTop: 8 }}>
            {prog && <span>{t('net.progress', { done: prog.processedBytes, total: prog.totalBytes })}</span>}
            <span className="spacer" />
            <button className="btn danger sm" onClick={() => s.id && void window.blazma.files.cancel(s.id)}><X size={13} /> {t('common.cancel')}</button>
          </div>
        </Card>
      )}
      {s.e && <Card><ErrorState code={s.e} /></Card>}
      {s.r && (
        <Card
          title={<Ltr mono>{`${s.r.target} (${s.r.address})`}</Ltr>}
          icon={ScanSearch}
          tone="blue"
          subtitle={t('net.portSummary', { open: s.r.results.filter((x) => x.state === 'open').length, total: s.r.results.length, time: formatDuration(t, s.r.durationMs) })}
          actions={<div className="row"><Toggle checked={onlyOpen} label={t('net.onlyOpen')} onChange={setOnlyOpen} /><span className="small">{t('net.onlyOpen')}</span></div>}
        >
          <DataTable maxHeight={480} rowKey={(x) => String(x.port)} rows={rows} columns={[
            { key: 'p', label: t('net.port'), width: 80, render: (x) => <Ltr mono>{x.port}</Ltr> },
            { key: 's', label: t('forensics.col.state'), render: (x) => <Badge tone={x.state === 'open' ? 'green' : x.state === 'closed' ? 'gray' : 'amber'}>{t(`net.state.${x.state}`)}</Badge> },
            { key: 'v', label: t('net.service'), render: (x) => <Ltr mono className="small">{x.service ?? '—'}</Ltr> },
            { key: 'l', label: t('net.latency'), render: (x) => (x.latencyMs !== null ? <Ltr mono className="small">{`${x.latencyMs} ms`}</Ltr> : '—') },
          ]} />
        </Card>
      )}
    </div>
  );
}

function AdaptersTab() {
  const { t } = useI18n();
  const [s, setS] = useState<{ r?: AdapterRow[]; e?: string }>({});
  useEffect(() => void window.blazma.net.adapters().then((r) => setS(r.ok ? { r: r.data } : { e: r.error })), []);
  if (s.e) return <Card><ErrorState code={s.e} /></Card>;
  if (!s.r) return <Card><Skeleton h={120} /></Card>;
  return (
    <div className="grid g-2">
      {s.r.map((a) => (
        <Card key={a.name} title={<Ltr>{a.name}</Ltr>} subtitle={a.description ?? undefined} icon={Network} tone={a.internal ? 'gray' : a.status && /up/i.test(a.status) ? 'green' : 'amber'}>
          <dl className="kv">
            <dt>{t('forensics.col.state')}</dt><dd>{a.status ?? '—'}{a.internal && <> · <Badge tone="gray">{t('net.loopback')}</Badge></>}</dd>
            <dt>MAC</dt><dd><Ltr mono>{a.mac ?? '—'}</Ltr></dd>
            {a.speed && (<><dt>{t('net.speed')}</dt><dd><Ltr>{a.speed}</Ltr></dd></>)}
            <dt>IPv4</dt><dd>{a.ipv4.length ? a.ipv4.map((x) => <div key={x}><Ltr mono>{x}</Ltr></div>) : '—'}</dd>
            <dt>IPv6</dt><dd>{a.ipv6.length ? a.ipv6.map((x) => <div key={x}><Ltr mono breakAll className="small">{x}</Ltr></div>) : '—'}</dd>
            <dt>{t('net.gateway')}</dt><dd><Ltr mono>{a.gateway ?? '—'}</Ltr></dd>
            <dt>DNS</dt><dd>{a.dns.length ? a.dns.map((x) => <div key={x}><Ltr mono>{x}</Ltr></div>) : '—'}</dd>
          </dl>
        </Card>
      ))}
    </div>
  );
}

function SimpleTable<T>({ load, columns, empty }: { load: () => Promise<{ ok: true; data: T[] } | { ok: false; error: string }>; columns: Array<{ key: string; label: string; render: (r: T) => React.ReactNode }>; empty: string }) {
  const [s, setS] = useState<{ r?: T[]; e?: string }>({});
  useEffect(() => void load().then((r) => setS(r.ok ? { r: r.data } : { e: r.error })), []); // eslint-disable-line react-hooks/exhaustive-deps
  if (s.e) return <Card><ErrorState code={s.e} /></Card>;
  if (!s.r) return <Card><Skeleton h={120} /></Card>;
  return <Card>{s.r.length === 0 ? <EmptyState title={empty} /> : <DataTable maxHeight={560} rowKey={(_, i) => String(i)} rows={s.r} columns={columns} />}</Card>;
}

function DiscoveryTab() {
  const { t } = useI18n();
  const { confirm } = useApp();
  const [subnets, setSubnets] = useState<Array<{ cidr: string; interface: string; address: string }> | null>(null);
  const [cidr, setCidr] = useState('');
  const [s, setS] = useState<{ busy?: boolean; r?: DiscoveryResult; e?: string; id?: string }>({});
  const prog = useTaskProgress(s.busy ? s.id ?? null : null);
  useEffect(() => void window.blazma.net.subnets().then((r) => { if (r.ok) { setSubnets(r.data); setCidr(r.data[0]?.cidr ?? ''); } }), []);
  const run = async () => {
    if (!(await confirm({ title: t('net.authTitle'), body: t('net.discoverBody', { subnet: cidr }), confirmLabel: t('net.discover'), requireCheck: t('net.authCheck') }))) return;
    const id = newTaskId();
    setS({ busy: true, id });
    const r = await window.blazma.net.discover(cidr, id);
    setS(r.ok ? { r: r.data } : { e: r.error });
  };
  const trustAll = async () => {
    const macs = (s.r?.alive ?? []).map((x) => x.mac).filter((m): m is string => !!m);
    await window.blazma.net.trustDevices(macs);
    setS((cur) => (cur.r ? { r: { ...cur.r, alive: cur.r.alive.map((x) => ({ ...x, status: x.mac ? 'trusted' : x.status })), newCount: 0 } } : cur));
  };
  if (!subnets) return <Card><Skeleton h={80} /></Card>;
  return (
    <div className="col" style={{ gap: 12 }}>
      <Notice tone="amber" icon={ShieldAlert}>{t('net.discoverNote')}</Notice>
      <Card>
        {subnets.length === 0 ? <EmptyState icon={Radar} title={t('net.noSubnets')} /> : (
          <div className="row-wrap" style={{ alignItems: 'flex-end' }}>
            <div className="field">
              <label>{t('net.subnet')}</label>
              <select className="select" style={{ width: 320 }} value={cidr} onChange={(e) => setCidr(e.target.value)}>
                {subnets.map((x) => <option key={x.cidr} value={x.cidr}>{`${x.cidr} — ${x.interface} (${x.address})`}</option>)}
              </select>
            </div>
            <button className="btn primary" disabled={!cidr || s.busy} onClick={() => void run()}><Radar size={15} /> {t('net.discover')}</button>
          </div>
        )}
      </Card>
      {s.busy && (
        <Card>
          <Progress value={prog ? (prog.processedBytes / prog.totalBytes) * 100 : undefined} indeterminate={!prog} />
          <div className="row small muted" style={{ marginTop: 8 }}>
            {prog && <span>{t('net.progress', { done: prog.processedBytes, total: prog.totalBytes })}</span>}
            <span className="spacer" />
            <button className="btn danger sm" onClick={() => s.id && void window.blazma.files.cancel(s.id)}><X size={13} /> {t('common.cancel')}</button>
          </div>
        </Card>
      )}
      {s.e && <Card><ErrorState code={s.e} /></Card>}
      {s.r && (
        <Card
          title={t('net.discoverSummary', { alive: s.r.alive.length, probed: s.r.probed })}
          subtitle={`${s.r.subnet} · ${formatDuration(t, s.r.durationMs)}`}
          icon={Radar}
          tone={s.r.newCount ? 'amber' : 'green'}
          actions={s.r.newCount > 0 ? <button className="btn sm" onClick={() => void trustAll()}>{t('net.watch.trustAll')}</button> : undefined}
        >
          {s.r.newCount > 0 && <Notice tone="amber" icon={ShieldAlert}>{t('net.watch.newDevices', { n: s.r.newCount })}</Notice>}
          {s.r.alive.length === 0 ? <EmptyState title={t('net.noHosts')} /> : (
            <DataTable rowKey={(x) => x.address} rows={s.r.alive} columns={[
              { key: 'a', label: t('net.address'), render: (x) => <Ltr mono>{x.address}</Ltr> },
              { key: 'm', label: 'MAC', render: (x) => <Ltr mono>{x.mac ?? '—'}</Ltr> },
              { key: 'v', label: t('net.maker.title'), render: (x) => <DeviceMaker maker={x.maker} /> },
              { key: 's', label: t('net.watch.status'), render: (x) => (
                x.status === 'new' ? <Badge tone="amber">{t('net.watch.new')}</Badge>
                  : x.status === 'trusted' ? <Badge tone="green">{t('net.watch.trusted')}</Badge>
                  : x.status === 'known' ? <Badge tone="gray">{t('net.watch.known')}</Badge>
                  : <span className="dim">—</span>
              ) },
            ]} />
          )}
          {s.r.offline.length > 0 && <div className="tiny dim" style={{ marginTop: 10 }}>{t('net.watch.offline', { n: s.r.offline.length })}</div>}
        </Card>
      )}
    </div>
  );
}

export function NetworkToolkit() {
  const { t } = useI18n();
  const [tab, setTab] = useState<Tab>('adapters');
  return (
    <div className="page">
      <div className="page-head">
        <IconTile icon={Network} tone="green" />
        <div>
          <h1 className="page-title">{t('net.title')}</h1>
          <div className="page-sub">{t('net.subtitle')}</div>
        </div>
      </div>
      <div>
        <Tabs<Tab> value={tab} onChange={setTab} items={(['adapters', 'ping', 'trace', 'dns', 'ports', 'routes', 'neighbors', 'discovery'] as const).map((id) => ({ id, label: t(`net.tab.${id}`) }))} />
      </div>
      <div className="col" style={{ gap: 12 }}>
        {['ping', 'trace', 'dns', 'ports'].includes(tab) && <OfflineBanner />}
        {['ping', 'trace', 'dns', 'ports'].includes(tab) && <div className="tiny dim">{t('net.localNote')}</div>}
        {tab === 'adapters' && <AdaptersTab />}
        {tab === 'ping' && <PingTab />}
        {tab === 'trace' && <TraceTab />}
        {tab === 'dns' && <DnsTab />}
        {tab === 'ports' && <PortsTab />}
        {tab === 'routes' && (
          <SimpleTable<RouteRow> load={() => window.blazma.net.routes()} empty={t('forensics.empty')} columns={[
            { key: 'd', label: t('net.destination'), render: (r) => <Ltr mono>{r.destination}</Ltr> },
            { key: 'g', label: t('net.gateway'), render: (r) => <Ltr mono>{r.gateway ?? t('net.onLink')}</Ltr> },
            { key: 'i', label: t('net.interface'), render: (r) => <Ltr>{r.interface ?? '—'}</Ltr> },
            { key: 'm', label: t('net.metric'), render: (r) => <Ltr mono>{r.metric ?? '—'}</Ltr> },
          ]} />
        )}
        {tab === 'neighbors' && (
          <SimpleTable<NeighborRow> load={() => window.blazma.net.neighbors()} empty={t('forensics.empty')} columns={[
            { key: 'a', label: t('net.address'), render: (r) => <Ltr mono>{r.address}</Ltr> },
            { key: 'm', label: 'MAC', render: (r) => <Ltr mono>{r.mac ?? '—'}</Ltr> },
            { key: 'v', label: t('net.maker.title'), render: (r) => <DeviceMaker maker={r.maker} /> },
            { key: 's', label: t('forensics.col.state'), render: (r) => <Badge tone="gray">{r.state ?? '—'}</Badge> },
            { key: 'i', label: t('net.interface'), render: (r) => <Ltr>{r.interface ?? '—'}</Ltr> },
          ]} />
        )}
        {tab === 'discovery' && <DiscoveryTab />}
      </div>
    </div>
  );
}
