import { useEffect, useState } from 'react';
import { AlertTriangle, Download, Radar, Server, ShieldAlert, X } from 'lucide-react';
import type { NmapFinding, NmapInfo, NmapProfile, NmapResult, TaskProgress } from '../../shared/api';
import { AddToCase } from '../components/AddToCase';
import { Badge, Card, DataTable, EmptyState, ErrorState, IconTile, Ltr, Notice, Progress, Skeleton, type Tone } from '../components/ui';
import { OptionPills } from '../components/intel';
import { useApp } from '../components/AppContext';
import { useI18n } from '../i18n/I18nProvider';
import { formatDuration, newTaskId } from '../format';

const SEV_TONE: Record<NmapFinding['severity'], Tone> = { high: 'red', medium: 'amber', low: 'blue' };
const PROFILES: NmapProfile[] = ['hosts', 'quick', 'standard'];

export function ServiceScan() {
  const { t } = useI18n();
  const { confirm, toast, prefillFor } = useApp();
  const preset = prefillFor('service-scan')?.value;
  const [info, setInfo] = useState<NmapInfo | null>(null);
  const [subnets, setSubnets] = useState<Array<{ cidr: string; interface: string; address: string }>>([]);
  const [target, setTarget] = useState(() => preset ?? '');
  const [profile, setProfile] = useState<NmapProfile>('quick');
  const [state, setState] = useState<{ running?: string; result?: NmapResult; error?: string }>({});
  const [p, setP] = useState<TaskProgress | null>(null);

  useEffect(() => {
    void window.blazma.nmap.info().then((r) => r.ok && setInfo(r.data));
    void window.blazma.nmap.targets().then((r) => {
      if (!r.ok) return;
      setSubnets(r.data);
      if (r.data[0] && !preset) setTarget(r.data[0].cidr);
    });
  }, []);
  useEffect(() => {
    setP(null);
    if (!state.running) return;
    return window.blazma.files.onProgress((x) => x.taskId === state.running && setP(x));
  }, [state.running]);

  const start = async () => {
    const tgt = target.trim();
    if (!(await confirm({ title: t('nmap.authTitle'), body: t('nmap.authBody', { target: tgt }), confirmLabel: t('nmap.start'), requireCheck: t('net.authCheck') }))) return;
    const taskId = newTaskId();
    setState({ running: taskId });
    const r = await window.blazma.nmap.scan(tgt, profile, true, taskId);
    setState(r.ok ? { result: r.data } : { error: r.error });
    if (!r.ok && r.error === 'nmap_target_not_local') toast('amber', t('errors.nmap_target_not_local'));
  };

  const r = state.result;
  return (
    <div className="page">
      <div className="page-head">
        <IconTile icon={Radar} tone="green" />
        <div>
          <h1 className="page-title">{t('nmap.title')}</h1>
          <div className="page-sub">{t('nmap.subtitle')}</div>
        </div>
      </div>
      <div className="col" style={{ gap: 16 }}>
        <Notice tone="amber" icon={ShieldAlert}>{t('nmap.authorizedOnly')}</Notice>
        {!info && <Card><Skeleton h={80} /></Card>}
        {info && !info.installed && (
          <Card>
            <EmptyState icon={Radar} title={t('nmap.notInstalled')} hint={t('nmap.installHint')}>
              <button className="btn primary" onClick={() => void window.blazma.app.openLink('https://nmap.org/download.html')}><Download size={15} /> {t('nmap.download')}</button>
            </EmptyState>
          </Card>
        )}
        {info?.installed && !state.running && !state.result && (
          <Card title={t('nmap.scanTitle')} subtitle={t('nmap.engine', { version: info.version ?? '?' })} icon={Radar} tone="green" explain="service_scan">
            <div className="col" style={{ gap: 14 }}>
              <label className="col" style={{ gap: 6 }}>
                <span className="small dim">{t('nmap.target')}</span>
                <div className="row-wrap" style={{ gap: 8 }}>
                  {subnets.map((s) => (
                    <button key={s.cidr} type="button" className={`btn sm ${target === s.cidr ? 'primary' : ''}`} onClick={() => setTarget(s.cidr)}>
                      <Ltr mono>{s.cidr}</Ltr> <span className="tiny">· {s.interface}</span>
                    </button>
                  ))}
                </div>
                <input className="input mono" dir="ltr" value={target} placeholder={t('nmap.targetPlaceholder')} onChange={(e) => setTarget(e.target.value)} />
                <span className="tiny dim">{t('nmap.targetNote')}</span>
              </label>
              <div>
                <div className="small dim" style={{ marginBottom: 6 }}>{t('nmap.profile')}</div>
                <OptionPills single items={PROFILES.map((id) => ({ id, label: t(`nmap.profiles.${id}`), checked: profile === id }))} onToggle={(id) => setProfile(id as NmapProfile)} />
                <div className="tiny dim" style={{ marginTop: 6 }}>{t(`nmap.profileHint.${profile}`)}</div>
              </div>
              <div><button className="btn primary" disabled={!target.trim()} onClick={() => void start()}><Radar size={15} /> {t('nmap.start')}</button></div>
            </div>
          </Card>
        )}
        {state.running && (
          <Card>
            <Progress value={p ? p.processedBytes / 10 : 0} indeterminate={!p} />
            <div className="row" style={{ marginTop: 10, gap: 10 }}>
              <span className="small muted">{t('nmap.running', { pct: p ? Math.round(p.processedBytes / 10) : 0 })}</span>
              <span className="spacer" />
              <button className="btn danger sm" onClick={() => void window.blazma.files.cancel(state.running!)}><X size={13} /> {t('common.cancel')}</button>
            </div>
          </Card>
        )}
        {state.error && <Card><ErrorState code={state.error} onRetry={() => setState({})} /></Card>}
        {r && (
          <>
            <Card
              title={t('nmap.resultTitle', { target: r.target })}
              subtitle={t('nmap.resultSub', { up: r.run.hostsUp, time: formatDuration(t, r.durationMs), profile: t(`nmap.profiles.${r.profile}`) })}
              icon={Server}
              tone={r.findings.some((f) => f.severity === 'high') ? 'red' : r.findings.length ? 'amber' : 'green'}
              actions={<div className="row" style={{ gap: 8 }}>
                <AddToCase items={r.run.hosts.map((h) => ({ kind: 'ip' as const, value: h.address, label: h.hostnames[0] ?? h.vendor, source: 'nmap', details: { mac: h.mac, vendor: h.vendor, open: h.ports.filter((x) => x.state === 'open').map((x) => `${x.port}/${x.service ?? '?'}`).join(' ') || null } }))} />
                <button className="btn sm" onClick={() => setState({})}>{t('nmap.again')}</button>
              </div>}
            >
              {r.findings.length === 0 ? <div className="small">{t('nmap.noFindings')}</div> : (
                <div className="col" style={{ gap: 8 }}>
                  {r.findings.map((f, i) => (
                    <div key={i} className={`devsec-row tone-${SEV_TONE[f.severity]}`}>
                      <div className="devsec-head" style={{ cursor: 'default' }}>
                        <AlertTriangle size={18} className="devsec-icon" />
                        <span className="devsec-title">{t(`nmap.risk.${f.risk}.title`, { host: f.host, port: f.port, service: f.service })}</span>
                        <span className="spacer" />
                        <Badge tone={SEV_TONE[f.severity]}>{t(`traffic.severity.${f.severity}`)}</Badge>
                      </div>
                      <div className="small muted devsec-detail">{t(`nmap.risk.${f.risk}.body`)}</div>
                    </div>
                  ))}
                </div>
              )}
            </Card>
            <Card title={t('nmap.hostsTitle')}>
              {r.run.hosts.length === 0 ? <EmptyState icon={Server} title={t('nmap.noHosts')} /> : (
                <DataTable maxHeight={560} rowKey={(h) => h.address} rows={r.run.hosts} columns={[
                  { key: 'a', label: t('net.address'), render: (h) => <div><Ltr mono>{h.address}</Ltr>{h.hostnames[0] && <div className="tiny dim"><Ltr>{h.hostnames[0]}</Ltr></div>}</div> },
                  { key: 'm', label: t('net.maker.title'), render: (h) => h.vendor ? <Ltr className="small">{h.vendor}</Ltr> : h.mac ? <Ltr mono className="tiny">{h.mac}</Ltr> : <span className="dim">—</span> },
                  { key: 'p', label: t('nmap.openServices'), render: (h) => {
                    const open = h.ports.filter((x) => x.state === 'open');
                    if (r.profile === 'hosts') return <span className="dim small">{t('nmap.hostsOnly')}</span>;
                    if (!open.length) return <span className="dim small">{t('nmap.noneOpen')}</span>;
                    return (
                      <div className="chip-list">
                        {open.map((x) => (
                          <span key={`${x.protocol}${x.port}`} className="chip" title={[x.product, x.version, x.extra].filter(Boolean).join(' ')}>
                            <Ltr mono>{`${x.port}/${x.service ?? '?'}`}</Ltr>{x.product && <span className="tiny dim"> · <Ltr>{[x.product, x.version].filter(Boolean).join(' ')}</Ltr></span>}
                          </span>
                        ))}
                      </div>
                    );
                  } },
                ]} />
              )}
            </Card>
          </>
        )}
      </div>
    </div>
  );
}
