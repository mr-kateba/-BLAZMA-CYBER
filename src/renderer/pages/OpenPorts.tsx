import { useEffect, useMemo, useState } from 'react';
import { DoorOpen, Globe, House, RefreshCw, ShieldAlert } from 'lucide-react';
import type { ConnectionRow, ForensicsResult } from '../../shared/api';
import { listeningServices, type ListeningService } from '../../core/listening';
import { Badge, Card, DataTable, EmptyState, ErrorState, FilterInput, IconTile, Ltr, Notice, Skeleton, Toggle, useFilter } from '../components/ui';
import { useI18n } from '../i18n/I18nProvider';

export function OpenPorts() {
  const { t } = useI18n();
  const [state, setState] = useState<{ loading: boolean; data?: ForensicsResult<ConnectionRow>; error?: string }>({ loading: true });
  const [udp, setUdp] = useState(false);

  const load = async () => {
    setState({ loading: true });
    const r = await window.blazma.forensics.collect('connections');
    setState(r.ok ? { loading: false, data: r.data as ForensicsResult<ConnectionRow> } : { loading: false, error: r.error });
  };
  useEffect(() => void load(), []);

  const list = useMemo(() => (state.data ? listeningServices(state.data.rows, udp) : []), [state.data, udp]);
  const { q, setQ, filtered } = useFilter(list, (s) => [s.port, s.process, s.known ? t(`ports.known.${s.known}`) : null]);
  const attention = list.filter((s) => s.attention);
  const network = list.filter((s) => s.reach === 'network').length;

  return (
    <div className="page">
      <div className="page-head">
        <IconTile icon={DoorOpen} tone="cyan" />
        <div>
          <h1 className="page-title">{t('ports.title')}</h1>
          <div className="page-sub">{t('ports.subtitle')}</div>
        </div>
      </div>
      <div className="col" style={{ gap: 16 }}>
        <Notice>{t('ports.intro')}</Notice>
        {state.loading && <Card><Skeleton h={120} /></Card>}
        {state.error && <Card><ErrorState code={state.error} onRetry={() => void load()} /></Card>}
        {state.data && (
          <>
            <div className="tstats">
              <div className="tstat"><div className="tstat-l">{t('ports.statTotal')}</div><div className="tstat-v"><Ltr>{list.length}</Ltr></div></div>
              <div className="tstat"><div className="tstat-l">{t('ports.statNetwork')}</div><div className="tstat-v"><Ltr>{network}</Ltr></div></div>
              <div className="tstat"><div className="tstat-l">{t('ports.statLocal')}</div><div className="tstat-v"><Ltr>{list.length - network}</Ltr></div></div>
              <div className="tstat"><div className="tstat-l">{t('ports.statAttention')}</div><div className="tstat-v"><Ltr>{attention.length}</Ltr></div></div>
            </div>
            {attention.length > 0 && (
              <Card title={t('ports.attentionTitle')} icon={ShieldAlert} tone="amber" explain="open_ports">
                <div className="col" style={{ gap: 8 }}>
                  {attention.map((s) => (
                    <div key={`${s.protocol}${s.port}${s.pid}`} className="devsec-row tone-amber">
                      <div className="devsec-head" style={{ cursor: 'default' }}>
                        <ShieldAlert size={18} className="devsec-icon" />
                        <span className="devsec-title">{t(`ports.attention.${s.kind}`, { port: s.port, program: s.process ?? '?' })}</span>
                      </div>
                      <div className="small muted devsec-detail">{t(`ports.advice.${s.kind}`)}</div>
                    </div>
                  ))}
                </div>
              </Card>
            )}
            <Card
              title={t('ports.listTitle')}
              subtitle={state.data.elevated === false ? t('ports.notElevated') : undefined}
              icon={DoorOpen}
              actions={<div className="row" style={{ gap: 10 }}>
                <Toggle checked={udp} onChange={setUdp} label={t('ports.showUdp')} />
                <span className="small">{t('ports.showUdp')}</span>
                <button className="btn sm" onClick={() => void load()}><RefreshCw size={13} /> {t('ports.refresh')}</button>
              </div>}
            >
              <div style={{ marginBottom: 10 }}><FilterInput value={q} onChange={setQ} placeholder={t('ports.filter')} /></div>
              {filtered.length === 0 ? <EmptyState icon={DoorOpen} title={t('ports.none')} /> : (
                <DataTable<ListeningService> maxHeight={560} rowKey={(s) => `${s.protocol}:${s.port}:${s.pid}`} rows={filtered} columns={[
                  { key: 'port', label: t('ports.colPort'), render: (s) => <Ltr mono>{`${s.port}/${s.protocol.toLowerCase()}`}</Ltr> },
                  { key: 'prog', label: t('ports.colProgram'), render: (s) => <div>{s.process ? <Ltr>{s.process}</Ltr> : <span className="dim">—</span>}{s.pid !== null && <div className="tiny dim"><Ltr>{t('ports.pid', { pid: s.pid })}</Ltr></div>}</div> },
                  { key: 'what', label: t('ports.colWhat'), render: (s) => <span className="small">{s.known ? t(`ports.known.${s.known}`) : <span className="dim">{t('ports.unknownPort')}</span>}</span> },
                  { key: 'reach', label: t('ports.colReach'), render: (s) => (
                    <div className="row" style={{ gap: 6 }}>
                      {s.reach === 'network' ? <Badge tone={s.attention ? 'amber' : 'blue'} icon={Globe}>{t('ports.reach.network')}</Badge> : <Badge tone="gray" icon={House}>{t('ports.reach.local')}</Badge>}
                    </div>
                  ) },
                  { key: 'addr', label: t('ports.colAddress'), render: (s) => <Ltr mono className="tiny">{s.addresses.join(', ')}</Ltr> },
                ]} />
              )}
              <div className="tiny dim" style={{ marginTop: 10 }}>{t('ports.firewallNote')}</div>
            </Card>
          </>
        )}
      </div>
    </div>
  );
}
