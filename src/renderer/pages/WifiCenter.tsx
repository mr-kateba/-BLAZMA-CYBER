import { useEffect, useState } from 'react';
import { AlertTriangle, EyeOff, Lock, LockOpen, MapPin, RefreshCw, Save, Wifi, WifiOff } from 'lucide-react';
import type { WifiFinding, WifiRating, WifiReport } from '../../shared/api';
import { Badge, Card, DataTable, EmptyState, ErrorState, Gauge, IconTile, Ltr, Notice, Skeleton, Tabs, type Tone } from '../components/ui';
import { useI18n } from '../i18n/I18nProvider';
import { formatDateTime } from '../format';

const RATING_TONE: Record<WifiRating, Tone> = { good: 'green', ok: 'green', weak: 'amber', bad: 'red', unknown: 'gray' };
const SEV_TONE: Record<WifiFinding['severity'], Tone> = { high: 'red', medium: 'amber', low: 'blue', info: 'gray' };

function SecurityBadge({ rating, label }: { rating: WifiRating; label: string | null }) {
  const { t } = useI18n();
  const Icon = rating === 'bad' ? LockOpen : Lock;
  return <Badge tone={RATING_TONE[rating]} icon={Icon}>{label ?? t(`wifi.rating.${rating}`)}</Badge>;
}

function SignalBars({ value }: { value: number | null }) {
  if (value === null) return <span className="dim">—</span>;
  const bars = value >= 80 ? 4 : value >= 60 ? 3 : value >= 40 ? 2 : 1;
  return (
    <span className="signal" title={`${value}%`}>
      {[1, 2, 3, 4].map((b) => <span key={b} className={b <= bars ? 'on' : ''} style={{ height: 4 + b * 3 }} />)}
      <Ltr className="tiny dim">{value}%</Ltr>
    </span>
  );
}

/** The least crowded non-overlapping 2.4 GHz channel (1, 6 or 11). */
function bestChannel(channels: WifiReport['channels'], current: number | null): number | null {
  const load = (c: number) => channels.filter((x) => x.band === '2.4' && Math.abs(x.channel - c) < 5).reduce((s, x) => s + x.networks, 0) - (current !== null && Math.abs(current - c) < 5 ? 1 : 0);
  const best = [1, 6, 11].sort((a, b) => load(a) - load(b))[0]!;
  return current !== null && load(best) < load(current) - 1 ? best : null;
}

type Tab = 'nearby' | 'saved' | 'channels';

export function WifiCenter() {
  const { t, locale } = useI18n();
  const [s, setS] = useState<{ loading?: boolean; r?: WifiReport; e?: string }>({ loading: true });
  const [tab, setTab] = useState<Tab>('nearby');
  const load = () => {
    setS((x) => ({ ...x, loading: true }));
    void window.blazma.wifi.report().then((r) => setS(r.ok ? { r: r.data } : { e: r.error }));
  };
  useEffect(load, []);

  const r = s.r;
  const conn = r?.connections[0] ?? null;
  const suggestion = r && conn?.band === '2.4' ? bestChannel(r.channels, conn.channel) : null;

  return (
    <div className="page">
      <div className="page-head">
        <IconTile icon={Wifi} tone="blue" />
        <div>
          <h1 className="page-title">{t('wifi.title')}</h1>
          <div className="page-sub">{t('wifi.subtitle')}</div>
        </div>
        <span className="spacer" />
        <button className="btn" disabled={s.loading} onClick={load}><RefreshCw size={15} /> {t('wifi.refresh')}</button>
      </div>

      <div className="col" style={{ gap: 16 }}>
        <Notice tone="blue">{t('wifi.readOnly')}</Notice>
        {s.e && <Card><ErrorState code={s.e} onRetry={load} /></Card>}
        {!r && !s.e && <Card><Skeleton h={160} /></Card>}

        {r && !r.available && (
          <Card><EmptyState icon={WifiOff} title={t(`wifi.reason.${r.reason ?? 'no_wifi_adapter'}`)} hint={t('wifi.reasonHint')} /></Card>
        )}

        {r && r.locationBlocked && (
          <Notice tone="amber" icon={MapPin}>
            <div className="row" style={{ justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
              <span>{t('wifi.locationBlocked')}</span>
              <button className="btn sm" onClick={() => void window.blazma.wifi.openLocationSettings()}><MapPin size={13} /> {t('wifi.openLocation')}</button>
            </div>
          </Notice>
        )}

        {r?.available && (
          <>
            <Card title={t('wifi.current')} icon={Wifi} tone={conn ? RATING_TONE[conn.rating] : 'gray'} subtitle={t('wifi.updated', { time: formatDateTime(locale, r.collectedAt) })}>
              {!conn ? (
                <div className="small muted">{t('wifi.notConnected')}</div>
              ) : (
                <div className="wifi-now">
                  <Gauge value={conn.signal} label={t('wifi.signal')} color={conn.signal !== null && conn.signal < 40 ? 'var(--amber)' : 'var(--green)'} />
                  <div className="col" style={{ gap: 10, minWidth: 0 }}>
                    <div className="big-value"><Ltr>{conn.ssid ?? t('wifi.nameHidden')}</Ltr></div>
                    <div className="row-wrap" style={{ gap: 8 }}>
                      <SecurityBadge rating={conn.rating} label={conn.authentication} />
                      {conn.band && <Badge tone="blue">{t('wifi.band', { band: conn.band })}</Badge>}
                      {conn.phy && <Badge tone="purple"><Ltr>{conn.phy}</Ltr></Badge>}
                    </div>
                    <dl className="kv">
                      <dt>{t('wifi.security')}</dt><dd>{t(`wifi.securityExplain.${conn.security}`)}</dd>
                      {conn.cipher && (<><dt>{t('wifi.cipher')}</dt><dd><Ltr>{conn.cipher}</Ltr></dd></>)}
                      {conn.channel && (<><dt>{t('wifi.channel')}</dt><dd><Ltr>{conn.channel}</Ltr>{suggestion && <span className="tiny dim"> · {t('wifi.suggestChannel', { channel: suggestion })}</span>}</dd></>)}
                      {(conn.rxMbps || conn.txMbps) && (<><dt>{t('wifi.speed')}</dt><dd><Ltr>{`↓ ${conn.rxMbps ?? '—'} / ↑ ${conn.txMbps ?? '—'} Mbps`}</Ltr></dd></>)}
                      {conn.rssi !== null && (<><dt>{t('wifi.rssi')}</dt><dd><Ltr>{`${conn.rssi} dBm`}</Ltr></dd></>)}
                      {conn.bssid && (<><dt>{t('wifi.bssid')}</dt><dd><Ltr mono>{conn.bssid}</Ltr></dd></>)}
                      <dt>{t('wifi.adapter')}</dt><dd><Ltr>{conn.interfaceName}</Ltr></dd>
                    </dl>
                  </div>
                </div>
              )}
            </Card>

            <Card title={t('wifi.findingsTitle')} icon={AlertTriangle} tone={r.findings.some((f) => f.severity === 'high') ? 'red' : r.findings.length ? 'amber' : 'green'}>
              {r.findings.length === 0 ? <div className="small">{t('wifi.noFindings')}</div> : (
                <div className="col" style={{ gap: 8 }}>
                  {r.findings.map((f, i) => (
                    <div key={`${f.id}-${i}`} className={`devsec-row tone-${SEV_TONE[f.severity]}`}>
                      <div className="devsec-head" style={{ cursor: 'default' }}>
                        <AlertTriangle size={18} className="devsec-icon" />
                        <span className="devsec-title">{t(`wifi.finding.${f.id}.title`, f.vars)}</span>
                        <span className="spacer" />
                        <Badge tone={SEV_TONE[f.severity]}>{t(`traffic.severity.${f.severity}`)}</Badge>
                      </div>
                      <div className="small muted devsec-detail">{t(`wifi.finding.${f.id}.body`, f.vars)}</div>
                    </div>
                  ))}
                </div>
              )}
            </Card>

            <Card>
              <Tabs<Tab> value={tab} onChange={setTab} items={([['nearby', r.networks.length], ['saved', r.profiles.length], ['channels', r.channels.length]] as const).map(([id, n]) => ({ id, label: `${t(`wifi.tab.${id}`)} (${n})` }))} />
              {tab === 'nearby' && (r.networks.length === 0 ? <EmptyState icon={Wifi} title={r.locationBlocked ? t('wifi.nearbyBlocked') : t('wifi.nearbyNone')} /> : (
                <DataTable maxHeight={480} rowKey={(n, i) => `${i}-${n.ssid}-${n.authentication}`} rows={r.networks} columns={[
                  { key: 'n', label: t('wifi.col.name'), render: (n) => (
                    <div className="row" style={{ gap: 6 }}>
                      {n.hidden ? <span className="dim"><EyeOff size={13} /> {t('wifi.hiddenNetwork')}</span> : <Ltr>{n.ssid}</Ltr>}
                      {n.connected && <Badge tone="green">{t('wifi.connected')}</Badge>}
                      {n.saved && !n.connected && <Badge tone="gray" icon={Save}>{t('wifi.saved')}</Badge>}
                    </div>
                  ) },
                  { key: 's', label: t('wifi.signal'), render: (n) => <SignalBars value={n.signal} /> },
                  { key: 'sec', label: t('wifi.security'), render: (n) => <SecurityBadge rating={n.rating} label={n.authentication} /> },
                  { key: 'c', label: t('wifi.channel'), render: (n) => n.channel ? <Ltr className="small">{`${n.channel} · ${n.band} GHz`}</Ltr> : <span className="dim">—</span> },
                  { key: 'ap', label: t('wifi.col.aps'), render: (n) => <Ltr className="small">{n.bssids}</Ltr> },
                ]} />
              ))}
              {tab === 'saved' && (!r.profilesReadable ? <Notice tone="gray">{t('wifi.profilesUnreadable')}</Notice> : r.profiles.length === 0 ? <EmptyState icon={Save} title={t('wifi.savedNone')} /> : (
                <>
                  <div className="tiny dim" style={{ marginBottom: 10 }}>{t('wifi.savedNote')}</div>
                  <DataTable maxHeight={480} rowKey={(p) => p.name} rows={r.profiles} columns={[
                    { key: 'n', label: t('wifi.col.name'), render: (p) => <div><Ltr>{p.name}</Ltr>{p.hidden && <div className="tiny dim"><EyeOff size={11} /> {t('wifi.hiddenProfile')}</div>}</div> },
                    { key: 'sec', label: t('wifi.security'), render: (p) => <SecurityBadge rating={p.rating} label={p.enterprise ? `${p.authentication ?? ''} · 802.1X` : p.authentication} /> },
                    { key: 'e', label: t('wifi.cipher'), render: (p) => <Ltr className="small">{p.encryption ?? '—'}</Ltr> },
                    { key: 'a', label: t('wifi.col.auto'), render: (p) => p.autoConnect ? <Badge tone={p.rating === 'bad' ? 'amber' : 'gray'}>{t('wifi.auto')}</Badge> : <span className="dim small">{t('wifi.manual')}</span> },
                  ]} />
                </>
              ))}
              {tab === 'channels' && (
                <div className="col" style={{ gap: 14 }}>
                  <div className="tiny dim">{t('wifi.channelsNote')}</div>
                  {(['2.4', '5', '6'] as const).map((band) => {
                    const rows = r.channels.filter((c) => c.band === band);
                    if (!rows.length) return null;
                    const max = Math.max(...rows.map((x) => x.networks));
                    return (
                      <div key={band}>
                        <div className="small" style={{ fontWeight: 600, marginBottom: 8 }}>{t('wifi.band', { band })}</div>
                        <div className="chan-chart">
                          {rows.map((c) => (
                            <div key={c.channel} className={`chan ${conn?.band === band && conn.channel === c.channel ? 'mine' : ''}`} title={t('wifi.channelTip', { channel: c.channel, n: c.networks })}>
                              <span className="bar" style={{ height: `${Math.max(8, (c.networks / max) * 100)}%` }} />
                              <Ltr className="tiny">{c.channel}</Ltr>
                            </div>
                          ))}
                        </div>
                      </div>
                    );
                  })}
                  {suggestion && <Notice tone="blue">{t('wifi.suggestLong', { channel: suggestion })}</Notice>}
                </div>
              )}
            </Card>
          </>
        )}
      </div>
    </div>
  );
}
