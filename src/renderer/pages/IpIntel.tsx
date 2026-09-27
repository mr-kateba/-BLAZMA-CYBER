import { useEffect, useMemo, useState } from 'react';
import { Building2, Earth, Globe, MapPin, Network, Route, Search, ShieldAlert, ShieldCheck } from 'lucide-react';
import { REPUTATION_FOR_KIND, type IpLookupOptions, type IpLookupResult, type ReputationService } from '../../shared/api';
import { isIP } from '../../core/validation';
import { Badge, Card, ErrorState, IconTile, Ltr, Notice, Progress } from '../components/ui';
import { hasRepKey, KV, OfflineBanner, OptionPills, ReputationCard, SourcesTable, useKeyStatus } from '../components/intel';
import { AddToCase } from '../components/AddToCase';
import { useI18n } from '../i18n/I18nProvider';
import { formatDateTime } from '../format';

const REP = REPUTATION_FOR_KIND.ip;

export function IpIntel() {
  const { t, locale } = useI18n();
  const keys = useKeyStatus();
  const [value, setValue] = useState('');
  const [opts, setOpts] = useState<IpLookupOptions>({ reverseDns: true, rdap: true, asn: true, geo: true, tor: true, reputation: [] });
  const [state, setState] = useState<{ loading?: boolean; result?: IpLookupResult; error?: string }>({});
  const valid = useMemo(() => isIP(value.trim()), [value]);

  // Pre-select reputation services that have a key.
  useEffect(() => {
    if (keys) setOpts((o) => ({ ...o, reputation: REP.filter((s) => hasRepKey(keys, s)) }));
  }, [keys]);

  const run = async () => {
    if (!valid) return;
    setState({ loading: true });
    const r = await window.blazma.intel.ip(value.trim(), opts);
    setState(r.ok ? { result: r.data } : { error: r.error });
  };

  const r = state.result;
  const hosting = r?.reputation.find((x) => x.service === 'abuseipdb')?.usageType;

  return (
    <div className="page">
      <div className="page-head">
        <IconTile icon={Earth} tone="blue" />
        <div>
          <h1 className="page-title">{t('ipintel.title')}</h1>
          <div className="page-sub">{t('ipintel.subtitle')}</div>
        </div>
      </div>

      <div className="col" style={{ gap: 16 }}>
        <OfflineBanner />
        <Card>
          <form className="lookup-bar" onSubmit={(e) => { e.preventDefault(); void run(); }}>
            <input
              className="input mono"
              dir="ltr"
              value={value}
              placeholder={t('ipintel.placeholder')}
              aria-label={t('ipintel.title')}
              aria-invalid={value.trim() !== '' && !valid}
              onChange={(e) => setValue(e.target.value)}
            />
            <button className="btn primary" type="submit" disabled={!valid || state.loading}>
              <Search size={16} /> {t('intel.lookup')}
            </button>
          </form>
          {value.trim() !== '' && !valid && <div className="small" style={{ color: 'var(--amber)', marginTop: 8 }}>{t('errors.invalid_ip')}</div>}
          <div style={{ marginTop: 14 }}>
            <div className="small dim" style={{ marginBottom: 8 }}>{t('intel.options')}</div>
            <OptionPills
              items={[
                ...(['reverseDns', 'rdap', 'asn', 'geo', 'tor'] as const).map((k) => ({ id: k, label: t(`ipintel.opt.${k}`), checked: opts[k] })),
                ...REP.map((s) => ({
                  id: s,
                  label: t(`intel.src.reputation:${s}`),
                  checked: opts.reputation.includes(s),
                  disabled: !hasRepKey(keys, s),
                  hint: keys && !hasRepKey(keys, s) ? t('intel.needsKey') : undefined,
                })),
              ]}
              onToggle={(id) =>
                setOpts((o) =>
                  (REP as readonly string[]).includes(id)
                    ? { ...o, reputation: o.reputation.includes(id as ReputationService) ? o.reputation.filter((x) => x !== id) : [...o.reputation, id as ReputationService] }
                    : { ...o, [id]: !o[id as keyof IpLookupOptions] },
                )
              }
            />
          </div>
          <div className="tiny dim" style={{ marginTop: 12 }}>{t('intel.externalNote')}</div>
        </Card>

        <Notice tone="amber" icon={MapPin}>{t('ipintel.geoNotice')}</Notice>

        {state.loading && <Card><Progress indeterminate /><div className="small muted" style={{ marginTop: 8 }}>{t('intel.looking')}</div></Card>}
        {state.error && <Card><ErrorState code={state.error} /></Card>}

        {r && (
          <>
            <div className="card row" style={{ gap: 16, flexWrap: 'wrap' }}>
              <IconTile icon={Globe} tone={r.scope === 'public' ? 'blue' : 'cyan'} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div className="big-value"><Ltr mono>{r.ip}</Ltr></div>
                <div className="row-wrap" style={{ marginTop: 6 }}>
                  <Badge tone={r.scope === 'public' ? 'blue' : 'cyan'}>{t(`ipintel.scope.${r.scope}`)}</Badge>
                  <Badge tone="gray">{t('ipintel.version', { v: r.version })}</Badge>
                  {r.tor === true && <Badge tone="red" icon={ShieldAlert}>{t('ipintel.torYes')}</Badge>}
                  {hosting && /hosting|data center/i.test(hosting) && <Badge tone="amber">{t('ipintel.hostingHint')}</Badge>}
                </div>
              </div>
              <AddToCase items={[{ kind: 'ip', value: r.ip, source: 'ipIntel', details: { scope: r.scope, asn: r.asn ? `AS${r.asn.asn}` : null, asName: r.asn?.name ?? null, country: r.rdap?.country ?? r.asn?.country ?? null, network: r.rdap?.name ?? null, tor: r.tor } }]} />
            </div>
            {r.scope !== 'public' && <Notice tone="cyan">{t('ipintel.scopeNote')}</Notice>}

            <div className="grid g-2">
              {opts.rdap && (
                <Card title={t('ipintel.network')} explain="ip_network" icon={Network} tone="blue">
                  {!r.rdap ? <div className="muted small">{sourceNote(r, 'rdap', t)}</div> : (
                    <dl className="kv">
                      <KV label={t('ipintel.netName')}><Ltr>{r.rdap.name ?? '—'}</Ltr></KV>
                      <KV label={t('ipintel.org')}><Ltr>{r.rdap.registrant ?? '—'}</Ltr></KV>
                      <KV label={t('ipintel.range')}>{r.rdap.startAddress ? <Ltr mono>{`${r.rdap.startAddress} – ${r.rdap.endAddress}`}</Ltr> : '—'}</KV>
                      <KV label={t('ipintel.cidr')}>{r.rdap.cidrs.length ? <Ltr mono>{r.rdap.cidrs.join(', ')}</Ltr> : '—'}</KV>
                      <KV label={t('ipintel.country')}><Ltr>{r.rdap.country ?? '—'}</Ltr></KV>
                      <KV label={t('ipintel.abuse')}>{r.rdap.abuseEmail ? <Ltr mono>{r.rdap.abuseEmail}</Ltr> : '—'}</KV>
                      <KV label={t('ipintel.registered')}>{formatDateTime(locale, r.rdap.registered)}</KV>
                      <KV label={t('ipintel.updated')}>{formatDateTime(locale, r.rdap.lastChanged)}</KV>
                      <KV label={t('ipintel.handle')}><Ltr mono>{r.rdap.handle ?? '—'}</Ltr></KV>
                      <KV label={t('ipintel.registry')}><Ltr mono>{r.rdap.source ?? '—'}</Ltr></KV>
                    </dl>
                  )}
                </Card>
              )}
              {opts.asn && (
                <Card title={t('ipintel.asnTitle')} explain="asn" icon={Route} tone="purple">
                  {!r.asn ? <div className="muted small">{sourceNote(r, 'asn', t)}</div> : (
                    <dl className="kv">
                      <KV label="ASN"><Ltr mono>{`AS${r.asn.asn}`}</Ltr></KV>
                      <KV label={t('ipintel.asnName')}><Ltr>{r.asn.name ?? '—'}</Ltr></KV>
                      <KV label={t('ipintel.prefix')}><Ltr mono>{r.asn.prefix ?? '—'}</Ltr></KV>
                      <KV label={t('ipintel.country')}><Ltr>{r.asn.country ?? '—'}</Ltr></KV>
                      <KV label={t('ipintel.registry')}><Ltr>{r.asn.registry?.toUpperCase() ?? '—'}</Ltr></KV>
                      <KV label={t('ipintel.allocated')}><Ltr>{r.asn.allocated ?? '—'}</Ltr></KV>
                    </dl>
                  )}
                </Card>
              )}
              {opts.geo && (
                <Card title={t('ipintel.location')} explain="geo" icon={MapPin} tone="amber" subtitle={t('ipintel.geoNotice')}>
                  {!r.geo ? <div className="muted small">{sourceNote(r, 'geo', t)}</div> : (
                    <dl className="kv">
                      <KV label={t('ipintel.country')}><Ltr>{r.geo.country ?? '—'}</Ltr></KV>
                      <KV label={t('ipintel.region')}><Ltr>{r.geo.region ?? '—'}</Ltr></KV>
                      <KV label={t('ipintel.city')}><Ltr>{r.geo.city ?? '—'}</Ltr></KV>
                      <KV label={t('ipintel.timezone')}><Ltr>{r.geo.timezone ?? '—'}</Ltr></KV>
                      <KV label={t('ipintel.coords')}><Ltr mono>{r.geo.loc ?? '—'}</Ltr></KV>
                      <KV label={t('ipintel.orgIsp')}><Ltr>{r.geo.org ?? '—'}</Ltr></KV>
                    </dl>
                  )}
                </Card>
              )}
              <Card title={t('ipintel.indicators')} explain="ip_indicators" icon={Building2} tone="cyan">
                <dl className="kv">
                  {opts.reverseDns && (
                    <KV label={t('ipintel.reverse')}>
                      {r.reverseDns === null ? <span className="dim small">{sourceNote(r, 'reverse_dns', t)}</span>
                        : r.reverseDns.length === 0 ? <span className="dim">{t('ipintel.noPtr')}</span>
                        : <div className="col" style={{ gap: 2 }}>{r.reverseDns.map((h) => <Ltr key={h} mono>{h}</Ltr>)}</div>}
                    </KV>
                  )}
                  {opts.tor && (
                    <KV label={t('ipintel.tor')}>
                      {r.tor === null ? <span className="dim small">{sourceNote(r, 'tor', t)}</span>
                        : r.tor ? <Badge tone="red">{t('ipintel.torYes')}</Badge> : <Badge tone="green" icon={ShieldCheck}>{t('ipintel.torNo')}</Badge>}
                    </KV>
                  )}
                </dl>
              </Card>
            </div>

            {r.reputation.length > 0 && (
              <div className="grid g-3">{r.reputation.map((x) => <ReputationCard key={x.service} r={x} />)}</div>
            )}
            <SourcesTable sources={r.sources} />
          </>
        )}
      </div>
    </div>
  );
}

/** Explains why a section is empty using the source's recorded status. */
export function sourceNote(r: { sources: Array<{ id: string; ok: boolean; error?: string }> }, id: string, t: (k: string) => string): string {
  const s = r.sources.find((x) => x.id === id);
  if (!s) return '—';
  return s.ok ? t('intel.notFound') : t(`errors.${s.error ?? 'unknown'}`);
}
