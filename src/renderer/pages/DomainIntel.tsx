import { useEffect, useMemo, useState } from 'react';
import { CalendarClock, Link2, LockKeyhole, Mail, Route, Search, Server, ShieldAlert, ShieldCheck } from 'lucide-react';
import type { DomainLookupOptions, DomainLookupResult } from '../../shared/api';
import { isDomain } from '../../core/validation';
import { Badge, Card, DataTable, ErrorState, IconTile, Ltr, Notice, Progress } from '../components/ui';
import { KV, OfflineBanner, OptionPills, ReputationCard, SourcesTable, useKeyStatus } from '../components/intel';
import { AddToCase } from '../components/AddToCase';
import { useI18n } from '../i18n/I18nProvider';
import { formatDateTime } from '../format';
import { sourceNote } from './IpIntel';
import { summarizeDomain } from '../../core/link-summary';

/** Loose client-side check; the main process does the authoritative normalization (IDN, URLs). */
function looksLikeDomain(v: string): boolean {
  const s = v.trim().replace(/^[a-z]+:\/\//i, '').split('/')[0] ?? '';
  return s.length > 0 && (isDomain(s.toLowerCase()) || /[^\x00-\x7f]/.test(s));
}

export function DomainIntel() {
  const { t, locale } = useI18n();
  const keys = useKeyStatus();
  const [value, setValue] = useState('');
  const [opts, setOpts] = useState<DomainLookupOptions>({ dns: true, rdap: true, tls: true, infrastructure: true, reputation: [] });
  const [state, setState] = useState<{ loading?: boolean; result?: DomainLookupResult; error?: string }>({});
  const valid = useMemo(() => looksLikeDomain(value), [value]);

  useEffect(() => {
    if (keys?.virustotal) setOpts((o) => ({ ...o, reputation: ['virustotal'] }));
  }, [keys]);

  const run = async () => {
    if (!valid) return;
    setState({ loading: true });
    const r = await window.blazma.intel.domain(value.trim(), opts);
    setState(r.ok ? { result: r.data } : { error: r.error });
  };

  const r = state.result;
  const ageDays = r?.rdap?.created ? (Date.now() - new Date(r.rdap.created).getTime()) / 86_400_000 : null;
  const dnsRows = r?.dns
    ? [
        ...r.dns.a.map((v) => ({ type: 'A', value: v })),
        ...r.dns.aaaa.map((v) => ({ type: 'AAAA', value: v })),
        ...r.dns.cname.map((v) => ({ type: 'CNAME', value: v })),
        ...r.dns.mx.map((m) => ({ type: 'MX', value: `${m.priority} ${m.exchange}` })),
        ...r.dns.ns.map((v) => ({ type: 'NS', value: v })),
        ...r.dns.txt.map((v) => ({ type: 'TXT', value: v })),
        ...r.dns.caa.map((v) => ({ type: 'CAA', value: v })),
        ...(r.dns.soa ? [{ type: 'SOA', value: `${r.dns.soa.nsname} ${r.dns.soa.hostmaster} ${r.dns.soa.serial}` }] : []),
      ]
    : [];

  return (
    <div className="page">
      <div className="page-head">
        <IconTile icon={Link2} tone="blue" />
        <div>
          <h1 className="page-title">{t('domainintel.title')}</h1>
          <div className="page-sub">{t('domainintel.subtitle')}</div>
        </div>
      </div>

      <div className="col" style={{ gap: 16 }}>
        <OfflineBanner />
        <Card>
          <form className="lookup-bar" onSubmit={(e) => { e.preventDefault(); void run(); }}>
            <input className="input mono" dir="ltr" value={value} placeholder={t('domainintel.placeholder')} aria-label={t('domainintel.title')} onChange={(e) => setValue(e.target.value)} />
            <button className="btn primary" type="submit" disabled={!valid || state.loading}><Search size={16} /> {t('intel.lookup')}</button>
          </form>
          <div style={{ marginTop: 14 }}>
            <div className="small dim" style={{ marginBottom: 8 }}>{t('intel.options')}</div>
            <OptionPills
              items={[
                ...(['dns', 'rdap', 'tls', 'infrastructure'] as const).map((k) => ({ id: k, label: t(`domainintel.opt.${k}`), checked: opts[k] })),
                { id: 'virustotal', label: t('intel.src.reputation:virustotal'), checked: opts.reputation.includes('virustotal'), disabled: !keys?.virustotal, hint: keys && !keys.virustotal ? t('intel.needsKey') : undefined },
              ]}
              onToggle={(id) =>
                setOpts((o) => id === 'virustotal'
                  ? { ...o, reputation: o.reputation.length ? [] : ['virustotal'] }
                  : { ...o, [id]: !o[id as keyof DomainLookupOptions] })
              }
            />
          </div>
          <div className="tiny dim" style={{ marginTop: 12 }}>{t('intel.externalNote')}</div>
        </Card>

        {state.loading && <Card><Progress indeterminate /><div className="small muted" style={{ marginTop: 8 }}>{t('intel.looking')}</div></Card>}
        {state.error && <Card><ErrorState code={state.error} /></Card>}

        {r && (
          <>
            <div className="card row" style={{ gap: 16 }}>
              <IconTile icon={Link2} tone="blue" />
              <div>
                <div className="big-value"><Ltr mono>{r.domain}</Ltr></div>
                {r.input.trim().toLowerCase() !== r.domain && <div className="small dim"><Ltr mono>{r.input}</Ltr></div>}
              </div>
              <span className="spacer" />
              <AddToCase items={[{ kind: 'domain', value: r.domain, source: 'domainIntel', details: { registrar: r.rdap?.registrar ?? null, created: r.rdap?.created ?? null, expires: r.rdap?.expires ?? null, tlsIssuer: r.tls?.issuer ?? null, spf: !!r.dns?.spf, dmarc: !!r.dns?.dmarc } }]} />
            </div>

            <LinkSummaryCard r={r} />
            {ageDays !== null && ageDays < 30 && <Notice tone="amber" icon={ShieldAlert}>{t('domainintel.youngDomain')}</Notice>}

            <div className="grid g-2">
              {opts.rdap && (
                <Card title={t('domainintel.registration')} explain="rdap" icon={CalendarClock} tone="purple">
                  {!r.rdap ? <div className="muted small">{sourceNote(r, 'rdap', t)}</div> : (
                    <dl className="kv">
                      <KV label={t('domainintel.registrar')}><Ltr>{r.rdap.registrar ?? '—'}</Ltr>{r.rdap.registrarIanaId && <span className="dim small"> (IANA <Ltr>{r.rdap.registrarIanaId}</Ltr>)</span>}</KV>
                      <KV label={t('domainintel.created')}>{formatDateTime(locale, r.rdap.created)}</KV>
                      <KV label={t('domainintel.expires')}>{formatDateTime(locale, r.rdap.expires)}</KV>
                      <KV label={t('domainintel.updated')}>{formatDateTime(locale, r.rdap.updated)}</KV>
                      <KV label={t('domainintel.status')}><div className="chip-list">{r.rdap.status.map((s) => <span key={s} className="chip"><Ltr>{s}</Ltr></span>)}</div></KV>
                      <KV label={t('domainintel.nameservers')}><div className="col" style={{ gap: 2 }}>{r.rdap.nameservers.map((n) => <Ltr key={n} mono>{n}</Ltr>)}</div></KV>
                      <KV label={t('domainintel.dnssec')}>{r.rdap.dnssec === null ? '—' : <Badge tone={r.rdap.dnssec ? 'green' : 'gray'}>{t(r.rdap.dnssec ? 'domainintel.signed' : 'domainintel.unsigned')}</Badge>}</KV>
                      <KV label={t('ipintel.abuse')}>{r.rdap.abuseEmail ? <Ltr mono>{r.rdap.abuseEmail}</Ltr> : '—'}</KV>
                      <KV label={t('ipintel.registry')}><Ltr mono>{r.rdap.source ?? '—'}</Ltr></KV>
                    </dl>
                  )}
                </Card>
              )}
              {opts.tls && (
                <Card title={t('domainintel.tls')} explain="tls" icon={LockKeyhole} tone={!r.tls ? 'gray' : r.tls.authorized && (r.tls.daysRemaining ?? 0) > 14 ? 'green' : 'amber'}>
                  {!r.tls ? <div className="muted small">{sourceNote(r, 'tls', t)}</div> : (
                    <dl className="kv">
                      <KV label={t('domainintel.status')}>
                        {r.tls.authorized ? <Badge tone="green" icon={ShieldCheck}>{t('domainintel.trusted')}</Badge> : <Badge tone="red">{t('domainintel.untrusted', { error: r.tls.authorizationError ?? '?' })}</Badge>}
                      </KV>
                      <KV label={t('domainintel.subject')}><Ltr>{r.tls.subject ?? '—'}</Ltr></KV>
                      <KV label={t('domainintel.issuer')}><Ltr>{r.tls.issuer ?? '—'}</Ltr></KV>
                      <KV label={t('domainintel.validFrom')}>{formatDateTime(locale, r.tls.validFrom)}</KV>
                      <KV label={t('domainintel.validTo')}>
                        {formatDateTime(locale, r.tls.validTo)}{' '}
                        {r.tls.daysRemaining !== null && (r.tls.daysRemaining < 0
                          ? <Badge tone="red">{t('domainintel.expired')}</Badge>
                          : <Badge tone={r.tls.daysRemaining < 15 ? 'amber' : 'green'}>{t('domainintel.daysLeft', { days: r.tls.daysRemaining })}</Badge>)}
                      </KV>
                      <KV label={t('domainintel.protocol')}><Ltr mono>{r.tls.protocol ?? '—'}</Ltr></KV>
                      <KV label={t('domainintel.sans')}><div className="chip-list">{r.tls.sans.slice(0, 30).map((s) => <span key={s} className="chip"><Ltr mono>{s}</Ltr></span>)}</div></KV>
                      <KV label={t('domainintel.fingerprint')}><Ltr mono breakAll className="small">{r.tls.fingerprint256 ?? '—'}</Ltr></KV>
                    </dl>
                  )}
                </Card>
              )}
            </div>

            {opts.dns && (
              <div className="grid g-3">
                <Card title={t('domainintel.dns')} explain="dns" icon={Server} tone="blue" className="span-2">
                  {!r.dns ? <div className="muted small">{sourceNote(r, 'dns', t)}</div> : dnsRows.length === 0 ? <div className="muted">{t('domainintel.noRecords')}</div> : (
                    <DataTable
                      maxHeight={380}
                      rowKey={(x, i) => `${x.type}-${i}`}
                      rows={dnsRows}
                      columns={[
                        { key: 't', label: t('domainintel.type'), width: 80, render: (x) => <Badge tone="blue">{x.type}</Badge> },
                        { key: 'v', label: t('domainintel.value'), render: (x) => <Ltr mono breakAll className="small">{x.value}</Ltr> },
                      ]}
                    />
                  )}
                </Card>
                <Card title={t('domainintel.email')} explain="spf_dmarc" icon={Mail} tone={r.dns?.spf && r.dns.dmarc ? 'green' : 'amber'}>
                  {r.dns && (
                    <div className="col" style={{ gap: 12 }}>
                      {(['spf', 'dmarc'] as const).map((k) => (
                        <div key={k}>
                          <div className="row" style={{ marginBottom: 4 }}>
                            <strong>{t(`domainintel.${k}`)}</strong>
                            <Badge tone={r.dns![k] ? 'green' : 'amber'}>{t(r.dns![k] ? 'domainintel.present' : 'domainintel.missing')}</Badge>
                          </div>
                          {r.dns![k] ? <Ltr mono breakAll className="small">{r.dns![k]}</Ltr> : <div className="small muted">{t(`domainintel.${k}Missing`)}</div>}
                        </div>
                      ))}
                    </div>
                  )}
                </Card>
              </div>
            )}

            {opts.infrastructure && r.infrastructure.length > 0 && (
              <Card title={t('domainintel.infrastructure')} explain="asn" icon={Route} tone="purple">
                <DataTable
                  rowKey={(x) => x.ip}
                  rows={r.infrastructure}
                  columns={[
                    { key: 'ip', label: t('domainintel.ip'), render: (x) => <Ltr mono>{x.ip}</Ltr> },
                    { key: 'asn', label: t('domainintel.asn'), render: (x) => (x.asn ? <Ltr mono>{`AS${x.asn.asn}`}</Ltr> : '—') },
                    { key: 'n', label: t('domainintel.network'), render: (x) => <Ltr>{x.asn?.name ?? '—'}</Ltr> },
                    { key: 'p', label: t('ipintel.prefix'), render: (x) => <Ltr mono>{x.asn?.prefix ?? '—'}</Ltr> },
                  ]}
                />
              </Card>
            )}

            {r.reputation.length > 0 && <div className="grid g-3">{r.reputation.map((x) => <ReputationCard key={x.service} r={x} />)}</div>}
            <SourcesTable sources={r.sources} />
          </>
        )}
      </div>
    </div>
  );
}

const LEVEL_TONE = { risky: 'red', caution: 'amber', no_red_flags: 'green', unknown: 'gray' } as const;

/** "Is this site trustworthy?" in plain words, built only from facts that were retrieved. */
function LinkSummaryCard({ r }: { r: DomainLookupResult }) {
  const { t } = useI18n();
  const sum = summarizeDomain(r, new Date());
  return (
    <Card title={t('linksum.title')} icon={sum.level === 'risky' ? ShieldAlert : ShieldCheck} tone={LEVEL_TONE[sum.level]}>
      <div className="col" style={{ gap: 10 }}>
        <div className="row" style={{ gap: 10 }}>
          <Badge tone={LEVEL_TONE[sum.level]}>{t(`linksum.level.${sum.level}`)}</Badge>
          <span className="small muted">{t(`linksum.levelHint.${sum.level}`)}</span>
        </div>
        {sum.signals.length > 0 && (
          <ul className="linksum-list">
            {sum.signals.map((s) => (
              <li key={s.key} className={`tone-${s.tone}`}>
                {t(`linksum.signal.${s.key}`, s.vars?.service ? { ...s.vars, service: t(`intel.src.reputation:${s.vars.service}`) } : s.vars)}
              </li>
            ))}
          </ul>
        )}
        <div className="tiny dim">{t('linksum.disclaimer')}</div>
      </div>
    </Card>
  );
}
