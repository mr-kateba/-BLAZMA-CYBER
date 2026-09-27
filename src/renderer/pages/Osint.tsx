import { useMemo, useState } from 'react';
import { Archive, AtSign, ExternalLink, FileBadge, GitBranch, Globe2, Link2, Mail, Scale, Search, User, UserSearch } from 'lucide-react';
import type { EvidenceKind, OsintOptions, OsintResult, OsintTargetType } from '../../shared/api';
import { normalizeOsintTarget } from '../../core/osint';
import { Badge, Card, DataTable, ErrorState, FilterInput, IconTile, Ltr, Notice, Progress, Tabs, useFilter } from '../components/ui';
import { KV, OfflineBanner, OptionPills, SourcesTable } from '../components/intel';
import { AddToCase } from '../components/AddToCase';
import { useApp } from '../components/AppContext';
import { useI18n } from '../i18n/I18nProvider';
import { formatDateTime } from '../format';
import { sourceNote } from './IpIntel';

const TYPE_OPTIONS: Record<OsintTargetType, Array<keyof OsintOptions>> = {
  domain: ['ct', 'wayback'],
  email: ['emailDns'],
  username: ['github'],
  url: ['wayback'],
};

const EVIDENCE_KIND: Record<OsintTargetType, EvidenceKind> = { domain: 'domain', email: 'email', username: 'other', url: 'url' };

export function Osint() {
  const { t, locale } = useI18n();
  const { confirm, toast } = useApp();
  const [type, setType] = useState<OsintTargetType>('domain');
  const [value, setValue] = useState('');
  const [opts, setOpts] = useState<OsintOptions>({ ct: true, wayback: true, github: true, emailDns: true });
  const [state, setState] = useState<{ loading?: boolean; result?: OsintResult; error?: string }>({});
  const valid = useMemo(() => normalizeOsintTarget(type, value) !== null, [type, value]);

  const run = async () => {
    if (!valid) return;
    setState({ loading: true });
    const r = await window.blazma.osint.lookup(type, value.trim(), opts);
    setState(r.ok ? { result: r.data } : { error: r.error });
  };

  const openPivot = async (r: OsintResult, id: string, url: string, dataKind: string) => {
    const host = new URL(url).host;
    const ok = await confirm({
      title: t('osint.pivots.confirmTitle', { site: t(`osint.pivot.${id}`) }),
      body: t('osint.pivots.confirmBody', { host, data: t(dataKind) }),
      confirmLabel: t('osint.pivots.open'),
    });
    if (!ok) return;
    const res = await window.blazma.osint.openPivot(r.type, r.value, id);
    if (!res.ok) toast('red', t(`errors.${res.error}`));
  };

  const r = state.result;
  const subs = useFilter(r?.ct?.subdomains ?? [], (s) => [s]);
  const on = (k: keyof OsintOptions) => !!r && TYPE_OPTIONS[r.type].includes(k) && opts[k];

  return (
    <div className="page">
      <div className="page-head">
        <IconTile icon={UserSearch} tone="purple" />
        <div>
          <h1 className="page-title">{t('osint.title')}</h1>
          <div className="page-sub">{t('osint.subtitle')}</div>
        </div>
      </div>

      <div className="col" style={{ gap: 16 }}>
        <OfflineBanner />
        <Notice tone="blue" icon={Scale}>{t('osint.lawful')}</Notice>
        <Card>
          <Tabs<OsintTargetType>
            value={type}
            onChange={(v) => { setType(v); setState({}); }}
            items={(['domain', 'email', 'username', 'url'] as const).map((id) => ({ id, label: t(`osint.type.${id}`) }))}
          />
          <form className="lookup-bar" style={{ marginTop: 14 }} onSubmit={(e) => { e.preventDefault(); void run(); }}>
            <input className="input mono" dir="ltr" value={value} placeholder={t(`osint.placeholder.${type}`)} aria-label={t(`osint.type.${type}`)} onChange={(e) => setValue(e.target.value)} />
            <button className="btn primary" type="submit" disabled={!valid || state.loading}><Search size={16} /> {t('intel.lookup')}</button>
          </form>
          {value.trim() !== '' && !valid && <div className="small" style={{ color: 'var(--amber)', marginTop: 8 }}>{t('errors.invalid_osint_target')}</div>}
          <div style={{ marginTop: 14 }}>
            <div className="small dim" style={{ marginBottom: 8 }}>{t('intel.options')}</div>
            <OptionPills
              items={TYPE_OPTIONS[type].map((k) => ({ id: k, label: t(`osint.opt.${k}`), checked: opts[k] }))}
              onToggle={(id) => setOpts((o) => ({ ...o, [id]: !o[id as keyof OsintOptions] }))}
            />
          </div>
          <div className="tiny dim" style={{ marginTop: 12 }}>{t('osint.externalNote')}</div>
        </Card>

        {state.loading && <Card><Progress indeterminate /><div className="small muted" style={{ marginTop: 8 }}>{t('intel.looking')}</div></Card>}
        {state.error && <Card><ErrorState code={state.error} /></Card>}

        {r && (
          <>
            <div className="card row" style={{ gap: 16 }}>
              <IconTile icon={r.type === 'email' ? AtSign : r.type === 'username' ? User : r.type === 'url' ? Link2 : Globe2} tone="purple" />
              <div>
                <div className="small dim">{t(`osint.type.${r.type}`)}</div>
                <div className="big-value"><Ltr mono breakAll>{r.value}</Ltr></div>
              </div>
              <span className="spacer" />
              <AddToCase
                items={[{
                  kind: EVIDENCE_KIND[r.type],
                  value: r.value,
                  label: r.type === 'username' ? t('osint.type.username') : null,
                  source: 'osint',
                  details: {
                    certificates: r.ct?.certificates ?? null,
                    subdomains: r.ct ? r.ct.subdomains.length : null,
                    firstArchived: r.wayback?.first?.timestamp ?? null,
                    github: r.github?.htmlUrl ?? null,
                    acceptsMail: r.email ? r.email.acceptsMail : null,
                  },
                }]}
              />
            </div>

            <div className="grid g-2">
              {on('ct') && (
                <Card title={t('osint.ct.title')} subtitle={t('osint.ct.sub')} icon={FileBadge} tone="blue">
                  {!r.ct ? <div className="muted small">{sourceNote(r, 'osint:ct', t)}</div> : r.ct.certificates === 0 ? <div className="muted">{t('osint.ct.none')}</div> : (
                    <dl className="kv">
                      <KV label={t('osint.ct.certs')}><Ltr>{r.ct.certificates}</Ltr></KV>
                      <KV label={t('osint.ct.names')}><Ltr>{r.ct.subdomains.length}</Ltr></KV>
                      <KV label={t('osint.ct.firstSeen')}>{formatDateTime(locale, r.ct.firstSeen)}</KV>
                      <KV label={t('osint.ct.lastSeen')}>{formatDateTime(locale, r.ct.lastSeen)}</KV>
                      <KV label={t('osint.ct.issuers')}>
                        <div className="chip-list">{r.ct.issuers.map((i) => <span key={i.name} className="chip"><Ltr>{i.name}</Ltr> · <Ltr>{i.count}</Ltr></span>)}</div>
                      </KV>
                    </dl>
                  )}
                </Card>
              )}
              {on('wayback') && (
                <Card title={t('osint.wayback.title')} subtitle={t('osint.wayback.sub')} icon={Archive} tone="amber">
                  {!r.wayback ? <div className="muted small">{sourceNote(r, 'osint:wayback', t)}</div> : !r.wayback.first && !r.wayback.last ? <div className="muted">{t('osint.wayback.none')}</div> : (
                    <dl className="kv">
                      {(['first', 'last'] as const).map((k) => (
                        <KV key={k} label={t(`osint.wayback.${k}`)}>
                          {r.wayback![k] ? (
                            <div className="col" style={{ gap: 2 }}>
                              <span>{formatDateTime(locale, r.wayback![k]!.timestamp)}</span>
                              <Ltr mono breakAll className="tiny dim">{r.wayback![k]!.url}</Ltr>
                            </div>
                          ) : '—'}
                        </KV>
                      ))}
                    </dl>
                  )}
                </Card>
              )}
              {on('github') && (
                <Card title={t('osint.github.title')} subtitle={t('osint.github.sub')} icon={GitBranch} tone="gray">
                  {!r.github ? <div className="muted small">{r.sources.find((s) => s.id === 'osint:github')?.ok ? t('osint.github.none') : sourceNote(r, 'osint:github', t)}</div> : (
                    <dl className="kv">
                      <KV label={t('osint.github.login')}><Ltr mono>{r.github.login}</Ltr></KV>
                      {r.github.name && <KV label={t('osint.github.name')}>{r.github.name}</KV>}
                      {r.github.company && <KV label={t('osint.github.company')}>{r.github.company}</KV>}
                      {r.github.location && <KV label={t('osint.github.location')}>{r.github.location}</KV>}
                      {r.github.blog && <KV label={t('osint.github.blog')}><Ltr mono breakAll>{r.github.blog}</Ltr></KV>}
                      {r.github.bio && <KV label={t('osint.github.bio')}>{r.github.bio}</KV>}
                      <KV label={t('osint.github.repos')}><Ltr>{r.github.publicRepos ?? '—'}</Ltr></KV>
                      <KV label={t('osint.github.followers')}><Ltr>{r.github.followers ?? '—'}</Ltr></KV>
                      <KV label={t('osint.github.created')}>{formatDateTime(locale, r.github.createdAt)}</KV>
                    </dl>
                  )}
                </Card>
              )}
              {on('emailDns') && (
                <Card title={t('osint.email.title')} subtitle={t('osint.email.sub')} icon={Mail} tone={r.email?.acceptsMail ? 'green' : 'amber'}>
                  {!r.email ? <div className="muted small">{sourceNote(r, 'osint:emailDns', t)}</div> : (
                    <dl className="kv">
                      <KV label={t('osint.email.domain')}><Ltr mono>{r.email.domain}</Ltr></KV>
                      <KV label={t('osint.email.accepts')}>
                        <Badge tone={r.email.acceptsMail ? 'green' : 'amber'}>{t(r.email.acceptsMail ? 'common.yes' : 'common.no')}</Badge>
                      </KV>
                      <KV label={t('osint.email.mx')}>
                        {r.email.mx.length === 0 ? t('osint.email.noMx') : <div className="col" style={{ gap: 2 }}>{r.email.mx.map((m) => <Ltr key={`${m.priority}-${m.exchange}`} mono>{`${m.priority} ${m.exchange || '.'}`}</Ltr>)}</div>}
                      </KV>
                      {(['spf', 'dmarc'] as const).map((k) => (
                        <KV key={k} label={t(`domainintel.${k}`)}>
                          {r.email![k] ? <Ltr mono breakAll className="small">{r.email![k]}</Ltr> : <Badge tone="amber">{t('domainintel.missing')}</Badge>}
                        </KV>
                      ))}
                    </dl>
                  )}
                  <div className="tiny dim" style={{ marginTop: 10 }}>{t('osint.email.note')}</div>
                </Card>
              )}
            </div>

            {on('ct') && r.ct && r.ct.subdomains.length > 0 && (
              <Card
                title={t('osint.ct.subdomains')}
                subtitle={r.ct.truncated ? t('osint.ct.truncated', { count: r.ct.subdomains.length }) : undefined}
                icon={Globe2}
                tone="blue"
                actions={<FilterInput value={subs.q} onChange={subs.setQ} placeholder={t('forensics.filter')} />}
              >
                <DataTable
                  maxHeight={360}
                  rowKey={(s) => s}
                  rows={subs.filtered}
                  columns={[{ key: 'n', label: t('osint.ct.name'), render: (s) => <Ltr mono>{s}</Ltr> }]}
                />
              </Card>
            )}

            <Card title={t('osint.pivots.title')} subtitle={t('osint.pivots.sub')} icon={ExternalLink} tone="purple">
              <div className="row-wrap">
                {r.pivots.map((p) => (
                  <button key={p.id} className="btn sm" onClick={() => void openPivot(r, p.id, p.url, p.dataKind)}>
                    <ExternalLink size={13} /> {t(`osint.pivot.${p.id}`)}
                  </button>
                ))}
              </div>
            </Card>

            <SourcesTable sources={r.sources} />
          </>
        )}
      </div>
    </div>
  );
}
