import { useState } from 'react';
import { Crosshair, Search, ShieldCheck, TriangleAlert } from 'lucide-react';
import type { HuntHit, HuntResult, PersistenceItem } from '../../shared/api';
import { Badge, Card, DataTable, EmptyState, ErrorState, IconTile, Ltr, Notice, Progress, Tabs, type Tone } from '../components/ui';
import { AddToCase } from '../components/AddToCase';
import { useApp } from '../components/AppContext';
import { useI18n } from '../i18n/I18nProvider';
import { formatDateTime, formatDuration, newTaskId } from '../format';

type Tab = 'search' | 'persistence';
const SOURCE_TONE: Record<string, Tone> = { case: 'blue', quarantine: 'red', activity: 'gray', network_log: 'amber', process: 'green', connection: 'cyan', service: 'purple', startup: 'purple', task: 'purple', yara_rule: 'amber' };

function SearchTab() {
  const { t, locale } = useI18n();
  const { navigate } = useApp();
  const [q, setQ] = useState('');
  const [s, setS] = useState<{ busy?: boolean; r?: HuntResult; e?: string }>({});
  const timeline = s.r ? s.r.hits.filter((h) => h.time).sort((a, b) => (a.time! < b.time! ? 1 : -1)) : [];
  const evKind = s.r?.indicatorType === 'ip' ? 'ip' : s.r?.indicatorType === 'domain' ? 'domain' : s.r?.indicatorType === 'hash' ? 'hash' : 'other';
  return (
    <div className="col" style={{ gap: 12 }}>
      <Notice tone="green" icon={ShieldCheck}>{t('hunt.localOnly')}</Notice>
      <Card>
        <form className="lookup-bar" onSubmit={async (e) => {
          e.preventDefault();
          if (!q.trim()) return;
          setS({ busy: true });
          const r = await window.blazma.hunt.search(q.trim(), newTaskId());
          setS(r.ok ? { r: r.data } : { e: r.error });
        }}>
          <input className="input mono" dir="ltr" value={q} placeholder={t('hunt.placeholder')} aria-label={t('hunt.title')} onChange={(e) => setQ(e.target.value)} />
          <button className="btn primary" type="submit" disabled={!q.trim() || s.busy}><Search size={16} /> {t('hunt.search')}</button>
        </form>
      </Card>
      {s.busy && <Card><Progress indeterminate /><div className="small muted" style={{ marginTop: 8 }}>{t('hunt.searching')}</div></Card>}
      {s.e && <Card><ErrorState code={s.e} /></Card>}
      {s.r && (
        <>
          <Card
            title={<span className="row"><Ltr mono>{s.r.query}</Ltr><Badge tone="blue">{t(`hunt.type.${s.r.indicatorType}`)}</Badge></span>}
            subtitle={t('hunt.summary', { count: s.r.hits.length, time: formatDuration(t, s.r.durationMs) })}
            icon={Crosshair}
            tone={s.r.hits.length ? 'amber' : 'green'}
            actions={<AddToCase items={[{ kind: evKind, value: s.r.query, source: 'hunt' }]} />}
          >
            {s.r.hits.length === 0 ? <EmptyState icon={ShieldCheck} title={t('hunt.noHits')} /> : (
              <DataTable<HuntHit>
                maxHeight={440}
                rowKey={(_, i) => String(i)}
                rows={s.r.hits}
                columns={[
                  { key: 's', label: t('hunt.col.source'), render: (h) => <Badge tone={SOURCE_TONE[h.source] ?? 'gray'}>{t(`hunt.source.${h.source}`)}</Badge> },
                  { key: 'm', label: t('hunt.col.match'), render: (h) => (h.source === 'case' && h.ref ? <button className="btn sm ghost" onClick={() => navigate('cases')}>{h.title}</button> : <Ltr breakAll>{h.title}</Ltr>) },
                  { key: 'd', label: t('hunt.col.detail'), render: (h) => <Ltr mono breakAll className="small">{h.detail ?? '—'}</Ltr> },
                  { key: 't', label: t('hunt.col.time'), render: (h) => <span className="small nowrap">{formatDateTime(locale, h.time)}</span> },
                ]}
              />
            )}
            <div className="row-wrap" style={{ marginTop: 12, alignItems: 'center' }}>
              <span className="small dim">{t('hunt.sourcesSearched')}:</span>
              {s.r.searched.map((x) => <Badge key={x.source} tone={x.ok ? 'gray' : 'amber'}>{t(`hunt.source.${x.source}`)}{x.ok ? '' : ' ✕'}</Badge>)}
            </div>
          </Card>
          {timeline.length > 0 && (
            <Card title={t('hunt.timeline')} icon={Crosshair} tone="purple">
              <ol style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 8 }}>
                {timeline.map((h, i) => (
                  <li key={i} className="row" style={{ alignItems: 'flex-start', borderInlineStart: '2px solid var(--border-strong)', paddingInlineStart: 12 }}>
                    <span className="small dim nowrap" style={{ minWidth: 170 }}>{formatDateTime(locale, h.time)}</span>
                    <Badge tone={SOURCE_TONE[h.source] ?? 'gray'}>{t(`hunt.source.${h.source}`)}</Badge>
                    <Ltr breakAll className="small">{h.title}</Ltr>
                  </li>
                ))}
              </ol>
            </Card>
          )}
        </>
      )}
    </div>
  );
}

function PersistenceTab() {
  const { t } = useI18n();
  const [s, setS] = useState<{ busy?: boolean; r?: PersistenceItem[]; e?: string }>({});
  return (
    <div className="col" style={{ gap: 12 }}>
      <Card>
        <div className="small muted" style={{ marginBottom: 12 }}>{t('hunt.persistenceDesc')}</div>
        <button className="btn primary" disabled={s.busy} onClick={async () => {
          setS({ busy: true });
          const r = await window.blazma.hunt.persistence();
          setS(r.ok ? { r: r.data } : { e: r.error });
        }}>{t('hunt.load')}</button>
      </Card>
      {s.busy && <Card><Progress indeterminate /></Card>}
      {s.e && <Card><ErrorState code={s.e} /></Card>}
      {s.r && (
        <Card>
          {s.r.length === 0 ? <EmptyState title={t('hunt.noItems')} /> : (
            <DataTable<PersistenceItem>
              maxHeight={520}
              rowKey={(_, i) => String(i)}
              rows={s.r}
              columns={[
                { key: 'k', label: t('cases.kindLabel'), render: (x) => <Badge tone="purple">{t(`hunt.kind.${x.kind}`)}</Badge> },
                { key: 'n', label: t('forensics.col.name'), render: (x) => <Ltr>{x.name}</Ltr> },
                { key: 'c', label: t('forensics.col.command'), render: (x) => <Ltr mono breakAll className="small">{x.command}</Ltr> },
                { key: 'f', label: '', render: (x) => <div className="col" style={{ gap: 4, alignItems: 'flex-start' }}>{x.flags.map((f) => <Badge key={f} tone="amber" icon={TriangleAlert}>{t(f)}</Badge>)}</div> },
              ]}
            />
          )}
        </Card>
      )}
    </div>
  );
}

export function ThreatHunting() {
  const { t } = useI18n();
  const [tab, setTab] = useState<Tab>('search');
  return (
    <div className="page">
      <div className="page-head">
        <IconTile icon={Crosshair} tone="red" />
        <div>
          <h1 className="page-title">{t('hunt.title')}</h1>
          <div className="page-sub">{t('hunt.subtitle')}</div>
        </div>
      </div>
      <Tabs<Tab> value={tab} onChange={setTab} items={(['search', 'persistence'] as const).map((x) => ({ id: x, label: t(`hunt.tab.${x}`) }))} />
      {tab === 'search' ? <SearchTab /> : <PersistenceTab />}
    </div>
  );
}
