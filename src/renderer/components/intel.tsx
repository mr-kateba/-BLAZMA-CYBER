import { Check, CircleCheck, CloudOff, ExternalLink, ShieldAlert, ShieldCheck, TriangleAlert } from 'lucide-react';
import { useEffect, useState } from 'react';
import type { ApiKeyService, LookupSource, ReputationResult } from '../../shared/api';
import { Badge, Card, DataTable, Ltr, Notice, type Tone } from './ui';
import { useApp } from './AppContext';
import { useI18n } from '../i18n/I18nProvider';
import { formatDateTime } from '../format';

export interface OptionItem {
  id: string;
  label: string;
  checked: boolean;
  disabled?: boolean;
  hint?: string;
}

export function OptionPills({ items, onToggle }: { items: OptionItem[]; onToggle: (id: string) => void }) {
  return (
    <div className="row-wrap">
      {items.map((o) => (
        <button key={o.id} type="button" className="opt" aria-pressed={o.checked} disabled={o.disabled} onClick={() => onToggle(o.id)} title={o.hint}>
          <span className="opt-box">{o.checked && <Check size={10} color="#fff" strokeWidth={3} />}</span>
          <span>{o.label}</span>
          {o.hint && <span className="opt-hint">· {o.hint}</span>}
        </button>
      ))}
    </div>
  );
}

export function OfflineBanner() {
  const { t } = useI18n();
  const { settings, navigate } = useApp();
  if (!settings.offlineMode) return null;
  return (
    <Notice tone="cyan" icon={CloudOff}>
      <div className="row" style={{ justifyContent: 'space-between', flexWrap: 'wrap' }}>
        <span>{t('intel.offlineBanner')}</span>
        <button className="btn sm" onClick={() => navigate('privacy')}>{t('intel.openPrivacy')}</button>
      </div>
    </Notice>
  );
}

export function SourcesTable({ sources }: { sources: LookupSource[] }) {
  const { t, locale } = useI18n();
  if (sources.length === 0) return null;
  return (
    <Card title={t('intel.sources')} subtitle={t('intel.sourcesSub')} icon={ShieldCheck} tone="gray">
      <DataTable<LookupSource>
        rowKey={(s) => s.id}
        rows={sources}
        columns={[
          { key: 's', label: t('intel.col.source'), render: (s) => t(`intel.src.${s.id}`) },
          { key: 'w', label: t('intel.col.where'), render: (s) => <Badge tone={s.external ? 'amber' : 'green'}>{t(s.external ? 'common.external' : 'common.local')}</Badge> },
          {
            key: 'st', label: t('intel.col.status'),
            render: (s) => s.ok ? <Badge tone="green" icon={CircleCheck}>{t('intel.ok')}</Badge> : (
              <span className="row" style={{ gap: 6 }}>
                <Badge tone={s.error === 'offline_mode' || s.error === 'not_public_ip' ? 'cyan' : 'amber'}>{t('intel.failed')}</Badge>
                <span className="small dim">{t(`errors.${s.error ?? 'unknown'}`)}</span>
              </span>
            ),
          },
          { key: 't', label: t('intel.col.time'), render: (s) => <span className="small nowrap">{formatDateTime(locale, s.queriedAt)}</span> },
          ...(sources.some((s) => s.url)
            ? [{ key: 'u', label: t('intel.col.url'), render: (s: LookupSource) => (s.url ? <Ltr mono breakAll className="tiny">{s.url}</Ltr> : '—') }]
            : []),
        ]}
      />
    </Card>
  );
}

function repTone(r: ReputationResult): Tone {
  if (!r.found) return 'gray';
  if ((r.malicious ?? 0) > 0 || (r.abuseScore ?? 0) >= 50 || (r.vulns?.length ?? 0) > 0) return 'red';
  if ((r.suspicious ?? 0) > 0 || (r.abuseScore ?? 0) >= 10) return 'amber';
  return 'green';
}

export function ReputationCard({ r }: { r: ReputationResult }) {
  const { t, locale } = useI18n();
  const tone = repTone(r);
  const Icon = tone === 'red' ? ShieldAlert : tone === 'amber' ? TriangleAlert : ShieldCheck;
  const kv = (label: string, v: React.ReactNode) => (<><dt>{label}</dt><dd>{v}</dd></>);
  const name = t(`intel.src.reputation:${r.service}`);
  return (
    <Card
      title={name}
      icon={Icon}
      tone={tone}
      actions={r.link ? <a className="btn sm" href={r.link} target="_blank" rel="noreferrer noopener"><ExternalLink size={13} /> {t('intel.rep.open')}</a> : undefined}
    >
      {!r.found ? <div className="muted">{t('intel.rep.notFound')}</div> : (
        <dl className="kv">
          {r.malicious !== undefined && kv(t('intel.rep.title'), <span>{t('intel.rep.detections', { malicious: r.malicious ?? 0, suspicious: r.suspicious ?? 0, harmless: r.harmless ?? 0, undetected: r.undetected ?? 0 })}</span>)}
          {r.reputation !== undefined && r.reputation !== null && kv(t('intel.rep.reputationScore'), <Ltr>{r.reputation}</Ltr>)}
          {r.typeDescription && kv(t('file.type'), <Ltr>{r.typeDescription}</Ltr>)}
          {r.names && r.names.length > 0 && kv(t('intel.rep.names'), <div className="chip-list">{r.names.map((n) => <span key={n} className="chip"><Ltr>{n}</Ltr></span>)}</div>)}
          {r.lastAnalysis && kv(t('intel.rep.lastAnalysis'), formatDateTime(locale, r.lastAnalysis))}
          {r.abuseScore !== undefined && kv(t('intel.rep.abuseScore'), <Badge tone={tone}><Ltr>{r.abuseScore}%</Ltr></Badge>)}
          {r.totalReports !== undefined && kv(t('intel.rep.reports', { count: '' }).trim(), t('intel.rep.reports', { count: r.totalReports }))}
          {r.lastReported && kv(t('intel.rep.lastReported'), formatDateTime(locale, r.lastReported))}
          {r.usageType && kv(t('intel.rep.usage'), <Ltr>{r.usageType}</Ltr>)}
          {r.isp && kv(t('intel.rep.isp'), <Ltr>{r.isp}</Ltr>)}
          {r.ports && kv(t('intel.rep.ports'), r.ports.length ? <div className="chip-list">{r.ports.map((p) => <span key={p} className="chip"><Ltr mono>{p}</Ltr></span>)}</div> : t('intel.none'))}
          {r.vulns && r.vulns.length > 0 && kv(t('intel.rep.vulns'), <div className="chip-list">{r.vulns.map((v) => <span key={v} className="chip"><Ltr mono>{v}</Ltr></span>)}</div>)}
          {r.hostnames && r.hostnames.length > 0 && kv(t('intel.rep.hostnames'), <div className="col" style={{ gap: 2 }}>{r.hostnames.map((h) => <Ltr key={h} mono>{h}</Ltr>)}</div>)}
          {r.tags && r.tags.length > 0 && kv(t('intel.rep.tags'), <div className="chip-list">{r.tags.map((x) => <span key={x} className="chip"><Ltr>{x}</Ltr></span>)}</div>)}
        </dl>
      )}
    </Card>
  );
}

/** Two-column key/value row helper. */
export function KV({ label, children }: { label: string; children: React.ReactNode }) {
  return (<><dt>{label}</dt><dd>{children ?? '—'}</dd></>);
}

/** Which API keys are configured (booleans only — keys never reach the renderer). */
export function useKeyStatus() {
  const [keys, setKeys] = useState<Record<ApiKeyService, boolean> | null>(null);
  useEffect(() => void window.blazma.secrets.status().then(setKeys), []);
  return keys;
}
