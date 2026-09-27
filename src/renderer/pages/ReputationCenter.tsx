import { useEffect, useMemo, useState } from 'react';
import { KeyRound, Scale, Search } from 'lucide-react';
import { REPUTATION_FOR_KIND, type IndicatorKind, type LookupSource, type ReputationResult, type ReputationService } from '../../shared/api';
import { isIP } from '../../core/validation';
import { Card, EmptyState, ErrorState, IconTile, Notice, Progress, Tabs } from '../components/ui';
import { hasRepKey, OfflineBanner, OptionPills, ReputationCard, SourcesTable, useKeyStatus } from '../components/intel';
import { useApp } from '../components/AppContext';
import { useI18n } from '../i18n/I18nProvider';

const FOR_KIND = REPUTATION_FOR_KIND;

export function ReputationCenter() {
  const { t } = useI18n();
  const { navigate } = useApp();
  const keys = useKeyStatus();
  const [kind, setKind] = useState<IndicatorKind>('ip');
  const [value, setValue] = useState('');
  const [selected, setSelected] = useState<ReputationService[]>([]);
  const [state, setState] = useState<{ loading?: boolean; data?: { results: ReputationResult[]; sources: LookupSource[] }; error?: string }>({});

  const available = FOR_KIND[kind].filter((s) => hasRepKey(keys, s));
  useEffect(() => setSelected(available), [kind, keys]); // eslint-disable-line react-hooks/exhaustive-deps

  const valid = useMemo(() => {
    const v = value.trim();
    if (!v) return false;
    if (kind === 'ip') return isIP(v);
    if (kind === 'hash') return /^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(v);
    return v.includes('.');
  }, [kind, value]);

  const anyKey = keys ? FOR_KIND.ip.concat(FOR_KIND.hash).some((s) => hasRepKey(keys, s)) : true;

  return (
    <div className="page">
      <div className="page-head">
        <IconTile icon={Scale} tone="purple" />
        <div>
          <h1 className="page-title">{t('reputation.title')}</h1>
          <div className="page-sub">{t('reputation.subtitle')}</div>
        </div>
      </div>
      <div className="col" style={{ gap: 16 }}>
        <OfflineBanner />
        {!anyKey && (
          <Notice tone="amber" icon={KeyRound}>
            <div className="row" style={{ justifyContent: 'space-between', flexWrap: 'wrap' }}>
              <span>{t('reputation.noKeys')}</span>
              <button className="btn sm" onClick={() => navigate('settings-api')}>{t('reputation.configureKeys')}</button>
            </div>
          </Notice>
        )}
        <Card>
          <Tabs<IndicatorKind> value={kind} onChange={(k) => { setKind(k); setState({}); }} items={(['ip', 'domain', 'hash'] as const).map((id) => ({ id, label: t(`reputation.kind.${id}`) }))} />
          <form
            className="lookup-bar"
            onSubmit={async (e) => {
              e.preventDefault();
              if (!valid || selected.length === 0) return;
              setState({ loading: true });
              const r = await window.blazma.intel.reputation(kind, value.trim(), selected);
              setState(r.ok ? { data: r.data } : { error: r.error });
            }}
          >
            <input className="input mono" dir="ltr" value={value} aria-label={t('reputation.value')} placeholder={t(`reputation.kind.${kind}`)} onChange={(e) => setValue(e.target.value)} />
            <button className="btn primary" type="submit" disabled={!valid || selected.length === 0 || state.loading}><Search size={16} /> {t('intel.lookup')}</button>
          </form>
          <div style={{ marginTop: 14 }}>
            <div className="small dim" style={{ marginBottom: 8 }}>{t('reputation.services')}</div>
            <OptionPills
              items={FOR_KIND[kind].map((s) => ({
                id: s,
                label: t(`intel.src.reputation:${s}`),
                checked: selected.includes(s),
                disabled: !hasRepKey(keys, s),
                hint: keys && !hasRepKey(keys, s) ? t('intel.needsKey') : undefined,
              }))}
              onToggle={(id) => setSelected((x) => (x.includes(id as ReputationService) ? x.filter((y) => y !== id) : [...x, id as ReputationService]))}
            />
          </div>
          <div className="tiny dim" style={{ marginTop: 12 }}>{kind === 'hash' ? t('reputation.hashOnly') : t('intel.externalNote')}</div>
        </Card>
        {state.loading && <Card><Progress indeterminate /></Card>}
        {state.error && <Card><ErrorState code={state.error} /></Card>}
        {state.data && (
          <>
            {state.data.results.length === 0 ? <Card><EmptyState title={t('intel.rep.notFound')} /></Card> : (
              <div className="grid g-3">{state.data.results.map((r) => <ReputationCard key={r.service} r={r} />)}</div>
            )}
            <SourcesTable sources={state.data.sources} />
          </>
        )}
      </div>
    </div>
  );
}
