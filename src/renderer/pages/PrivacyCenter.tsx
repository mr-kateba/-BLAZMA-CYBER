import { CircleCheck, CloudOff, Cloud, FolderOpen, History, ShieldCheck, Trash2 } from 'lucide-react';
import type { ClearTarget } from '../../shared/api';
import type { NetworkActivityEntry } from '../../core/network-gate';
import { Badge, Card, DataTable, EmptyState, Explain, IconTile, Ltr, Skeleton, Toggle, usePoll } from '../components/ui';
import { useApp } from '../components/AppContext';
import { useI18n } from '../i18n/I18nProvider';
import { formatDateTime } from '../format';

const OUTCOME_TONE = { allowed: 'green', blocked_offline: 'cyan', error: 'red' } as const;
const TARGETS: ClearTarget[] = ['activity', 'network_activity', 'intel_cache', 'reports', 'cases', 'logs', 'temp'];

export function PrivacyCenter() {
  const { t, locale } = useI18n();
  const { settings, updateSettings, confirm, toast } = useApp();
  const net = usePoll(() => window.blazma.privacy.networkActivity(), 5000);
  const offline = settings.offlineMode;

  const clear = async (target: ClearTarget) => {
    const what = t(`privacy.clear.${target}`);
    const ok = await confirm({ title: t('privacy.confirmTitle'), body: t('privacy.confirmBody', { what }), confirmLabel: what, danger: true });
    if (!ok) return;
    const r = await window.blazma.privacy.clear(target);
    if (r.ok) {
      toast('green', t('privacy.cleared', { what }));
      net.reload();
    } else toast('red', t(`errors.${r.error}`));
  };

  return (
    <div className="page">
      <div className="page-head">
        <IconTile icon={ShieldCheck} tone="cyan" />
        <div>
          <h1 className="page-title">{t('privacy.title')}</h1>
          <div className="page-sub">{t('privacy.subtitle')}</div>
        </div>
      </div>

      <div className="grid g-2-1">
        <div className="card" style={{ borderColor: offline ? 'rgba(34,211,238,0.35)' : 'rgba(34,197,94,0.35)' }}>
          <div className="row" style={{ gap: 16, alignItems: 'flex-start' }}>
            <IconTile icon={offline ? CloudOff : Cloud} tone={offline ? 'cyan' : 'green'} />
            <div style={{ flex: 1 }}>
              <div className="row">
                <h3 className="card-title" style={{ fontSize: 17 }}>{t('privacy.offlineTitle')}<Explain term="offline_mode" /></h3>
                <span className="spacer" />
                <Toggle checked={offline} label={t('privacy.offlineTitle')} onChange={(v) => void updateSettings({ offlineMode: v })} />
              </div>
              <div style={{ marginTop: 6, fontWeight: 600, color: offline ? 'var(--cyan)' : 'var(--green)' }}>
                {t(offline ? 'privacy.offlineOn' : 'privacy.offlineOff')}
              </div>
              <p className="muted small" style={{ marginBottom: 0 }}>{t('privacy.offlineDesc')}</p>
            </div>
          </div>
        </div>
        <Card title={t('privacy.principles')} icon={CircleCheck} tone="green">
          <div className="status-list">
            {['p1', 'p2', 'p3', 'p4'].map((k) => (
              <div key={k} className="status-item"><CircleCheck size={15} color="var(--green)" style={{ marginTop: 3, flexShrink: 0 }} /><span>{t(`privacy.${k}`)}</span></div>
            ))}
          </div>
        </Card>
      </div>

      <Card title={t('privacy.activityTitle')} subtitle={t('privacy.activitySub')} icon={History} tone="blue" style={{ marginTop: 16 }}>
        {!net.data ? (
          <Skeleton h={80} />
        ) : net.data.length === 0 ? (
          <EmptyState icon={CloudOff} title={t('privacy.noActivity')} />
        ) : (
          <DataTable<NetworkActivityEntry>
            maxHeight={340}
            rowKey={(r) => r.id}
            rows={net.data}
            columns={[
              { key: 't', label: t('privacy.col.time'), render: (r) => <span className="nowrap small">{formatDateTime(locale, r.timestamp)}</span> },
              { key: 'm', label: t('privacy.col.module'), render: (r) => t(`privacy.module.${r.module}`) },
              { key: 's', label: t('privacy.col.service'), render: (r) => <Ltr>{r.service}</Ltr> },
              { key: 'h', label: t('privacy.col.host'), render: (r) => <Ltr mono>{r.host}</Ltr> },
              { key: 'd', label: t('privacy.col.data'), render: (r) => <span className="small">{t(r.dataKind)}</span> },
              { key: 'o', label: t('privacy.col.outcome'), render: (r) => <Badge tone={OUTCOME_TONE[r.outcome]}>{t(`privacy.outcome.${r.outcome}`)}</Badge> },
            ]}
          />
        )}
      </Card>

      <Card
        title={t('privacy.clearTitle')} subtitle={t('privacy.clearSub')} icon={Trash2} tone="red" style={{ marginTop: 16 }}
        actions={<button className="btn sm" onClick={() => void window.blazma.app.openDataFolder()}><FolderOpen size={14} /> {t('privacy.dataFolder')}</button>}
      >
        <div className="row-wrap">
          {TARGETS.map((x) => (
            <button key={x} className="btn danger" onClick={() => void clear(x)}>
              <Trash2 size={15} /> {t(`privacy.clear.${x}`)}
            </button>
          ))}
        </div>
      </Card>
    </div>
  );
}
