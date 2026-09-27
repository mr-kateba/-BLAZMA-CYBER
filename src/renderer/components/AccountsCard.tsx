import { useEffect, useState } from 'react';
import { ExternalLink, Users, X } from 'lucide-react';
import type { AccountCheck, AccountsResult, AccountStatus, TaskProgress } from '../../shared/api';
import { Card, DataTable, EmptyState, ErrorState, Ltr, Notice, Progress, Tabs } from './ui';
import { useApp } from './AppContext';
import { useI18n } from '../i18n/I18nProvider';
import { formatDuration } from '../format';

export type AccountsState = { running?: { taskId: string }; result?: AccountsResult; error?: string };

/** Accounts found for a username on social networks and other public sites (WhatsMyName rules). */
export function AccountsCard({ state }: { state: AccountsState }) {
  const { t } = useI18n();
  const { confirm, toast } = useApp();
  const [p, setP] = useState<TaskProgress | null>(null);
  const [tab, setTab] = useState<AccountStatus>('found');
  const taskId = state.running?.taskId;

  useEffect(() => {
    setP(null);
    if (!taskId) return;
    return window.blazma.files.onProgress((x) => x.taskId === taskId && setP(x));
  }, [taskId]);
  useEffect(() => setTab('found'), [state.result]);

  const open = async (username: string, a: AccountCheck) => {
    if (!a.url) return;
    const ok = await confirm({
      title: t('osint.pivots.confirmTitle', { site: a.name }),
      body: t('osint.pivots.confirmBody', { host: new URL(a.url).host, data: t('privacy.data.username') }),
      confirmLabel: t('osint.pivots.open'),
    });
    if (!ok) return;
    const res = await window.blazma.osint.openAccount(username, a.id);
    if (!res.ok) toast('red', t(`errors.${res.error}`));
  };

  const title = t('osint.accounts.title');
  if (state.running) {
    const done = p?.processedBytes ?? 0;
    const total = p?.totalBytes ?? 0;
    return (
      <Card title={title} icon={Users} tone="purple">
        <Progress value={total ? (done / total) * 100 : 0} indeterminate={!total} />
        <div className="row" style={{ marginTop: 10, gap: 10 }}>
          <span className="small muted">{t('osint.accounts.running', { done, total })}</span>
          <span className="spacer" />
          <button className="btn danger sm" onClick={() => void window.blazma.files.cancel(state.running!.taskId)}><X size={13} /> {t('common.cancel')}</button>
        </div>
      </Card>
    );
  }
  if (state.error) return <Card title={title} icon={Users} tone="purple"><ErrorState code={state.error} /></Card>;
  const r = state.result;
  if (!r) return null;

  const rows = r.accounts.filter((a) => a.status === tab);
  return (
    <Card
      title={title}
      icon={Users}
      tone={r.found > 0 ? 'green' : 'purple'}
      subtitle={t('osint.accounts.sub', { checked: r.checked, total: r.total, time: formatDuration(t, r.durationMs) })}
    >
      <div className="col" style={{ gap: 12 }}>
        {r.cancelled && <Notice tone="amber">{t('osint.accounts.cancelled', { checked: r.checked, total: r.total })}</Notice>}
        {r.checked > 0 && r.unknown === r.checked && <Notice tone="amber">{t('osint.accounts.allFailed')}</Notice>}
        <Tabs<AccountStatus>
          value={tab}
          onChange={setTab}
          items={(['found', 'unknown', 'missing'] as const).map((id) => ({ id, label: `${t(`osint.accounts.tab.${id}`)} (${r[id]})` }))}
        />
        {rows.length === 0 ? (
          <EmptyState icon={Users} title={t(`osint.accounts.empty.${tab}`)} />
        ) : (
          <DataTable
            maxHeight={440}
            rowKey={(a) => a.id}
            rows={rows}
            columns={[
              { key: 'site', label: t('osint.accounts.col.site'), render: (a) => <span><Ltr>{a.name}</Ltr> <span className="tiny dim">· {t(`osint.accounts.cat.${a.cat}`)}</span></span> },
              tab === 'unknown'
                ? { key: 'why', label: t('osint.accounts.col.reason'), render: (a) => <span className="small muted">{t(`osint.accounts.reason.${a.reason ?? 'no_match'}`)}</span> }
                : { key: 'url', label: t('osint.accounts.col.page'), render: (a) => (a.url ? <Ltr mono breakAll className="tiny">{a.url}</Ltr> : <span className="dim">—</span>) },
              {
                key: 'open', label: '', render: (a) => a.url && tab !== 'missing' ? (
                  <button className="btn sm" onClick={() => void open(r.username, a)}><ExternalLink size={13} /> {t('osint.accounts.open')}</button>
                ) : null,
              },
            ]}
          />
        )}
        <div className="tiny dim">{t('osint.accounts.note')}</div>
        <div className="tiny dim">{t('osint.accounts.source')} <Ltr mono>{r.source}</Ltr></div>
      </div>
    </Card>
  );
}
