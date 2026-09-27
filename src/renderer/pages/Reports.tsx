import { useEffect, useState } from 'react';
import { ExternalLink, FolderOpen, ScrollText, Trash2 } from 'lucide-react';
import type { ReportRecord } from '../../shared/api';
import { Badge, Card, DataTable, EmptyState, ErrorState, IconTile, Ltr, Skeleton } from '../components/ui';
import { useApp } from '../components/AppContext';
import { useI18n } from '../i18n/I18nProvider';
import { formatBytes, formatDateTime } from '../format';

export function Reports() {
  const { t, locale } = useI18n();
  const { confirm, toast, navigate } = useApp();
  const [list, setList] = useState<ReportRecord[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const load = () => void window.blazma.reports.list().then((r) => (r.ok ? setList(r.data) : setErr(r.error)));
  useEffect(load, []);
  return (
    <div className="page">
      <div className="page-head">
        <IconTile icon={ScrollText} tone="purple" />
        <div>
          <h1 className="page-title">{t('reports.title')}</h1>
          <div className="page-sub">{t('reports.subtitle')}</div>
        </div>
      </div>
      <Card>
        {err ? <ErrorState code={err} /> : !list ? <Skeleton h={120} /> : list.length === 0 ? (
          <EmptyState icon={ScrollText} title={t('reports.empty')} hint={t('reports.emptyHint')}>
            <button className="btn" onClick={() => navigate('cases')}>{t('cases.title')}</button>
          </EmptyState>
        ) : (
          <DataTable<ReportRecord>
            rowKey={(r) => r.id}
            rows={list}
            columns={[
              { key: 'c', label: t('reports.col.case'), render: (r) => <div><Ltr mono className="small">{r.caseId}</Ltr><div>{r.caseName}</div></div> },
              { key: 'f', label: t('reports.col.format'), render: (r) => <Badge tone="blue">{r.format.toUpperCase()}</Badge> },
              { key: 'l', label: t('reports.col.language'), render: (r) => (r.language === 'ar' ? 'العربية' : 'English') },
              { key: 'd', label: t('reports.col.created'), render: (r) => <span className="small nowrap">{formatDateTime(locale, r.createdAt)}</span> },
              { key: 's', label: t('reports.col.size'), render: (r) => <span className="small">{formatBytes(t, r.sizeBytes)}</span> },
              {
                key: 'a', label: '',
                render: (r) => (
                  <div className="row-wrap" style={{ gap: 6 }}>
                    <button className="btn sm" onClick={async () => { const x = await window.blazma.reports.open(r.id); if (!x.ok) toast('red', t(`errors.${x.error}`)); }}><ExternalLink size={13} /> {t('reports.open')}</button>
                    <button className="btn sm" onClick={() => void window.blazma.reports.reveal(r.id)}><FolderOpen size={13} /> {t('reports.reveal')}</button>
                    <button className="btn danger sm" aria-label={t('reports.delete')} onClick={async () => {
                      if (!(await confirm({ title: t('privacy.confirmTitle'), body: t('privacy.confirmBody', { what: r.caseName }), confirmLabel: t('reports.delete'), danger: true }))) return;
                      await window.blazma.reports.remove(r.id);
                      load();
                    }}><Trash2 size={13} /></button>
                  </div>
                ),
              },
            ]}
          />
        )}
      </Card>
    </div>
  );
}
