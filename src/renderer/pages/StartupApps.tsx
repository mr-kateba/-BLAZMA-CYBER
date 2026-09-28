import { useEffect, useState } from 'react';
import { ExternalLink, FileSearch, Power, RefreshCw, ShieldAlert } from 'lucide-react';
import type { ForensicsResult, SignatureRow, StartupRow } from '../../shared/api';
import { reviewStartup, startupProgram, type StartupItem } from '../../core/startup-review';
import { Badge, Card, EmptyState, ErrorState, IconTile, Ltr, Notice, Skeleton, type Tone } from '../components/ui';
import { useApp } from '../components/AppContext';
import { useI18n } from '../i18n/I18nProvider';
import { newTaskId } from '../format';

const SIG_TONE: Record<NonNullable<StartupItem['signature']>, Tone> = { valid: 'green', not_signed: 'amber', hash_mismatch: 'red', not_trusted: 'amber', unknown_error: 'gray', other: 'gray' };

/** Loads the startup list and the signatures of the programs it runs (both read-only). */
export async function loadStartupReview(): Promise<{ items: StartupItem[] } | { error: string }> {
  const r = await window.blazma.forensics.collect('startup');
  if (!r.ok) return { error: r.error };
  const rows = (r.data as ForensicsResult<StartupRow>).rows;
  const paths = rows.map((x) => startupProgram(x.command)).filter((p): p is string => !!p);
  const s = paths.length ? await window.blazma.forensics.signatures(paths, newTaskId()) : { ok: true as const, data: [] as SignatureRow[] };
  return { items: reviewStartup(rows, s.ok ? s.data : []) };
}

export function StartupApps() {
  const { t } = useI18n();
  const { analyzeFile, toast } = useApp();
  const [state, setState] = useState<{ loading: boolean; items?: StartupItem[]; error?: string }>({ loading: true });

  const load = async () => {
    setState({ loading: true });
    const r = await loadStartupReview();
    setState('error' in r ? { loading: false, error: r.error } : { loading: false, items: r.items });
  };
  useEffect(() => void load(), []);
  const openSettings = async () => {
    const r = await window.blazma.device.openSettings('startupApps');
    if (!r.ok) toast('red', t(`errors.${r.error}`));
  };

  const items = state.items ?? [];
  const attention = items.filter((i) => i.attention).length;

  return (
    <div className="page">
      <div className="page-head">
        <IconTile icon={Power} tone="amber" />
        <div>
          <h1 className="page-title">{t('startup.title')}</h1>
          <div className="page-sub">{t('startup.subtitle')}</div>
        </div>
      </div>
      <div className="col" style={{ gap: 16 }}>
        <Notice>{t('startup.intro')}</Notice>
        {state.loading && <Card><Skeleton h={120} /></Card>}
        {state.error && <Card><ErrorState code={state.error} onRetry={() => void load()} /></Card>}
        {state.items && (
          <Card
            title={t('startup.listTitle', { n: items.length })}
            subtitle={attention ? t('startup.attentionSub', { n: attention }) : t('startup.allFine')}
            icon={attention ? ShieldAlert : Power}
            tone={attention ? 'amber' : 'green'}
            explain="startup_apps"
            actions={<div className="row" style={{ gap: 8 }}>
              <button className="btn sm" onClick={() => void openSettings()}><ExternalLink size={13} /> {t('startup.openSettings')}</button>
              <button className="btn sm" onClick={() => void load()}><RefreshCw size={13} /> {t('startup.refresh')}</button>
            </div>}
          >
            {items.length === 0 ? <EmptyState icon={Power} title={t('startup.none')} /> : (
              <div className="col" style={{ gap: 8 }}>
                {items.map((i, n) => (
                  <div key={`${i.name}-${n}`} className={`devsec-row tone-${i.attention ? 'amber' : i.signature === 'valid' ? 'green' : 'gray'}`}>
                    <div className="devsec-head" style={{ cursor: 'default' }}>
                      {i.attention ? <ShieldAlert size={18} className="devsec-icon" /> : <Power size={18} className="devsec-icon" />}
                      <div className="col" style={{ gap: 3, flex: 1, minWidth: 0 }}>
                        <span className="devsec-title">{i.name}</span>
                        <Ltr mono breakAll className="tiny dim">{i.program ?? i.command}</Ltr>
                        <div className="row-wrap" style={{ gap: 6 }}>
                          {i.signature
                            ? <Badge tone={SIG_TONE[i.signature]}>{i.signature === 'valid' && i.publisher ? t('startup.signedBy', { publisher: i.publisher }) : t(`startup.sig.${i.signature}`)}</Badge>
                            : <Badge tone="gray">{t('startup.sig.unchecked')}</Badge>}
                          <Badge tone="gray">{t(`startup.scope.${i.scope}`)}</Badge>
                          {i.flags.map((f) => <Badge key={f} tone="amber">{t(f)}</Badge>)}
                        </div>
                      </div>
                      {i.program && <button className="btn sm" onClick={() => analyzeFile(i.program!)}><FileSearch size={13} /> {t('startup.analyze')}</button>}
                    </div>
                  </div>
                ))}
              </div>
            )}
            <div className="tiny dim" style={{ marginTop: 12 }}>{t('startup.howToDisable')}</div>
          </Card>
        )}
      </div>
    </div>
  );
}
