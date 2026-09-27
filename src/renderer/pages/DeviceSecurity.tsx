import { useCallback, useEffect, useState } from 'react';
import { BadgeCheck, ChevronDown, CircleCheck, CircleHelp, CircleX, ExternalLink, RefreshCw, TriangleAlert } from 'lucide-react';
import type { DeviceCheck, DeviceSecurityReport } from '../../shared/api';
import { Badge, Card, ErrorState, Gauge, IconTile, Notice, Skeleton, type Tone } from '../components/ui';
import { useApp } from '../components/AppContext';
import { useI18n } from '../i18n/I18nProvider';
import { formatDateTime } from '../format';

const ORDER: Record<DeviceCheck['status'], number> = { fail: 0, warn: 1, unknown: 2, pass: 3 };
const TONE: Record<DeviceCheck['status'], Tone> = { pass: 'green', warn: 'amber', fail: 'red', unknown: 'gray' };
const ICON = { pass: CircleCheck, warn: TriangleAlert, fail: CircleX, unknown: CircleHelp } as const;
const GRADE_COLOR = { good: '#22c55e', fair: '#f59e0b', poor: '#ef4444' } as const;

export function DeviceSecurity() {
  const { t, locale } = useI18n();
  const { toast } = useApp();
  const [state, setState] = useState<{ loading: boolean; report?: DeviceSecurityReport; error?: string }>({ loading: true });
  const [open, setOpen] = useState<string | null>(null);

  const run = useCallback(async (force = false) => {
    setState({ loading: true });
    const r = await window.blazma.device.security(force);
    setState(r.ok ? { loading: false, report: r.data } : { loading: false, error: r.error });
  }, []);
  useEffect(() => void run(), [run]);

  const openSettings = async (c: DeviceCheck) => {
    if (!c.link) return;
    const r = await window.blazma.device.openSettings(c.link);
    if (!r.ok) toast('red', t(`errors.${r.error}`));
  };

  const r = state.report;
  const checks = r ? [...r.checks].sort((a, b) => ORDER[a.status] - ORDER[b.status] || b.weight - a.weight) : [];
  const count = (s: DeviceCheck['status']) => checks.filter((c) => c.status === s).length;

  return (
    <div className="page">
      <div className="page-head">
        <IconTile icon={BadgeCheck} tone="green" />
        <div>
          <h1 className="page-title">{t('devsec.title')}</h1>
          <div className="page-sub">{t('devsec.subtitle')}</div>
        </div>
        <span className="spacer" />
        <button className="btn" onClick={() => void run(true)} disabled={state.loading}><RefreshCw size={15} /> {t('devsec.rescan')}</button>
      </div>

      <div className="col" style={{ gap: 16 }}>
        <Notice tone="blue">{t('devsec.readOnly')}</Notice>
        {state.loading && <Card><Skeleton h={120} /><div className="small muted" style={{ marginTop: 10 }}>{t('devsec.scanning')}</div></Card>}
        {state.error && <Card><ErrorState code={state.error} onRetry={() => void run(true)} /></Card>}

        {r && (
          <>
            <Card>
              <div className="row" style={{ gap: 24, flexWrap: 'wrap' }}>
                <Gauge value={r.score} label={t('devsec.score')} unit="/100" size={150} color={r.grade ? GRADE_COLOR[r.grade] : '#64748b'} />
                <div className="col" style={{ gap: 8, flex: 1, minWidth: 240 }}>
                  <div className="big-value">{r.grade ? t(`devsec.grade.${r.grade}`) : t('devsec.grade.none')}</div>
                  <div className="muted">{r.grade ? t(`devsec.gradeHint.${r.grade}`) : t('devsec.gradeHint.none')}</div>
                  <div className="row-wrap" style={{ gap: 8 }}>
                    <Badge tone="red" icon={CircleX}>{t('devsec.count.fail', { n: count('fail') })}</Badge>
                    <Badge tone="amber" icon={TriangleAlert}>{t('devsec.count.warn', { n: count('warn') })}</Badge>
                    <Badge tone="green" icon={CircleCheck}>{t('devsec.count.pass', { n: count('pass') })}</Badge>
                    {count('unknown') > 0 && <Badge tone="gray" icon={CircleHelp}>{t('devsec.count.unknown', { n: count('unknown') })}</Badge>}
                  </div>
                  <div className="tiny dim">{t('devsec.checkedAt', { time: formatDateTime(locale, r.collectedAt) })}</div>
                </div>
              </div>
            </Card>

            <Card title={t('devsec.checks')} subtitle={t('devsec.checksSub')}>
              <div className="col" style={{ gap: 8 }}>
                {checks.map((c) => {
                  const Icon = ICON[c.status];
                  const expanded = open === c.id;
                  return (
                    <div key={c.id} className={`devsec-row tone-${TONE[c.status]}`}>
                      <button className="devsec-head" aria-expanded={expanded} onClick={() => setOpen(expanded ? null : c.id)}>
                        <Icon size={18} className="devsec-icon" />
                        <span className="devsec-title">{t(`devsec.check.${c.id}.title`)}</span>
                        <span className="spacer" />
                        <Badge tone={TONE[c.status]}>{t(`devsec.status.${c.status}`)}</Badge>
                        <ChevronDown size={16} className={`devsec-chevron ${expanded ? 'open' : ''}`} />
                      </button>
                      {c.detail && <div className="small muted devsec-detail">{t(c.detail.key, c.detail.vars)}</div>}
                      {c.status === 'unknown' && c.reason && <div className="small dim devsec-detail">{t(`errors.${c.reason}`)}</div>}
                      {expanded && (
                        <div className="devsec-body">
                          <div><strong>{t('devsec.why')}</strong> {t(`devsec.check.${c.id}.why`)}</div>
                          {c.status !== 'pass' && <div><strong>{t('devsec.fix')}</strong> {t(`devsec.check.${c.id}.fix`)}</div>}
                          {c.link && c.status !== 'pass' && (
                            <button className="btn sm" onClick={() => void openSettings(c)}><ExternalLink size={13} /> {t('devsec.openSettings')}</button>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </Card>
            {!r.elevated && <div className="tiny dim">{t('devsec.adminNote')}</div>}
          </>
        )}
      </div>
    </div>
  );
}
