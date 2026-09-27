import { useEffect, useState } from 'react';
import { MemoryStick, ScanSearch, ShieldCheck, ShieldHalf, X } from 'lucide-react';
import type { MemoryScanSummary, SuspiciousProcess } from '../../shared/api';
import { Badge, Card, EmptyState, ErrorState, IconTile, Ltr, Notice, Progress, type Tone } from '../components/ui';
import { useApp } from '../components/AppContext';
import { useI18n } from '../i18n/I18nProvider';
import { formatDuration, newTaskId } from '../format';

const SEV_TONE: Record<SuspiciousProcess['severity'], Tone> = { high: 'red', medium: 'amber', low: 'gray' };

export function MemoryScan() {
  const { t } = useI18n();
  const { navigate } = useApp();
  const [engine, setEngine] = useState<{ available: boolean; version: string | null } | null>(null);
  const [state, setState] = useState<{ taskId?: string; result?: MemoryScanSummary & { durationMs: number }; error?: string }>({});
  useEffect(() => void window.blazma.memory.engine().then(setEngine), []);

  const scan = async () => {
    const taskId = newTaskId();
    setState({ taskId });
    const r = await window.blazma.memory.scan(taskId);
    setState(r.ok ? { result: r.data } : { error: r.error });
  };
  const r = state.result;

  return (
    <div className="page">
      <div className="page-head">
        <IconTile icon={MemoryStick} tone="purple" />
        <div>
          <h1 className="page-title">{t('memscan.title')}</h1>
          <div className="page-sub">{t('memscan.subtitle')}</div>
        </div>
      </div>
      <div className="col" style={{ gap: 16 }}>
        <Notice tone="blue">{t('memscan.readOnly')}</Notice>
        {engine && !engine.available && <Card><EmptyState icon={MemoryStick} title={t('errors.engine_not_bundled')} hint={t('memscan.notBundledHint')} /></Card>}
        {engine?.available && !state.taskId && (
          <Card title={t('memscan.startTitle')} explain="memory_implants" icon={ScanSearch} tone="purple" subtitle={t('memscan.engine', { version: engine.version ?? '' })}>
            <div className="col" style={{ gap: 10 }}>
              <div className="small">{t('memscan.scope')}</div>
              <div><button className="btn primary" onClick={() => void scan()}><ScanSearch size={15} /> {t('memscan.scan')}</button></div>
            </div>
          </Card>
        )}
        {state.taskId && (
          <Card>
            <Progress indeterminate />
            <div className="row" style={{ marginTop: 10 }}>
              <span className="small muted">{t('memscan.scanning')}</span>
              <span className="spacer" />
              <button className="btn danger sm" onClick={() => void window.blazma.files.cancel(state.taskId!)}><X size={13} /> {t('common.cancel')}</button>
            </div>
          </Card>
        )}
        {state.error && <Card><ErrorState code={state.error} onRetry={() => setState({})} /></Card>}
        {r && (
          <>
            <Card title={t('memscan.resultTitle')} icon={r.suspicious.some((p) => p.severity === 'high') ? ShieldHalf : ShieldCheck}
              tone={r.suspicious.some((p) => p.severity === 'high') ? 'red' : r.suspicious.length ? 'amber' : 'green'}
              actions={<button className="btn sm" onClick={() => setState({})}>{t('memscan.again')}</button>}>
              <div className="col" style={{ gap: 8 }}>
                <div className="row-wrap" style={{ gap: 8 }}>
                  <Badge tone="blue">{t('memscan.scanned', { n: r.scanned ?? '—' })}</Badge>
                  <Badge tone={r.suspicious.length ? 'amber' : 'green'}>{t('memscan.suspiciousCount', { n: r.suspicious.length })}</Badge>
                  {r.failed ? <Badge tone="gray">{t('memscan.failed', { n: r.failed })}</Badge> : null}
                </div>
                <div className="small">{r.suspicious.length === 0 ? t('memscan.nothing') : t('memscan.found')}</div>
                <div className="tiny dim">{formatDuration(t, r.durationMs)} · {t('memscan.disclaimer')}</div>
              </div>
            </Card>
            {r.suspicious.length > 0 && (
              <Card title={t('memscan.listTitle')} subtitle={t('memscan.listSub')}>
                <div className="col" style={{ gap: 8 }}>
                  {r.suspicious.map((p) => (
                    <div key={p.pid} className={`devsec-row tone-${SEV_TONE[p.severity]}`}>
                      <div className="devsec-head" style={{ cursor: 'default' }}>
                        <span className="devsec-title"><Ltr>{p.name}</Ltr></span>
                        <span className="small dim">PID <Ltr mono>{p.pid}</Ltr>{p.managed ? ' · .NET' : ''}</span>
                        <span className="spacer" />
                        <Badge tone={SEV_TONE[p.severity]}>{t(`memscan.severity.${p.severity}`)}</Badge>
                      </div>
                      <ul className="linksum-list devsec-detail">
                        {Object.entries(p.indicators).map(([k, v]) => <li key={k} className={`tone-${['implanted_pe', 'implanted_shc', 'replaced'].includes(k) ? 'red' : 'amber'}`}>{t(`memscan.indicator.${k}`, { n: v ?? 0 })}</li>)}
                      </ul>
                    </div>
                  ))}
                  <div className="small"><strong>{t('memscan.whatToDo')}</strong> {t('memscan.advice')}</div>
                  <div><button className="btn sm" onClick={() => navigate('security-center')}><ShieldHalf size={13} /> {t('memscan.openSecurityCenter')}</button></div>
                </div>
              </Card>
            )}
          </>
        )}
      </div>
    </div>
  );
}
