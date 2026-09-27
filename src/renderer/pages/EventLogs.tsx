import { useEffect, useState } from 'react';
import { FileClock, FolderOpen, Monitor, ShieldAlert, X } from 'lucide-react';
import type { EventHuntOptions, EventHuntResult, EventHuntSource, EventLevel } from '../../shared/api';
import { Badge, Card, DataTable, EmptyState, ErrorState, IconTile, Ltr, Notice, Progress, Tabs, type Tone } from '../components/ui';
import { OptionPills } from '../components/intel';
import { useApp } from '../components/AppContext';
import { useI18n } from '../i18n/I18nProvider';
import { formatDateTime, formatDuration, newTaskId } from '../format';

const LEVEL_TONE: Record<EventLevel, Tone> = { critical: 'red', high: 'red', medium: 'amber', low: 'blue', informational: 'gray' };
const SHOW = 500;

export function EventLogs() {
  const { t, locale } = useI18n();
  const { confirm, toast } = useApp();
  const [engine, setEngine] = useState<{ available: boolean; version: string | null } | null>(null);
  const [opts, setOpts] = useState<EventHuntOptions>({ minLevel: 'medium', days: 30 });
  const [state, setState] = useState<{ running?: { taskId: string; live: boolean }; result?: EventHuntResult; error?: string }>({});
  const [levelFilter, setLevelFilter] = useState<'all' | EventLevel>('all');
  const isWindows = navigator.userAgent.includes('Windows');

  useEffect(() => void window.blazma.hunt.eventEngine().then(setEngine), []);

  const run = async (source: EventHuntSource) => {
    const taskId = newTaskId();
    setState({ running: { taskId, live: source.kind === 'live' } });
    const r = await window.blazma.hunt.events(source, opts, taskId);
    setState(r.ok ? { result: r.data } : { error: r.error });
    if (!r.ok && r.error === 'elevation_cancelled') toast('amber', t('errors.elevation_cancelled'));
  };
  const pick = async (kind: 'file' | 'dir') => {
    const path = await window.blazma.hunt.pickEvents(kind);
    if (path) void run({ kind, path });
  };
  const live = async () => {
    if (!(await confirm({ title: t('evlog.liveTitle'), body: t('evlog.liveBody'), confirmLabel: t('evlog.liveConfirm') }))) return;
    void run({ kind: 'live' });
  };

  const r = state.result;
  const rows = r ? r.rows.filter((d) => levelFilter === 'all' || d.level === levelFilter) : [];

  return (
    <div className="page">
      <div className="page-head">
        <IconTile icon={FileClock} tone="purple" />
        <div>
          <h1 className="page-title">{t('evlog.title')}</h1>
          <div className="page-sub">{t('evlog.subtitle')}</div>
        </div>
      </div>

      <div className="col" style={{ gap: 16 }}>
        <Notice tone="blue">{t('evlog.readOnly')}</Notice>
        {engine && !engine.available && <Card><EmptyState icon={FileClock} title={t('errors.engine_not_bundled')} hint={t('evlog.notBundledHint')} /></Card>}

        {engine?.available && !state.running && (
          <Card title={t('evlog.sourceTitle')} explain="event_logs" icon={FileClock} tone="purple" subtitle={t('evlog.engine', { version: engine.version ?? '' })}>
            <div className="col" style={{ gap: 14 }}>
              <div className="row-wrap" style={{ gap: 10 }}>
                <button className="btn primary" disabled={!isWindows} onClick={() => void live()}><Monitor size={15} /> {t('evlog.live')}</button>
                <button className="btn" onClick={() => void pick('file')}><FileClock size={15} /> {t('evlog.pickFile')}</button>
                <button className="btn" onClick={() => void pick('dir')}><FolderOpen size={15} /> {t('evlog.pickDir')}</button>
              </div>
              {!isWindows && <div className="tiny dim">{t('evlog.liveWindowsOnly')}</div>}
              <div>
                <div className="small dim" style={{ marginBottom: 6 }}>{t('evlog.minLevel')}</div>
                <OptionPills
                  items={(['low', 'medium', 'high', 'critical'] as const).map((l) => ({ id: l, label: t(`evlog.level.${l}`), checked: opts.minLevel === l }))}
                  onToggle={(id) => setOpts((o) => ({ ...o, minLevel: id as EventHuntOptions['minLevel'] }))}
                />
              </div>
              <div>
                <div className="small dim" style={{ marginBottom: 6 }}>{t('evlog.period')}</div>
                <OptionPills
                  items={([1, 7, 30, 90, null] as const).map((d) => ({ id: String(d), label: d === null ? t('evlog.allTime') : t('evlog.lastDays', { n: d }), checked: opts.days === d }))}
                  onToggle={(id) => setOpts((o) => ({ ...o, days: id === 'null' ? null : (Number(id) as EventHuntOptions['days']) }))}
                />
              </div>
            </div>
          </Card>
        )}

        {state.running && (
          <Card>
            <Progress indeterminate />
            <div className="row" style={{ marginTop: 10, gap: 10 }}>
              <span className="small muted">{t(state.running.live ? 'evlog.runningLive' : 'evlog.running')}</span>
              <span className="spacer" />
              {!state.running.live && <button className="btn danger sm" onClick={() => void window.blazma.files.cancel(state.running!.taskId)}><X size={13} /> {t('common.cancel')}</button>}
            </div>
          </Card>
        )}
        {state.error && <Card><ErrorState code={state.error} onRetry={() => setState({})} /></Card>}

        {r && (
          <>
            <Card title={t('evlog.resultTitle')} icon={ShieldAlert} tone={r.byLevel.critical + r.byLevel.high > 0 ? 'red' : r.byLevel.medium > 0 ? 'amber' : 'green'}
              actions={<button className="btn sm" onClick={() => setState({})}>{t('evlog.again')}</button>}>
              <div className="col" style={{ gap: 10 }}>
                <div className="row-wrap" style={{ gap: 8 }}>
                  {(['critical', 'high', 'medium', 'low', 'informational'] as const).filter((l) => r.byLevel[l] > 0 || l === 'critical' || l === 'high').map((l) => (
                    <Badge key={l} tone={LEVEL_TONE[l]}>{t(`evlog.level.${l}`)}: {r.byLevel[l]}</Badge>
                  ))}
                </div>
                <div className="small">{r.total === 0 ? t('evlog.noneFound') : t('evlog.summary', { total: r.total, rules: r.topRules.length })}</div>
                <div className="tiny dim">
                  {t('evlog.scanned', { source: r.source.kind === 'live' ? t('evlog.thisComputer') : '' })}{r.source.path && <Ltr mono>{r.source.path}</Ltr>}
                  {' · '}{formatDuration(t, r.durationMs)}{r.first && r.last && <> · {formatDateTime(locale, r.first)} — {formatDateTime(locale, r.last)}</>}
                </div>
                {r.tactics.length > 0 && (
                  <div className="chip-list">{r.tactics.map((x) => <span key={x.id} className="chip">{t(`evlog.tactic.${x.id}`)} · {x.count}</span>)}</div>
                )}
                <div className="tiny dim">{t('evlog.disclaimer')}</div>
              </div>
            </Card>

            {r.topRules.length > 0 && (
              <Card title={t('evlog.rulesTitle')} subtitle={t('evlog.rulesSub')}>
                <DataTable
                  maxHeight={320}
                  rowKey={(x) => x.rule}
                  rows={r.topRules}
                  columns={[
                    { key: 'l', label: t('evlog.col.level'), render: (x) => <Badge tone={LEVEL_TONE[x.level]}>{t(`evlog.level.${x.level}`)}</Badge> },
                    { key: 'r', label: t('evlog.col.rule'), render: (x) => <div><Ltr>{x.rule}</Ltr>{x.author && <div className="tiny dim">{t('evlog.by', { author: '' })}<Ltr>{x.author}</Ltr></div>}</div> },
                    { key: 'c', label: t('evlog.col.count'), render: (x) => <Ltr mono>{x.count}</Ltr> },
                  ]}
                />
              </Card>
            )}

            {r.rows.length > 0 && (
              <Card title={t('evlog.detectionsTitle')} subtitle={t('evlog.detectionsSub', { shown: Math.min(rows.length, SHOW), total: r.total })}>
                <Tabs<'all' | EventLevel>
                  value={levelFilter}
                  onChange={setLevelFilter}
                  items={[{ id: 'all', label: t('evlog.allLevels') }, ...(['critical', 'high', 'medium', 'low'] as const).filter((l) => r.byLevel[l] > 0).map((l) => ({ id: l, label: t(`evlog.level.${l}`) }))]}
                />
                <DataTable
                  maxHeight={520}
                  rowKey={(d, i) => `${i}-${d.recordId ?? ''}-${d.rule}`}
                  rows={rows.slice(0, SHOW)}
                  columns={[
                    { key: 't', label: t('evlog.col.time'), render: (d) => <span className="small nowrap">{d.time ? formatDateTime(locale, d.time) : '—'}</span> },
                    { key: 'l', label: t('evlog.col.level'), render: (d) => <Badge tone={LEVEL_TONE[d.level]}>{t(`evlog.level.${d.level}`)}</Badge> },
                    {
                      key: 'r', label: t('evlog.col.rule'), render: (d) => (
                        <div>
                          <Ltr>{d.rule}</Ltr>
                          <div className="tiny dim"><Ltr mono>{[d.channel, d.eventId !== null ? `EID ${d.eventId}` : null, d.computer, ...d.techniques].filter(Boolean).join(' · ')}</Ltr></div>
                          {d.ruleAuthor && <div className="tiny dim">{t('evlog.by', { author: '' })}<Ltr>{d.ruleAuthor}</Ltr></div>}
                        </div>
                      ),
                    },
                    {
                      key: 'd', label: t('evlog.col.details'), render: (d) => (
                        <Ltr mono className="tiny" breakAll>{d.details.slice(0, 8).map(([k, v]) => (k ? `${k}: ${v}` : v)).join(' ¦ ')}</Ltr>
                      ),
                    },
                  ]}
                />
              </Card>
            )}
          </>
        )}
      </div>
    </div>
  );
}
