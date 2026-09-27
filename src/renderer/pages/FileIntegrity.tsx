import { useEffect, useState } from 'react';
import { AlertTriangle, FileSearch, FolderCheck, FolderPlus, RefreshCw, ShieldCheck, Trash2, X } from 'lucide-react';
import type { FimChange, FimCheckResult, FimPreset, FimWatch, TaskProgress } from '../../shared/api';
import { isExecutableLike } from '../../core/fim';
import { Badge, Card, DataTable, EmptyState, ErrorState, FilterInput, IconTile, Ltr, Notice, Progress, Skeleton, Tabs, useFilter, type Tone } from '../components/ui';
import { useApp } from '../components/AppContext';
import { useI18n } from '../i18n/I18nProvider';
import { formatBytes, formatDateTime, formatNumber, newTaskId } from '../format';

const CHANGE_TONE: Record<FimChange['change'], Tone> = { modified: 'amber', added: 'blue', removed: 'gray' };
type Running = { taskId: string; label: string };
type Filter = 'all' | FimChange['change'];

export function FileIntegrity() {
  const { t, locale } = useI18n();
  const { confirm, toast, analyzeFile } = useApp();
  const [watches, setWatches] = useState<FimWatch[] | null>(null);
  const [presets, setPresets] = useState<FimPreset[]>([]);
  const [running, setRunning] = useState<Running | null>(null);
  const [p, setP] = useState<TaskProgress | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<FimCheckResult | null>(null);
  const [filter, setFilter] = useState<Filter>('all');

  const reload = () => void window.blazma.fim.list().then((r) => setWatches(r.ok ? r.data : []));
  useEffect(() => {
    reload();
    void window.blazma.fim.presets().then((r) => r.ok && setPresets(r.data));
  }, []);
  useEffect(() => {
    setP(null);
    if (!running) return;
    return window.blazma.files.onProgress((x) => x.taskId === running.taskId && setP(x));
  }, [running]);

  const task = async <T,>(label: string, work: (taskId: string) => Promise<{ ok: true; data: T } | { ok: false; error: string }>): Promise<T | null> => {
    const taskId = newTaskId();
    setError(null);
    setRunning({ taskId, label });
    const r = await work(taskId);
    setRunning(null);
    if (!r.ok) {
      if (r.error !== 'cancelled') setError(r.error);
      return null;
    }
    return r.data;
  };

  const create = async (folder: string, name = '') => {
    const w = await task(t('fim.fingerprinting'), (id) => window.blazma.fim.create(folder, name, id));
    if (w) {
      toast('green', t('fim.created', { files: formatNumber(locale, w.files) }));
      reload();
    }
  };
  const pick = async () => {
    const folder = await window.blazma.files.pickFolder();
    if (folder) await create(folder);
  };
  const check = async (w: FimWatch) => {
    setResult(null);
    setFilter('all');
    const r = await task(t('fim.checking', { name: w.name }), (id) => window.blazma.fim.check(w.id, id));
    if (r) {
      setResult(r);
      reload();
    }
  };
  const accept = async (w: FimWatch) => {
    if (!(await confirm({ title: t('fim.acceptTitle'), body: t('fim.acceptBody', { name: w.name }), confirmLabel: t('fim.accept') }))) return;
    const r = await task(t('fim.fingerprinting'), (id) => window.blazma.fim.accept(w.id, id));
    if (r) {
      setResult(null);
      toast('green', t('fim.accepted'));
      reload();
    }
  };
  const remove = async (w: FimWatch) => {
    if (!(await confirm({ title: t('fim.removeTitle'), body: t('fim.removeBody', { name: w.name }), confirmLabel: t('fim.remove'), danger: true }))) return;
    await window.blazma.fim.remove(w.id);
    if (result?.watch.id === w.id) setResult(null);
    reload();
  };
  const analyze = async (w: FimWatch, path: string) => {
    const r = await window.blazma.fim.resolve(w.id, path);
    if (r.ok) analyzeFile(r.data);
    else toast('red', t(`errors.${r.error}`));
  };

  const watched = new Set((watches ?? []).map((w) => w.root.toLowerCase()));
  const freePresets = presets.filter((x) => !watched.has(x.path.toLowerCase()));
  const files = p?.stage?.startsWith('files:') ? Number(p.stage.slice(6)) : 0;

  return (
    <div className="page">
      <div className="page-head">
        <IconTile icon={FolderCheck} tone="green" />
        <div>
          <h1 className="page-title">{t('fim.title')}</h1>
          <div className="page-sub">{t('fim.subtitle')}</div>
        </div>
      </div>
      <div className="col" style={{ gap: 16 }}>
        {running ? (
          <Card>
            <Progress indeterminate />
            <div className="row" style={{ marginTop: 10, gap: 10 }}>
              <span className="small muted">{running.label} · {t('fim.progress', { files: formatNumber(locale, files), size: formatBytes(t, p?.processedBytes ?? 0) })}</span>
              <span className="spacer" />
              <button className="btn danger sm" onClick={() => void window.blazma.files.cancel(running.taskId)}><X size={13} /> {t('common.cancel')}</button>
            </div>
          </Card>
        ) : (
          <Card title={t('fim.newTitle')} subtitle={t('fim.newSub')} icon={FolderPlus} tone="green" explain="file_integrity">
            <div className="col" style={{ gap: 12 }}>
              {freePresets.length > 0 && (
                <div className="col" style={{ gap: 8 }}>
                  <span className="small dim">{t('fim.suggested')}</span>
                  <div className="row-wrap" style={{ gap: 8 }}>
                    {freePresets.map((x) => (
                      <button key={x.id} className="btn sm" title={x.path} onClick={() => void create(x.path, t(`fim.preset.${x.id}`))}>
                        <FolderCheck size={14} /> {t(`fim.preset.${x.id}`)}
                      </button>
                    ))}
                  </div>
                </div>
              )}
              <div><button className="btn primary" onClick={() => void pick()}><FolderPlus size={15} /> {t('fim.chooseFolder')}</button></div>
              <span className="tiny dim">{t('fim.privacyNote')}</span>
            </div>
          </Card>
        )}
        {error && <Card><ErrorState code={error} onRetry={() => setError(null)} /></Card>}

        {result && <CheckResult r={result} filter={filter} setFilter={setFilter} onAccept={() => void accept(result.watch)} onAnalyze={(path) => void analyze(result.watch, path)} busy={!!running} />}

        <Card title={t('fim.watchesTitle')} icon={ShieldCheck}>
          {!watches ? <Skeleton h={60} /> : watches.length === 0 ? <EmptyState icon={FolderCheck} title={t('fim.noWatches')} hint={t('fim.noWatchesHint')} /> : (
            <div className="col" style={{ gap: 10 }}>
              {watches.map((w) => {
                const lc = w.lastCheck;
                const changed = lc ? lc.added + lc.removed + lc.modified : 0;
                return (
                  <div key={w.id} className="fim-row">
                    <div className="col" style={{ gap: 3, minWidth: 0, flex: 1 }}>
                      <div className="row" style={{ gap: 8 }}>
                        <strong>{w.name}</strong>
                        {lc && (changed ? <Badge tone="amber">{t('fim.changesBadge', { n: changed })}</Badge> : <Badge tone="green">{t('fim.noChangesBadge')}</Badge>)}
                        {w.truncated && <Badge tone="gray">{t('fim.truncatedBadge')}</Badge>}
                      </div>
                      <Ltr mono className="tiny dim">{w.root}</Ltr>
                      <span className="tiny dim">
                        {t('fim.watchMeta', { files: formatNumber(locale, w.files), size: formatBytes(t, w.bytes), date: formatDateTime(locale, w.createdAt) })}
                        {lc && ` · ${t('fim.lastCheck', { date: formatDateTime(locale, lc.at) })}`}
                      </span>
                    </div>
                    <div className="row" style={{ gap: 8 }}>
                      <button className="btn primary sm" disabled={!!running} onClick={() => void check(w)}><RefreshCw size={13} /> {t('fim.checkNow')}</button>
                      <button className="btn sm" disabled={!!running} title={t('fim.remove')} aria-label={t('fim.remove')} onClick={() => void remove(w)}><Trash2 size={13} /></button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}

function CheckResult({ r, filter, setFilter, onAccept, onAnalyze, busy }: {
  r: FimCheckResult; filter: Filter; setFilter: (f: Filter) => void; onAccept: () => void; onAnalyze: (path: string) => void; busy: boolean;
}) {
  const { t, locale } = useI18n();
  const count = (c: FimChange['change']) => r.diff.changes.filter((x) => x.change === c).length;
  const rows = r.diff.changes.filter((c) => filter === 'all' || c.change === filter);
  const { q, setQ, filtered: shown } = useFilter(rows, (c) => [c.path]);
  const hidden = new Set(r.diff.hiddenEdits);
  const execChanged = r.diff.changes.filter((c) => c.change !== 'removed' && isExecutableLike(c.path)).length;
  const total = r.totalChanges;

  return (
    <Card
      title={t('fim.resultTitle', { name: r.watch.name })}
      subtitle={total ? t('fim.resultChanged', { n: formatNumber(locale, total) }) : t('fim.resultSame')}
      icon={total ? AlertTriangle : ShieldCheck}
      tone={r.diff.hiddenEdits.length ? 'red' : total ? 'amber' : 'green'}
      actions={total > 0 ? <button className="btn sm" disabled={busy} onClick={onAccept}>{t('fim.accept')}</button> : undefined}
    >
      <div className="col" style={{ gap: 14 }}>
        <div className="tstats">
          <div className="tstat"><div className="tstat-l">{t('fim.change.modified')}</div><div className="tstat-v"><Ltr>{count('modified')}</Ltr></div></div>
          <div className="tstat"><div className="tstat-l">{t('fim.change.added')}</div><div className="tstat-v"><Ltr>{count('added')}</Ltr></div></div>
          <div className="tstat"><div className="tstat-l">{t('fim.change.removed')}</div><div className="tstat-v"><Ltr>{count('removed')}</Ltr></div></div>
          <div className="tstat"><div className="tstat-l">{t('fim.unchanged')}</div><div className="tstat-v"><Ltr>{formatNumber(locale, r.diff.unchanged)}</Ltr></div></div>
        </div>
        {r.diff.hiddenEdits.length > 0 && <Notice tone="red" icon={AlertTriangle}>{t('fim.hiddenEdits', { n: r.diff.hiddenEdits.length })}</Notice>}
        {execChanged > 0 && <Notice tone="amber" icon={AlertTriangle}>{t('fim.execChanged', { n: execChanged })}</Notice>}
        {r.diff.touched > 0 && <div className="small dim">{t('fim.touched', { n: formatNumber(locale, r.diff.touched) })}</div>}
        {r.unreadableNow.length > 0 && <div className="small dim">{t('fim.unreadable', { n: r.unreadableNow.length })}</div>}
        {total > 0 && (
          <>
            <div className="row-wrap" style={{ gap: 10, justifyContent: 'space-between' }}>
              <Tabs<Filter> value={filter} onChange={setFilter} items={(['all', 'modified', 'added', 'removed'] as const).map((id) => ({ id, label: id === 'all' ? t('fim.all') : t(`fim.change.${id}`) }))} />
              <FilterInput value={q} onChange={setQ} placeholder={t('fim.filter')} />
            </div>
            <DataTable maxHeight={520} rowKey={(c) => `${c.change}:${c.path}`} rows={shown} columns={[
              { key: 'c', label: t('fim.colChange'), render: (c) => <Badge tone={CHANGE_TONE[c.change]}>{t(`fim.change.${c.change}`)}</Badge> },
              { key: 'p', label: t('fim.colFile'), render: (c) => (
                <div>
                  <Ltr mono breakAll className="small">{c.path}</Ltr>
                  {(hidden.has(c.path) || isExecutableLike(c.path)) && (
                    <div className="row" style={{ gap: 6, marginTop: 4 }}>
                      {hidden.has(c.path) && <Badge tone="red">{t('fim.sameTime')}</Badge>}
                      {isExecutableLike(c.path) && <Badge tone="purple">{t('fim.runnable')}</Badge>}
                    </div>
                  )}
                </div>
              ) },
              { key: 's', label: t('fim.colSize'), render: (c) => <Ltr className="small">{[c.before, c.after].map((x) => (x ? formatBytes(t, x.size) : '—')).join(' → ')}</Ltr> },
              { key: 'm', label: t('fim.colTime'), render: (c) => <span className="small">{formatDateTime(locale, new Date((c.after ?? c.before)!.mtimeMs).toISOString())}</span> },
              { key: 'a', label: '', render: (c) => (c.change === 'removed' ? null : <button className="btn sm" title={t('fim.analyze')} onClick={() => onAnalyze(c.path)}><FileSearch size={13} /> {t('fim.analyze')}</button>) },
            ]} />
            {r.diff.changes.length < total && <div className="tiny dim">{t('fim.listCapped', { shown: r.diff.changes.length, total })}</div>}
          </>
        )}
      </div>
    </Card>
  );
}
