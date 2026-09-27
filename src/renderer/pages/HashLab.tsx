import { useEffect, useMemo, useState } from 'react';
import { Fingerprint, GitCompare, Hash, Search, ShieldCheck, TriangleAlert, X } from 'lucide-react';
import type { HashResult, TaskProgress } from '../../shared/api';
import type { HashIdResult } from '../../core/hash-id';
import { Badge, Card, ErrorState, FileDrop, IconTile, Ltr, Notice, Progress, Tabs } from '../components/ui';
import { useI18n } from '../i18n/I18nProvider';
import { formatBytes, newTaskId } from '../format';
import { HashRows } from './FileAnalyzer';

type Tab = 'text' | 'file' | 'identify' | 'compare';
const ALGO_LABEL: Record<string, string> = { md5: 'MD5', sha1: 'SHA-1', sha256: 'SHA-256', sha512: 'SHA-512' };
const norm = (s: string) => s.trim().toLowerCase();

function findMatch(hashes: HashResult | null, expected: string): string | null {
  if (!hashes || !expected.trim()) return null;
  const e = norm(expected);
  return (Object.keys(ALGO_LABEL) as Array<keyof HashResult>).find((k) => hashes[k] === e) ?? null;
}

function TextTab() {
  const { t } = useI18n();
  const [text, setText] = useState('');
  const [res, setRes] = useState<HashResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  return (
    <div className="grid g-2">
      <Card title={t('hashlab.textLabel')} icon={Hash}>
        <textarea className="textarea" value={text} placeholder={t('hashlab.textPlaceholder')} onChange={(e) => setText(e.target.value)} />
        <div className="row" style={{ marginTop: 12 }}>
          <button
            className="btn primary"
            onClick={async () => {
              const r = await window.blazma.hashlab.hashText(text);
              if (r.ok) { setRes(r.data); setErr(null); } else setErr(r.error);
            }}
          >
            {t('hashlab.calculate')}
          </button>
          <span className="small dim">{t('hashlab.privacyNote')}</span>
        </div>
      </Card>
      <Card title={t('file.hashes')} icon={Fingerprint} tone="cyan">
        {err ? <ErrorState code={err} /> : res ? <HashRows hashes={res as unknown as Record<string, string>} /> : <div className="small dim">—</div>}
      </Card>
    </div>
  );
}

function FileTab() {
  const { t } = useI18n();
  const [expected, setExpected] = useState('');
  const [run, setRun] = useState<{ taskId: string; path: string; progress: TaskProgress | null } | null>(null);
  const [res, setRes] = useState<(HashResult & { sizeBytes: number; path: string }) | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => window.blazma.files.onProgress((p) => setRun((r) => (r && r.taskId === p.taskId ? { ...r, progress: p } : r))), []);

  const start = async (path: string) => {
    const taskId = newTaskId();
    setRes(null);
    setErr(null);
    setRun({ taskId, path, progress: null });
    const r = await window.blazma.files.hash(path, taskId);
    setRun(null);
    if (r.ok) setRes({ ...r.data, path });
    else if (r.error !== 'cancelled') setErr(r.error);
  };

  const match = findMatch(res, expected);
  const pct = run?.progress && run.progress.totalBytes ? (run.progress.processedBytes / run.progress.totalBytes) * 100 : 0;

  return (
    <div className="col" style={{ gap: 16 }}>
      <Card>
        <div className="field">
          <label htmlFor="expected">{t('hashlab.expectedLabel')}</label>
          <input id="expected" className="input mono" dir="ltr" value={expected} placeholder={t('hashlab.expectedPlaceholder')} onChange={(e) => setExpected(e.target.value)} />
        </div>
      </Card>
      {run ? (
        <Card>
          <div className="row" style={{ marginBottom: 12 }}>
            <div style={{ flex: 1, minWidth: 0 }} className="small"><Ltr mono>{run.path}</Ltr></div>
            <button className="btn danger sm" onClick={() => void window.blazma.files.cancel(run.taskId)}><X size={14} /> {t('common.cancel')}</button>
          </div>
          <Progress value={pct} indeterminate={!run.progress} />
          {run.progress && <div className="small muted" style={{ marginTop: 8 }}>{formatBytes(t, run.progress.processedBytes)} / {formatBytes(t, run.progress.totalBytes)}</div>}
        </Card>
      ) : !res ? (
        <FileDrop onFile={start} title={t('hashlab.fileLabel')} hint={t('file.dropHint')} activeText={t('file.dropActive')} browseLabel={t('common.browse')} />
      ) : null}
      {err && <Card><ErrorState code={err} onRetry={() => setErr(null)} /></Card>}
      {res && (
        <Card
          title={<Ltr breakAll>{res.path.split(/[\\/]/).pop()}</Ltr>}
          subtitle={formatBytes(t, res.sizeBytes)}
          icon={Fingerprint}
          tone="cyan"
          actions={<button className="btn sm" onClick={() => setRes(null)}>{t('file.analyzeAnother')}</button>}
        >
          {expected.trim() && (
            <div style={{ marginBottom: 12 }}>
              {match ? (
                <Notice tone="green" icon={ShieldCheck}>{t('hashlab.match', { algo: ALGO_LABEL[match]! })}</Notice>
              ) : (
                <Notice tone="red" icon={TriangleAlert}>{t('hashlab.mismatch')}</Notice>
              )}
            </div>
          )}
          <HashRows hashes={res as unknown as Record<string, string>} highlight={match} />
        </Card>
      )}
    </div>
  );
}

function IdentifyTab() {
  const { t } = useI18n();
  const [value, setValue] = useState('');
  const [res, setRes] = useState<HashIdResult | null>(null);
  const tone = { high: 'green', medium: 'amber', low: 'gray' } as const;
  return (
    <div className="grid g-2">
      <Card title={t('hashlab.identifyLabel')} icon={Search}>
        <input className="input mono" dir="ltr" value={value} placeholder={t('hashlab.identifyPlaceholder')} onChange={(e) => setValue(e.target.value)} />
        <button
          className="btn primary"
          style={{ marginTop: 12 }}
          disabled={!value.trim()}
          onClick={async () => {
            const r = await window.blazma.hashlab.identify(value);
            if (r.ok) setRes(r.data);
          }}
        >
          {t('hashlab.identify')}
        </button>
      </Card>
      <Card title={t('hashlab.candidates')} icon={Fingerprint} tone="purple">
        {!res ? <div className="small dim">—</div> : res.candidates.length === 0 ? (
          <div className="muted">{t('hashlab.noCandidates')}</div>
        ) : (
          <div className="col" style={{ gap: 8 }}>
            {res.candidates.length > 1 && <Notice tone="amber">{t('hashlab.ambiguous')}</Notice>}
            {res.candidates.map((c) => (
              <div key={c.id} className="hash-row" style={{ gridTemplateColumns: '1fr auto' }}>
                <Ltr>{c.name}</Ltr>
                <Badge tone={tone[c.confidence]}>{t(`hashlab.confidence.${c.confidence}`)}</Badge>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}

function CompareTab() {
  const { t } = useI18n();
  const [a, setA] = useState('');
  const [b, setB] = useState('');
  const equal = useMemo(() => (a.trim() && b.trim() ? norm(a) === norm(b) : null), [a, b]);
  return (
    <Card icon={GitCompare} title={t('hashlab.tab.compare')} subtitle={t('hashlab.compareHint')}>
      <div className="grid g-2">
        <div className="field"><label>{t('hashlab.compareA')}</label><input className="input mono" dir="ltr" value={a} onChange={(e) => setA(e.target.value)} /></div>
        <div className="field"><label>{t('hashlab.compareB')}</label><input className="input mono" dir="ltr" value={b} onChange={(e) => setB(e.target.value)} /></div>
      </div>
      {equal !== null && (
        <div style={{ marginTop: 14 }}>
          {equal ? <Notice tone="green" icon={ShieldCheck}>{t('hashlab.compareEqual')}</Notice> : <Notice tone="red" icon={TriangleAlert}>{t('hashlab.compareDifferent')}</Notice>}
        </div>
      )}
    </Card>
  );
}

export function HashLab() {
  const { t } = useI18n();
  const [tab, setTab] = useState<Tab>('file');
  return (
    <div className="page">
      <div className="page-head">
        <IconTile icon={Hash} tone="purple" />
        <div>
          <h1 className="page-title">{t('hashlab.title')}</h1>
          <div className="page-sub">{t('hashlab.subtitle')}</div>
        </div>
      </div>
      <Tabs<Tab>
        value={tab}
        onChange={setTab}
        items={(['file', 'text', 'identify', 'compare'] as const).map((id) => ({ id, label: t(`hashlab.tab.${id}`) }))}
      />
      {tab === 'text' && <TextTab />}
      {tab === 'file' && <FileTab />}
      {tab === 'identify' && <IdentifyTab />}
      {tab === 'compare' && <CompareTab />}
    </div>
  );
}
