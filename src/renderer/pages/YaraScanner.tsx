import { useEffect, useState } from 'react';
import { CircleCheck, Cpu, FileCode, FilePlus, FolderSearch, ScanSearch, ShieldAlert, ShieldCheck, Trash2, Upload, X } from 'lucide-react';
import type { YaraEngineInfo, YaraRuleFile, YaraScanResult } from '../../shared/api';
import { Badge, Card, EmptyState, ErrorState, IconTile, Ltr, Notice, Progress, Skeleton, Tabs, Toggle, DataTable } from '../components/ui';
import { useApp } from '../components/AppContext';
import { useI18n } from '../i18n/I18nProvider';
import { formatDuration, newTaskId } from '../format';
import { useElapsed } from './SecurityCenter';

type Tab = 'scan' | 'rules' | 'engine';

function EngineTab({ engine, onChange }: { engine: YaraEngineInfo | null; onChange: () => void }) {
  const { t } = useI18n();
  const { toast } = useApp();
  if (!engine) return <Card><Skeleton h={60} /></Card>;
  return (
    <Card title={t('yara.tab.engine')} icon={Cpu} tone={engine.available ? 'green' : 'amber'}>
      <div className="col" style={{ gap: 12 }}>
        {engine.available ? (
          <>
            <Badge tone="green" icon={CircleCheck}>{t('yara.engineInstalled', { version: engine.version ?? '' })}</Badge>
            <div className="small"><span className="dim">{t('yara.enginePath')}: </span><Ltr mono breakAll>{engine.path}</Ltr></div>
          </>
        ) : (
          <Notice tone="amber" icon={ShieldAlert}>
            <div style={{ fontWeight: 600 }}>{t('yara.engineMissing')}</div>
            <div>{t(`errors.${engine.reason ?? 'yara_not_installed'}`)}</div>
          </Notice>
        )}
        <div className="small muted">{t('yara.installHelp')}</div>
        <div className="row-wrap">
          <button
            className="btn primary"
            onClick={async () => {
              const r = await window.blazma.yara.pickEngine();
              if (r.ok && r.data) toast('green', t('yara.engineSaved'));
              else if (!r.ok) toast('red', t(`errors.${r.error}`));
              onChange();
            }}
          >
            {t('yara.chooseEngine')}
          </button>
          <button className="btn" onClick={async () => { await window.blazma.yara.clearEngine(); onChange(); }}>{t('yara.useDefault')}</button>
        </div>
      </div>
    </Card>
  );
}

function RulesTab({ engine }: { engine: YaraEngineInfo | null }) {
  const { t } = useI18n();
  const { toast, confirm } = useApp();
  const [rules, setRules] = useState<YaraRuleFile[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [open, setOpen] = useState<{ id: string; source: string } | null>(null);
  const [draft, setDraft] = useState<{ name: string; source: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const load = async () => {
    const r = await window.blazma.yara.rules();
    if (r.ok) setRules(r.data);
    else setErr(r.error);
  };
  useEffect(() => void load(), []);

  const savedToast = (r: YaraRuleFile) =>
    toast(r.valid === false ? 'amber' : 'green', t(r.valid === false ? 'yara.rules.savedInvalid' : r.valid === null ? 'yara.rules.savedUnchecked' : 'yara.rules.saved'));

  if (err) return <Card><ErrorState code={err} onRetry={() => void load()} /></Card>;
  if (!rules) return <Card><Skeleton h={100} /></Card>;
  const enabled = rules.filter((r) => r.enabled).length;

  return (
    <div className="col" style={{ gap: 16 }}>
      <Card
        title={t('yara.tab.rules')}
        subtitle={t('yara.rules.count', { enabled, total: rules.length })}
        icon={FileCode}
        tone="purple"
        actions={
          <div className="row-wrap">
            <button className="btn sm" disabled={!engine?.available || busy} onClick={async () => { setBusy(true); const r = await window.blazma.yara.validate(); setBusy(false); if (r.ok) setRules(r.data); }}>
              <ShieldCheck size={13} /> {t('yara.rules.validateAll')}
            </button>
            <button className="btn sm" onClick={() => setDraft({ name: '', source: 'rule My_Rule\n{\n  meta:\n    description = ""\n    severity = "suspicious"\n  strings:\n    $a = "example"\n  condition:\n    $a\n}\n' })}>
              <FilePlus size={13} /> {t('yara.rules.newRule')}
            </button>
            <button className="btn sm" onClick={async () => { const r = await window.blazma.yara.importFile(); if (r.ok && r.data) { savedToast(r.data); void load(); } else if (!r.ok) toast('red', t(`errors.${r.error}`)); }}>
              <Upload size={13} /> {t('yara.rules.import')}
            </button>
          </div>
        }
      >
        <div className="small dim" style={{ marginBottom: 10 }}>{t('yara.rules.importNote')}</div>
        {rules.length === 0 ? <EmptyState title={t('yara.rules.empty')} /> : (
          <DataTable<YaraRuleFile>
            rowKey={(r) => r.id}
            rows={rules}
            columns={[
              { key: 'e', label: '', width: 60, render: (r) => <Toggle checked={r.enabled} label={r.name} disabled={r.valid === false} onChange={async (v) => { const x = await window.blazma.yara.setEnabled(r.id, v); if (x.ok) setRules(x.data); }} /> },
              { key: 'n', label: t('yara.rules.name'), render: (r) => <div><Ltr>{r.name}</Ltr><div className="tiny dim"><Ltr mono>{r.id}</Ltr></div></div> },
              { key: 'o', label: '', render: (r) => <Badge tone={r.origin === 'builtin' ? 'blue' : 'purple'}>{t(`yara.rules.origin.${r.origin}`)}</Badge> },
              {
                key: 'v', label: '',
                render: (r) => r.valid === true ? <Badge tone="green">{t('yara.rules.valid')}</Badge>
                  : r.valid === false ? <span title={r.error}><Badge tone="red">{t('yara.rules.invalid')}</Badge></span>
                  : <Badge tone="gray">{t('yara.rules.unchecked')}</Badge>,
              },
              {
                key: 'a', label: '',
                render: (r) => (
                  <div className="row-wrap" style={{ gap: 6 }}>
                    <button className="btn sm" onClick={async () => {
                      if (open?.id === r.id) return setOpen(null);
                      const s = await window.blazma.yara.source(r.id);
                      if (s.ok) setOpen({ id: r.id, source: s.data });
                    }}>{t(open?.id === r.id ? 'yara.rules.hide' : 'yara.rules.view')}</button>
                    <button className="btn danger sm" onClick={async () => {
                      if (!(await confirm({ title: t('yara.rules.deleteTitle'), body: t('yara.rules.deleteBody', { name: r.name }), confirmLabel: t('yara.rules.delete'), danger: true }))) return;
                      const x = await window.blazma.yara.remove(r.id);
                      if (x.ok) setRules(x.data);
                    }}><Trash2 size={13} /></button>
                  </div>
                ),
              },
            ]}
          />
        )}
        {open && (
          <div style={{ marginTop: 12 }}>
            {rules.find((r) => r.id === open.id)?.error && <Notice tone="red"><Ltr mono breakAll>{rules.find((r) => r.id === open.id)!.error}</Ltr></Notice>}
            <pre className="table-wrap mono small" dir="ltr" style={{ padding: 12, margin: '8px 0 0', maxHeight: 320, whiteSpace: 'pre-wrap' }}>{open.source}</pre>
          </div>
        )}
      </Card>

      {draft && (
        <Card title={t('yara.rules.newRule')} icon={FilePlus} tone="blue" actions={<button className="icon-btn" aria-label={t('common.close')} onClick={() => setDraft(null)}><X size={16} /></button>}>
          <div className="col" style={{ gap: 12 }}>
            <div className="field"><label>{t('yara.rules.name')}</label><input className="input" value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} /></div>
            <div className="field"><label>{t('yara.rules.source')}</label><textarea className="textarea mono" dir="ltr" style={{ minHeight: 220 }} spellCheck={false} value={draft.source} onChange={(e) => setDraft({ ...draft, source: e.target.value })} /></div>
            <div>
              <button className="btn primary" disabled={!draft.name.trim() || !draft.source.trim() || busy} onClick={async () => {
                setBusy(true);
                const r = await window.blazma.yara.save(draft.name, draft.source);
                setBusy(false);
                if (r.ok) { savedToast(r.data); setDraft(null); void load(); } else toast('red', t(`errors.${r.error}`));
              }}>{t('yara.rules.save')}</button>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}

function ScanTab({ engine }: { engine: YaraEngineInfo | null }) {
  const { t } = useI18n();
  const { toast, confirm } = useApp();
  const [target, setTarget] = useState<string | null>(null);
  const [recursive, setRecursive] = useState(true);
  const [run, setRun] = useState<string | null>(null);
  const [result, setResult] = useState<YaraScanResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const elapsed = useElapsed(run !== null);

  if (engine && !engine.available) {
    return <Card><Notice tone="amber" icon={ShieldAlert}><div style={{ fontWeight: 600 }}>{t('yara.engineMissing')}</div><div>{t('yara.installHelp')}</div></Notice></Card>;
  }
  const rows = (result?.files ?? []).flatMap((f) => f.matches.map((m) => ({ path: f.path, m })));

  return (
    <div className="col" style={{ gap: 16 }}>
      <Card title={t('yara.target')} icon={FolderSearch} tone="purple">
        <div className="col" style={{ gap: 12 }}>
          <div className="row-wrap">
            <button className="btn" onClick={async () => { const p = await window.blazma.files.pickFile(); if (p) setTarget(p); }}>{t('yara.chooseFile')}</button>
            <button className="btn" onClick={async () => { const p = await window.blazma.files.pickFolder(); if (p) setTarget(p); }}>{t('yara.chooseFolder')}</button>
          </div>
          {target && <div className="small"><Ltr mono breakAll>{target}</Ltr></div>}
          <div className="row"><Toggle checked={recursive} label={t('yara.recursive')} onChange={setRecursive} /><span>{t('yara.recursive')}</span></div>
          <div>
            {run ? (
              <button className="btn danger" onClick={() => void window.blazma.files.cancel(run)}><X size={14} /> {t('common.cancel')}</button>
            ) : (
              <button className="btn primary" disabled={!target} onClick={async () => {
                const taskId = newTaskId();
                setRun(taskId); setErr(null); setResult(null);
                const r = await window.blazma.yara.scan(target!, recursive, taskId);
                setRun(null);
                if (r.ok) setResult(r.data); else if (r.error !== 'cancelled') setErr(r.error);
              }}><ScanSearch size={15} /> {t('yara.start')}</button>
            )}
          </div>
          {run && <div><Progress indeterminate /><div className="small muted" style={{ marginTop: 8 }}>{t('yara.running')} · {formatDuration(t, elapsed)}</div></div>}
        </div>
      </Card>
      {err && <Card><ErrorState code={err} /></Card>}
      {result && (
        <Card
          title={t('yara.summary', { files: result.files.length, matched: result.matchedFiles, rules: result.rulesUsed })}
          subtitle={formatDuration(t, result.durationMs)}
          icon={result.matchedFiles ? ShieldAlert : CircleCheck}
          tone={result.matchedFiles ? 'amber' : 'green'}
        >
          {rows.length === 0 ? <div className="muted">{t('yara.noMatches')}</div> : (
            <DataTable
              rowKey={(r, i) => `${r.path}-${r.m.namespace}-${r.m.rule}-${i}`}
              rows={rows}
              columns={[
                { key: 'f', label: t('yara.col.file'), render: (r) => <Ltr mono breakAll className="small">{r.path}</Ltr> },
                { key: 'r', label: t('yara.col.rule'), render: (r) => <Ltr mono>{r.m.rule}</Ltr> },
                { key: 'n', label: t('yara.col.namespace'), render: (r) => <Ltr mono className="small">{r.m.namespace}</Ltr> },
                { key: 't', label: t('yara.col.tags'), render: (r) => <div className="chip-list">{r.m.tags.map((x) => <span key={x} className="chip"><Ltr>{x}</Ltr></span>)}</div> },
                { key: 'd', label: t('yara.col.description'), render: (r) => <span className="small">{String(r.m.meta.description ?? '')}</span> },
                {
                  key: 'q', label: '',
                  render: (r) => (
                    <button className="btn danger sm" onClick={async () => {
                      const name = r.path.split(/[\\/]/).pop() ?? r.path;
                      if (!(await confirm({ title: t('file.quarantineTitle'), body: t('file.quarantineBody', { name }), confirmLabel: t('file.quarantineThis'), danger: true }))) return;
                      const q = await window.blazma.quarantine.add(r.path, `yara:${r.m.rule}`);
                      if (q.ok) toast('green', t('file.quarantined')); else toast('red', t(`errors.${q.error}`));
                    }}>{t('file.quarantineThis')}</button>
                  ),
                },
              ]}
            />
          )}
        </Card>
      )}
    </div>
  );
}

export function YaraScanner() {
  const { t } = useI18n();
  const [tab, setTab] = useState<Tab>('scan');
  const [engine, setEngine] = useState<YaraEngineInfo | null>(null);
  const loadEngine = () => void window.blazma.yara.engine().then(setEngine);
  useEffect(loadEngine, []);
  return (
    <div className="page">
      <div className="page-head">
        <IconTile icon={ScanSearch} tone="purple" />
        <div>
          <h1 className="page-title">{t('yara.title')}</h1>
          <div className="page-sub">{t('yara.subtitle')}</div>
        </div>
        <span className="spacer" />
        {engine && (engine.available ? <Badge tone="green">{t('yara.engineInstalled', { version: engine.version ?? '' })}</Badge> : <Badge tone="amber">{t('yara.engineMissing')}</Badge>)}
      </div>
      <Tabs<Tab> value={tab} onChange={setTab} items={(['scan', 'rules', 'engine'] as const).map((id) => ({ id, label: t(`yara.tab.${id}`) }))} />
      {tab === 'scan' && <ScanTab engine={engine} />}
      {tab === 'rules' && <RulesTab engine={engine} />}
      {tab === 'engine' && <EngineTab engine={engine} onChange={loadEngine} />}
    </div>
  );
}
