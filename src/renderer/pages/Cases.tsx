import { useEffect, useState } from 'react';
import { ArrowLeft, FileText, FolderOpen, Plus, ScrollText, Trash2 } from 'lucide-react';
import type { CaseSummary, EvidenceKind, InvestigationCase, ReportFormat } from '../../shared/api';
import type { Lang } from '../../core/i18n';
import { Badge, Card, DataTable, EmptyState, ErrorState, IconTile, Ltr, Notice, Skeleton, Tabs, Toggle } from '../components/ui';
import { useApp } from '../components/AppContext';
import { useI18n } from '../i18n/I18nProvider';
import { formatDateTime } from '../format';

const KINDS: EvidenceKind[] = ['file', 'hash', 'ip', 'domain', 'url', 'email', 'process', 'connection', 'finding', 'other'];
type Tab = 'evidence' | 'notes' | 'timeline' | 'report';

function NewCaseForm({ onCreated }: { onCreated: (id: string) => void }) {
  const { t } = useI18n();
  const { toast } = useApp();
  const [name, setName] = useState('');
  const [desc, setDesc] = useState('');
  const [tags, setTags] = useState('');
  return (
    <Card title={t('cases.new')} icon={Plus} tone="blue">
      <div className="col" style={{ gap: 10 }}>
        <div className="field"><label htmlFor="case-name">{t('cases.name')}</label><input id="case-name" className="input" dir="auto" value={name} onChange={(e) => setName(e.target.value)} /></div>
        <div className="field"><label htmlFor="case-desc">{t('cases.description')}</label><textarea id="case-desc" className="textarea" dir="auto" style={{ minHeight: 70 }} value={desc} onChange={(e) => setDesc(e.target.value)} /></div>
        <div className="field"><label htmlFor="case-tags">{t('cases.tags')}</label><input id="case-tags" className="input" dir="auto" value={tags} onChange={(e) => setTags(e.target.value)} /></div>
        <div>
          <button className="btn primary" disabled={!name.trim()} onClick={async () => {
            const r = await window.blazma.cases.create(name.trim(), desc, tags.split(',').map((x) => x.trim()).filter(Boolean));
            if (r.ok) { setName(''); setDesc(''); setTags(''); onCreated(r.data.id); } else toast('red', t(`errors.${r.error}`));
          }}>{t('cases.create')}</button>
        </div>
      </div>
    </Card>
  );
}

function CaseList({ onOpen }: { onOpen: (id: string) => void }) {
  const { t, locale } = useI18n();
  const [list, setList] = useState<CaseSummary[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const load = () => void window.blazma.cases.list().then((r) => (r.ok ? setList(r.data) : setErr(r.error)));
  useEffect(load, []);
  return (
    <div className="grid g-3">
      <Card className="span-2">
        {err ? <ErrorState code={err} /> : !list ? <Skeleton h={120} /> : list.length === 0 ? (
          <EmptyState icon={FolderOpen} title={t('cases.empty')} hint={t('cases.emptyHint')} />
        ) : (
          <DataTable<CaseSummary>
            rowKey={(c) => c.id}
            rows={list}
            columns={[
              { key: 'id', label: 'ID', render: (c) => <button className="btn sm ghost" onClick={() => onOpen(c.id)}><Ltr mono>{c.id}</Ltr></button> },
              { key: 'n', label: t('cases.name'), render: (c) => <div><div>{c.name}</div><div className="chip-list">{c.tags.map((x) => <span key={x} className="chip">{x}</span>)}</div></div> },
              { key: 's', label: t('report.status'), render: (c) => <Badge tone={c.status === 'open' ? 'green' : 'gray'}>{t(`cases.status.${c.status}`)}</Badge> },
              { key: 'e', label: t('report.evidence'), render: (c) => <span className="small">{t('cases.evidenceCount', { count: c.evidenceCount })} · {t('cases.noteCount', { count: c.noteCount })}</span> },
              { key: 'u', label: t('report.updated'), render: (c) => <span className="small nowrap">{formatDateTime(locale, c.updatedAt)}</span> },
            ]}
          />
        )}
      </Card>
      <NewCaseForm onCreated={(id) => { load(); onOpen(id); }} />
    </div>
  );
}

function EvidenceTab({ c, onChange }: { c: InvestigationCase; onChange: (c: InvestigationCase) => void }) {
  const { t, locale } = useI18n();
  const { toast } = useApp();
  const [kind, setKind] = useState<EvidenceKind>('ip');
  const [value, setValue] = useState('');
  const [label, setLabel] = useState('');
  return (
    <div className="col" style={{ gap: 12 }}>
      <Notice tone="blue">{t('cases.evidenceSep')}</Notice>
      <Card title={t('cases.addEvidence')} icon={Plus}>
        <div className="row-wrap" style={{ alignItems: 'flex-end' }}>
          <div className="field"><label>{t('cases.kindLabel')}</label>
            <select className="select" style={{ width: 160 }} value={kind} onChange={(e) => setKind(e.target.value as EvidenceKind)}>{KINDS.map((k) => <option key={k} value={k}>{t(`cases.kind.${k}`)}</option>)}</select>
          </div>
          <div className="field" style={{ flex: 1, minWidth: 220 }}><label>{t('cases.value')}</label><input className="input mono" dir="ltr" value={value} onChange={(e) => setValue(e.target.value)} /></div>
          <div className="field" style={{ flex: 1, minWidth: 180 }}><label>{t('cases.label')}</label><input className="input" value={label} onChange={(e) => setLabel(e.target.value)} /></div>
          <button className="btn primary" disabled={!value.trim()} onClick={async () => {
            const r = await window.blazma.cases.addEvidence(c.id, { kind, value: value.trim(), label: label.trim() || null, source: 'manual' });
            if (r.ok) { onChange(r.data); setValue(''); setLabel(''); } else toast('red', t(`errors.${r.error}`));
          }}>{t('cases.add')}</button>
        </div>
      </Card>
      <Card>
        {c.evidence.length === 0 ? <EmptyState title={t('cases.noEvidence')} /> : (
          <DataTable
            rowKey={(e) => e.id}
            rows={c.evidence}
            columns={[
              { key: 'k', label: t('cases.kindLabel'), render: (e) => <Badge tone="blue">{t(`cases.kind.${e.kind}`)}</Badge> },
              {
                key: 'v', label: t('cases.value'),
                render: (e) => (
                  <div>
                    <Ltr mono breakAll className="small">{e.value}</Ltr>
                    {e.label && <div className="small dim">{e.label}</div>}
                    {e.details && <div className="tiny dim">{Object.entries(e.details).filter(([, v]) => v !== null && v !== '').map(([k, v]) => <span key={k} style={{ marginInlineEnd: 10 }}>{k}: <Ltr mono>{String(v)}</Ltr></span>)}</div>}
                  </div>
                ),
              },
              { key: 's', label: t('report.source'), render: (e) => <span className="small">{t(`report.module.${e.source}`)}</span> },
              { key: 'a', label: t('report.added'), render: (e) => <span className="small nowrap">{formatDateTime(locale, e.addedAt)}</span> },
              { key: 'x', label: '', render: (e) => <button className="icon-btn" aria-label={t('common.remove')} onClick={async () => { const r = await window.blazma.cases.removeEvidence(c.id, e.id); if (r.ok) onChange(r.data); }}><Trash2 size={14} /></button> },
            ]}
          />
        )}
      </Card>
    </div>
  );
}

function NotesTab({ c, onChange }: { c: InvestigationCase; onChange: (c: InvestigationCase) => void }) {
  const { t, locale } = useI18n();
  const [text, setText] = useState('');
  const [editing, setEditing] = useState<{ id: string; text: string } | null>(null);
  return (
    <div className="col" style={{ gap: 12 }}>
      <Card>
        <textarea className="textarea" dir="auto" value={text} placeholder={t('cases.notePlaceholder')} onChange={(e) => setText(e.target.value)} />
        <button className="btn primary" style={{ marginTop: 10 }} disabled={!text.trim()} onClick={async () => {
          const r = await window.blazma.cases.addNote(c.id, text);
          if (r.ok) { onChange(r.data); setText(''); }
        }}>{t('cases.addNote')}</button>
      </Card>
      {c.notes.length === 0 ? <Card><EmptyState title={t('cases.noNotes')} /></Card> : [...c.notes].reverse().map((n) => (
        <Card key={n.id}>
          <div className="row" style={{ marginBottom: 8 }}>
            <span className="small dim">{formatDateTime(locale, n.createdAt)}</span>
            <span className="spacer" />
            <button className="btn sm ghost" onClick={() => setEditing({ id: n.id, text: n.text })}>{t('cases.edit')}</button>
            <button className="icon-btn" aria-label={t('common.remove')} onClick={async () => { const r = await window.blazma.cases.removeNote(c.id, n.id); if (r.ok) onChange(r.data); }}><Trash2 size={14} /></button>
          </div>
          {editing?.id === n.id ? (
            <div className="col">
              <textarea className="textarea" dir="auto" value={editing.text} onChange={(e) => setEditing({ ...editing, text: e.target.value })} />
              <div><button className="btn primary sm" onClick={async () => { const r = await window.blazma.cases.updateNote(c.id, n.id, editing.text); if (r.ok) { onChange(r.data); setEditing(null); } }}>{t('cases.save')}</button></div>
            </div>
          ) : <div dir="auto" style={{ whiteSpace: 'pre-wrap' }}>{n.text}</div>}
        </Card>
      ))}
    </div>
  );
}

function TimelineTab({ c, onChange }: { c: InvestigationCase; onChange: (c: InvestigationCase) => void }) {
  const { t, locale } = useI18n();
  const [title, setTitle] = useState('');
  const [time, setTime] = useState('');
  const items = [...c.timeline].sort((a, b) => b.time.localeCompare(a.time));
  const label = (x: string) => (x.startsWith('case.') ? t(`cases.tl.${x.slice(5)}`) : x);
  return (
    <div className="col" style={{ gap: 12 }}>
      <Card title={t('cases.addEvent')} icon={Plus}>
        <div className="row-wrap" style={{ alignItems: 'flex-end' }}>
          <div className="field" style={{ flex: 1, minWidth: 240 }}><label>{t('cases.eventTitle')}</label><input className="input" dir="auto" value={title} onChange={(e) => setTitle(e.target.value)} /></div>
          <div className="field"><label>{t('cases.eventTime')}</label><input className="input" type="datetime-local" dir="ltr" value={time} onChange={(e) => setTime(e.target.value)} /></div>
          <button className="btn primary" disabled={!title.trim()} onClick={async () => {
            const r = await window.blazma.cases.addEvent(c.id, title.trim(), null, time ? new Date(time).toISOString() : null);
            if (r.ok) { onChange(r.data); setTitle(''); setTime(''); }
          }}>{t('cases.add')}</button>
        </div>
      </Card>
      <Card>
        <ol style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 10 }}>
          {items.map((ev) => (
            <li key={ev.id} className="row" style={{ alignItems: 'flex-start', borderInlineStart: '2px solid var(--border-strong)', paddingInlineStart: 12 }}>
              <div style={{ minWidth: 170 }} className="small dim nowrap">{formatDateTime(locale, ev.time)}</div>
              <div>
                <div><Badge tone={ev.kind === 'evidence' ? 'blue' : ev.kind === 'note' ? 'purple' : ev.kind === 'status' ? 'gray' : 'cyan'}>{label(ev.title)}</Badge></div>
                {ev.detail && <div className="small"><Ltr mono breakAll>{ev.detail}</Ltr></div>}
              </div>
            </li>
          ))}
        </ol>
      </Card>
    </div>
  );
}

function ReportTab({ c }: { c: InvestigationCase }) {
  const { t, lang } = useI18n();
  const { toast, navigate } = useApp();
  const [format, setFormat] = useState<ReportFormat>('html');
  const [language, setLanguage] = useState<Lang>(lang);
  const [notes, setNotes] = useState(true);
  const [timeline, setTimeline] = useState(true);
  const [machine, setMachine] = useState(false);
  const [busy, setBusy] = useState(false);
  return (
    <Card title={t('reports.generate')} icon={ScrollText} tone="purple">
      <div className="col" style={{ gap: 12 }}>
        <div className="row-wrap">
          <div className="field"><label>{t('reports.format')}</label>
            <div className="row-wrap">{(['html', 'pdf', 'json'] as const).map((f) => <button key={f} type="button" className="opt" aria-pressed={format === f} onClick={() => setFormat(f)}>{f.toUpperCase()}</button>)}</div>
          </div>
          <div className="field"><label>{t('reports.language')}</label>
            <div className="row-wrap">{(['ar', 'en'] as const).map((l) => <button key={l} type="button" className="opt" aria-pressed={language === l} onClick={() => setLanguage(l)}>{l === 'ar' ? 'العربية' : 'English'}</button>)}</div>
          </div>
        </div>
        <div className="row"><Toggle checked={notes} label={t('reports.includeNotes')} onChange={setNotes} /><span>{t('reports.includeNotes')}</span></div>
        <div className="row"><Toggle checked={timeline} label={t('reports.includeTimeline')} onChange={setTimeline} /><span>{t('reports.includeTimeline')}</span></div>
        <div className="row" style={{ alignItems: 'flex-start' }}><Toggle checked={machine} label={t('reports.includeMachine')} onChange={setMachine} /><div><div>{t('reports.includeMachine')}</div><div className="small dim">{t('reports.machineNote')}</div></div></div>
        <div className="row-wrap">
          <button className="btn primary" disabled={busy} onClick={async () => {
            setBusy(true);
            const r = await window.blazma.reports.generate(c.id, { format, language, includeNotes: notes, includeTimeline: timeline, includeMachineInfo: machine });
            setBusy(false);
            if (r.ok && r.data) { toast('green', t('reports.generated')); void window.blazma.reports.open(r.data.id); }
            else if (!r.ok) toast('red', t(`errors.${r.error}`));
          }}><FileText size={15} /> {t('reports.generate')}</button>
          <button className="btn" onClick={() => navigate('reports')}>{t('reports.title')}</button>
        </div>
      </div>
    </Card>
  );
}

function CaseDetail({ id, onBack }: { id: string; onBack: () => void }) {
  const { t, locale } = useI18n();
  const { confirm, toast } = useApp();
  const [c, setC] = useState<InvestigationCase | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>('evidence');
  useEffect(() => void window.blazma.cases.get(id).then((r) => (r.ok ? setC(r.data) : setErr(r.error))), [id]);
  if (err) return <Card><ErrorState code={err} /></Card>;
  if (!c) return <Card><Skeleton h={160} /></Card>;
  return (
    <div className="col" style={{ gap: 14 }}>
      <div className="row-wrap" style={{ alignItems: 'center' }}>
        <button className="btn sm" onClick={onBack}><ArrowLeft size={14} className="flip-rtl" /> {t('cases.back')}</button>
        <span className="spacer" />
        <button className="btn sm" onClick={async () => { const r = await window.blazma.cases.update(c.id, { status: c.status === 'open' ? 'closed' : 'open' }); if (r.ok) setC(r.data); }}>
          {t(c.status === 'open' ? 'cases.close' : 'cases.reopen')}
        </button>
        <button className="btn danger sm" onClick={async () => {
          if (!(await confirm({ title: t('cases.delete'), body: t('cases.deleteBody', { name: c.name }), confirmLabel: t('cases.delete'), danger: true }))) return;
          const r = await window.blazma.cases.remove(c.id);
          if (r.ok) onBack(); else toast('red', t(`errors.${r.error}`));
        }}><Trash2 size={13} /> {t('cases.delete')}</button>
      </div>
      <div className="card">
        <div className="row" style={{ gap: 12 }}>
          <IconTile icon={FolderOpen} tone="blue" />
          <div style={{ flex: 1 }}>
            <div className="small dim"><Ltr mono>{c.id}</Ltr> · {formatDateTime(locale, c.createdAt)}</div>
            <div className="big-value" style={{ fontSize: 20 }}>{c.name}</div>
            {c.description && <div className="muted small" dir="auto">{c.description}</div>}
          </div>
          <Badge tone={c.status === 'open' ? 'green' : 'gray'}>{t(`cases.status.${c.status}`)}</Badge>
        </div>
      </div>
      <Tabs<Tab> value={tab} onChange={setTab} items={(['evidence', 'notes', 'timeline', 'report'] as const).map((x) => ({ id: x, label: t(`cases.tab.${x}`) }))} />
      {tab === 'evidence' && <EvidenceTab c={c} onChange={setC} />}
      {tab === 'notes' && <NotesTab c={c} onChange={setC} />}
      {tab === 'timeline' && <TimelineTab c={c} onChange={setC} />}
      {tab === 'report' && <ReportTab c={c} />}
    </div>
  );
}

export function Cases() {
  const { t } = useI18n();
  const [open, setOpen] = useState<string | null>(null);
  return (
    <div className="page">
      <div className="page-head">
        <IconTile icon={FolderOpen} tone="blue" />
        <div>
          <h1 className="page-title">{t('cases.title')}</h1>
          <div className="page-sub">{t('cases.subtitle')}</div>
        </div>
      </div>
      {open ? <CaseDetail id={open} onBack={() => setOpen(null)} /> : <CaseList onOpen={setOpen} />}
    </div>
  );
}
