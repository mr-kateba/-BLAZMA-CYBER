import { useEffect, useState } from 'react';
import {
  AlertOctagon, AlertTriangle, Binary, Boxes, CircleCheck, Cpu, CircleHelp, FileSearch, Fingerprint, Globe, Link2, ListTree, RotateCcw, ScanSearch, ShieldAlert,
  ShieldCheck, ShieldHalf, TriangleAlert, X, type LucideIcon,
} from 'lucide-react';
import { REPUTATION_FOR_KIND, type FileAnalysis, type LookupSource, type ReputationResult, type TaskProgress } from '../../shared/api';
import { abusechSignal, assess, vtSignal, type SignalSource, type Verdict } from '../../core/detection';
import { entropyLabel } from '../../core/entropy';
import { Badge, Card, CopyButton, Explain, DataTable, ErrorState, FileDrop, IconTile, Ltr, Notice, Progress, type Tone } from '../components/ui';
import { useI18n } from '../i18n/I18nProvider';
import { useApp } from '../components/AppContext';
import { hasRepKey, ReputationCard, useKeyStatus } from '../components/intel';
import { AddToCase } from '../components/AddToCase';
import { formatBytes, formatDateTime, formatDuration, newTaskId } from '../format';

const VERDICT: Record<Verdict, { tone: Tone; icon: LucideIcon }> = {
  no_detections: { tone: 'green', icon: CircleCheck },
  unknown: { tone: 'gray', icon: CircleHelp },
  suspicious: { tone: 'amber', icon: TriangleAlert },
  malicious: { tone: 'red', icon: AlertOctagon },
};

type State =
  | { kind: 'idle' }
  | { kind: 'running'; path: string; taskId: string; progress: TaskProgress | null }
  | { kind: 'done'; result: FileAnalysis }
  | { kind: 'error'; code: string; path: string };

export function HashRows({ hashes, highlight }: { hashes: Record<string, string>; highlight?: string | null }) {
  const labels: Record<string, string> = { md5: 'MD5', sha1: 'SHA-1', sha256: 'SHA-256', sha512: 'SHA-512' };
  return (
    <div>
      {Object.entries(hashes).filter(([k]) => k in labels).map(([k, v]) => (
        <div key={k} className={`hash-row ${highlight === k ? 'match' : ''}`}>
          <span className="algo">{labels[k]}</span>
          <Ltr mono breakAll>{v}</Ltr>
          <CopyButton value={v} />
        </div>
      ))}
    </div>
  );
}

export function AnalysisResult({ r, onReset, inQuarantine = false }: { r: FileAnalysis; onReset: () => void; inQuarantine?: boolean }) {
  const { t, locale } = useI18n();
  const { confirm, toast, settings } = useApp();
  const keys = useKeyStatus();
  const [quarantined, setQuarantined] = useState(false);
  const [assessment, setAssessment] = useState(r.assessment);
  const [rep, setRep] = useState<{ loading?: boolean; results?: ReputationResult[]; failed?: LookupSource[]; error?: string }>({});
  const hashServices = REPUTATION_FOR_KIND.hash.filter((s) => hasRepKey(keys, s));
  const checkHash = async () => {
    setRep({ loading: true });
    const x = await window.blazma.intel.reputation('hash', r.hashes.sha256, hashServices);
    if (!x.ok) return setRep({ error: x.error });
    const failed = x.data.sources.filter((s) => !s.ok);
    if (x.data.results.length === 0) return setRep({ error: failed[0]?.error ?? 'unknown' });
    setRep({ results: x.data.results, failed });
    const available = new Set<SignalSource>(['entropy', 'static', 'hash_reputation']);
    if (r.defender.ran) available.add('defender');
    if (r.yara.ran) available.add('yara');
    if (r.signature.checked) available.add('signature');
    const repSignals = x.data.results.map((res) => (res.service === 'virustotal' ? vtSignal(res) : abusechSignal(res)));
    setAssessment(assess([...r.assessment.signals.filter((s) => s.source !== 'hash_reputation'), ...repSignals], { availableSources: available }));
    toast('blue', t('file.reassessed'));
  };
  const moveToQuarantine = async () => {
    if (!(await confirm({ title: t('file.quarantineTitle'), body: t('file.quarantineBody', { name: r.name }), confirmLabel: t('file.quarantineThis'), danger: true }))) return;
    const q = await window.blazma.quarantine.add(r.path, `verdict:${assessment.verdict}`);
    if (q.ok) {
      setQuarantined(true);
      toast('green', t('file.quarantined'));
    } else toast('red', t(`errors.${q.error}`));
  };
  const v = VERDICT[assessment.verdict];
  const VIcon = v.icon;
  const sig = r.signature;
  const sigTone: Tone = !sig.checked ? 'gray' : sig.status === 'valid' ? 'green' : sig.status === 'not_signed' ? 'amber' : 'red';
  const iocCount = r.iocs.urls.length + r.iocs.domains.length + r.iocs.ipv4.length + r.iocs.emails.length;
  const funcs = r.pe?.imports.reduce((n, i) => n + i.functions.length, 0) ?? 0;

  return (
    <div className="col" style={{ gap: 16 }}>
      <div className="verdict" style={{ '--tone': `var(--${v.tone === 'gray' ? 'text-3' : v.tone === 'amber' ? 'amber' : v.tone})` } as React.CSSProperties}>
        <IconTile icon={VIcon} tone={v.tone} />
        <div style={{ flex: 1 }}>
          <div className="small dim">{t('file.assessment')}</div>
          <div className="v-title">{t(`verdict.${assessment.verdict}`)}</div>
          <div className="muted small">{t(`verdict.desc.${assessment.verdict}`)}</div>
          <div className="verdict-advice"><strong>{t('verdict.adviceTitle')}</strong> {t(`verdict.advice.${assessment.verdict}`)}</div>
        </div>
        <div className="row-wrap" style={{ justifyContent: 'flex-end' }}>
          <AddToCase
            small={false}
            items={[{ kind: 'file', value: r.path, label: r.name, source: 'fileAnalyzer', details: { sha256: r.hashes.sha256, md5: r.hashes.md5, verdict: assessment.verdict, type: r.type.id, size: r.sizeBytes } }]}
          />
          {inQuarantine ? (
            <Badge tone="cyan" icon={ShieldCheck}>{t('file.inQuarantine')}</Badge>
          ) : quarantined ? (
            <Badge tone="green" icon={ShieldCheck}>{t('file.quarantined')}</Badge>
          ) : (
            <button className="btn danger" onClick={() => void moveToQuarantine()}>
              <ShieldCheck size={15} /> {t('file.quarantineThis')}
            </button>
          )}
          <button className="btn" onClick={onReset}>
            <RotateCcw size={15} /> {t(inQuarantine ? 'common.close' : 'file.analyzeAnother')}
          </button>
        </div>
      </div>

      <Card title={t('file.engines')} explain="engines" icon={ScanSearch} tone="blue">
        <div className="grid g-2">
          <div className="row" style={{ alignItems: 'flex-start', gap: 12 }}>
            <IconTile icon={ShieldHalf} tone={!r.defender.ran ? 'gray' : r.defender.threats.length ? 'red' : 'green'} small />
            <div style={{ minWidth: 0 }}>
              <div style={{ fontWeight: 600 }}>{t('file.engine.defender')}</div>
              {!r.defender.ran ? (
                <div className="small dim">{t('file.notRun')} · {t(`errors.${r.defender.reason}`)}</div>
              ) : r.defender.threats.length === 0 ? (
                <Badge tone="green">{t('file.defenderClean')}</Badge>
              ) : (
                <div className="col" style={{ gap: 4, alignItems: 'flex-start' }}>
                  {r.defender.threats.map((x) => <Badge key={x} tone="red">{t('file.defenderThreat')}: {x}</Badge>)}
                </div>
              )}
            </div>
          </div>
          <div className="row" style={{ alignItems: 'flex-start', gap: 12 }}>
            <IconTile icon={ScanSearch} tone={!r.yara.ran ? 'gray' : r.yara.matches.length ? 'amber' : 'green'} small />
            <div style={{ minWidth: 0 }}>
              <div style={{ fontWeight: 600 }}>{t('file.engine.yara')}</div>
              {!r.yara.ran ? (
                <div className="small dim">{t('file.notRun')} · {t(`errors.${r.yara.reason}`)}</div>
              ) : r.yara.matches.length === 0 ? (
                <Badge tone="green">{t('file.yaraNone', { rules: r.yara.rulesUsed })}</Badge>
              ) : (
                <div className="col" style={{ gap: 4, alignItems: 'flex-start' }}>
                  <Badge tone="amber">{t('file.yaraMatched', { count: r.yara.matches.length })}</Badge>
                  {r.yara.matches.map((m, i) => (
                    <div key={i} className="small"><Ltr mono>{m.rule}</Ltr>{m.meta.description ? <span className="dim"> — {String(m.meta.description)}</span> : null}</div>
                  ))}
                </div>
              )}
            </div>
          </div>
          <div className="row" style={{ alignItems: 'flex-start', gap: 12 }}>
            <IconTile icon={Cpu} tone={!r.capa.ran ? 'gray' : r.capa.risky.length ? 'amber' : 'green'} small />
            <div style={{ minWidth: 0 }}>
              <div style={{ fontWeight: 600 }}>{t('file.engine.capa')}</div>
              {!r.capa.ran ? (
                <div className="small dim">{t('file.notRun')} · {t(`errors.${r.capa.reason === 'engine_not_applicable' ? 'engine_unsupported_file' : r.capa.reason}`)}</div>
              ) : (
                <Badge tone={r.capa.risky.length ? 'amber' : 'green'}>{t('file.capa.found', { count: r.capa.capabilities.length })}</Badge>
              )}
            </div>
          </div>
          <div className="row" style={{ alignItems: 'flex-start', gap: 12 }}>
            <IconTile icon={Boxes} tone={!r.die.ran ? 'gray' : r.die.packers.length ? 'amber' : 'green'} small />
            <div style={{ minWidth: 0 }}>
              <div style={{ fontWeight: 600 }}>{t('file.engine.die')}</div>
              {!r.die.ran ? (
                <div className="small dim">{t('file.notRun')} · {t(`errors.${r.die.reason}`)}</div>
              ) : r.die.detections.length === 0 ? (
                <Badge tone="gray">{t('file.die.none')}</Badge>
              ) : (
                <div className="chip-list">{r.die.detections.slice(0, 6).map((d) => <span key={d.type + d.name} className="chip"><Ltr>{`${d.name}${d.version ? ` ${d.version}` : ''}`}</Ltr></span>)}</div>
              )}
            </div>
          </div>
        </div>
      </Card>

      {r.capa.ran && r.capa.capabilities.length > 0 && <CapaCard capa={r.capa} />}

      {rep.results ? (
        <>
          <div className="grid g-3">{rep.results.map((x) => <ReputationCard key={x.service} r={x} />)}</div>
          {rep.failed && rep.failed.length > 0 && (
            <Notice tone="amber">
              {rep.failed.map((f) => <div key={f.id}>{t(`intel.src.${f.id}`)}: {t(`errors.${f.error ?? 'unknown'}`)}</div>)}
            </Notice>
          )}
        </>
      ) : (
        <Card title={t('file.hashRep')} explain="reputation" icon={Globe} tone="purple">
          <div className="row-wrap" style={{ alignItems: 'center' }}>
            <button className="btn" disabled={hashServices.length === 0 || settings.offlineMode || rep.loading} onClick={() => void checkHash()}>
              <Globe size={15} /> {t('file.hashRepCheck')}
            </button>
            <span className="small dim">
              {settings.offlineMode ? t('file.hashRepOffline') : keys && hashServices.length === 0 ? t('file.hashRepNeedsKey') : t('file.hashRepNote', { services: hashServices.map((s) => t(`intel.src.reputation:${s}`)).join(' · ') })}
            </span>
          </div>
          {rep.loading && <div style={{ marginTop: 10 }}><Progress indeterminate /></div>}
          {rep.error && <div style={{ marginTop: 10 }}><Notice tone="amber">{t(`errors.${rep.error}`)}</Notice></div>}
        </Card>
      )}

      <div className="grid g-2">
        <Card title={t('file.reasons')} explain="verdict" icon={ShieldAlert} tone={v.tone}>
          {assessment.reasons.length === 0 ? (
            <div className="muted small">{t('file.noReasons')}</div>
          ) : (
            <ul style={{ margin: 0, paddingInlineStart: 18, display: 'grid', gap: 6 }}>
              {assessment.reasons.map((x, i) => <li key={i}>{t(x.key, x.args)}</li>)}
            </ul>
          )}
          {assessment.incomplete && <div style={{ marginTop: 12 }}><Notice tone="amber" icon={TriangleAlert}>{t('file.incompleteNote')}</Notice></div>}
          <div className="small dim" style={{ marginTop: 12 }}>{t('file.enginesMissing')}:</div>
          <div className="col" style={{ gap: 4, marginTop: 6 }}>
            {r.unavailableEngines.filter((e) => !(e.engine === 'hash_reputation' && rep.results)).map((e) => (
              <div key={e.engine} className="row small">
                <Badge tone="gray">{t(`file.engine.${e.engine}`)}</Badge>
                <span className="dim">{t(`errors.${e.reason}`)}</span>
              </div>
            ))}
          </div>
          <div className="tiny dim" style={{ marginTop: 12 }}>{t('file.falsePositives')}</div>
        </Card>

        <Card title={t('file.overview')} explain="filetype" icon={FileSearch} tone="blue">
          <dl className="kv">
            <dt>{t('file.name')}</dt><dd><Ltr breakAll>{r.name}</Ltr></dd>
            <dt>{t('file.path')}</dt><dd><Ltr mono breakAll className="small">{r.path}</Ltr></dd>
            <dt>{t('file.size')}</dt><dd>{formatBytes(t, r.sizeBytes)} <span className="dim small">(<Ltr>{r.sizeBytes.toLocaleString('en')}</Ltr>)</span></dd>
            <dt>{t('file.type')}</dt><dd><Ltr>{r.type.description}</Ltr></dd>
            <dt>{t('file.mime')}</dt><dd><Ltr mono className="small">{r.type.mime}</Ltr></dd>
            <dt>{t('file.created')}</dt><dd>{formatDateTime(locale, r.created)}</dd>
            <dt>{t('file.modified')}</dt><dd>{formatDateTime(locale, r.modified)}</dd>
            <dt>{t('file.entropy')}<Explain term="entropy" /></dt>
            <dd>
              <Ltr>{r.entropy.toFixed(3)}</Ltr> / 8 · <Badge tone={entropyLabel(r.entropy) === 'high' ? 'amber' : 'gray'}>{t(`file.entropyLevel.${entropyLabel(r.entropy)}`)}</Badge>
            </dd>
            {r.die.ran && r.die.detections.length > 0 && (
              <>
                <dt>{t('file.die.builtWith')}<Explain term="die" /></dt>
                <dd className="col" style={{ gap: 2 }}>
                  {r.die.detections.map((d) => (
                    <span key={d.type + d.name} className="small">
                      <span className="dim">{t(`die.type.${d.type.toLowerCase()}`) === `die.type.${d.type.toLowerCase()}` ? d.type : t(`die.type.${d.type.toLowerCase()}`)}: </span>
                      <Ltr>{`${d.name}${d.version ? ` ${d.version}` : ''}${d.info ? ` (${d.info})` : ''}`}</Ltr>
                    </span>
                  ))}
                </dd>
              </>
            )}
            <dt>{t('file.duration')}</dt><dd>{formatDuration(t, r.durationMs)}</dd>
          </dl>
        </Card>
      </div>

      {r.encryption && (
        <Notice tone="amber" icon={ShieldAlert}>
          {t('file.encryptedNotice', { scheme: r.encryption.scheme ?? r.encryption.format })}
        </Notice>
      )}

      <div className="grid g-2">
        <Card title={t('file.hashes')} explain="hash" icon={Fingerprint} tone="cyan">
          <HashRows hashes={r.hashes as unknown as Record<string, string>} />
        </Card>
        <Card title={t('file.signature')} explain="signature" icon={ShieldAlert} tone={sigTone}>
          {!sig.checked ? (
            <div className="col" style={{ alignItems: 'flex-start' }}>
              <Badge tone="gray">{t('file.sig.notChecked')}</Badge>
              <span className="small muted">{t(`errors.${sig.reason ?? 'unknown'}`)}</span>
            </div>
          ) : (
            <dl className="kv">
              <dt>{t('file.signature')}</dt>
              <dd><Badge tone={sigTone}>{t(`file.sig.${sig.status}`, { raw: sig.rawStatus ?? '' })}</Badge></dd>
              {sig.publisher && (<><dt>{t('file.sig.publisher')}</dt><dd><Ltr>{sig.publisher}</Ltr></dd></>)}
              {sig.issuer && (<><dt>{t('file.sig.issuer')}</dt><dd><Ltr>{sig.issuer}</Ltr></dd></>)}
              {sig.validTo && (<><dt>{t('file.sig.validity')}</dt><dd>{formatDateTime(locale, sig.validFrom)} → {formatDateTime(locale, sig.validTo)}</dd></>)}
              {sig.thumbprint && (<><dt>{t('file.sig.thumbprint')}</dt><dd><Ltr mono breakAll className="small">{sig.thumbprint}</Ltr></dd></>)}
            </dl>
          )}
        </Card>
      </div>

      {(r.pe || r.peError) && (
        <Card title={t('file.pe.title')} explain="pe" icon={Binary} tone="purple">
          {r.peError ? (
            <Notice tone="amber">{t('file.pe.parseError', { reason: r.peError })}</Notice>
          ) : r.pe && (
            <div className="col" style={{ gap: 16 }}>
              <dl className="kv" style={{ gridTemplateColumns: 'repeat(4, max-content 1fr)' }}>
                <dt>{t('file.pe.machine')}</dt><dd><Ltr>{r.pe.machine}</Ltr></dd>
                <dt>{t('file.pe.kind')}</dt><dd>{t(r.pe.isDll ? 'file.pe.dll' : 'file.pe.exe')}</dd>
                <dt>{t('file.pe.subsystem')}</dt><dd><Ltr mono className="small">{r.pe.subsystem}</Ltr></dd>
                <dt>{t('file.pe.entry')}</dt><dd><Ltr mono>0x{r.pe.entryPoint.toString(16)}</Ltr></dd>
                <dt>{t('file.pe.timestamp')}</dt>
                <dd title={t('file.pe.timestampNote')}>{formatDateTime(locale, new Date(r.pe.timestamp * 1000).toISOString())} <span className="tiny dim">({t('file.pe.timestampNote')})</span></dd>
              </dl>
              {r.pe.packerHints.length > 0 && <Notice tone="amber">{t('file.pe.packer')}: <Ltr mono>{r.pe.packerHints.join(', ')}</Ltr></Notice>}
              <div>
                <h4 className="small" style={{ marginBottom: 8 }}>{t('file.pe.sections')} ({r.pe.sections.length})</h4>
                <DataTable
                  rowKey={(s, i) => `${s.name}-${i}`}
                  rows={r.pe.sections}
                  columns={[
                    { key: 'n', label: t('file.pe.sectionName'), render: (s) => <Ltr mono>{s.name || '—'}</Ltr> },
                    { key: 'v', label: t('file.pe.virtualSize'), render: (s) => formatBytes(t, s.virtualSize) },
                    { key: 'r', label: t('file.pe.rawSize'), render: (s) => formatBytes(t, s.rawSize) },
                    {
                      key: 'e', label: t('file.pe.entropy'),
                      render: (s) => <span className="row"><Ltr mono>{s.entropy.toFixed(2)}</Ltr>{entropyLabel(s.entropy) === 'high' && <Badge tone="amber">{t('file.entropyLevel.high')}</Badge>}</span>,
                    },
                    { key: 'f', label: t('file.pe.flags'), render: (s) => <Ltr mono className="small">{`${s.executable ? 'X' : '-'}${s.writable ? 'W' : '-'}`}</Ltr> },
                  ]}
                />
              </div>
              <div className="grid g-2">
                <div>
                  <h4 className="small" style={{ marginBottom: 8 }}>
                    {t('file.pe.imports')} · <span className="dim">{t('file.pe.importsCount', { dlls: r.pe.imports.length, funcs })}</span>
                  </h4>
                  {r.pe.imports.length === 0 ? <div className="small dim">{t('file.pe.noImports')}</div> : (
                    <div className="table-wrap" style={{ maxHeight: 260, padding: 10 }}>
                      {r.pe.imports.map((imp) => (
                        <details key={imp.dll} style={{ marginBottom: 4 }}>
                          <summary style={{ cursor: 'pointer' }}><Ltr mono>{imp.dll}</Ltr> <span className="dim small">({imp.functions.length})</span></summary>
                          <div className="chip-list" style={{ margin: '6px 0 8px', paddingInlineStart: 14 }}>
                            {imp.functions.map((f, i) => <span key={i} className="chip"><Ltr mono>{f}</Ltr></span>)}
                          </div>
                        </details>
                      ))}
                    </div>
                  )}
                </div>
                <div>
                  <h4 className="small" style={{ marginBottom: 8 }}>{t('file.pe.exports')} ({r.pe.exports.length})</h4>
                  {r.pe.exports.length === 0 ? <div className="small dim">{t('file.pe.noExports')}</div> : (
                    <div className="table-wrap chip-list" style={{ maxHeight: 260, padding: 10 }}>
                      {r.pe.exports.slice(0, 500).map((e, i) => <span key={i} className="chip"><Ltr mono>{e}</Ltr></span>)}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </Card>
      )}

      <div className="grid g-2">
        <Card title={`${t('file.iocs')} (${iocCount})`} explain="iocs" icon={Link2} tone="amber">
          {iocCount === 0 ? <div className="small muted">{t('file.noIocs')}</div> : (
            <div className="col" style={{ gap: 12 }}>
              {([['urls', r.iocs.urls], ['domains', r.iocs.domains], ['ips', r.iocs.ipv4], ['emails', r.iocs.emails]] as const).map(([k, list]) =>
                list.length > 0 && (
                  <div key={k}>
                    <div className="small dim" style={{ marginBottom: 5 }}>{t(`file.${k}`)} ({list.length})</div>
                    <div className="table-wrap" style={{ maxHeight: 160, padding: 8 }}>
                      {list.slice(0, 200).map((x) => <div key={x} className="small"><Ltr mono breakAll>{x}</Ltr></div>)}
                    </div>
                  </div>
                ),
              )}
            </div>
          )}
        </Card>
        <Card title={`${t('file.strings')} (${r.interestingStrings.length})`} explain="strings" icon={ListTree} tone="purple" subtitle={t('file.stringsNote', { size: formatBytes(t, r.stringsScannedBytes) })}>
          {r.interestingStrings.length === 0 ? <div className="small muted">{t('file.noStrings')}</div> : (
            <div className="table-wrap" style={{ maxHeight: 300, padding: 8 }}>
              {r.interestingStrings.map((s, i) => <div key={i} className="small" style={{ padding: '3px 0' }}><Ltr mono breakAll>{s}</Ltr></div>)}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}

export function FileAnalyzer() {
  const { t } = useI18n();
  const { takePendingFile } = useApp();
  const [state, setState] = useState<State>({ kind: 'idle' });

  useEffect(
    () =>
      window.blazma.files.onProgress((p) =>
        setState((s) => (s.kind === 'running' && s.taskId === p.taskId ? { ...s, progress: p } : s)),
      ),
    [],
  );

  const start = async (path: string) => {
    const taskId = newTaskId();
    setState({ kind: 'running', path, taskId, progress: null });
    const r = await window.blazma.files.analyze(path, taskId);
    setState((s) => {
      if (s.kind !== 'running' || s.taskId !== taskId) return s;
      return r.ok ? { kind: 'done', result: r.data } : r.error === 'cancelled' ? { kind: 'idle' } : { kind: 'error', code: r.error, path };
    });
  };

  useEffect(() => {
    const p = takePendingFile();
    if (p) void start(p);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const pct = state.kind === 'running' && state.progress && state.progress.totalBytes > 0
    ? (state.progress.processedBytes / state.progress.totalBytes) * 100 : 0;

  return (
    <div className="page">
      <div className="page-head">
        <IconTile icon={FileSearch} tone="purple" />
        <div>
          <h1 className="page-title">{t('file.title')}</h1>
          <div className="page-sub">{t('file.subtitle')}</div>
        </div>
      </div>

      {state.kind === 'idle' && (
        <FileDrop onFile={start} title={t('file.dropTitle')} hint={t('file.dropHint')} activeText={t('file.dropActive')} browseLabel={t('common.browse')} />
      )}

      {state.kind === 'running' && (
        <Card>
          <div className="row" style={{ marginBottom: 14 }}>
            <IconTile icon={FileSearch} tone="cyan" small />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontWeight: 600 }}>{t('file.analyzing')}</div>
              <div className="small dim" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}><Ltr mono>{state.path}</Ltr></div>
            </div>
            <button className="btn danger sm" onClick={() => void window.blazma.files.cancel(state.taskId)}>
              <X size={14} /> {t('common.cancel')}
            </button>
          </div>
          <Progress value={pct} indeterminate={!state.progress || state.progress.stage === 'analyzing' || state.progress.stage === 'scanning'} />
          <div className="row small muted" style={{ marginTop: 8 }}>
            <span>{t(state.progress?.stage === 'scanning' ? 'file.scanning' : state.progress?.stage === 'analyzing' ? 'file.processing' : 'file.hashing')}</span>
            <span className="spacer" />
            {state.progress && <span>{formatBytes(t, state.progress.processedBytes)} / {formatBytes(t, state.progress.totalBytes)} · <Ltr>{Math.round(pct)}%</Ltr></span>}
          </div>
        </Card>
      )}

      {state.kind === 'error' && (
        <Card>
          <ErrorState code={state.code} onRetry={() => setState({ kind: 'idle' })} />
          <div className="small dim" style={{ textAlign: 'center' }}><Ltr mono>{state.path}</Ltr></div>
        </Card>
      )}

      {state.kind === 'done' && <AnalysisResult r={state.result} onReset={() => setState({ kind: 'idle' })} />}
    </div>
  );
}

/** "What can this program do?" — capa capabilities grouped by area, with MITRE ATT&CK techniques. */
function CapaCard({ capa }: { capa: Extract<FileAnalysis['capa'], { ran: true }> }) {
  const { t } = useI18n();
  const groups = new Map<string, typeof capa.capabilities>();
  for (const c of capa.capabilities) groups.set(c.group, [...(groups.get(c.group) ?? []), c]);
  return (
    <Card title={t('file.capa.title')} explain="capa" icon={Cpu} tone={capa.risky.length ? 'amber' : 'blue'} subtitle={t('file.capa.sub')}>
      <div className="col" style={{ gap: 14 }}>
        {capa.risky.length > 0 && (
          <Notice tone="amber" icon={AlertTriangle}>
            <div>{t('file.capa.riskyTitle')}</div>
            <div className="chip-list" style={{ marginTop: 6 }}>{capa.risky.map((k) => <span key={k} className="chip">{t(`capa.risk.${k}`)}</span>)}</div>
          </Notice>
        )}
        {[...groups.entries()].map(([g, list]) => (
          <div key={g}>
            <div className="small" style={{ fontWeight: 600, marginBottom: 6 }}>{t(`capa.group.${g}`, {}) === `capa.group.${g}` ? g : t(`capa.group.${g}`)} <span className="dim">({list.length})</span></div>
            <div className="col" style={{ gap: 4 }}>
              {list.map((c) => (
                <div key={c.name} className="row-wrap small" style={{ gap: 6 }}>
                  <Ltr>{c.name}</Ltr>
                  {c.attack.map((a) => <span key={a.id} className="chip" title={`${a.tactic} — ${a.technique}`}><Ltr mono>{a.id}</Ltr></span>)}
                </div>
              ))}
            </div>
          </div>
        ))}
        {capa.attack.length > 0 && (
          <div className="tiny dim">{t('file.capa.attackNote', { count: capa.attack.length })}</div>
        )}
      </div>
    </Card>
  );
}
