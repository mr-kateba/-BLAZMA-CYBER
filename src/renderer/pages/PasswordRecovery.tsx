import { useEffect, useRef, useState } from 'react';
import { Cpu, ExternalLink, FileLock2, Gauge, KeyRound, Lock, Pause, Play, RotateCcw, ShieldAlert, ShieldCheck, Square } from 'lucide-react';
import type { EncryptionInfo } from '../../core/encrypted';
import type { RecoveryEngineInfo, RecoveryEngineKind, RecoveryEventMsg, RecoveryMode, RecoveryPerformance, RecoveryProgress } from '../../shared/api';
import { Badge, Card, CopyButton, ErrorState, FileDrop, IconTile, Ltr, Notice, Progress, type Tone } from '../components/ui';
import { useApp } from '../components/AppContext';
import { useI18n } from '../i18n/I18nProvider';
import { formatBytes, formatDuration } from '../format';

type Detected = { encryption: EncryptionInfo; name: string; sizeBytes: number; path: string };
type ModeType = RecoveryMode['type'];

/** Official download pages (opened in the browser; Blazma never downloads engines itself). */
const ENGINE_SITES: Record<RecoveryEngineKind, string> = { john: 'https://www.openwall.com/john/', hashcat: 'https://hashcat.net/hashcat/' };

const STRENGTH_TONE: Record<string, Tone> = { strong: 'green', weak: 'amber', unknown: 'gray' };

function EnginePicker({ engines, onChange }: { engines: Record<RecoveryEngineKind, RecoveryEngineInfo | null>; onChange: () => void }) {
  const { t } = useI18n();
  const { toast } = useApp();
  const pick = async (kind: RecoveryEngineKind) => {
    const r = await window.blazma.recovery.pickEngine(kind);
    if (r.ok && r.data) toast('green', t('recovery.engineSaved'));
    else if (!r.ok) toast('red', t(`errors.${r.error}`));
    onChange();
  };
  return (
    <Card title={t('recovery.engine')} icon={Cpu} tone={engines.john?.available || engines.hashcat?.available ? 'green' : 'amber'}>
      <div className="col" style={{ gap: 10 }}>
        {(['john', 'hashcat'] as const).map((k) => {
          const e = engines[k];
          const name = k === 'john' ? 'John the Ripper' : 'hashcat';
          return (
            <div key={k} className="row-wrap" style={{ alignItems: 'center', justifyContent: 'space-between' }}>
              <div className="row">
                {e?.available ? <Badge tone="green" icon={ShieldCheck}>{t('recovery.engineReady', { engine: name, version: e.version ?? '' })}</Badge> : <Badge tone="gray">{name}</Badge>}
                {e?.available && <span className="tiny dim"><Ltr mono breakAll>{e.path}</Ltr></span>}
              </div>
              <div className="row">
                {!e?.available && <button className="btn sm ghost" onClick={() => void window.blazma.app.openLink(ENGINE_SITES[k])}><ExternalLink size={12} /> {t('recovery.officialSite')}</button>}
                <button className="btn sm" onClick={() => void pick(k)}>{t(k === 'john' ? 'recovery.chooseJohn' : 'recovery.chooseHashcat')}</button>
                {e?.available && <button className="btn sm ghost" onClick={async () => { await window.blazma.recovery.clearEngine(k); onChange(); }}>{t('common.remove')}</button>}
              </div>
            </div>
          );
        })}
        <div className="small muted">{t('recovery.engineHelp')}</div>
        {!engines.john?.available && !engines.hashcat?.available && (
          <ol className="small muted" style={{ margin: 0, paddingInlineStart: 20 }}>
            <li>{t('recovery.setup1')}</li>
            <li>{t('recovery.setup2')}</li>
            <li>{t('recovery.setup3')}</li>
          </ol>
        )}
      </div>
    </Card>
  );
}

function RunningView({ progress, paused, onPause, onStop }: { progress: RecoveryProgress; paused: boolean; onPause: (p: boolean) => void; onStop: () => void }) {
  const { t } = useI18n();
  const pct = progress.total ? (progress.tried / progress.total) * 100 : undefined;
  return (
    <Card title={t('recovery.running')} icon={KeyRound} tone="blue">
      <Progress value={pct} indeterminate={pct === undefined} />
      <div className="row-wrap" style={{ marginTop: 12, gap: 14 }}>
        {progress.rate !== null && <Badge tone="blue">{t('recovery.rate', { rate: progress.rate.toLocaleString('en') })}</Badge>}
        <Badge tone="gray">{progress.total ? t('recovery.progressOf', { tried: progress.tried.toLocaleString('en'), total: progress.total.toLocaleString('en') }) : t('recovery.tried', { tried: progress.tried.toLocaleString('en') })}</Badge>
        <Badge tone="gray">{t('recovery.elapsed')}: {formatDuration(t, progress.elapsedMs)}</Badge>
        {paused && <Badge tone="amber">{t('recovery.paused')}</Badge>}
        <span className="spacer" />
        <button className="btn sm" onClick={() => onPause(!paused)}>{paused ? <><Play size={13} /> {t('recovery.resume')}</> : <><Pause size={13} /> {t('recovery.pause')}</>}</button>
        <button className="btn danger sm" onClick={onStop}><Square size={13} /> {t('recovery.stop')}</button>
      </div>
    </Card>
  );
}

export function PasswordRecovery() {
  const { t } = useI18n();
  const { toast } = useApp();
  const [engines, setEngines] = useState<Record<RecoveryEngineKind, RecoveryEngineInfo | null>>({ john: null, hashcat: null });
  const [file, setFile] = useState<Detected | null>(null);
  const [mode, setMode] = useState<ModeType>('wordlist');
  const [wordlist, setWordlist] = useState<string | null>(null);
  const [mask, setMask] = useState('?u?l?l?l?l?d?d');
  const [intensity, setIntensity] = useState<RecoveryPerformance['intensity']>('balanced');
  const [device, setDevice] = useState<RecoveryPerformance['device']>('auto');
  const [authorized, setAuthorized] = useState(false);
  const [session, setSession] = useState<{ id: string; progress: RecoveryProgress; paused: boolean } | null>(null);
  const [result, setResult] = useState<{ found: boolean; password: string | null } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const sessionRef = useRef<string | null>(null);

  const loadEngines = () => {
    void window.blazma.recovery.engine('john').then((john) => setEngines((e) => ({ ...e, john })));
    void window.blazma.recovery.engine('hashcat').then((hashcat) => setEngines((e) => ({ ...e, hashcat })));
  };
  useEffect(loadEngines, []);

  useEffect(
    () =>
      window.blazma.recovery.onEvent((ev: RecoveryEventMsg) => {
        if (ev.id !== sessionRef.current) return;
        if (ev.type === 'progress') setSession((s) => (s ? { ...s, progress: ev.progress } : s));
        else if (ev.type === 'done') { setResult({ found: ev.found, password: ev.password }); setSession(null); sessionRef.current = null; }
        else if (ev.type === 'error') { setError(ev.error); setSession(null); sessionRef.current = null; }
        else if (ev.type === 'stopped') { setSession(null); sessionRef.current = null; }
      }),
    [],
  );

  const detect = async (path: string) => {
    setResult(null);
    setError(null);
    const r = await window.blazma.recovery.detect(path);
    if (r.ok) setFile({ ...r.data, path });
    else toast('red', t(`errors.${r.error}`));
  };

  const engineForFile = engines.john?.available ? 'john' : engines.hashcat?.available ? 'hashcat' : null;
  const canStart = !!file && (file.encryption.encrypted || !!file.encryption.undetermined) && !!engineForFile && authorized && (mode === 'mask' ? mask.trim().length > 0 : mode === 'wordlist' ? !!wordlist : true);

  const start = async () => {
    if (!file || !engineForFile) return;
    const m: RecoveryMode = mode === 'mask' ? { type: 'mask', mask: mask.trim() } : { type: mode, path: wordlist! };
    const perf: RecoveryPerformance = { intensity, device: engineForFile === 'hashcat' ? device : 'auto' };
    setResult(null);
    setError(null);
    const r = await window.blazma.recovery.start(engineForFile, file.path, m, perf, authorized);
    if (r.ok) {
      sessionRef.current = r.data.id;
      setSession({ id: r.data.id, progress: { id: r.data.id, tried: 0, total: null, rate: null, recovered: false, elapsedMs: 0 }, paused: false });
    } else setError(r.error);
  };

  const reset = () => { setFile(null); setResult(null); setError(null); setAuthorized(false); };

  return (
    <div className="page">
      <div className="page-head">
        <IconTile icon={KeyRound} tone="amber" />
        <div>
          <h1 className="page-title">{t('recovery.title')}</h1>
          <div className="page-sub">{t('recovery.subtitle')}</div>
        </div>
      </div>

      <div className="col" style={{ gap: 16 }}>
        <Notice tone="amber" icon={ShieldAlert}>{t('recovery.authorizedOnly')}</Notice>
        <Notice tone="cyan" icon={Lock}>{t('recovery.byoEngine')}</Notice>

        <EnginePicker engines={engines} onChange={loadEngines} />

        {!file ? (
          <FileDrop onFile={detect} title={t('recovery.dropTitle')} hint={t('recovery.dropHint')} activeText={t('file.dropActive')} browseLabel={t('common.browse')} />
        ) : (
          <Card
            title={<Ltr breakAll>{file.name}</Ltr>}
            subtitle={formatBytes(t, file.sizeBytes)}
            icon={FileLock2}
            tone={file.encryption.encrypted ? 'blue' : file.encryption.undetermined ? 'amber' : 'gray'}
            actions={<button className="btn sm" onClick={reset}>{t('recovery.newSession')}</button>}
          >
            <dl className="kv">
              <dt>{t('recovery.format')}</dt><dd><Ltr>{file.encryption.format.toUpperCase()}</Ltr></dd>
              <dt>{t('recovery.encryption')}</dt>
              <dd>
                {file.encryption.encrypted ? (
                  <span className="row"><Ltr mono>{file.encryption.scheme}</Ltr><Badge tone={STRENGTH_TONE[file.encryption.strength]}>{t(`recovery.strength.${file.encryption.strength}`)}</Badge></span>
                ) : file.encryption.undetermined ? (
                  <Badge tone="amber">{t('recovery.undetermined')}</Badge>
                ) : (
                  <Badge tone="gray">{t('recovery.notEncrypted')}</Badge>
                )}
              </dd>
            </dl>
            {file.encryption.notes.map((n) => <div key={n} style={{ marginTop: 8 }}><Notice tone="gray">{t(n)}</Notice></div>)}
            {!file.encryption.encrypted && !file.encryption.undetermined && <div style={{ marginTop: 10 }}><Notice tone="gray">{t('recovery.notEncrypted')}</Notice></div>}
          </Card>
        )}

        {file && (file.encryption.encrypted || file.encryption.undetermined) && !session && !result && (
          <>
            {!engineForFile && <Notice tone="amber" icon={Cpu}>{t('errors.engine_not_configured')}</Notice>}
            <Card title={t('recovery.mode')} icon={KeyRound} tone="purple">
              <div className="row-wrap" style={{ marginBottom: 12 }}>
                {(['wordlist', 'mask', 'candidates'] as const).map((m) => (
                  <button key={m} type="button" className="opt" aria-pressed={mode === m} onClick={() => setMode(m)}>{t(`recovery.modeName.${m}`)}</button>
                ))}
              </div>
              <div className="small muted" style={{ marginBottom: 12 }}>{t(`recovery.modeDesc.${mode}`)}</div>
              {(mode === 'wordlist' || mode === 'candidates') && (
                <div className="row-wrap" style={{ alignItems: 'center' }}>
                  <button className="btn" onClick={async () => { const p = await window.blazma.recovery.pickWordlist(); if (p) setWordlist(p); }}>{t('recovery.chooseWordlist')}</button>
                  {wordlist && <Ltr mono breakAll className="small">{wordlist}</Ltr>}
                </div>
              )}
              {mode === 'mask' && (
                <div className="field">
                  <label>{t('recovery.maskLabel')}</label>
                  <input className="input mono" dir="ltr" value={mask} onChange={(e) => setMask(e.target.value)} />
                  <span className="tiny dim">{t('recovery.maskHelp')}</span>
                </div>
              )}
            </Card>
            <Card title={t('recovery.performance')} icon={Gauge} tone="amber">
              <div className="small muted" style={{ marginBottom: 12 }}>{t('recovery.performanceHint')}</div>
              <div className="field">
                <label>{t('recovery.intensity')}</label>
                <div className="row-wrap">
                  {(['balanced', 'max'] as const).map((v) => (
                    <button key={v} type="button" className="opt" aria-pressed={intensity === v} onClick={() => setIntensity(v)}>{t(`recovery.intensityName.${v}`)}</button>
                  ))}
                </div>
                <span className="tiny dim">{t(`recovery.intensityDesc.${intensity}`)}</span>
              </div>
              {engineForFile === 'hashcat' && (
                <div className="field" style={{ marginTop: 12 }}>
                  <label>{t('recovery.device')}</label>
                  <div className="row-wrap">
                    {(['auto', 'gpu', 'cpu'] as const).map((v) => (
                      <button key={v} type="button" className="opt" aria-pressed={device === v} onClick={() => setDevice(v)}>{t(`recovery.deviceName.${v}`)}</button>
                    ))}
                  </div>
                  <span className="tiny dim">{t(`recovery.deviceDesc.${device}`)}</span>
                </div>
              )}
            </Card>
            <Card>
              <label className="row" style={{ alignItems: 'flex-start', cursor: 'pointer' }}>
                <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} style={{ marginTop: 4 }} />
                <span>{t('recovery.authCheck')}</span>
              </label>
              <button className="btn primary" style={{ marginTop: 14 }} disabled={!canStart} onClick={() => void start()}>
                <KeyRound size={15} /> {t('recovery.start')}
              </button>
            </Card>
          </>
        )}

        {session && (
          <RunningView
            progress={session.progress}
            paused={session.paused}
            onPause={async (p) => {
              const ok = await window.blazma.recovery.setPaused(session.id, p);
              if (ok) setSession((s) => (s ? { ...s, paused: p } : s));
              else toast('amber', t('recovery.pauseUnsupported'));
            }}
            onStop={() => void window.blazma.recovery.stop(session.id)}
          />
        )}

        {error && <Card><ErrorState code={error} onRetry={() => setError(null)} /></Card>}

        {result && (
          <Card
            title={result.found ? t('recovery.found') : t('recovery.notFound')}
            icon={result.found ? ShieldCheck : ShieldAlert}
            tone={result.found ? 'green' : 'amber'}
            actions={<button className="btn sm" onClick={reset}>{t('recovery.newSession')}</button>}
          >
            {result.found && result.password ? (
              <>
                <div className="hash-row match" style={{ gridTemplateColumns: 'auto 1fr auto' }}>
                  <span className="algo">{t('recovery.reveal')}</span>
                  <Ltr mono breakAll>{result.password}</Ltr>
                  <CopyButton value={result.password} />
                </div>
                <div className="small dim" style={{ marginTop: 10 }}>{t('recovery.foundNote')}</div>
              </>
            ) : (
              <div className="muted">{t('recovery.notFoundHint')}</div>
            )}
          </Card>
        )}
      </div>
    </div>
  );
}
