import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import { basename } from 'node:path';
import type { EngineRun, FileAnalysis, HashResult, SignatureInfo, TaskProgress, YaraMatch } from '../../shared/api';
import { validateAbsolutePath } from '../../core/validation';
import { detectFileType } from '../../core/filetype';
import { detectEncryption } from '../../core/encrypted';
import { entropyLabel } from '../../core/entropy';
import { extractAsciiStrings, extractIocs } from '../../core/ioc';
import { parsePe } from '../../core/pe';
import { assess, type Signal, type SignalSource } from '../../core/detection';

/** Bytes kept in memory for PE parsing and string extraction. Hashing always covers the whole file. */
export const ANALYSIS_WINDOW = 32 * 1024 * 1024;

export class AnalysisError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

export async function statRegularFile(path: unknown) {
  const v = validateAbsolutePath(path);
  if (!v.ok) throw new AnalysisError(v.reason);
  let st;
  try {
    st = await stat(v.path);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    throw new AnalysisError(code === 'ENOENT' ? 'file_not_found' : code === 'EACCES' || code === 'EPERM' ? 'access_denied' : 'file_unreadable');
  }
  if (!st.isFile()) throw new AnalysisError('not_a_file');
  return { path: v.path, st };
}

interface StreamResult {
  hashes: HashResult;
  histogram: number[];
  window: Buffer;
  totalBytes: number;
}

/** Single streaming pass: all hashes + byte histogram + first ANALYSIS_WINDOW bytes. Never loads the whole file. */
export function streamFile(
  path: string,
  size: number,
  signal: AbortSignal,
  onProgress: (p: Omit<TaskProgress, 'taskId'>) => void,
  keepWindow = true,
): Promise<StreamResult> {
  return new Promise((resolve, reject) => {
    const md5 = createHash('md5');
    const sha1 = createHash('sha1');
    const sha256 = createHash('sha256');
    const sha512 = createHash('sha512');
    const histogram = new Array<number>(256).fill(0);
    const chunks: Buffer[] = [];
    let kept = 0;
    let processed = 0;
    let lastEmit = 0;

    const stream = createReadStream(path, { highWaterMark: 1024 * 1024 });
    const onAbort = () => stream.destroy(new AnalysisError('cancelled'));
    if (signal.aborted) return reject(new AnalysisError('cancelled'));
    signal.addEventListener('abort', onAbort, { once: true });

    stream.on('data', (chunk) => {
      const buf = chunk as Buffer;
      md5.update(buf);
      sha1.update(buf);
      sha256.update(buf);
      sha512.update(buf);
      for (let i = 0; i < buf.length; i++) histogram[buf[i]!]!++;
      if (keepWindow && kept < ANALYSIS_WINDOW) {
        const take = buf.subarray(0, Math.min(buf.length, ANALYSIS_WINDOW - kept));
        chunks.push(Buffer.from(take));
        kept += take.length;
      }
      processed += buf.length;
      const now = Date.now();
      if (now - lastEmit > 100) {
        lastEmit = now;
        onProgress({ processedBytes: processed, totalBytes: size, stage: 'hashing' });
      }
    });
    stream.on('error', (err) => {
      signal.removeEventListener('abort', onAbort);
      if (err instanceof AnalysisError) return reject(err);
      const code = (err as NodeJS.ErrnoException).code;
      reject(new AnalysisError(code === 'EACCES' || code === 'EPERM' || code === 'EBUSY' ? 'access_denied' : 'file_unreadable'));
    });
    stream.on('end', () => {
      signal.removeEventListener('abort', onAbort);
      onProgress({ processedBytes: processed, totalBytes: size, stage: 'analyzing' });
      resolve({
        hashes: { md5: md5.digest('hex'), sha1: sha1.digest('hex'), sha256: sha256.digest('hex'), sha512: sha512.digest('hex') },
        histogram,
        window: Buffer.concat(chunks),
        totalBytes: processed,
      });
    });
  });
}

function entropyFromHistogram(h: number[], total: number): number {
  if (!total) return 0;
  let e = 0;
  for (const c of h) {
    if (!c) continue;
    const p = c / total;
    e -= p * Math.log2(p);
  }
  return e;
}

// Well-known living-off-the-land binaries and persistence locations. These are
// INDICATORS for an analyst to review, not proof of malicious intent.
const INTERESTING = [
  'powershell', 'cmd.exe', 'wscript', 'cscript', 'mshta', 'rundll32', 'regsvr32', 'certutil', 'bitsadmin',
  'schtasks', '\\currentversion\\run', 'frombase64string', 'invoke-expression', 'downloadstring',
];

export function pickInterestingStrings(strings: string[], cap = 100): string[] {
  const out: string[] = [];
  for (const s of strings) {
    const l = s.toLowerCase();
    if (INTERESTING.some((k) => l.includes(k))) {
      out.push(s.length > 300 ? `${s.slice(0, 300)}…` : s);
      if (out.length >= cap) break;
    }
  }
  return out;
}

export type DefenderRun = EngineRun<{ threats: string[] }>;
export type YaraRun = EngineRun<{ matches: YaraMatch[]; rulesUsed: number }>;

export interface AnalysisEngines {
  verifySignature: (path: string) => Promise<SignatureInfo>;
  defender?: (path: string, signal: AbortSignal) => Promise<DefenderRun>;
  yara?: (path: string, signal: AbortSignal) => Promise<YaraRun>;
}

/** Maps a YARA rule's `severity` meta to evidence weight. Unknown/missing severity = strong. */
export function yaraWeight(meta: YaraMatch['meta']): Signal['weight'] {
  const sev = String(meta.severity ?? '').toLowerCase();
  if (sev === 'malicious' || sev === 'critical') return 'malicious';
  if (sev === 'info' || sev === 'low' || sev === 'informational') return 'weak';
  return 'strong';
}

export function buildSignals(input: {
  typeId: string;
  entropy: number;
  packerHints: string[];
  signature: SignatureInfo;
  interestingCount: number;
  defender?: DefenderRun;
  yara?: YaraRun;
}): { signals: Signal[]; available: Set<SignalSource> } {
  const signals: Signal[] = [];
  const available = new Set<SignalSource>(['entropy', 'static']);
  const isExecutable = input.typeId === 'pe';

  if (input.defender?.ran) {
    available.add('defender');
    if (input.defender.threats.length === 0) {
      signals.push({ source: 'defender', weight: 'clean', reasonKey: 'assessment.reason.defender_clean' });
    }
    for (const name of input.defender.threats) {
      signals.push({ source: 'defender', weight: 'malicious', reasonKey: 'assessment.reason.defender_detection', reasonArgs: { name } });
    }
  }
  if (input.yara?.ran) {
    available.add('yara');
    for (const m of input.yara.matches) {
      signals.push({ source: 'yara', weight: yaraWeight(m.meta), reasonKey: 'assessment.reason.yara_match', reasonArgs: { rule: m.rule } });
    }
  }

  if (input.signature.checked) {
    available.add('signature');
    switch (input.signature.status) {
      case 'valid':
        signals.push({ source: 'signature', weight: 'clean', reasonKey: 'assessment.reason.signed_valid', reasonArgs: { publisher: input.signature.publisher ?? '?' } });
        break;
      case 'hash_mismatch':
        signals.push({ source: 'signature', weight: 'strong', reasonKey: 'assessment.reason.signature_mismatch' });
        break;
      case 'not_signed':
        signals.push({ source: 'signature', weight: isExecutable ? 'weak' : 'neutral', reasonKey: 'assessment.reason.unsigned_executable' });
        break;
      default:
        signals.push({ source: 'signature', weight: 'weak', reasonKey: 'assessment.reason.signature_untrusted' });
    }
  }
  if (isExecutable && entropyLabel(input.entropy) === 'high') {
    signals.push({ source: 'entropy', weight: 'weak', reasonKey: 'assessment.reason.high_entropy', reasonArgs: { value: input.entropy.toFixed(2) } });
  }
  if (input.packerHints.length) {
    signals.push({ source: 'static', weight: 'weak', reasonKey: 'assessment.reason.packer_sections', reasonArgs: { names: input.packerHints.join(', ') } });
  }
  if (input.interestingCount >= 3) {
    signals.push({ source: 'static', weight: 'weak', reasonKey: 'assessment.reason.interesting_strings', reasonArgs: { count: input.interestingCount } });
  }
  return { signals, available };
}

export async function analyzeFile(
  rawPath: unknown,
  signal: AbortSignal,
  onProgress: (p: Omit<TaskProgress, 'taskId'>) => void,
  engines: AnalysisEngines,
): Promise<FileAnalysis> {
  const started = Date.now();
  const { path, st } = await statRegularFile(rawPath);
  const s = await streamFile(path, st.size, signal, onProgress);

  const type = detectFileType(s.window.subarray(0, 4096));
  const enc = detectEncryption(s.window.subarray(0, 64), s.window);
  const encryption = enc.encrypted ? enc : null;
  const entropy = entropyFromHistogram(s.histogram, s.totalBytes);
  const peRes = type.id === 'pe' ? parsePe(s.window) : null;
  const strings = extractAsciiStrings(s.window, 5);
  const iocs = extractIocs(strings.join('\n'));
  const interestingStrings = pickInterestingStrings(strings);
  if (signal.aborted) throw new AnalysisError('cancelled');

  onProgress({ processedBytes: s.totalBytes, totalBytes: st.size, stage: 'scanning' });
  // Engines run independently; one failing never breaks the analysis.
  const settle = async <T,>(fn: (() => Promise<T>) | undefined, fallback: T): Promise<T> => {
    if (!fn) return fallback;
    try {
      return await fn();
    } catch (e) {
      if (signal.aborted) throw new AnalysisError('cancelled');
      return { ran: false, reason: (e as { code?: string }).code ?? 'engine_failed' } as T;
    }
  };
  const [signature, defender, yara] = await Promise.all([
    engines.verifySignature(path).catch((): SignatureInfo => ({ checked: false, reason: 'engine_failed' })),
    settle<DefenderRun>(engines.defender ? () => engines.defender!(path, signal) : undefined, { ran: false, reason: 'engine_disabled' }),
    settle<YaraRun>(engines.yara ? () => engines.yara!(path, signal) : undefined, { ran: false, reason: 'engine_disabled' }),
  ]);
  if (signal.aborted) throw new AnalysisError('cancelled');

  const { signals, available } = buildSignals({
    typeId: type.id,
    entropy,
    packerHints: peRes?.ok ? peRes.pe.packerHints : [],
    signature,
    interestingCount: interestingStrings.length,
    defender,
    yara,
  });

  const unavailableEngines: Array<{ engine: string; reason: string }> = [];
  if (!defender.ran) unavailableEngines.push({ engine: 'defender', reason: defender.reason });
  if (!yara.ran) unavailableEngines.push({ engine: 'yara', reason: yara.reason });
  if (!signature.checked) unavailableEngines.push({ engine: 'signature', reason: signature.reason ?? 'unknown' });
  unavailableEngines.push({ engine: 'hash_reputation', reason: 'engine_not_integrated_yet' });

  onProgress({ processedBytes: s.totalBytes, totalBytes: st.size, stage: 'done' });

  return {
    path,
    name: basename(path),
    sizeBytes: st.size,
    created: st.birthtime ? st.birthtime.toISOString() : null,
    modified: st.mtime.toISOString(),
    type,
    encryption,
    hashes: s.hashes,
    signature,
    defender,
    yara,
    entropy,
    pe: peRes?.ok ? peRes.pe : null,
    peError: peRes && !peRes.ok ? peRes.reason : null,
    iocs,
    interestingStrings,
    stringsScannedBytes: s.window.length,
    assessment: assess(signals, { availableSources: available }),
    unavailableEngines,
    durationMs: Date.now() - started,
  };
}

export async function hashFile(rawPath: unknown, signal: AbortSignal, onProgress: (p: Omit<TaskProgress, 'taskId'>) => void) {
  const { path, st } = await statRegularFile(rawPath);
  const s = await streamFile(path, st.size, signal, onProgress, false);
  onProgress({ processedBytes: s.totalBytes, totalBytes: st.size, stage: 'done' });
  return { ...s.hashes, sizeBytes: st.size };
}

export function hashText(text: string): HashResult {
  const h = (a: string) => createHash(a).update(text, 'utf8').digest('hex');
  return { md5: h('md5'), sha1: h('sha1'), sha256: h('sha256'), sha512: h('sha512') };
}
