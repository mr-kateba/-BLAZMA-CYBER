// Combined assessment model.
// A single weak heuristic never decides a verdict. Signals are gathered from independent
// sources (Defender, YARA, signature, entropy, hash reputation) and combined into one of
// four honest statuses, always with the reasons that produced it.

export type Verdict = 'no_detections' | 'unknown' | 'suspicious' | 'malicious';

export type SignalSource =
  | 'defender'
  | 'yara'
  | 'signature'
  | 'entropy'
  | 'hash_reputation'
  | 'static';

export interface Signal {
  source: SignalSource;
  /** Direction of the evidence for THIS signal. */
  weight: 'clean' | 'neutral' | 'weak' | 'strong' | 'malicious';
  /** i18n key describing the signal, resolved by the UI. */
  reasonKey: string;
  /** Optional interpolation values for the reason string. */
  reasonArgs?: Record<string, string | number>;
}

export interface Assessment {
  verdict: Verdict;
  signals: Signal[];
  reasons: Array<{ key: string; args?: Record<string, string | number> }>;
  /** True whenever at least one source could not run (e.g. Defender absent, YARA not installed). */
  incomplete: boolean;
}

const SCORE: Record<Signal['weight'], number> = {
  clean: -2,
  neutral: 0,
  weak: 1,
  strong: 3,
  malicious: 6,
};

/**
 * Combines signals into a verdict. The thresholds are deliberately conservative and the
 * result always carries `incomplete` when a source was unavailable, so the UI can communicate
 * uncertainty rather than implying a clean bill of health.
 */
export function assess(signals: Signal[], opts: { availableSources: Set<SignalSource> }): Assessment {
  const reasons = signals
    .filter((s) => s.weight !== 'neutral' && s.weight !== 'clean')
    .map((s) => ({ key: s.reasonKey, ...(s.reasonArgs ? { args: s.reasonArgs } : {}) }));

  const hasDefinitiveMalicious = signals.some(
    (s) => (s.source === 'defender' || s.source === 'yara') && s.weight === 'malicious',
  );

  const total = signals.reduce((sum, s) => sum + SCORE[s.weight], 0);
  const incomplete =
    opts.availableSources.size === 0 ||
    !['defender', 'yara', 'signature'].every((s) => opts.availableSources.has(s as SignalSource));

  let verdict: Verdict;
  if (hasDefinitiveMalicious || total >= 6) {
    verdict = 'malicious';
  } else if (total >= 3) {
    verdict = 'suspicious';
  } else if (signals.length === 0 || incomplete) {
    // No corroborating engine ran, or nothing was checked: never claim "clean".
    verdict = signals.some((s) => s.weight === 'clean') && !incomplete ? 'no_detections' : 'unknown';
  } else {
    verdict = 'no_detections';
  }

  return { verdict, signals, reasons, incomplete };
}
