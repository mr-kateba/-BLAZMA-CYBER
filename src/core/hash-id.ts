// Hash format identification for the Hash Lab (integrity + audit workflows).
// Many encodings share the same shape (e.g. 32 hex characters), so this returns a ranked
// list of possible formats with a confidence level instead of claiming false certainty.

export type HashConfidence = 'high' | 'medium' | 'low';

export interface HashCandidate {
  /** Stable id, also used as an i18n key suffix. */
  id: string;
  name: string;
  confidence: HashConfidence;
}

interface Rule {
  test: RegExp;
  candidates: HashCandidate[];
}

const c = (id: string, name: string, confidence: HashConfidence): HashCandidate => ({ id, name, confidence });

// Structured/prefixed encodings are unambiguous, so they are checked first.
const RULES: Rule[] = [
  { test: /^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}$/, candidates: [c('bcrypt', 'bcrypt', 'high')] },
  {
    test: /^\$argon2(id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$/,
    candidates: [c('argon2', 'Argon2', 'high')],
  },
  { test: /^\$6\$/, candidates: [c('sha512crypt', 'SHA-512 Crypt (Unix)', 'high')] },
  { test: /^\$5\$/, candidates: [c('sha256crypt', 'SHA-256 Crypt (Unix)', 'high')] },
  { test: /^\$1\$/, candidates: [c('md5crypt', 'MD5 Crypt (Unix)', 'high')] },
  // Plain hex digests, distinguished only by length -> multiple candidates.
  {
    test: /^[a-fA-F0-9]{32}$/,
    candidates: [c('md5', 'MD5', 'medium'), c('ntlm', 'NTLM', 'low'), c('md4', 'MD4', 'low')],
  },
  { test: /^[a-fA-F0-9]{40}$/, candidates: [c('sha1', 'SHA-1', 'high')] },
  { test: /^[a-fA-F0-9]{56}$/, candidates: [c('sha224', 'SHA-224', 'high')] },
  {
    test: /^[a-fA-F0-9]{64}$/,
    candidates: [c('sha256', 'SHA-256', 'high'), c('sha3_256', 'SHA3-256', 'low'), c('blake2s', 'BLAKE2s-256', 'low')],
  },
  { test: /^[a-fA-F0-9]{96}$/, candidates: [c('sha384', 'SHA-384', 'high')] },
  {
    test: /^[a-fA-F0-9]{128}$/,
    candidates: [c('sha512', 'SHA-512', 'high'), c('sha3_512', 'SHA3-512', 'low'), c('blake2b', 'BLAKE2b-512', 'low')],
  },
  { test: /^[a-fA-F0-9]{8}$/, candidates: [c('crc32', 'CRC-32', 'low')] },
];

export interface HashIdResult {
  input: string;
  normalized: string;
  candidates: HashCandidate[];
}

/**
 * Identifies the possible algorithms for a hash string.
 * Returns an empty candidate list when nothing matches (the UI shows an honest "unknown format").
 */
export function identifyHash(input: string): HashIdResult {
  const normalized = input.trim();
  const candidates: HashCandidate[] = [];
  const seen = new Set<string>();
  for (const rule of RULES) {
    if (rule.test.test(normalized)) {
      for (const cand of rule.candidates) {
        if (!seen.has(cand.id)) {
          seen.add(cand.id);
          candidates.push(cand);
        }
      }
    }
  }
  const order: Record<HashConfidence, number> = { high: 0, medium: 1, low: 2 };
  candidates.sort((a, b) => order[a.confidence] - order[b.confidence]);
  return { input, normalized, candidates };
}
