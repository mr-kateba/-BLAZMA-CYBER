// Redaction applied to every structured log entry before it is written.
// Secrets must never reach disk through logs, even at DEBUG level.

const SENSITIVE_KEY = /(pass(word)?|secret|token|api[-_]?key|authorization|cookie|credential|private[-_]?key|recovered)/i;

const INLINE_PATTERNS: Array<[RegExp, string]> = [
  [/(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi, '$1[REDACTED]'],
  [/([?&](?:key|apikey|api_key|token)=)[^&\s]+/gi, '$1[REDACTED]'],
  [/(x-apikey:\s*)\S+/gi, '$1[REDACTED]'],
];

export const REDACTED = '[REDACTED]';

export function redactString(value: string): string {
  let out = value;
  for (const [re, rep] of INLINE_PATTERNS) out = out.replace(re, rep);
  return out;
}

export function redact(value: unknown, depth = 0): unknown {
  if (depth > 8) return '[DEPTH_LIMIT]';
  if (typeof value === 'string') return redactString(value);
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1));
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = SENSITIVE_KEY.test(k) ? REDACTED : redact(v, depth + 1);
    }
    return out;
  }
  return value;
}
