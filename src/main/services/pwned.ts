// "Was my password leaked?" — Pwned Passwords check through NetworkGate (Offline Mode + Network Activity).
// Only a 5-character SHA-1 prefix leaves the machine. The password is never logged, stored or returned.

import { MAX_PASSWORD_CHARS, parsePwnedRange, pwnedQuery, pwnedRangeUrl } from '../../core/pwned';
import type { NetworkGate } from '../../core/network-gate';
import type { PwnedResult } from '../../shared/api';

export class PwnedError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

const MAX_BODY = 1024 * 1024;

export async function checkPwnedPassword(gate: NetworkGate, password: unknown, now: () => Date = () => new Date()): Promise<PwnedResult> {
  if (typeof password !== 'string' || password.length === 0 || [...password].length > MAX_PASSWORD_CHARS) throw new PwnedError('invalid_input');
  const { prefix, suffix } = pwnedQuery(password);
  let res: Response;
  try {
    res = await gate.request({
      module: 'passwordCheck',
      service: 'pwned-passwords',
      url: pwnedRangeUrl(prefix),
      dataKind: 'privacy.data.password_hash_prefix',
      // Padding makes every response a similar size, so even the response length reveals nothing.
      init: { headers: { 'Add-Padding': 'true', 'user-agent': 'BLAZMA-CYBER' } },
      timeoutMs: 15_000,
    });
  } catch (e) {
    const code = (e as { code?: string }).code;
    if (code === 'offline_mode') throw e;
    const name = (e as Error).name;
    throw new PwnedError(name === 'AbortError' || name === 'TimeoutError' ? 'timeout' : 'network_error');
  }
  if (res.status === 429) throw new PwnedError('rate_limited');
  if (!res.ok) throw new PwnedError('api_error');
  const body = await res.text();
  if (body.length > MAX_BODY) throw new PwnedError('response_too_large');
  const count = parsePwnedRange(body, suffix);
  if (count === null) throw new PwnedError('invalid_response');
  return { found: count > 0, count, checkedAt: now().toISOString() };
}
