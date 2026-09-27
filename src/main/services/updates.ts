// Manual update check: only when the user presses "Check for updates", through NetworkGate (blocked in
// Offline Mode, logged). Reads the public release list of Blazma's own repository; nothing is sent
// except the request itself, and nothing is downloaded or installed — the user gets a link.

import type { NetworkGate } from '../../core/network-gate';
import { compareSemver, newestRelease, parseSemver } from '../../core/version';
import type { UpdateCheck } from '../../shared/api';

export const UPDATE_REPO = 'mr-kateba/-BLAZMA-CYBER';

export class UpdateError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}


let lastUrl: string | null = null;

export async function checkForUpdates(gate: NetworkGate, current: string): Promise<UpdateCheck> {
  let res: Response;
  try {
    res = await gate.request({
      module: 'settings',
      service: 'github-releases',
      url: `https://api.github.com/repos/${UPDATE_REPO}/releases?per_page=20`,
      dataKind: 'privacy.data.none',
      init: { headers: { accept: 'application/vnd.github+json', 'user-agent': 'Blazma-Cyber' } },
      timeoutMs: 15_000,
    });
  } catch (e) {
    if ((e as { code?: string }).code === 'offline_mode') throw e;
    throw new UpdateError((e as Error).name === 'AbortError' ? 'timeout' : 'network_error');
  }
  if (res.status === 403 || res.status === 429) throw new UpdateError('rate_limited');
  if (!res.ok) throw new UpdateError('api_error');
  let json: unknown;
  try {
    json = JSON.parse((await res.text()).slice(0, 4 * 1024 * 1024));
  } catch {
    throw new UpdateError('invalid_response');
  }
  const latest = newestRelease(json, UPDATE_REPO);
  const cur = parseSemver(current);
  const lat = latest ? parseSemver(latest.tag) : null;
  lastUrl = latest?.url ?? null;
  return { current, latest, newer: !!(cur && lat && compareSemver(lat, cur) > 0), checkedAt: new Date().toISOString() };
}

/** The release page found by the last check (never a URL from the renderer). */
export function lastReleaseUrl(): string | null {
  return lastUrl;
}
