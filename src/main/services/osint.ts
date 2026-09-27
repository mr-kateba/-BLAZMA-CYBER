// OSINT workspace: lawful public sources, provenance on every result.
//
// Sources (all queried only when the user starts a lookup, all through NetworkGate):
//  - Certificate Transparency via crt.sh (public CT log search)          → domain
//  - Wayback Machine availability API (first / latest snapshot)          → domain, url
//  - GitHub public REST API (unauthenticated public profile)             → username
//  - MX / SPF / DMARC of the email's domain via the user's resolver       → email
// Pivot links are never fetched here: they open in the user's browser after an explicit click,
// are blocked in Offline Mode and are recorded in Network Activity like any other request.

import type { LookupSource, OsintOptions, OsintResult, OsintTargetType } from '../../shared/api';
import type { NetworkGate } from '../../core/network-gate';
import { emailDomain, normalizeOsintTarget, osintPivots, parseCrtSh, parseGithubUser, parseWaybackAvailable, type WaybackSnapshot } from '../../core/osint';
import { IntelError, type IntelService } from './intel';

export interface OsintDeps {
  intel: IntelService;
  gate: NetworkGate;
  openExternal: (url: string) => Promise<void>;
}

const enc = encodeURIComponent;

export class OsintService {
  constructor(private readonly deps: OsintDeps) {}

  private target(type: unknown, raw: unknown): { type: OsintTargetType; value: string } {
    const value = normalizeOsintTarget(type, raw);
    if (!value) throw new IntelError('invalid_osint_target');
    return { type: type as OsintTargetType, value };
  }

  async lookup(typeRaw: unknown, raw: unknown, opts: OsintOptions): Promise<OsintResult> {
    const { type, value } = this.target(typeRaw, raw);
    const { intel } = this.deps;
    const sources: LookupSource[] = [];
    const result: OsintResult = { type, value, ct: null, wayback: null, github: null, email: null, pivots: osintPivots(type, value), sources };
    const tasks: Array<Promise<unknown>> = [];

    if (type === 'domain' && opts.ct) {
      const url = `https://crt.sh/?q=${enc(`%.${value}`)}&output=json`;
      tasks.push(
        intel.step(sources, 'osint:ct', true, null, async () => {
          const json = await intel.getJson(url, { module: 'osint', service: 'crt.sh', dataKind: 'privacy.data.domain', maxBytes: 24 * 1024 * 1024, timeoutMs: 30_000 });
          result.ct = parseCrtSh(json ?? [], value);
        }, url),
      );
    }

    if ((type === 'domain' || type === 'url') && opts.wayback) {
      const base = `https://archive.org/wayback/available?url=${enc(value)}`;
      const dataKind = type === 'domain' ? 'privacy.data.domain' : 'privacy.data.url';
      const snap = async (u: string): Promise<WaybackSnapshot | null> =>
        parseWaybackAvailable(await intel.getJson(u, { module: 'osint', service: 'wayback', dataKind, timeoutMs: 20_000 }));
      tasks.push(
        intel.step(sources, 'osint:wayback', true, null, async () => {
          const [first, last] = await Promise.all([snap(`${base}&timestamp=19960101`), snap(base)]);
          result.wayback = { first, last };
        }, base),
      );
    }

    if (type === 'username' && opts.github) {
      const url = `https://api.github.com/users/${enc(value)}`;
      tasks.push(
        intel.step(sources, 'osint:github', true, null, async () => {
          const json = await intel.getJson(url, {
            module: 'osint', service: 'github', dataKind: 'privacy.data.username',
            headers: { accept: 'application/vnd.github+json', 'user-agent': 'BLAZMA-CYBER' },
          });
          // 404 → no public profile with that name: a result, not an error.
          result.github = json ? parseGithubUser(json) : null;
        }, url),
      );
    }

    if (type === 'email' && opts.emailDns) {
      const domain = emailDomain(value);
      tasks.push(
        intel.step(sources, 'osint:emailDns', true, null, async () => {
          const d = await intel.dnsRecords(domain, 'osint');
          const nullMx = d.mx.length > 0 && d.mx.every((m) => m.exchange === '' || m.exchange === '.');
          result.email = {
            domain,
            mx: d.mx,
            spf: d.spf,
            dmarc: d.dmarc,
            acceptsMail: !nullMx && (d.mx.length > 0 || d.a.length + d.aaaa.length > 0),
          };
        }),
      );
    }

    await Promise.all(tasks);
    sources.sort((a, b) => a.id.localeCompare(b.id));
    return result;
  }

  /** Opens a pivot link after re-deriving it here — the renderer can't make us open arbitrary URLs. */
  async openPivot(typeRaw: unknown, raw: unknown, pivotId: unknown): Promise<void> {
    const { type, value } = this.target(typeRaw, raw);
    const pivot = osintPivots(type, value).find((p) => p.id === pivotId);
    if (!pivot) throw new IntelError('invalid_input');
    const url = new URL(pivot.url);
    if (url.protocol !== 'https:') throw new IntelError('invalid_input');
    await this.deps.gate.run({ module: 'osint', service: `browser:${pivot.id}`, host: url.host, dataKind: pivot.dataKind }, () => this.deps.openExternal(pivot.url));
  }
}
