// Plain-language summary of a domain lookup for everyday users ("Is this site trustworthy?").
// It only restates facts that were actually retrieved; "no red flags" is never presented as "safe".

import type { DomainLookupResult } from '../shared/api';

export type LinkLevel = 'risky' | 'caution' | 'no_red_flags' | 'unknown';
export type SignalTone = 'red' | 'amber' | 'green';

export interface LinkSignal {
  /** i18n key under linksum.signal.* */
  key: string;
  tone: SignalTone;
  vars?: Record<string, string | number>;
}

export interface LinkSummary {
  level: LinkLevel;
  signals: LinkSignal[];
}

const DAY = 86_400_000;

export function summarizeDomain(r: DomainLookupResult, now: Date): LinkSummary {
  const s: LinkSignal[] = [];
  let facts = 0;

  // Reputation (only when a service actually answered)
  for (const rep of r.reputation) {
    if (!rep.found) continue;
    facts++;
    if (rep.listed) {
      // abuse.ch: on a malware-distribution / IOC list (still active, or only in the past).
      s.push(rep.listedActive === false ? { key: 'listedHistorical', tone: 'amber', vars: { service: rep.service } } : { key: 'listedActive', tone: 'red', vars: { service: rep.service } });
      continue;
    }
    const bad = (rep.malicious ?? 0) + (rep.suspicious ?? 0);
    if ((rep.malicious ?? 0) > 0) s.push({ key: 'reputationBad', tone: 'red', vars: { service: rep.service, count: bad } });
    else if ((rep.suspicious ?? 0) > 0) s.push({ key: 'reputationSuspicious', tone: 'amber', vars: { service: rep.service, count: bad } });
    else s.push({ key: 'reputationClean', tone: 'green', vars: { service: rep.service } });
  }

  // Domain age from the registry
  const created = r.rdap?.created ? new Date(r.rdap.created) : null;
  if (created && !Number.isNaN(created.getTime())) {
    facts++;
    const days = Math.max(0, Math.floor((now.getTime() - created.getTime()) / DAY));
    if (days < 30) s.push({ key: 'veryYoung', tone: 'red', vars: { days } });
    else if (days < 180) s.push({ key: 'young', tone: 'amber', vars: { days } });
    else if (days >= 730) s.push({ key: 'old', tone: 'green', vars: { years: Math.floor(days / 365) } });
  }

  // TLS certificate
  if (r.tls) {
    facts++;
    if (!r.tls.authorized) s.push({ key: 'tlsUntrusted', tone: 'amber' });
    else if (r.tls.daysRemaining !== null && r.tls.daysRemaining < 0) s.push({ key: 'tlsExpired', tone: 'amber' });
    else s.push({ key: 'tlsOk', tone: 'green' });
  }

  // DNS: the name doesn't point anywhere
  if (r.dns) {
    facts++;
    if (r.dns.a.length === 0 && r.dns.aaaa.length === 0 && r.dns.cname.length === 0) s.push({ key: 'noAddress', tone: 'amber' });
  }

  const level: LinkLevel =
    s.some((x) => x.tone === 'red') ? 'risky' : s.some((x) => x.tone === 'amber') ? 'caution' : facts > 0 ? 'no_red_flags' : 'unknown';
  const order: Record<SignalTone, number> = { red: 0, amber: 1, green: 2 };
  s.sort((a, b) => order[a.tone] - order[b.tone]);
  return { level, signals: s };
}
