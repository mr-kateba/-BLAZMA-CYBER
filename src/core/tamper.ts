// "Signs of tampering" (pure): settings that malware changes to spy on or cut off the user —
// the hosts file, the web proxy, DNS servers and user-added trusted root certificates.
// Each finding lists the evidence it is based on. Legitimate software can make some of these
// changes too (ad-blockers, corporate proxies, debugging proxies), so ambiguous cases are "warn"
// with an explanation, never "infected". Nothing here changes anything.

import { classifyIP, isIP } from './validation';

export type TamperStatus = 'pass' | 'warn' | 'fail' | 'unknown';

export interface TamperItem {
  value: string;
  /** i18n key under tamper.note.* explaining why this item is listed. */
  note: string;
  tone: 'red' | 'amber' | 'gray';
}

export interface TamperFinding {
  id: 'hosts' | 'proxy' | 'dns' | 'root_certs';
  status: TamperStatus;
  detail: { key: string; vars?: Record<string, string | number> } | null;
  reason?: string;
  items: TamperItem[];
}

export interface TamperReport {
  findings: TamperFinding[];
  collectedAt: string;
}

export interface RawTamperFacts {
  /** Contents of the hosts file; null = could not be read. */
  hosts?: string | null;
  proxy?: { enabled?: number | null; server?: string | null; pac?: string | null } | null;
  dns?: Array<{ iface: string; server: string }> | { iface: string; server: string } | null;
  userRoots?: Array<{ thumbprint: string; subject: string | null; notAfter: string | null }> | { thumbprint: string; subject: string | null; notAfter: string | null } | null;
}

// ------------------------------------------------------------------ hosts

export interface HostsEntry {
  ip: string;
  names: string[];
  line: number;
}

export function parseHosts(text: string): HostsEntry[] {
  const out: HostsEntry[] = [];
  text.split(/\r?\n/).slice(0, 200_000).forEach((raw, i) => {
    const line = raw.replace(/#.*/, '').trim();
    if (!line) return;
    const [ip, ...names] = line.split(/\s+/);
    if (!ip || names.length === 0 || !isIP(ip)) return;
    out.push({ ip: ip.toLowerCase(), names: names.map((n) => n.toLowerCase()), line: i + 1 });
  });
  return out;
}

/** Domains whose redirection or blocking is a classic malware move (stops updates and security tools). */
const PROTECTED = [
  'microsoft.com', 'windowsupdate.com', 'windows.com', 'update.microsoft.com', 'msftncsi.com', 'live.com', 'office.com',
  'virustotal.com', 'abuse.ch', 'google.com', 'gstatic.com', 'apple.com',
  'kaspersky.com', 'eset.com', 'avast.com', 'avg.com', 'malwarebytes.com', 'bitdefender.com', 'norton.com', 'nortonlifelock.com',
  'mcafee.com', 'sophos.com', 'trendmicro.com', 'f-secure.com', 'drweb.com', 'avira.com', 'escan.com', 'pandasecurity.com',
  'emsisoft.com', 'webroot.com', 'clamav.net', 'hitmanpro.com',
];
const isProtected = (name: string) => PROTECTED.some((d) => name === d || name.endsWith(`.${d}`));
const LOCAL_NAMES = new Set(['localhost', 'localhost.localdomain', 'local', 'broadcasthost', 'ip6-localhost', 'ip6-loopback', 'ip6-localnet', 'ip6-mcastprefix', 'ip6-allnodes', 'ip6-allrouters', 'ip6-allhosts']);
const isSink = (ip: string) => ip === '0.0.0.0' || ip === '::' || classifyIP(ip) === 'loopback';

export function evaluateHosts(text: string | null | undefined): TamperFinding {
  if (text == null) return { id: 'hosts', status: 'unknown', detail: null, reason: 'not_readable', items: [] };
  const items: TamperItem[] = [];
  let blocked = 0;
  let redirected = 0;
  let hijacked = 0;
  for (const e of parseHosts(text)) {
    for (const name of e.names) {
      if (LOCAL_NAMES.has(name)) continue;
      if (isProtected(name)) {
        hijacked++;
        items.push({ value: `${e.ip} ${name}`, note: isSink(e.ip) ? 'hosts_blocks_security' : 'hosts_redirects_security', tone: 'red' });
      } else if (isSink(e.ip)) {
        blocked++;
      } else if (classifyIP(e.ip) !== 'public') {
        // Names pointed at the local network (this PC's own name, a NAS, a printer) are normal.
        if (items.length < 200) items.push({ value: `${e.ip} ${name}`, note: 'hosts_local', tone: 'gray' });
      } else {
        redirected++;
        if (items.length < 200) items.push({ value: `${e.ip} ${name}`, note: 'hosts_redirect', tone: 'amber' });
      }
    }
  }
  const status: TamperStatus = hijacked > 0 ? 'fail' : redirected > 0 ? 'warn' : 'pass';
  return { id: 'hosts', status, detail: { key: 'tamper.detail.hosts', vars: { hijacked, redirected, blocked } }, items: items.slice(0, 200) };
}

// ------------------------------------------------------------------ proxy

function proxyHost(server: string): string | null {
  // "host:port" or "http=host:port;https=host:port"
  const first = server.split(';').map((p) => p.replace(/^[a-z]+=/i, '').trim()).find(Boolean);
  if (!first) return null;
  const m = /^(?:[a-z]+:\/\/)?(\[[^\]]+\]|[^:/]+)/i.exec(first);
  return m ? m[1]!.replace(/^\[|\]$/g, '').toLowerCase() : null;
}

export function evaluateProxy(p: RawTamperFacts['proxy']): TamperFinding {
  if (p == null) return { id: 'proxy', status: 'unknown', detail: null, reason: 'not_readable', items: [] };
  const items: TamperItem[] = [];
  const server = p.enabled === 1 && p.server?.trim() ? p.server.trim() : null;
  const pac = p.pac?.trim() || null;
  if (server) {
    const host = proxyHost(server);
    const local = host === 'localhost' || (host !== null && isIP(host) && classifyIP(host) === 'loopback');
    items.push({ value: server, note: local ? 'proxy_local' : 'proxy_server', tone: 'amber' });
  }
  if (pac) {
    let insecure = true;
    try {
      insecure = new URL(pac).protocol !== 'https:';
    } catch {
      insecure = true;
    }
    items.push({ value: pac, note: insecure ? 'pac_insecure' : 'pac', tone: insecure ? 'red' : 'amber' });
  }
  const status: TamperStatus = items.some((i) => i.tone === 'red') ? 'fail' : items.length ? 'warn' : 'pass';
  return { id: 'proxy', status, detail: items.length ? null : { key: 'tamper.detail.noProxy' }, items };
}

// ------------------------------------------------------------------ DNS

/** Well-known public resolvers (operator names are proper nouns, shown as-is). */
const KNOWN_DNS: Record<string, string> = {
  '8.8.8.8': 'Google', '8.8.4.4': 'Google', '2001:4860:4860::8888': 'Google', '2001:4860:4860::8844': 'Google',
  '1.1.1.1': 'Cloudflare', '1.0.0.1': 'Cloudflare', '1.1.1.2': 'Cloudflare', '1.0.0.2': 'Cloudflare', '1.1.1.3': 'Cloudflare', '1.0.0.3': 'Cloudflare',
  '2606:4700:4700::1111': 'Cloudflare', '2606:4700:4700::1001': 'Cloudflare',
  '9.9.9.9': 'Quad9', '149.112.112.112': 'Quad9', '2620:fe::fe': 'Quad9', '2620:fe::9': 'Quad9',
  '208.67.222.222': 'OpenDNS', '208.67.220.220': 'OpenDNS', '208.67.222.123': 'OpenDNS', '208.67.220.123': 'OpenDNS',
  '94.140.14.14': 'AdGuard', '94.140.15.15': 'AdGuard', '94.140.14.15': 'AdGuard', '94.140.15.16': 'AdGuard',
  '185.228.168.9': 'CleanBrowsing', '185.228.169.9': 'CleanBrowsing', '76.76.2.0': 'Control D', '76.76.10.0': 'Control D',
  // Cloud platforms' built-in resolvers
  '168.63.129.16': 'Microsoft Azure',
};

export function evaluateDns(raw: RawTamperFacts['dns']): TamperFinding {
  const list = raw == null ? null : Array.isArray(raw) ? raw : [raw];
  if (!list) return { id: 'dns', status: 'unknown', detail: null, reason: 'not_readable', items: [] };
  const items: TamperItem[] = [];
  const seen = new Set<string>();
  for (const { iface, server } of list) {
    const s = String(server ?? '').trim().toLowerCase();
    if (!s || seen.has(s) || !isIP(s)) continue;
    seen.add(s);
    // fec0:0:0:ffff::1/2/3 are Windows' deprecated site-local placeholders shown on many adapters.
    if (/^fec0:0:0:ffff::[123]$/.test(s)) continue;
    const scope = classifyIP(s);
    const known = KNOWN_DNS[s];
    const value = `${s} (${iface})`;
    if (scope !== 'public') items.push({ value, note: 'dns_local', tone: 'gray' });
    else if (known) items.push({ value: `${s} — ${known} (${iface})`, note: 'dns_known', tone: 'gray' });
    else items.push({ value, note: 'dns_unknown', tone: 'amber' });
  }
  const status: TamperStatus = items.some((i) => i.tone === 'amber') ? 'warn' : 'pass';
  return { id: 'dns', status, detail: { key: 'tamper.detail.dns', vars: { count: items.length } }, items };
}

// ------------------------------------------------------------------ root certificates

export function evaluateRootCerts(raw: RawTamperFacts['userRoots']): TamperFinding {
  const list = raw == null ? null : Array.isArray(raw) ? raw : [raw];
  if (!list) return { id: 'root_certs', status: 'unknown', detail: null, reason: 'not_readable', items: [] };
  const items = list
    .filter((c) => /^[0-9a-f]{40}$/i.test(String(c.thumbprint ?? '')))
    .map<TamperItem>((c) => ({ value: `${c.subject ?? '—'} · ${String(c.thumbprint).toUpperCase()}`, note: 'root_user_added', tone: 'amber' }));
  return { id: 'root_certs', status: items.length ? 'warn' : 'pass', detail: { key: 'tamper.detail.roots', vars: { count: items.length } }, items };
}

export function evaluateTamper(raw: RawTamperFacts, now: Date): TamperReport {
  return {
    findings: [evaluateHosts(raw.hosts), evaluateProxy(raw.proxy), evaluateDns(raw.dns), evaluateRootCerts(raw.userRoots)],
    collectedAt: now.toISOString(),
  };
}
