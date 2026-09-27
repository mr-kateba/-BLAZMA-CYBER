// IP / Domain / Reputation intelligence.
//
// Every network operation goes through NetworkGate (Offline Mode + Network Activity log):
//  - HTTP (RDAP, ipinfo, Tor list, reputation APIs) via gate.request
//  - DNS (records, reverse DNS, Team Cymru ASN) and TLS handshakes via gate.run
// Each source is independent: one failing source never breaks the lookup; it is reported in
// `sources` with its error code. Private/reserved IPs are never sent to external services.

import { Resolver } from 'node:dns/promises';
import { connect as tlsConnect, type PeerCertificate, type TLSSocket } from 'node:tls';
import { domainToASCII } from 'node:url';
import type {
  ApiKeyService, AsnInfo, DnsRecords, DomainLookupOptions, DomainLookupResult, DomainRdap, GeoInfo, IndicatorKind, IpLookupOptions,
  IpLookupResult, IpRdap, LookupSource, ReputationResult, ReputationService, TlsInfo,
} from '../../shared/api';
import { REPUTATION_FOR_KIND, REPUTATION_KEY, REPUTATION_SERVICES } from '../../shared/api';
import { ABUSECH_ENDPOINTS, abusechStatus, parseMalwareBazaar, parseThreatFox, parseUrlhausHost, parseUrlhausPayload } from '../../core/abusech';
import { NetworkGate } from '../../core/network-gate';
import { classifyIP, isDomain, isIP, isIPv4 } from '../../core/validation';
import {
  cymruOriginName, parseAbuseIpdb, parseCymruAsName, parseCymruOrigin, parseDomainRdap, parseIpRdap, parseIpinfo, parseShodanHost,
  parseTorExitList, parseVirusTotal, pickDmarc, pickSpf, rdapBaseForDomain, rdapBaseForIp, vtPath, type VtKind,
} from '../../core/intel';

export class IntelError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

type Resolverish = Pick<Resolver, 'reverse' | 'resolve4' | 'resolve6' | 'resolveMx' | 'resolveTxt' | 'resolveNs' | 'resolveCname' | 'resolveSoa' | 'resolveCaa' | 'getServers'>;

export interface TlsProbe {
  (host: string, port: number, timeoutMs: number): Promise<TlsInfo>;
}

export interface IntelDeps {
  gate: NetworkGate;
  secret: (s: ApiKeyService) => string | null;
  resolver?: Resolverish;
  tls?: TlsProbe;
  now?: () => number;
}

const MAX_JSON_BYTES = 4 * 1024 * 1024;
const BOOTSTRAP_TTL = 7 * 24 * 3600_000;
const TOR_TTL = 3600_000;
const HASH_RE = /^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i;

/** Real TLS probe: handshake only, reads the certificate, sends no application data. */
export const realTlsProbe: TlsProbe = (host, port, timeoutMs) =>
  new Promise((resolve, reject) => {
    const socket: TLSSocket = tlsConnect({ host, port, servername: isIP(host) ? undefined : host, rejectUnauthorized: false, timeout: timeoutMs });
    const done = (fn: () => void) => {
      socket.removeAllListeners();
      socket.destroy();
      fn();
    };
    socket.once('secureConnect', () => {
      const cert = socket.getPeerCertificate() as PeerCertificate;
      const info = certToInfo(host, port, cert, socket.authorized, socket.authorizationError ? String(socket.authorizationError) : null, socket.getProtocol());
      done(() => resolve(info));
    });
    socket.once('timeout', () => done(() => reject(new IntelError('timeout'))));
    socket.once('error', (e: NodeJS.ErrnoException) => done(() => reject(new IntelError(e.code === 'ENOTFOUND' ? 'dns_not_found' : 'tls_failed'))));
  });

const dnName = (x: unknown): string | null => {
  if (!x || typeof x !== 'object') return null;
  const o = x as Record<string, string | string[]>;
  const pick = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v);
  const cn = pick(o.CN);
  const org = pick(o.O);
  return [org, cn].filter(Boolean).join(' — ') || null;
};

export function certToInfo(host: string, port: number, cert: PeerCertificate, authorized: boolean, authorizationError: string | null, protocol: string | null): TlsInfo {
  const validTo = cert.valid_to ? new Date(cert.valid_to) : null;
  const validFrom = cert.valid_from ? new Date(cert.valid_from) : null;
  const ok = (d: Date | null) => (d && !Number.isNaN(d.getTime()) ? d : null);
  const to = ok(validTo);
  return {
    host,
    port,
    protocol,
    authorized,
    authorizationError,
    subject: dnName(cert.subject),
    issuer: dnName(cert.issuer),
    validFrom: ok(validFrom)?.toISOString() ?? null,
    validTo: to?.toISOString() ?? null,
    daysRemaining: to ? Math.floor((to.getTime() - Date.now()) / 86_400_000) : null,
    sans: (cert.subjectaltname ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.startsWith('DNS:') || s.startsWith('IP Address:'))
      .map((s) => s.replace(/^DNS:|^IP Address:/, ''))
      .slice(0, 200),
    fingerprint256: cert.fingerprint256 ?? null,
    serialNumber: cert.serialNumber ?? null,
  };
}

/** Normalizes user input to an ASCII domain (accepts URLs, IDNs, trailing dots). */
export function normalizeDomainInput(input: string): string | null {
  let s = input.trim();
  if (!s || s.length > 2048) return null;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
    try {
      s = new URL(s).hostname;
    } catch {
      return null;
    }
  }
  s = s.replace(/\.$/, '').toLowerCase();
  const ascii = domainToASCII(s);
  return ascii && isDomain(ascii) ? ascii : null;
}

export class IntelService {
  private readonly gate: NetworkGate;
  private readonly secret: IntelDeps['secret'];
  private readonly resolver: Resolverish;
  private readonly tls: TlsProbe;
  private readonly now: () => number;
  private bootstrap = new Map<string, { at: number; data: unknown }>();
  private tor: { at: number; set: Set<string> } | null = null;

  constructor(deps: IntelDeps) {
    this.gate = deps.gate;
    this.secret = deps.secret;
    this.resolver = deps.resolver ?? new Resolver({ timeout: 5000, tries: 2 });
    this.tls = deps.tls ?? realTlsProbe;
    this.now = deps.now ?? Date.now;
  }

  clearCache(): void {
    this.bootstrap.clear();
    this.tor = null;
  }

  private dnsHost(): string {
    return this.resolver.getServers()[0] ?? 'system-resolver';
  }

  // ------------------------------------------------------------ HTTP helpers

  /** GET JSON through the gate, following up to 3 https redirects (each hop is gated/logged). Shared with OSINT. */
  async getJson(url: string, meta: { module: string; service: string; dataKind: string; headers?: Record<string, string>; authenticated?: boolean; maxBytes?: number; timeoutMs?: number }): Promise<unknown | null> {
    const maxBytes = meta.maxBytes ?? MAX_JSON_BYTES;
    let current = url;
    for (let hop = 0; hop < 4; hop++) {
      const res = await this.gate.request({
        module: meta.module,
        service: meta.service,
        url: current,
        dataKind: meta.dataKind,
        redirect: 'manual',
        init: { headers: { accept: 'application/rdap+json, application/json', ...(meta.headers ?? {}) } },
        timeoutMs: meta.timeoutMs ?? 15_000,
      });
      if (res.status >= 300 && res.status < 400) {
        const loc = res.headers.get('location');
        if (!loc) throw new IntelError('api_error');
        const next = new URL(loc, current);
        if (next.protocol !== 'https:') throw new IntelError('insecure_redirect');
        current = next.toString();
        continue;
      }
      if (res.status === 404) return null;
      return readJsonResponse(res, !!meta.authenticated, maxBytes);
    }
    throw new IntelError('too_many_redirects');
  }

  /** POST through the gate (no redirects followed). `body` is form-encoded or JSON; the answer must be JSON. */
  async postJson(url: string, body: { form: Record<string, string> } | { json: unknown }, meta: { module: string; service: string; dataKind: string; headers?: Record<string, string>; authenticated?: boolean; timeoutMs?: number }): Promise<unknown> {
    const isForm = 'form' in body;
    const res = await this.gate.request({
      module: meta.module,
      service: meta.service,
      url,
      dataKind: meta.dataKind,
      init: {
        method: 'POST',
        headers: { accept: 'application/json', 'content-type': isForm ? 'application/x-www-form-urlencoded' : 'application/json', ...(meta.headers ?? {}) },
        body: isForm ? new URLSearchParams(body.form).toString() : JSON.stringify(body.json),
      },
      timeoutMs: meta.timeoutMs ?? 15_000,
    });
    return readJsonResponse(res, !!meta.authenticated, MAX_JSON_BYTES);
  }

  private async getBootstrap(kind: 'ipv4' | 'ipv6' | 'dns', module: string): Promise<unknown> {
    const hit = this.bootstrap.get(kind);
    if (hit && this.now() - hit.at < BOOTSTRAP_TTL) return hit.data;
    const data = await this.getJson(`https://data.iana.org/rdap/${kind}.json`, { module, service: 'iana-rdap-bootstrap', dataKind: 'privacy.data.none' });
    if (!data) throw new IntelError('rdap_unavailable');
    this.bootstrap.set(kind, { at: this.now(), data });
    return data;
  }

  // ------------------------------------------------------------ building blocks

  private async rdapIp(ip: string): Promise<IpRdap | null> {
    const base = rdapBaseForIp(await this.getBootstrap(isIPv4(ip) ? 'ipv4' : 'ipv6', 'ipIntel'), ip);
    if (!base) throw new IntelError('rdap_unavailable');
    const json = await this.getJson(`${base}ip/${ip}`, { module: 'ipIntel', service: 'rdap', dataKind: 'privacy.data.ip_address' });
    return json ? parseIpRdap(json, new URL(base).host) : null;
  }

  private async rdapDomain(domain: string): Promise<DomainRdap | null> {
    const base = rdapBaseForDomain(await this.getBootstrap('dns', 'domainIntel'), domain);
    if (!base) throw new IntelError('rdap_unavailable');
    const json = await this.getJson(`${base}domain/${domain}`, { module: 'domainIntel', service: 'rdap', dataKind: 'privacy.data.domain' });
    return json ? parseDomainRdap(json, new URL(base).host) : null;
  }

  /** Team Cymru IP→ASN over DNS (two TXT queries). */
  private async asn(ip: string, module: string): Promise<AsnInfo | null> {
    return this.gate.run({ module, service: 'team-cymru', host: this.dnsHost(), dataKind: 'privacy.data.ip_address' }, async () => {
      const origin = parseCymruOrigin(await this.resolver.resolveTxt(cymruOriginName(ip)).catch(dnsEmpty));
      if (!origin) return null;
      const name = parseCymruAsName(await this.resolver.resolveTxt(`AS${origin.asn}.asn.cymru.com`).catch(dnsEmpty));
      return { ...origin, name };
    });
  }

  private async reverse(ip: string, module: string): Promise<string[]> {
    return this.gate.run({ module, service: 'dns', host: this.dnsHost(), dataKind: 'privacy.data.ip_address' }, () =>
      this.resolver.reverse(ip).catch(dnsEmpty),
    );
  }

  private async geo(ip: string): Promise<GeoInfo | null> {
    const token = this.secret('ipinfo');
    const url = `https://ipinfo.io/${encodeURIComponent(ip)}/json${token ? `?token=${encodeURIComponent(token)}` : ''}`;
    const json = await this.getJson(url, { module: 'ipIntel', service: 'ipinfo.io', dataKind: 'privacy.data.ip_address', authenticated: !!token });
    return json ? parseIpinfo(json) : null;
  }

  private async torList(): Promise<Set<string>> {
    if (this.tor && this.now() - this.tor.at < TOR_TTL) return this.tor.set;
    const res = await this.gate.request({ module: 'ipIntel', service: 'tor-project', url: 'https://check.torproject.org/torbulkexitlist', dataKind: 'privacy.data.none', timeoutMs: 20_000 });
    if (!res.ok) throw new IntelError('api_error');
    const text = await res.text();
    if (text.length > 16 * 1024 * 1024) throw new IntelError('response_too_large');
    this.tor = { at: this.now(), set: parseTorExitList(text) };
    return this.tor.set;
  }

  private async reputationOne(service: ReputationService, kind: IndicatorKind, value: string, module: string): Promise<ReputationResult> {
    const key = this.secret(REPUTATION_KEY[service]);
    if (!key) throw new IntelError('api_key_missing');
    const dataKind = kind === 'ip' ? 'privacy.data.ip_address' : kind === 'domain' ? 'privacy.data.domain' : 'privacy.data.file_hash';
    if (service === 'malwarebazaar' || service === 'urlhaus' || service === 'threatfox') return this.abusech(service, kind, value, module, dataKind, key);
    if (service === 'virustotal') {
      const json = await this.getJson(vtPath(kind as VtKind, value), { module, service: 'virustotal', dataKind, headers: { 'x-apikey': key }, authenticated: true });
      return json ? parseVirusTotal(json, kind as VtKind, value) : { service, found: false };
    }
    if (kind !== 'ip') throw new IntelError('unsupported_indicator');
    if (service === 'abuseipdb') {
      const json = await this.getJson(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(value)}&maxAgeInDays=90`, {
        module, service: 'abuseipdb', dataKind, headers: { Key: key }, authenticated: true,
      });
      return json ? parseAbuseIpdb(json) : { service, found: false };
    }
    const json = await this.getJson(`https://api.shodan.io/shodan/host/${encodeURIComponent(value)}?key=${encodeURIComponent(key)}`, { module, service: 'shodan', dataKind, authenticated: true });
    return json ? parseShodanHost(json) : { service, found: false };
  }

  /** abuse.ch (MalwareBazaar / URLhaus / ThreatFox): POST APIs with the user's Auth-Key. */
  private async abusech(service: 'malwarebazaar' | 'urlhaus' | 'threatfox', kind: IndicatorKind, value: string, module: string, dataKind: string, key: string): Promise<ReputationResult> {
    const meta = { module, service, dataKind, headers: { 'Auth-Key': key }, authenticated: true };
    let json: unknown;
    if (service === 'malwarebazaar') {
      json = await this.postJson(ABUSECH_ENDPOINTS.malwarebazaar, { form: { query: 'get_info', hash: value } }, meta);
    } else if (service === 'urlhaus') {
      json = kind === 'hash'
        ? await this.postJson(ABUSECH_ENDPOINTS.urlhausPayload, { form: value.length === 32 ? { md5_hash: value } : { sha256_hash: value } }, meta)
        : await this.postJson(ABUSECH_ENDPOINTS.urlhausHost, { form: { host: value } }, meta);
    } else {
      json = await this.postJson(ABUSECH_ENDPOINTS.threatfox, { json: kind === 'hash' ? { query: 'search_hash', hash: value } : { query: 'search_ioc', search_term: value } }, meta);
    }
    const status = abusechStatus(json);
    if (status === 'not_found') return { service, found: false };
    if (status !== 'ok') throw new IntelError(status);
    if (service === 'malwarebazaar') return parseMalwareBazaar(json);
    if (service === 'threatfox') return parseThreatFox(json);
    return kind === 'hash' ? parseUrlhausPayload(json) : parseUrlhausHost(json);
  }

  /** Why a service cannot answer for this indicator, or null when it can. */
  private repSkip(service: ReputationService, kind: IndicatorKind, value: string): string | null {
    if (!REPUTATION_FOR_KIND[kind].includes(service)) return 'unsupported_indicator';
    // URLhaus payloads and ThreatFox hashes are indexed by MD5 / SHA-256 only.
    if (kind === 'hash' && (service === 'urlhaus' || service === 'threatfox') && value.length === 40) return 'unsupported_indicator';
    return null;
  }

  // ------------------------------------------------------------ public API

  async ip(raw: unknown, opts: IpLookupOptions): Promise<IpLookupResult> {
    if (typeof raw !== 'string' || !isIP(raw.trim())) throw new IntelError('invalid_ip');
    const ip = raw.trim().toLowerCase();
    const scope = classifyIP(ip)!;
    const isPublic = scope === 'public';
    const sources: LookupSource[] = [];
    const step = <T,>(id: string, enabled: boolean, needsPublic: boolean, fn: () => Promise<T>): Promise<T | null> =>
      this.step(sources, id, enabled, needsPublic && !isPublic ? 'not_public_ip' : null, fn);

    const [reverseDns, rdap, asn, geo, torSet, reputation] = await Promise.all([
      step('reverse_dns', opts.reverseDns, false, () => this.reverse(ip, 'ipIntel')),
      step('rdap', opts.rdap, true, () => this.rdapIp(ip)),
      step('asn', opts.asn, true, () => this.asn(ip, 'ipIntel')),
      step('geo', opts.geo, true, () => this.geo(ip)),
      step('tor', opts.tor, true, () => this.torList()),
      Promise.all(
        uniq(opts.reputation).filter((s) => REPUTATION_FOR_KIND.ip.includes(s)).map((svc) => step(`reputation:${svc}`, true, true, () => this.reputationOne(svc, 'ip', ip, 'ipIntel'))),
      ),
    ]);

    return {
      ip,
      version: isIPv4(ip) ? 4 : 6,
      scope,
      reverseDns,
      rdap,
      asn,
      geo,
      tor: torSet ? torSet.has(ip) : null,
      reputation: reputation.filter((r): r is ReputationResult => !!r),
      sources,
    };
  }

  async domain(raw: unknown, opts: DomainLookupOptions): Promise<DomainLookupResult> {
    if (typeof raw !== 'string') throw new IntelError('invalid_domain');
    const domain = normalizeDomainInput(raw);
    if (!domain) throw new IntelError('invalid_domain');
    const sources: LookupSource[] = [];
    const step = <T,>(id: string, enabled: boolean, fn: () => Promise<T>) => this.step(sources, id, enabled, null, fn);

    const [dns, rdap, tls, reputation] = await Promise.all([
      step('dns', opts.dns || opts.infrastructure, () => this.dnsRecords(domain)),
      step('rdap', opts.rdap, () => this.rdapDomain(domain)),
      step('tls', opts.tls, () =>
        this.gate.run({ module: 'domainIntel', service: 'tls', host: `${domain}:443`, dataKind: 'privacy.data.domain' }, () => this.tls(domain, 443, 10_000)),
      ),
      Promise.all(uniq(opts.reputation).filter((s) => REPUTATION_FOR_KIND.domain.includes(s)).map((svc) => step(`reputation:${svc}`, true, () => this.reputationOne(svc, 'domain', domain, 'domainIntel')))),
    ]);

    let infrastructure: DomainLookupResult['infrastructure'] = [];
    if (opts.infrastructure && dns) {
      const ips = [...dns.a, ...dns.aaaa].slice(0, 6);
      const res = await step('infrastructure', ips.length > 0, () =>
        Promise.all(ips.map(async (ip) => ({ ip, asn: classifyIP(ip) === 'public' ? await this.asn(ip, 'domainIntel').catch(() => null) : null }))),
      );
      infrastructure = res ?? [];
    }

    return {
      input: raw,
      domain,
      dns: opts.dns ? dns : null,
      rdap,
      tls,
      infrastructure,
      reputation: reputation.filter((r): r is ReputationResult => !!r),
      sources,
    };
  }

  async reputation(kind: unknown, raw: unknown, services: unknown): Promise<{ results: ReputationResult[]; sources: LookupSource[] }> {
    if (kind !== 'ip' && kind !== 'domain' && kind !== 'hash') throw new IntelError('invalid_input');
    if (typeof raw !== 'string') throw new IntelError('invalid_input');
    let value = raw.trim();
    if (kind === 'ip') {
      if (!isIP(value)) throw new IntelError('invalid_ip');
      if (classifyIP(value) !== 'public') throw new IntelError('not_public_ip');
    } else if (kind === 'domain') {
      const d = normalizeDomainInput(value);
      if (!d) throw new IntelError('invalid_domain');
      value = d;
    } else {
      value = value.toLowerCase();
      if (!HASH_RE.test(value)) throw new IntelError('invalid_hash');
    }
    const list = (Array.isArray(services) ? services : []).filter((s): s is ReputationService => (REPUTATION_SERVICES as readonly unknown[]).includes(s));
    const applicable = uniq(list).filter((s) => REPUTATION_FOR_KIND[kind].includes(s));
    if (applicable.length === 0) throw new IntelError('no_service_selected');
    const sources: LookupSource[] = [];
    const module = kind === 'hash' ? 'fileAnalyzer' : 'reputation';
    const results = await Promise.all(applicable.map((svc) => this.step(sources, `reputation:${svc}`, true, this.repSkip(svc, kind, value), () => this.reputationOne(svc, kind, value, module))));
    return { results: results.filter((r): r is ReputationResult => !!r), sources };
  }

  async dnsRecords(domain: string, module = 'domainIntel'): Promise<DnsRecords> {
    return this.gate.run({ module, service: 'dns', host: this.dnsHost(), dataKind: 'privacy.data.domain' }, async () => {
      const r = this.resolver;
      const [a, aaaa, mx, txt, ns, cname, soa, caa, dmarcTxt] = await Promise.all([
        r.resolve4(domain).catch(dnsEmpty),
        r.resolve6(domain).catch(dnsEmpty),
        r.resolveMx(domain).catch(dnsEmpty),
        r.resolveTxt(domain).catch(dnsEmpty),
        r.resolveNs(domain).catch(dnsEmpty),
        r.resolveCname(domain).catch(dnsEmpty),
        r.resolveSoa(domain).catch(() => null),
        r.resolveCaa(domain).catch(dnsEmpty),
        r.resolveTxt(`_dmarc.${domain}`).catch(dnsEmpty),
      ]);
      const txtFlat = txt.map((c) => c.join(''));
      return {
        a,
        aaaa,
        mx: mx.sort((x, y) => x.priority - y.priority).map((m) => ({ exchange: m.exchange, priority: m.priority })),
        txt: txtFlat,
        ns: ns.map((n) => n.toLowerCase()).sort(),
        cname,
        soa: soa ? { nsname: soa.nsname, hostmaster: soa.hostmaster, serial: soa.serial } : null,
        caa: caa.map((c) => Object.entries(c).filter(([k]) => k !== 'critical').map(([k, v]) => `${k} ${String(v)}`).join(' ')),
        spf: pickSpf(txtFlat),
        dmarc: pickDmarc(dmarcTxt.map((c) => c.join(''))),
      };
    });
  }

  /** Runs one independent source and records its outcome (shared with OSINT; `url` = provenance). */
  async step<T>(sources: LookupSource[], id: string, enabled: boolean, skipReason: string | null, fn: () => Promise<T>, url?: string): Promise<T | null> {
    if (!enabled) return null;
    const queriedAt = new Date(this.now()).toISOString();
    const prov = url ? { url } : {};
    if (skipReason) {
      sources.push({ id, external: true, ok: false, error: skipReason, queriedAt, ...prov });
      return null;
    }
    try {
      const r = await fn();
      sources.push({ id, external: true, ok: true, queriedAt, ...prov });
      return r;
    } catch (e) {
      const code = (e as { code?: string }).code;
      const dnsCodes: Record<string, string> = { ETIMEOUT: 'timeout', ESERVFAIL: 'dns_error', EREFUSED: 'dns_error', ECONNREFUSED: 'dns_error' };
      const known =
        e instanceof IntelError || code === 'offline_mode' ? code!
        : code && dnsCodes[code] ? dnsCodes[code]!
        : (e as Error).name === 'AbortError' || (e as Error).name === 'TimeoutError' ? 'timeout'
        : 'network_error';
      sources.push({ id, external: true, ok: false, error: known, queriedAt, ...prov });
      return null;
    }
  }
}

async function readJsonResponse(res: Response, authenticated: boolean, maxBytes: number): Promise<unknown> {
  // 401/403 means "bad key" only when we actually sent one; otherwise the server refused us.
  if (res.status === 401 || res.status === 403) throw new IntelError(authenticated ? 'api_key_invalid' : 'remote_forbidden');
  if (res.status === 429) throw new IntelError('rate_limited');
  if (!res.ok) throw new IntelError('api_error');
  const len = Number(res.headers.get('content-length') ?? 0);
  if (len > maxBytes) throw new IntelError('response_too_large');
  const text = await res.text();
  if (text.length > maxBytes) throw new IntelError('response_too_large');
  try {
    return JSON.parse(text);
  } catch {
    throw new IntelError('invalid_response');
  }
}

/** DNS "no data" answers are results (empty), not failures. */
function dnsEmpty(e: NodeJS.ErrnoException): never[] {
  // SERVFAIL / REFUSED / TIMEOUT are real failures and are reported as errors, never hidden.
  if (e && ['ENODATA', 'ENOTFOUND', 'NOTFOUND', 'ENOTIMP'].includes(String(e.code))) return [];
  throw e;
}

function uniq<T>(a: T[]): T[] {
  return [...new Set(a)];
}
