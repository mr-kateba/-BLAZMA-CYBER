// Typed contract between the renderer (UI) and the main process (backend).
// The preload script exposes exactly this surface as window.blazma. Every argument is
// re-validated in the main process; the renderer is treated as untrusted.

import type { Lang } from '../core/i18n';
import type { NetworkActivityEntry } from '../core/network-gate';
import type { HashIdResult } from '../core/hash-id';
import type { FileTypeInfo } from '../core/filetype';
import type { PeInfo } from '../core/pe';
import type { ExtractedIocs } from '../core/ioc';
import type { Assessment } from '../core/detection';

export type Theme = 'dark' | 'midnight';
export type StartPage = 'dashboard' | 'file-analyzer' | 'hash-lab' | 'privacy';

export interface Settings {
  language: Lang | null; // null until the first-launch picker is completed
  theme: Theme;
  startPage: StartPage;
  offlineMode: boolean;
  keepHistory: boolean;
  notifications: boolean;
  logLevel: 'INFO' | 'DEBUG';
  reportLanguage: Lang;
  /** Absolute path to the YARA-X CLI (yr / yr.exe) chosen by the user; null = look for `yr` on PATH. */
  yaraPath: string | null;
  /** Run a Microsoft Defender custom scan as part of File Analyzer (Windows). */
  defenderOnAnalyze: boolean;
  /** Run enabled YARA rules as part of File Analyzer. */
  yaraOnAnalyze: boolean;
}

export const DEFAULT_SETTINGS: Settings = {
  language: null,
  theme: 'dark',
  startPage: 'dashboard',
  // Privacy-first default: nothing leaves the machine until the user opts in.
  offlineMode: true,
  keepHistory: true,
  notifications: true,
  logLevel: 'INFO',
  reportLanguage: 'en',
  yaraPath: null,
  defenderOnAnalyze: true,
  yaraOnAnalyze: true,
};

/** Result wrapper: modules never throw across IPC; they return a translatable error code. */
export type Result<T> = { ok: true; data: T } | { ok: false; error: string; detail?: string };

export interface CpuInfo {
  model: string;
  logicalCores: number;
  physicalCores: number | null;
  speedMHz: number;
  usagePercent: number | null; // null on the very first sample
}

export interface MemoryInfo {
  totalBytes: number;
  freeBytes: number;
  usedPercent: number;
}

export interface DiskInfo {
  mount: string;
  totalBytes: number;
  freeBytes: number;
  usedPercent: number;
  mediaType: string | null;
}

export interface NetInterface {
  name: string;
  address: string;
  family: 'IPv4' | 'IPv6';
  mac: string;
  internal: boolean;
}

export interface SystemSnapshot {
  platform: string;
  osName: string; // e.g. "Microsoft Windows 11 Pro" or "Linux 6.x"
  osVersion: string;
  osBuild: string | null;
  arch: string;
  uptimeSec: number;
  cpu: CpuInfo;
  memory: MemoryInfo;
  disk: DiskInfo | null;
  interfaces: NetInterface[];
  primaryIPv4: string | null;
  networkUp: boolean; // at least one non-internal interface has an address (no external probe!)
  processCount: number | null;
}

export type EngineState = 'on' | 'off' | 'unknown';

export interface DefenderStatus {
  available: boolean;
  reason?: string; // i18n error code when unavailable
  antivirusEnabled?: EngineState;
  realTimeProtection?: EngineState;
  signatureVersion?: string | null;
  signatureAgeDays?: number | null;
  lastQuickScan?: string | null;
  lastFullScan?: string | null;
}

export interface FirewallProfile {
  name: string;
  enabled: boolean;
}

export interface FirewallStatus {
  available: boolean;
  reason?: string;
  profiles?: FirewallProfile[];
}

export interface SecurityStatus {
  platformSupported: boolean;
  defender: DefenderStatus;
  firewall: FirewallStatus;
  checkedAt: string;
}

export interface HashResult {
  md5: string;
  sha1: string;
  sha256: string;
  sha512: string;
}

export interface SignatureInfo {
  /** false when the platform cannot verify Authenticode (non-Windows) or the check failed. */
  checked: boolean;
  reason?: string;
  status?: 'valid' | 'not_signed' | 'hash_mismatch' | 'not_trusted' | 'unknown_error' | 'other';
  rawStatus?: string;
  publisher?: string | null;
  issuer?: string | null;
  validFrom?: string | null;
  validTo?: string | null;
  thumbprint?: string | null;
}

/** Result of an optional engine inside an analysis: either it ran, or why it did not. */
export type EngineRun<T> = ({ ran: true } & T) | { ran: false; reason: string };

export interface YaraMatch {
  rule: string;
  namespace: string;
  tags: string[];
  meta: Record<string, string | number | boolean>;
}

export interface YaraFileResult {
  path: string;
  matches: YaraMatch[];
}

export interface YaraScanResult {
  target: string;
  files: YaraFileResult[];
  matchedFiles: number;
  rulesUsed: number;
  durationMs: number;
}

export interface YaraRuleFile {
  id: string;
  name: string;
  enabled: boolean;
  origin: 'builtin' | 'custom' | 'imported';
  createdAt: string;
  sizeBytes: number;
  /** null = never validated (engine missing when saved). */
  valid: boolean | null;
  error?: string;
}

export interface YaraEngineInfo {
  available: boolean;
  path?: string;
  version?: string;
  reason?: string;
}

export type DefenderScanKind = 'quick' | 'full' | 'path';

export interface DefenderScanResult {
  kind: DefenderScanKind;
  target: string | null;
  status: 'no_threats' | 'threats_found';
  threats: string[];
  exitCode: number;
  durationMs: number;
}

export interface DefenderThreat {
  id: string;
  name: string | null;
  severity: number | null;
  detected: string | null;
  resources: string[];
  actionSuccess: boolean;
}

export interface QuarantineEntry {
  id: string;
  originalPath: string;
  originalName: string;
  sizeBytes: number;
  sha256: string;
  typeId: string;
  typeDescription: string;
  quarantinedAt: string;
  /** i18n key or short free text describing why the item was quarantined. */
  reason: string;
}

export interface FileAnalysis {
  path: string;
  name: string;
  sizeBytes: number;
  created: string | null;
  modified: string | null;
  type: FileTypeInfo;
  hashes: HashResult;
  signature: SignatureInfo;
  defender: EngineRun<{ threats: string[] }>;
  yara: EngineRun<{ matches: YaraMatch[]; rulesUsed: number }>;
  entropy: number;
  pe: PeInfo | null;
  peError: string | null;
  iocs: ExtractedIocs;
  interestingStrings: string[];
  stringsScannedBytes: number;
  assessment: Assessment;
  /** Engines that did not run, so the UI can explain the gaps. */
  unavailableEngines: Array<{ engine: string; reason: string }>;
  durationMs: number;
}

export interface ActivityEntry {
  id: string;
  timestamp: string;
  kind:
    | 'file_analysis' | 'hash_file' | 'hash_text' | 'hash_identify' | 'hash_compare'
    | 'defender_scan' | 'yara_scan' | 'quarantine' | 'restore'
    | 'ip_lookup' | 'domain_lookup' | 'reputation_lookup'
    | 'forensics' | 'port_check' | 'discovery';
  /** Displayable subject, e.g. a filename. Never a secret. */
  subject: string;
  summaryKey: string;
}

export interface TaskProgress {
  taskId: string;
  processedBytes: number;
  totalBytes: number;
  stage: 'hashing' | 'analyzing' | 'scanning' | 'done';
}

export interface AppInfo {
  version: string;
  platform: string;
  dataDir: string;
  electron: string;
  secureStorageAvailable: boolean;
}

export type ApiKeyService = 'virustotal' | 'abuseipdb' | 'shodan' | 'censys' | 'ipinfo';

// ---------------- Intelligence (Phase 3) ----------------

/** Provenance of each piece of intelligence: where it came from, when, and whether it left the machine. */
export interface LookupSource {
  id: string;
  external: boolean;
  ok: boolean;
  /** i18n error code when !ok (e.g. offline_mode, api_key_missing, not_public_ip). */
  error?: string;
  queriedAt: string;
}

export interface IpRdap {
  handle: string | null;
  name: string | null;
  type: string | null;
  country: string | null;
  startAddress: string | null;
  endAddress: string | null;
  cidrs: string[];
  registrant: string | null;
  abuseEmail: string | null;
  registered: string | null;
  lastChanged: string | null;
  source: string | null;
}

export interface AsnInfo {
  asn: number;
  prefix: string | null;
  country: string | null;
  registry: string | null;
  allocated: string | null;
  name: string | null;
}

export interface GeoInfo {
  provider: string;
  city: string | null;
  region: string | null;
  country: string | null;
  loc: string | null;
  timezone: string | null;
  org: string | null;
}

export type ReputationService = 'virustotal' | 'abuseipdb' | 'shodan';

export interface ReputationResult {
  service: ReputationService;
  found: boolean;
  malicious?: number;
  suspicious?: number;
  harmless?: number;
  undetected?: number;
  reputation?: number | null;
  abuseScore?: number;
  totalReports?: number;
  lastReported?: string | null;
  usageType?: string | null;
  isp?: string | null;
  isTor?: boolean | null;
  ports?: number[];
  hostnames?: string[];
  vulns?: string[];
  tags?: string[];
  names?: string[];
  typeDescription?: string | null;
  lastAnalysis?: string | null;
  link?: string;
}

export interface IpLookupOptions {
  reverseDns: boolean;
  rdap: boolean;
  asn: boolean;
  geo: boolean;
  tor: boolean;
  reputation: ReputationService[];
}

export interface IpLookupResult {
  ip: string;
  version: 4 | 6;
  scope: 'private' | 'loopback' | 'link-local' | 'multicast' | 'reserved' | 'cgnat' | 'public';
  reverseDns: string[] | null;
  rdap: IpRdap | null;
  asn: AsnInfo | null;
  geo: GeoInfo | null;
  tor: boolean | null;
  reputation: ReputationResult[];
  sources: LookupSource[];
}

export interface DnsRecords {
  a: string[];
  aaaa: string[];
  mx: Array<{ exchange: string; priority: number }>;
  txt: string[];
  ns: string[];
  cname: string[];
  soa: { nsname: string; hostmaster: string; serial: number } | null;
  caa: string[];
  spf: string | null;
  dmarc: string | null;
}

export interface DomainRdap {
  ldhName: string | null;
  handle: string | null;
  registrar: string | null;
  registrarIanaId: string | null;
  created: string | null;
  expires: string | null;
  updated: string | null;
  status: string[];
  nameservers: string[];
  dnssec: boolean | null;
  abuseEmail: string | null;
  source: string | null;
}

export interface TlsInfo {
  host: string;
  port: number;
  protocol: string | null;
  authorized: boolean;
  authorizationError: string | null;
  subject: string | null;
  issuer: string | null;
  validFrom: string | null;
  validTo: string | null;
  daysRemaining: number | null;
  sans: string[];
  fingerprint256: string | null;
  serialNumber: string | null;
}

export interface DomainLookupOptions {
  dns: boolean;
  rdap: boolean;
  tls: boolean;
  infrastructure: boolean;
  reputation: ReputationService[];
}

export interface DomainLookupResult {
  input: string;
  domain: string;
  dns: DnsRecords | null;
  rdap: DomainRdap | null;
  tls: TlsInfo | null;
  infrastructure: Array<{ ip: string; asn: AsnInfo | null }>;
  reputation: ReputationResult[];
  sources: LookupSource[];
}

export type IndicatorKind = 'ip' | 'domain' | 'hash';

// ---------------- Forensics (Phase 4) ----------------

export interface ForensicsResult<T> {
  rows: T[];
  collectedAt: string;
  source: 'powershell' | 'procfs';
  /** Whether the collector ran elevated (null = unknown). */
  elevated: boolean | null;
  /** i18n key when some data could not be read (e.g. access denied as standard user). */
  partial?: string;
}

export interface ProcessRow {
  pid: number;
  ppid: number | null;
  name: string;
  path: string | null;
  commandLine: string | null;
  user: string | null;
  started: string | null;
}

export interface ConnectionRow {
  protocol: 'TCP' | 'UDP';
  localAddress: string;
  localPort: number;
  remoteAddress: string | null;
  remotePort: number | null;
  state: string | null;
  pid: number | null;
  process: string | null;
}

export interface ServiceRow {
  name: string;
  displayName: string | null;
  state: string | null;
  startMode: string | null;
  commandLine: string | null;
  binaryPath: string | null;
  account: string | null;
  pid: number | null;
  description: string | null;
  unquotedPath: boolean;
}

export interface DriverRow {
  name: string;
  displayName: string | null;
  state: string | null;
  startMode: string | null;
  path: string | null;
}

export interface StartupRow {
  name: string;
  command: string;
  location: string;
  user: string | null;
}

export interface TaskRow {
  name: string;
  path: string;
  state: string | null;
  author: string | null;
  actions: string[];
  microsoft: boolean;
}

export interface UserRow {
  name: string;
  enabled: boolean | null;
  lastLogon: string | null;
  description: string | null;
  admin: boolean;
}

export interface SoftwareRow {
  name: string;
  version: string | null;
  publisher: string | null;
  installDate: string | null;
  scope: 'machine' | 'user';
}

export interface UsbRow {
  name: string;
  serial: string | null;
  vendorProduct: string | null;
}

export interface EventRow {
  time: string | null;
  id: number;
  level: string | null;
  provider: string | null;
  message: string;
}

export type EventLogName =
  | 'System'
  | 'Application'
  | 'Security'
  | 'Windows PowerShell'
  | 'Microsoft-Windows-PowerShell/Operational'
  | 'Microsoft-Windows-Windows Defender/Operational';

export interface SignatureRow {
  path: string;
  status: NonNullable<SignatureInfo['status']>;
  publisher: string | null;
}

export type ForensicsModule = 'processes' | 'connections' | 'services' | 'drivers' | 'startup' | 'tasks' | 'users' | 'software' | 'usb';

// ---------------- Network Toolkit (Phase 4) ----------------

export interface PingResult {
  target: string;
  address: string;
  sent: number;
  received: number;
  rtts: Array<number | null>;
  min: number | null;
  avg: number | null;
  max: number | null;
}

export interface TraceResult {
  target: string;
  address: string;
  hops: Array<{ hop: number; address: string | null; rttMs: number | null }>;
  reached: boolean;
}

export interface PortResult {
  port: number;
  state: 'open' | 'closed' | 'filtered';
  service: string | null;
  latencyMs: number | null;
}

export interface PortCheckResult {
  target: string;
  address: string;
  results: PortResult[];
  durationMs: number;
}

export interface DnsLookupResult {
  name: string;
  server: string | null;
  records: Record<'A' | 'AAAA' | 'CNAME' | 'MX' | 'TXT' | 'NS', string[]>;
}

export interface AdapterRow {
  name: string;
  description: string | null;
  status: string | null;
  mac: string | null;
  speed: string | null;
  ipv4: string[];
  ipv6: string[];
  gateway: string | null;
  dns: string[];
  internal: boolean;
}

export interface RouteRow {
  destination: string;
  gateway: string | null;
  interface: string | null;
  metric: number | null;
}

export interface NeighborRow {
  address: string;
  mac: string | null;
  state: string | null;
  interface: string | null;
}

export interface DiscoveryResult {
  subnet: string;
  interface: string;
  probed: number;
  alive: Array<{ address: string; mac: string | null }>;
  durationMs: number;
}

export type ClearTarget = 'activity' | 'network_activity' | 'logs' | 'temp' | 'intel_cache';

export interface BlazmaApi {
  app: {
    info(): Promise<AppInfo>;
    openDataFolder(): Promise<Result<true>>;
  };
  settings: {
    get(): Promise<Settings>;
    update(patch: Partial<Settings>): Promise<Result<Settings>>;
  };
  system: {
    snapshot(): Promise<Result<SystemSnapshot>>;
    security(): Promise<Result<SecurityStatus>>;
  };
  files: {
    pathForFile(file: File): string;
    pickFile(): Promise<string | null>;
    pickFolder(): Promise<string | null>;
    analyze(path: string, taskId: string): Promise<Result<FileAnalysis>>;
    hash(path: string, taskId: string): Promise<Result<HashResult & { sizeBytes: number }>>;
    cancel(taskId: string): Promise<void>;
    onProgress(cb: (p: TaskProgress) => void): () => void;
  };
  hashlab: {
    hashText(text: string): Promise<Result<HashResult>>;
    identify(value: string): Promise<Result<HashIdResult>>;
  };
  privacy: {
    networkActivity(): Promise<NetworkActivityEntry[]>;
    clear(target: ClearTarget): Promise<Result<true>>;
    publicIp(): Promise<Result<{ ip: string; service: string }>>;
  };
  activity: {
    recent(limit: number): Promise<ActivityEntry[]>;
  };
  quarantine: {
    list(): Promise<Result<QuarantineEntry[]>>;
    add(path: string, reason: string): Promise<Result<QuarantineEntry>>;
    restore(id: string): Promise<Result<{ path: string }>>;
    /** Asks where to restore (save dialog). Resolves null data if the user cancels. */
    restoreTo(id: string): Promise<Result<{ path: string } | null>>;
    remove(id: string): Promise<Result<true>>;
    rescan(id: string, taskId: string): Promise<Result<FileAnalysis>>;
  };
  defender: {
    scan(kind: DefenderScanKind, target: string | null, taskId: string): Promise<Result<DefenderScanResult>>;
    history(): Promise<Result<DefenderThreat[]>>;
  };
  yara: {
    engine(): Promise<YaraEngineInfo>;
    /** Lets the user pick the yr executable; validates it before saving the path. */
    pickEngine(): Promise<Result<YaraEngineInfo | null>>;
    clearEngine(): Promise<Result<YaraEngineInfo>>;
    rules(): Promise<Result<YaraRuleFile[]>>;
    validate(): Promise<Result<YaraRuleFile[]>>;
    setEnabled(id: string, enabled: boolean): Promise<Result<YaraRuleFile[]>>;
    source(id: string): Promise<Result<string>>;
    save(name: string, source: string): Promise<Result<YaraRuleFile>>;
    importFile(): Promise<Result<YaraRuleFile | null>>;
    remove(id: string): Promise<Result<YaraRuleFile[]>>;
    scan(target: string, recursive: boolean, taskId: string): Promise<Result<YaraScanResult>>;
  };
  intel: {
    ip(ip: string, options: IpLookupOptions): Promise<Result<IpLookupResult>>;
    domain(domain: string, options: DomainLookupOptions): Promise<Result<DomainLookupResult>>;
    reputation(kind: IndicatorKind, value: string, services: ReputationService[]): Promise<Result<{ results: ReputationResult[]; sources: LookupSource[] }>>;
  };
  forensics: {
    collect(module: ForensicsModule): Promise<Result<ForensicsResult<unknown>>>;
    events(log: EventLogName, levels: number[], max: number): Promise<Result<ForensicsResult<EventRow>>>;
    signatures(paths: string[], taskId: string): Promise<Result<SignatureRow[]>>;
    powershellHistory(): Promise<Result<{ path: string; lines: string[]; total: number }>>;
  };
  net: {
    ping(target: string, count: number, taskId: string): Promise<Result<PingResult>>;
    traceroute(target: string, taskId: string): Promise<Result<TraceResult>>;
    dns(name: string): Promise<Result<DnsLookupResult>>;
    reverse(ip: string): Promise<Result<{ address: string; names: string[] }>>;
    portCheck(target: string, ports: string, taskId: string): Promise<Result<PortCheckResult>>;
    adapters(): Promise<Result<AdapterRow[]>>;
    routes(): Promise<Result<RouteRow[]>>;
    neighbors(): Promise<Result<NeighborRow[]>>;
    subnets(): Promise<Result<Array<{ cidr: string; interface: string; address: string }>>>;
    discover(cidr: string, taskId: string): Promise<Result<DiscoveryResult>>;
  };
  secrets: {
    status(): Promise<Record<ApiKeyService, boolean>>;
    set(service: ApiKeyService, value: string): Promise<Result<true>>;
    remove(service: ApiKeyService): Promise<Result<true>>;
  };
}
