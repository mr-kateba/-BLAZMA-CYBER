// Typed contract between the renderer (UI) and the main process (backend).
// The preload script exposes exactly this surface as window.blazma. Every argument is
// re-validated in the main process; the renderer is treated as untrusted.

import type { Lang } from '../core/i18n';
import type { NetworkActivityEntry } from '../core/network-gate';
import type { HashIdResult } from '../core/hash-id';
import type { FileTypeInfo } from '../core/filetype';
import type { PeInfo } from '../core/pe';
import type { EncryptionInfo } from '../core/encrypted';
import type { ExtractedIocs } from '../core/ioc';
import type { Assessment } from '../core/detection';
import type { DeviceSecurityReport, SettingsLink } from '../core/device-security';
import type { TamperReport } from '../core/tamper';
import type { ExtensionAudit } from '../core/extensions';
import type { DownloadEvent, DownloadsWatchState } from '../core/downloads';
import type { ReleaseInfo } from '../core/version';
import type { EventDetection, EventHuntSummary } from '../core/hayabusa';
import type { MemoryScanSummary } from '../core/hollows';
import type { CapaSummary } from '../core/capa';
import type { EmailAnalysis } from '../core/email';
import type { DieSummary } from '../core/die';
import type { CtSummary, GithubProfile, OsintPivot, OsintTargetType, WaybackSnapshot } from '../core/osint';
import type { AccountStatus, AccountUnknownReason, UsernameGroup } from '../core/username-check';
import type { MacKind } from '../core/oui';
import type { TrafficReport } from '../core/traffic/analyzer';
import type { SavedProfile, WifiConnection, WifiFinding, WifiNetwork } from '../core/wifi';
import type { NmapFinding, NmapProfile, NmapRun } from '../core/nmap';

/** 'system' follows the Windows light/dark app mode. */
export type Theme = 'dark' | 'midnight' | 'light' | 'system';
export type StartPage = 'dashboard' | 'file-analyzer' | 'hash-lab' | 'privacy';
/** simple = the essentials for everyday users; expert = every module. */
export type UiMode = 'simple' | 'expert';

export interface Settings {
  language: Lang | null; // null until the first-launch picker is completed
  uiMode: UiMode;
  theme: Theme;
  startPage: StartPage;
  offlineMode: boolean;
  keepHistory: boolean;
  notifications: boolean;
  logLevel: 'INFO' | 'DEBUG';
  reportLanguage: Lang;
  /** Absolute path to the YARA-X CLI (yr / yr.exe) chosen by the user; null = look for `yr` on PATH. */
  yaraPath: string | null;
  johnPath: string | null;
  hashcatPath: string | null;
  /** Run a Microsoft Defender custom scan as part of File Analyzer (Windows). */
  defenderOnAnalyze: boolean;
  /** Run enabled YARA rules as part of File Analyzer. */
  yaraOnAnalyze: boolean;
  /** Run the bundled capa ("what can this program do?") on programs in File Analyzer. */
  capaOnAnalyze: boolean;
  /** Run the bundled Detect It Easy (compiler / packer identification) in File Analyzer. */
  dieOnAnalyze: boolean;
  /** While Blazma is open, analyze new downloads statically (opt-in). */
  watchDownloads: boolean;
}

export const DEFAULT_SETTINGS: Settings = {
  language: null,
  uiMode: 'simple',
  theme: 'dark',
  startPage: 'dashboard',
  // Privacy-first default: nothing leaves the machine until the user opts in.
  offlineMode: true,
  keepHistory: true,
  notifications: true,
  logLevel: 'INFO',
  reportLanguage: 'en',
  yaraPath: null,
  johnPath: null,
  hashcatPath: null,
  defenderOnAnalyze: true,
  yaraOnAnalyze: true,
  capaOnAnalyze: true,
  dieOnAnalyze: true,
  watchDownloads: false,
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
/** capa (Mandiant): capabilities with MITRE ATT&CK mapping. */
export type CapaRun = EngineRun<CapaSummary & { durationMs: number }>;
/** Detect It Easy: compiler / packer / installer identification. */
export type DieRun = EngineRun<DieSummary>;

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
  /** pack = a rule set shipped with Blazma (read-only; can be disabled, not deleted). */
  origin: 'builtin' | 'custom' | 'imported' | 'pack';
  createdAt: string;
  sizeBytes: number;
  /** null = never validated (engine missing when saved). */
  valid: boolean | null;
  error?: string;
}

export interface YaraEngineInfo {
  available: boolean;
  /** true when this is the YARA-X shipped with Blazma (verified at build time). */
  bundled?: boolean;
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
  encryption: EncryptionInfo | null;
  hashes: HashResult;
  signature: SignatureInfo;
  defender: EngineRun<{ threats: string[] }>;
  yara: EngineRun<{ matches: YaraMatch[]; rulesUsed: number }>;
  capa: CapaRun;
  die: DieRun;
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
    | 'ip_lookup' | 'domain_lookup' | 'reputation_lookup' | 'osint_lookup' | 'email_check' | 'event_hunt' | 'memory_scan' | 'traffic_analysis' | 'nmap_scan'
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

/** The developer shown in About, the first-launch screen and the installer metadata. */
export const APP_AUTHOR = 'mr-kateba';
export const APP_COPYRIGHT_YEAR = 2026;

export interface AppInfo {
  version: string;
  platform: string;
  dataDir: string;
  electron: string;
  secureStorageAvailable: boolean;
  /** Running as a portable copy (data kept next to the program). */
  portable: boolean;
}

export type ApiKeyService = 'virustotal' | 'abuseipdb' | 'shodan' | 'censys' | 'ipinfo' | 'abusech';

// ---------------- Intelligence (Phase 3) ----------------

/** Provenance of each piece of intelligence: where it came from, when, and whether it left the machine. */
export interface LookupSource {
  id: string;
  external: boolean;
  ok: boolean;
  /** i18n error code when !ok (e.g. offline_mode, api_key_missing, not_public_ip). */
  error?: string;
  queriedAt: string;
  /** Provenance: the public endpoint that produced the data (OSINT). Never contains API keys. */
  url?: string;
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

export type ReputationService = 'virustotal' | 'abuseipdb' | 'shodan' | 'malwarebazaar' | 'urlhaus' | 'threatfox';

export const REPUTATION_SERVICES: readonly ReputationService[] = ['virustotal', 'abuseipdb', 'shodan', 'malwarebazaar', 'urlhaus', 'threatfox'];

/** Which reputation services can answer for which indicator kind. */
export const REPUTATION_FOR_KIND: Record<'ip' | 'domain' | 'hash', readonly ReputationService[]> = {
  ip: ['virustotal', 'abuseipdb', 'shodan', 'urlhaus', 'threatfox'],
  domain: ['virustotal', 'urlhaus', 'threatfox'],
  hash: ['virustotal', 'malwarebazaar', 'urlhaus', 'threatfox'],
};

/** The API key each reputation service uses (one abuse.ch Auth-Key covers MalwareBazaar, URLhaus and ThreatFox). */
export const REPUTATION_KEY: Record<ReputationService, ApiKeyService> = {
  virustotal: 'virustotal', abuseipdb: 'abuseipdb', shodan: 'shodan', malwarebazaar: 'abusech', urlhaus: 'abusech', threatfox: 'abusech',
};

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
  /** abuse.ch: the indicator is on a malware/abuse list (true) — `listedActive` false means only historical. */
  listed?: boolean;
  listedActive?: boolean;
  /** abuse.ch: malware family / signature / threat type as reported. */
  threat?: string | null;
  firstSeen?: string | null;
  lastSeen?: string | null;
  urlCount?: number;
  onlineUrls?: number;
  /** ThreatFox confidence level 0–100 (highest among matching IOCs). */
  confidence?: number;
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

export type { OsintTargetType } from '../core/osint';
export type { AccountStatus, AccountUnknownReason, UsernameGroup } from '../core/username-check';
export type { MacKind } from '../core/oui';
export type { NmapFinding, NmapHost, NmapPort, NmapProfile, NmapRun, ServiceRisk } from '../core/nmap';
export type { SavedProfile, WifiConnection, WifiFinding, WifiNetwork, WifiSecurity, WifiRating } from '../core/wifi';
export type { TrafficReport, TrafficFinding, TrafficDevice, TrafficConversation, FindingSeverity } from '../core/traffic/analyzer';
export type { EmailAnalysis, EmailAttachment, EmailLink, EmailSignal, AuthResult } from '../core/email';

/** Pwned Passwords answer. Never contains the password or its hash. */
export interface PwnedResult {
  found: boolean;
  /** How many times the password appears in the breach corpus (0 = not found). */
  count: number;
  checkedAt: string;
}
export type { AttackRef, Capability, CapaSummary } from '../core/capa';
export type { DieDetection, DieSummary } from '../core/die';
export type { DeviceCheck, DeviceSecurityReport, SettingsLink } from '../core/device-security';
export type { TamperFinding, TamperItem, TamperReport } from '../core/tamper';
export type { DownloadEvent, DownloadsWatchState } from '../core/downloads';
export type { ReleaseInfo } from '../core/version';
export interface UpdateCheck { current: string; latest: ReleaseInfo | null; newer: boolean; checkedAt: string }
export type { EventDetection, EventHuntSummary, EventLevel } from '../core/hayabusa';
export type { ImplantIndicator, MemoryScanSummary, SuspiciousProcess } from '../core/hollows';
export type EventHuntSource = { kind: 'file' | 'dir'; path: string } | { kind: 'live' };
export interface EventHuntOptions { minLevel: 'low' | 'medium' | 'high' | 'critical'; days: 1 | 7 | 30 | 90 | null }
export interface EventHuntResult extends EventHuntSummary { rows: EventDetection[]; source: { kind: EventHuntSource['kind']; path: string | null }; durationMs: number }
export type { BrowserExtension, BrowserId, ExtensionAudit, ExtensionFlag, ExtensionRisk } from '../core/extensions';

export interface OsintOptions {
  /** Certificate Transparency (crt.sh) — domain */
  ct: boolean;
  /** Wayback Machine first/last snapshot — domain, url */
  wayback: boolean;
  /** GitHub public profile — username */
  github: boolean;
  /** MX / SPF / DMARC of the email domain via your resolver — email */
  emailDns: boolean;
}

export interface EmailDomainInfo {
  domain: string;
  mx: Array<{ exchange: string; priority: number }>;
  spf: string | null;
  dmarc: string | null;
  /** Null MX (RFC 7505) or no MX/A: the domain doesn't accept mail. */
  acceptsMail: boolean;
}

export interface AccountCheck {
  id: string;
  name: string;
  cat: string;
  group: UsernameGroup;
  status: AccountStatus;
  reason?: AccountUnknownReason;
  /** Public profile page (display + open); null when the site has no page to open. */
  url: string | null;
}

export interface AccountsResult {
  username: string;
  groups: UsernameGroup[];
  /** Sites in the chosen groups. */
  total: number;
  /** Sites that answered or failed (less than total when cancelled). */
  checked: number;
  found: number;
  missing: number;
  unknown: number;
  accounts: AccountCheck[];
  cancelled: boolean;
  durationMs: number;
  /** Where the site list and detection rules come from (WhatsMyName commit). */
  source: string;
}

export interface NmapInfo {
  installed: boolean;
  version: string | null;
}

export interface NmapResult {
  target: string;
  profile: NmapProfile;
  run: NmapRun;
  findings: NmapFinding[];
  durationMs: number;
}

export interface WifiReport {
  /** false when Windows has no Wi-Fi adapter / WLAN service, or the WLAN API could not be used. */
  available: boolean;
  reason: 'no_wifi_adapter' | 'wlan_unavailable' | null;
  interfaces: string[];
  connections: WifiConnection[];
  networks: WifiNetwork[];
  channels: Array<{ band: '2.4' | '5' | '6'; channel: number; networks: number }>;
  /** Windows withheld Wi-Fi names/scan results because desktop apps may not use location. */
  locationBlocked: boolean;
  locationSetting: 'on' | 'off' | null;
  profiles: SavedProfile[];
  profilesReadable: boolean;
  findings: WifiFinding[];
  collectedAt: string;
}

export interface CaptureEnvironment {
  platform: 'windows' | 'other';
  /** Wireshark's dumpcap + Npcap installed: unelevated live capture. */
  dumpcap: boolean;
  npcap: boolean;
  /** Wireshark itself, to open saved captures. */
  wireshark: boolean;
  /** Windows' built-in packet monitor (needs administrator rights, asked per capture). */
  pktmon: boolean;
}

export interface CaptureInterface {
  id: string;
  name: string;
  loopback: boolean;
}

export interface TrafficCaptureOptions {
  seconds: 15 | 30 | 60 | 120 | 300;
  backend: 'pktmon' | 'dumpcap';
  /** dumpcap interface index (from traffic.interfaces()); null = first interface. */
  iface: string | null;
  /** Keep the .pcapng in Blazma's captures folder after analysis. */
  keep: boolean;
}

export interface TrafficResult {
  report: TrafficReport;
  /** Set when the file ended in a damaged record: the report covers everything before it. */
  readError: string | null;
  source: {
    kind: 'file' | 'live';
    name: string | null;
    sizeBytes: number;
    backend: 'pktmon' | 'dumpcap' | null;
    seconds: number | null;
    keptPath: string | null;
  };
  durationMs: number;
}

export interface OsintResult {
  type: OsintTargetType;
  value: string;
  ct: CtSummary | null;
  wayback: { first: WaybackSnapshot | null; last: WaybackSnapshot | null } | null;
  github: GithubProfile | null;
  email: EmailDomainInfo | null;
  pivots: OsintPivot[];
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

/** Who made a device, from its MAC address (offline IEEE registry). */
export interface MacMaker {
  kind: MacKind;
  vendor: string | null;
}

export interface NeighborRow {
  address: string;
  mac: string | null;
  maker: MacMaker | null;
  state: string | null;
  interface: string | null;
}

export interface DiscoveryResult {
  subnet: string;
  interface: string;
  probed: number;
  alive: Array<{ address: string; mac: string | null; maker: MacMaker | null }>;
  durationMs: number;
}

// ---------------- Investigations (Phase 6) ----------------

export type EvidenceKind = 'file' | 'hash' | 'ip' | 'domain' | 'url' | 'email' | 'process' | 'connection' | 'finding' | 'other';

export interface Evidence {
  id: string;
  kind: EvidenceKind;
  /** The indicator itself (hash, IP, domain, path…). */
  value: string;
  label: string | null;
  /** Module that produced it (fileAnalyzer, ipIntel, hunt, manual…). */
  source: string;
  addedAt: string;
  /** Optional structured snapshot (e.g. verdict, hashes, ASN) captured when added. */
  details: Record<string, string | number | boolean | null> | null;
}

export interface CaseNote {
  id: string;
  text: string;
  createdAt: string;
  updatedAt: string;
}

export interface TimelineEvent {
  id: string;
  time: string;
  title: string;
  detail: string | null;
  kind: 'evidence' | 'note' | 'event' | 'status';
}

export interface InvestigationCase {
  id: string; // CASE-YYYY-NNN
  name: string;
  description: string;
  tags: string[];
  status: 'open' | 'closed';
  createdAt: string;
  updatedAt: string;
  evidence: Evidence[];
  notes: CaseNote[];
  timeline: TimelineEvent[];
}

export type CaseSummary = Pick<InvestigationCase, 'id' | 'name' | 'status' | 'tags' | 'createdAt' | 'updatedAt'> & { evidenceCount: number; noteCount: number };

/** csv / stix = indicators only (IOC export). */
export type ReportFormat = 'html' | 'json' | 'pdf' | 'csv' | 'stix';

export interface ReportOptions {
  format: ReportFormat;
  language: Lang;
  includeMachineInfo: boolean;
  includeNotes: boolean;
  includeTimeline: boolean;
}

export interface ReportRecord {
  id: string;
  caseId: string;
  caseName: string;
  format: ReportFormat;
  language: Lang;
  path: string;
  createdAt: string;
  sizeBytes: number;
}

export type HuntSource = 'case' | 'quarantine' | 'activity' | 'network_log' | 'process' | 'connection' | 'service' | 'startup' | 'task' | 'yara_rule';

export interface HuntHit {
  source: HuntSource;
  title: string;
  detail: string | null;
  time: string | null;
  /** Reference for navigation, e.g. a case id. */
  ref: string | null;
}

export interface HuntResult {
  query: string;
  indicatorType: 'ip' | 'domain' | 'hash' | 'text';
  hits: HuntHit[];
  searched: Array<{ source: HuntSource; ok: boolean; error?: string }>;
  durationMs: number;
}

export interface PersistenceItem {
  kind: 'startup' | 'task' | 'service';
  name: string;
  command: string;
  location: string | null;
  flags: string[]; // i18n keys under hunt.flag.*
}

// ---------------- Password Recovery (Phase 5) ----------------

export type RecoveryEngineKind = 'john' | 'hashcat';

export type RecoveryMode =
  | { type: 'wordlist'; path: string }
  | { type: 'candidates'; path: string }
  | { type: 'mask'; mask: string };

export interface RecoveryEngineInfo {
  kind: RecoveryEngineKind;
  available: boolean;
  path?: string;
  version?: string;
  reason?: string;
}

export interface RecoverySessionInfo {
  id: string;
  engine: RecoveryEngineKind;
  target: string;
  mode: RecoveryMode['type'];
  startedAt: string;
}

export interface RecoveryProgress {
  id: string;
  tried: number;
  total: number | null;
  rate: number | null;
  recovered: boolean;
  elapsedMs: number;
}

export interface RecoveryStartResult {
  id: string;
  info: RecoverySessionInfo;
}

/** Event pushed to the renderer during a session. `password` is delivered once and never logged. */
export type RecoveryEventMsg =
  | { id: string; type: 'progress'; progress: RecoveryProgress }
  | { id: string; type: 'done'; found: boolean; password: string | null }
  | { id: string; type: 'error'; error: string }
  | { id: string; type: 'stopped' };

export type ClearTarget = 'activity' | 'network_activity' | 'logs' | 'temp' | 'intel_cache' | 'reports' | 'cases';

export interface BlazmaApi {
  app: {
    info(): Promise<AppInfo>;
    openDataFolder(): Promise<Result<true>>;
    /** Opens an allowlisted https result page in the default browser (gated, logged). */
    openLink(url: string): Promise<Result<true>>;
    /** Engines shipped with this build (verified at build time); empty when none are bundled. */
    bundledEngines(): Promise<Array<{ id: 'yara-x' | 'capa' | 'die' | 'hayabusa' | 'hollows-hunter'; name: string; version: string; license: string }>>;
    /** Manual update check against this project's GitHub releases (gated; nothing is downloaded). */
    checkUpdates(): Promise<Result<UpdateCheck>>;
    /** Opens the release page found by the last check in the browser. */
    openReleasePage(): Promise<Result<true>>;
    /** Opens the regular Windows terminal (Windows Terminal, else PowerShell) in its own window. */
    openTerminal(): Promise<Result<'windows-terminal' | 'powershell'>>;
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
  email: {
    /** Lets the user choose a saved email (.eml); returns its path or null. */
    pick(): Promise<string | null>;
    analyzeFile(path: string): Promise<Result<EmailAnalysis & { token: string }>>;
    analyzeText(source: string): Promise<Result<EmailAnalysis & { token: string }>>;
    /** Writes attachment #index to Blazma's temp folder (non-executable name) for File Analyzer. */
    extractAttachment(token: string, index: number): Promise<Result<string>>;
  };
  password: {
    /** "Was my password leaked?" — sends only a 5-char SHA-1 prefix (k-anonymity) through NetworkGate. */
    checkPwned(password: string): Promise<Result<PwnedResult>>;
  };
  memory: {
    /** Bundled HollowsHunter, if this build ships it. */
    engine(): Promise<{ available: boolean; version: string | null }>;
    /** Looks for injected / replaced code in the memory of the current user's running programs (read-only). */
    scan(taskId: string): Promise<Result<MemoryScanSummary & { durationMs: number }>>;
  };
  downloads: {
    /** State of the opt-in Downloads watcher (enabled via settings.watchDownloads). */
    state(): Promise<Result<DownloadsWatchState>>;
    onState(cb: (s: DownloadsWatchState) => void): () => void;
    /** Fired when the user clicks a "suspicious download" notification. */
    onOpen(cb: (ev: DownloadEvent) => void): () => void;
  };
  extensions: {
    /** Read-only audit of browser extensions (Chromium browsers + Firefox) for the current user. */
    audit(): Promise<Result<ExtensionAudit>>;
  };
  device: {
    /** Read-only Device Security Score (Windows). */
    security(force?: boolean): Promise<Result<DeviceSecurityReport>>;
    /** Signs of tampering: hosts file, proxy, DNS servers, user-added root certificates (read-only). */
    tamper(): Promise<Result<TamperReport>>;
    /** Opens a fixed Windows settings page (never changes a setting). */
    openSettings(link: SettingsLink): Promise<Result<true>>;
  };
  nmap: {
    info(): Promise<Result<NmapInfo>>;
    /** Local subnets this computer is attached to (the only networks Nmap may scan). */
    targets(): Promise<Result<Array<{ cidr: string; interface: string; address: string }>>>;
    scan(target: string, profile: NmapProfile, authorized: boolean, taskId: string): Promise<Result<NmapResult>>;
  };
  wifi: {
    /** Read-only: current connection, nearby networks and saved networks (never passwords). */
    report(): Promise<Result<WifiReport>>;
    /** Opens Windows' location privacy page (fixed URI). */
    openLocationSettings(): Promise<Result<true>>;
  };
  traffic: {
    environment(): Promise<Result<CaptureEnvironment>>;
    interfaces(): Promise<Result<CaptureInterface[]>>;
    /** File dialog for .pcap / .pcapng / .cap files. */
    pickFile(): Promise<string | null>;
    analyzeFile(path: string, taskId: string): Promise<Result<TrafficResult>>;
    /** Explicit, time-limited live capture (pktmon asks for administrator rights each time). */
    capture(options: TrafficCaptureOptions, taskId: string): Promise<Result<TrafficResult>>;
    /** Opens a capture Blazma kept or the user picked, in the user's Wireshark. */
    openInWireshark(path: string): Promise<Result<true>>;
    openCapturesFolder(): Promise<Result<true>>;
  };
  osint: {
    lookup(type: OsintTargetType, value: string, options: OsintOptions): Promise<Result<OsintResult>>;
    /** Opens a pivot link in the default browser (blocked in Offline Mode, recorded in Network Activity). */
    openPivot(type: OsintTargetType, value: string, pivotId: string): Promise<Result<void>>;
    /** How many sites each group of the accounts check asks. */
    accountSites(): Promise<Result<Record<UsernameGroup, number>>>;
    /** Asks public sites whether the username exists (long task: progress + files.cancel). */
    accounts(username: string, groups: UsernameGroup[], taskId: string): Promise<Result<AccountsResult>>;
    /** Opens a found profile in the default browser (URL re-derived in main). */
    openAccount(username: string, siteId: string): Promise<Result<void>>;
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
  cases: {
    list(): Promise<Result<CaseSummary[]>>;
    get(id: string): Promise<Result<InvestigationCase>>;
    create(name: string, description: string, tags: string[]): Promise<Result<InvestigationCase>>;
    update(id: string, patch: { name?: string; description?: string; tags?: string[]; status?: 'open' | 'closed' }): Promise<Result<InvestigationCase>>;
    remove(id: string): Promise<Result<true>>;
    addEvidence(id: string, ev: { kind: EvidenceKind; value: string; label?: string | null; source: string; details?: Evidence['details'] }): Promise<Result<InvestigationCase>>;
    removeEvidence(id: string, evidenceId: string): Promise<Result<InvestigationCase>>;
    addNote(id: string, text: string): Promise<Result<InvestigationCase>>;
    updateNote(id: string, noteId: string, text: string): Promise<Result<InvestigationCase>>;
    removeNote(id: string, noteId: string): Promise<Result<InvestigationCase>>;
    addEvent(id: string, title: string, detail: string | null, time: string | null): Promise<Result<InvestigationCase>>;
  };
  reports: {
    generate(caseId: string, options: ReportOptions): Promise<Result<ReportRecord | null>>;
    list(): Promise<Result<ReportRecord[]>>;
    open(id: string): Promise<Result<true>>;
    reveal(id: string): Promise<Result<true>>;
    remove(id: string): Promise<Result<true>>;
  };
  hunt: {
    search(query: string, taskId: string): Promise<Result<HuntResult>>;
    persistence(): Promise<Result<PersistenceItem[]>>;
    /** Bundled Hayabusa engine, if this build ships it. */
    eventEngine(): Promise<{ available: boolean; version: string | null }>;
    /** Lets the user choose an .evtx file or a folder of logs; returns its path or null. */
    pickEvents(kind: 'file' | 'dir'): Promise<string | null>;
    /** Hayabusa over event logs. `live` = this computer (asks Windows for administrator rights). */
    events(source: EventHuntSource, options: EventHuntOptions, taskId: string): Promise<Result<EventHuntResult>>;
  };
  recovery: {
    detect(path: string): Promise<Result<{ encryption: EncryptionInfo; name: string; sizeBytes: number }>>;
    engine(kind: RecoveryEngineKind): Promise<RecoveryEngineInfo>;
    pickEngine(kind: RecoveryEngineKind): Promise<Result<RecoveryEngineInfo | null>>;
    clearEngine(kind: RecoveryEngineKind): Promise<Result<true>>;
    pickWordlist(): Promise<string | null>;
    start(kind: RecoveryEngineKind, target: string, mode: RecoveryMode, authorized: boolean): Promise<Result<RecoveryStartResult>>;
    stop(id: string): Promise<void>;
    setPaused(id: string, paused: boolean): Promise<boolean>;
    onEvent(cb: (ev: RecoveryEventMsg) => void): () => void;
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
