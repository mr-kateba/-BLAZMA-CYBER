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

export interface FileAnalysis {
  path: string;
  name: string;
  sizeBytes: number;
  created: string | null;
  modified: string | null;
  type: FileTypeInfo;
  hashes: HashResult;
  signature: SignatureInfo;
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
  kind: 'file_analysis' | 'hash_file' | 'hash_text' | 'hash_identify' | 'hash_compare';
  /** Displayable subject, e.g. a filename. Never a secret. */
  subject: string;
  summaryKey: string;
}

export interface TaskProgress {
  taskId: string;
  processedBytes: number;
  totalBytes: number;
  stage: 'hashing' | 'analyzing' | 'done';
}

export interface AppInfo {
  version: string;
  platform: string;
  dataDir: string;
  electron: string;
  secureStorageAvailable: boolean;
}

export type ApiKeyService = 'virustotal' | 'abuseipdb' | 'shodan' | 'censys';

export type ClearTarget = 'activity' | 'network_activity' | 'logs' | 'temp';

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
  secrets: {
    status(): Promise<Record<ApiKeyService, boolean>>;
    set(service: ApiKeyService, value: string): Promise<Result<true>>;
    remove(service: ApiKeyService): Promise<Result<true>>;
  };
}
