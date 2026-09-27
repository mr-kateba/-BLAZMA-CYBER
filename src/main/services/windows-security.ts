import type { DefenderStatus, FirewallStatus, SecurityStatus, SignatureInfo } from '../../shared/api';
import { runPowerShellJson } from './powershell';

// Read-only status queries. Nothing here changes Defender or firewall configuration.
const SECURITY_SCRIPT = `
$r = [ordered]@{}
try { $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop; $r.os = @{ caption = [string]$os.Caption; version = [string]$os.Version; build = [string]$os.BuildNumber } } catch { $r.os = $null }
try { $r.cores = [int](Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Measure-Object -Property NumberOfCores -Sum).Sum } catch { $r.cores = $null }
try { $r.processes = @(Get-Process -ErrorAction Stop).Count } catch { $r.processes = $null }
try {
  $m = Get-MpComputerStatus -ErrorAction Stop
  $r.defender = @{
    available = $true
    av = [bool]$m.AntivirusEnabled
    rtp = [bool]$m.RealTimeProtectionEnabled
    mode = [string]$m.AMRunningMode
    sig = [string]$m.AntivirusSignatureVersion
    age = [int]$m.AntivirusSignatureAge
    qs = if ($m.QuickScanEndTime) { $m.QuickScanEndTime.ToString('o') } else { $null }
    fs = if ($m.FullScanEndTime) { $m.FullScanEndTime.ToString('o') } else { $null }
  }
} catch { $r.defender = @{ available = $false; error = [string]$_.Exception.GetType().Name } }
try { $r.firewall = @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { @{ name = [string]$_.Name; enabled = ([string]$_.Enabled -eq 'True') } }) } catch { $r.firewall = $null }
$r | ConvertTo-Json -Depth 5 -Compress
`;

interface RawSecurity {
  os: { caption: string; version: string; build: string } | null;
  cores: number | null;
  processes: number | null;
  defender: { available: boolean; error?: string; av?: boolean; rtp?: boolean; mode?: string; sig?: string; age?: number; qs?: string | null; fs?: string | null };
  firewall: Array<{ name: string; enabled: boolean }> | { name: string; enabled: boolean } | null;
}

export interface WindowsFacts {
  osCaption: string | null;
  osVersion: string | null;
  osBuild: string | null;
  physicalCores: number | null;
  processCount: number | null;
  security: SecurityStatus;
}

let cache: { at: number; value: WindowsFacts } | null = null;

export async function getWindowsFacts(maxAgeMs = 30000): Promise<WindowsFacts> {
  if (cache && Date.now() - cache.at < maxAgeMs) return cache.value;
  const checkedAt = new Date().toISOString();

  if (process.platform !== 'win32') {
    const unavailable = { available: false, reason: 'unsupported_platform' };
    return {
      osCaption: null, osVersion: null, osBuild: null, physicalCores: null, processCount: null,
      security: { platformSupported: false, defender: unavailable, firewall: unavailable, checkedAt },
    };
  }

  const res = await runPowerShellJson<RawSecurity>(SECURITY_SCRIPT, { timeoutMs: 25000 });
  if (!res.ok) {
    const failed = { available: false, reason: res.error };
    return {
      osCaption: null, osVersion: null, osBuild: null, physicalCores: null, processCount: null,
      security: { platformSupported: true, defender: failed, firewall: failed, checkedAt },
    };
  }
  const d = res.data;
  const defender: DefenderStatus = d.defender?.available
    ? {
        available: true,
        antivirusEnabled: d.defender.av ? 'on' : 'off',
        realTimeProtection: d.defender.rtp ? 'on' : 'off',
        signatureVersion: d.defender.sig ?? null,
        signatureAgeDays: typeof d.defender.age === 'number' ? d.defender.age : null,
        lastQuickScan: d.defender.qs ?? null,
        lastFullScan: d.defender.fs ?? null,
      }
    : { available: false, reason: 'defender_unavailable' };
  const profiles = d.firewall == null ? null : Array.isArray(d.firewall) ? d.firewall : [d.firewall];
  const firewall: FirewallStatus = profiles ? { available: true, profiles } : { available: false, reason: 'firewall_unavailable' };

  const value: WindowsFacts = {
    osCaption: d.os?.caption ?? null,
    osVersion: d.os?.version ?? null,
    osBuild: d.os?.build ?? null,
    physicalCores: d.cores ?? null,
    processCount: d.processes ?? null,
    security: { platformSupported: true, defender, firewall, checkedAt },
  };
  cache = { at: Date.now(), value };
  return value;
}

// The file path arrives via $env:BLAZMA_ARG_PATH, never inside the script text.
const SIGNATURE_SCRIPT = `
$s = Get-AuthenticodeSignature -LiteralPath $env:BLAZMA_ARG_PATH -ErrorAction Stop
$c = $s.SignerCertificate
@{
  status = [string]$s.Status
  subject = if ($c) { [string]$c.Subject } else { $null }
  issuer = if ($c) { [string]$c.Issuer } else { $null }
  from = if ($c) { $c.NotBefore.ToString('o') } else { $null }
  to = if ($c) { $c.NotAfter.ToString('o') } else { $null }
  thumb = if ($c) { [string]$c.Thumbprint } else { $null }
} | ConvertTo-Json -Compress
`;

function cnOf(dn: string | null): string | null {
  if (!dn) return null;
  const m = /CN=("?)([^,"]+)\1/.exec(dn);
  return m ? m[2]!.trim() : dn;
}

export async function verifySignature(path: string): Promise<SignatureInfo> {
  if (process.platform !== 'win32') return { checked: false, reason: 'unsupported_platform' };
  const res = await runPowerShellJson<{ status: string; subject: string | null; issuer: string | null; from: string | null; to: string | null; thumb: string | null }>(
    SIGNATURE_SCRIPT,
    { args: { PATH: path }, timeoutMs: 30000 },
  );
  if (!res.ok) return { checked: false, reason: res.error };
  const map: Record<string, SignatureInfo['status']> = {
    Valid: 'valid', NotSigned: 'not_signed', HashMismatch: 'hash_mismatch', NotTrusted: 'not_trusted', UnknownError: 'unknown_error',
  };
  return {
    checked: true,
    status: map[res.data.status] ?? 'other',
    rawStatus: res.data.status,
    publisher: cnOf(res.data.subject),
    issuer: cnOf(res.data.issuer),
    validFrom: res.data.from,
    validTo: res.data.to,
    thumbprint: res.data.thumb,
  };
}

export const __scriptsForTest = { SECURITY_SCRIPT, SIGNATURE_SCRIPT };
