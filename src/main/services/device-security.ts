// Device Security Score: collects read-only facts with ONE fixed PowerShell script (no parameters),
// then scores them in src/core/device-security.ts. Nothing here changes any setting; "Open settings"
// only opens a fixed Windows page chosen by id (never a URL from the renderer).

import { shell } from 'electron';
import { evaluateDevice, SETTINGS_URIS, type DeviceSecurityReport, type RawDeviceFacts, type SettingsLink } from '../../core/device-security';
import { runPowerShellJson } from './powershell';

export class DeviceSecurityError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

// Every probe is wrapped in try/catch so one unreadable fact never hides the others.
// Registry helpers return -1 / 'absent' when a value is not set (Windows default applies).
export const DEVICE_SCRIPT = `
$e = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
function RegNum($path, $name) {
  if (-not (Test-Path -LiteralPath $path)) { return -1 }
  $p = Get-ItemProperty -LiteralPath $path -ErrorAction Stop
  if ($null -eq $p.$name) { return -1 }
  return [int]$p.$name
}
$r = [ordered]@{ elevated = $e }
try {
  $m = Get-MpComputerStatus -ErrorAction Stop
  $r.defender = @{ available = $true; rtp = [bool]$m.RealTimeProtectionEnabled; age = [int]$m.AntivirusSignatureAge; tamper = if ($null -ne $m.IsTamperProtected) { [bool]$m.IsTamperProtected } else { $null } }
} catch { $r.defender = @{ available = $false } }
try { $r.firewall = @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { @{ name = [string]$_.Name; enabled = ([string]$_.Enabled -eq 'True') } }) } catch { $r.firewall = $null }
try { $sys = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'; $r.uac = @{ lua = RegNum $sys 'EnableLUA'; consent = RegNum $sys 'ConsentPromptBehaviorAdmin' } } catch { $r.uac = $null }
try {
  $smb = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10'
  $r.smb1Client = if (Test-Path -LiteralPath $smb) { RegNum $smb 'Start' } else { -1 }
} catch { $r.smb1Client = $null }
try {
  $ts = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server'
  $r.rdp = @{ deny = RegNum $ts 'fDenyTSConnections'; nla = RegNum ($ts + '\\WinStations\\RDP-Tcp') 'UserAuthentication' }
} catch { $r.rdp = $null }
try {
  $sb = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State'
  $v = RegNum $sb 'UEFISecureBootEnabled'
  $r.secureBoot = if ($v -eq -1) { $null } else { $v }
} catch { $r.secureBoot = $null }
try {
  $shellApp = [Activator]::CreateInstance([Type]::GetTypeFromProgID('Shell.Application'))
  $b = $shellApp.NameSpace($env:SystemDrive + '\\').Self.ExtendedProperty('System.Volume.BitLockerProtection')
  $r.bitlocker = if ($null -eq $b) { $null } else { [int]$b }
} catch { $r.bitlocker = $null }
$last = $null
try {
  $session = [Activator]::CreateInstance([Type]::GetTypeFromProgID('Microsoft.Update.Session'))
  $searcher = $session.CreateUpdateSearcher()
  $count = $searcher.GetTotalHistoryCount()
  if ($count -gt 0) {
    $ok = @($searcher.QueryHistory(0, [Math]::Min($count, 100)) | Where-Object { $_.ResultCode -eq 2 -and $_.Date })
    if ($ok.Count -gt 0) { $last = ($ok | Sort-Object -Property Date -Descending | Select-Object -First 1).Date }
  }
} catch { }
try {
  $hf = Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } | Sort-Object -Property InstalledOn -Descending | Select-Object -First 1
  if ($hf -and ($null -eq $last -or $hf.InstalledOn -gt $last)) { $last = $hf.InstalledOn }
} catch { }
$r.lastUpdate = if ($last) { ([datetime]$last).ToUniversalTime().ToString('o') } else { $null }
try {
  $wl = 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'
  $p = Get-ItemProperty -LiteralPath $wl -ErrorAction Stop
  $r.autoLogon = if ($null -eq $p.AutoAdminLogon) { 'absent' } else { [string]$p.AutoAdminLogon }
} catch { $r.autoLogon = $null }
try { $g = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -like 'S-1-5-21-*-501' } | Select-Object -First 1; $r.guestEnabled = if ($g) { [bool]$g.Enabled } else { $null } } catch { $r.guestEnabled = $null }
try { $r.lsaPpl = RegNum 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' 'RunAsPPL' } catch { $r.lsaPpl = $null }
try { $r.vbs = [int](Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop).VirtualizationBasedSecurityStatus } catch { $r.vbs = $null }
try { $r.execPolicy = [string](Get-ExecutionPolicy) } catch { $r.execPolicy = $null }
$r.tpm = $null
if ($e) { try { $t = Get-Tpm -ErrorAction Stop; $r.tpm = @{ present = [bool]$t.TpmPresent; ready = [bool]$t.TpmReady } } catch { } }
$r | ConvertTo-Json -Depth 5 -Compress
`;

const CACHE_MS = 10 * 60_000;
let cache: { at: number; report: DeviceSecurityReport } | null = null;
let inflight: Promise<DeviceSecurityReport> | null = null;

async function collect(): Promise<DeviceSecurityReport> {
  const res = await runPowerShellJson<RawDeviceFacts>(DEVICE_SCRIPT, { timeoutMs: 60_000 });
  if (!res.ok) throw new DeviceSecurityError(res.error);
  return evaluateDevice(res.data ?? {}, new Date());
}

/** Cached for 10 minutes; at most one PowerShell run at a time. `force` re-checks now. */
export function deviceSecurity(force = false): Promise<DeviceSecurityReport> {
  if (process.platform !== 'win32') return Promise.reject(new DeviceSecurityError('unsupported_platform'));
  if (!force && cache && Date.now() - cache.at < CACHE_MS) return Promise.resolve(cache.report);
  inflight ??= collect()
    .then((report) => {
      cache = { at: Date.now(), report };
      return report;
    })
    .finally(() => {
      inflight = null;
    });
  return inflight;
}

/** Opens a fixed Windows settings page by id. */
export async function openSettingsPage(link: unknown): Promise<void> {
  if (process.platform !== 'win32') throw new DeviceSecurityError('unsupported_platform');
  if (typeof link !== 'string' || !Object.prototype.hasOwnProperty.call(SETTINGS_URIS, link)) throw new DeviceSecurityError('invalid_input');
  await shell.openExternal(SETTINGS_URIS[link as SettingsLink]);
}
