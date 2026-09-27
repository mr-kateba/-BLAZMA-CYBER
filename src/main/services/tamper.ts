// "Signs of tampering": reads the hosts file directly (any OS) and, on Windows, the proxy settings,
// DNS servers of connected adapters and user-added trusted root certificates with ONE fixed,
// query-only PowerShell script. Nothing is changed.

import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { evaluateTamper, type RawTamperFacts, type TamperReport } from '../../core/tamper';
import { runPowerShellJson } from './powershell';

export const TAMPER_SCRIPT = `
$r = [ordered]@{}
try {
  $is = Get-ItemProperty -LiteralPath 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -ErrorAction Stop
  $r.proxy = @{ enabled = if ($null -eq $is.ProxyEnable) { 0 } else { [int]$is.ProxyEnable }; server = [string]$is.ProxyServer; pac = [string]$is.AutoConfigURL }
} catch { $r.proxy = $null }
try {
  $up = @(Get-NetIPInterface -ConnectionState Connected -ErrorAction Stop | ForEach-Object { $_.InterfaceIndex }) | Sort-Object -Unique
  $r.dns = @(Get-DnsClientServerAddress -ErrorAction Stop | Where-Object { $up -contains $_.InterfaceIndex } | ForEach-Object {
    $alias = [string]$_.InterfaceAlias
    foreach ($s in $_.ServerAddresses) { @{ iface = $alias; server = [string]$s } }
  })
} catch { $r.dns = $null }
try {
  $k = 'HKCU:\\Software\\Microsoft\\SystemCertificates\\Root\\Certificates'
  $list = @()
  if (Test-Path -LiteralPath $k) {
    $list = @(Get-ChildItem -LiteralPath $k -ErrorAction Stop | ForEach-Object {
      $tp = [string]$_.PSChildName
      $c = Get-Item -LiteralPath ('Cert:\\CurrentUser\\Root\\' + $tp) -ErrorAction SilentlyContinue
      @{ thumbprint = $tp; subject = if ($c) { [string]$c.Subject } else { $null }; notAfter = if ($c) { $c.NotAfter.ToUniversalTime().ToString('o') } else { $null } }
    })
  }
  $r.userRoots = $list
} catch { $r.userRoots = $null }
$r | ConvertTo-Json -Depth 5 -Compress
`;

export function hostsPath(): string {
  return process.platform === 'win32' ? join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'drivers', 'etc', 'hosts') : '/etc/hosts';
}

export async function tamperChecks(): Promise<TamperReport> {
  // The hosts file is small; cap the read anyway (malware has padded it to hide entries).
  const hosts = await readFile(hostsPath())
    .then((b) => b.subarray(0, 8 * 1024 * 1024).toString('utf8'))
    .catch(() => null);
  let raw: RawTamperFacts = { hosts };
  if (process.platform === 'win32') {
    const res = await runPowerShellJson<RawTamperFacts>(TAMPER_SCRIPT, { timeoutMs: 45_000 });
    raw = res.ok && res.data ? { ...res.data, hosts } : { hosts, proxy: null, dns: null, userRoots: null };
  }
  const report = evaluateTamper(raw, new Date());
  if (process.platform !== 'win32') {
    for (const f of report.findings) if (f.id !== 'hosts') Object.assign(f, { status: 'unknown', reason: 'unsupported_platform', detail: null, items: [] });
  }
  return report;
}
