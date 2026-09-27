// Read-only local forensics.
//
// Windows: fixed PowerShell scripts that only QUERY (Get-*, CIM, registry reads). Nothing here
// modifies the system. Parameters (log name, count, path lists) arrive via BLAZMA_ARG_* env vars.
// Linux: /proc-based fallbacks for processes and connections, so the module is useful (and testable)
// everywhere; Windows-only modules report `unsupported_platform` honestly.
//
// Access denied is expected for some data as a standard user; modules degrade and say so.

import { readFile, readdir, readlink } from 'node:fs/promises';
import { writeFileSync, rmSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import type {
  ConnectionRow, DriverRow, EventLogName, EventRow, ForensicsResult, ProcessRow, ServiceRow, SignatureRow, SoftwareRow, StartupRow,
  TaskRow, UsbRow, UserRow,
} from '../../shared/api';
import { isUnquotedServicePath, parseProcNet, parseServiceBinary } from '../../core/netparse';
import { runPowerShellJson } from './powershell';
import { subDir } from './paths';

export class ForensicsError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

const isWin = () => process.platform === 'win32';
const now = () => new Date().toISOString();

/** Wraps any script so it also reports whether the session is elevated. */
const ELEVATED = "$e = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);";
const wrap = (body: string) => `${ELEVATED}\n$rows = @(\n${body}\n)\n@{ elevated = $e; rows = $rows } | ConvertTo-Json -Depth 5 -Compress`;
const iso = (expr: string) => `if (${expr}) { ([datetime]${expr}).ToString('o') } else { $null }`;

export const SCRIPTS = {
  processes: wrap(`
$users = @{}
try { Get-Process -IncludeUserName -ErrorAction Stop | ForEach-Object { $users[[int]$_.Id] = [string]$_.UserName } } catch { }
Get-CimInstance -ClassName Win32_Process -ErrorAction Stop | ForEach-Object {
  @{
    pid = [int]$_.ProcessId
    ppid = [int]$_.ParentProcessId
    name = [string]$_.Name
    path = [string]$_.ExecutablePath
    cmd = [string]$_.CommandLine
    user = $users[[int]$_.ProcessId]
    started = ${iso('$_.CreationDate')}
  }
}`),
  connections: wrap(`
$names = @{}
Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $names[[int]$_.Id] = [string]$_.ProcessName }
Get-NetTCPConnection -ErrorAction Stop | ForEach-Object {
  @{ p = 'TCP'; la = [string]$_.LocalAddress; lp = [int]$_.LocalPort; ra = [string]$_.RemoteAddress; rp = [int]$_.RemotePort; st = [string]$_.State; pid = [int]$_.OwningProcess; pn = $names[[int]$_.OwningProcess] }
}
Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object {
  @{ p = 'UDP'; la = [string]$_.LocalAddress; lp = [int]$_.LocalPort; ra = $null; rp = $null; st = $null; pid = [int]$_.OwningProcess; pn = $names[[int]$_.OwningProcess] }
}`),
  services: wrap(`
Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | ForEach-Object {
  @{ name = [string]$_.Name; display = [string]$_.DisplayName; state = [string]$_.State; mode = [string]$_.StartMode; path = [string]$_.PathName; account = [string]$_.StartName; pid = [int]$_.ProcessId; desc = [string]$_.Description }
}`),
  drivers: wrap(`
Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction Stop | ForEach-Object {
  @{ name = [string]$_.Name; display = [string]$_.DisplayName; state = [string]$_.State; mode = [string]$_.StartMode; path = [string]$_.PathName }
}`),
  startup: wrap(`
Get-CimInstance -ClassName Win32_StartupCommand -ErrorAction Stop | ForEach-Object {
  @{ name = [string]$_.Name; command = [string]$_.Command; location = [string]$_.Location; user = [string]$_.User }
}`),
  tasks: wrap(`
Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
  $acts = @($_.Actions | ForEach-Object { if ($_.Execute) { ([string]$_.Execute + ' ' + [string]$_.Arguments).Trim() } elseif ($_.ClassId) { 'COM ' + [string]$_.ClassId } })
  @{ name = [string]$_.TaskName; path = [string]$_.TaskPath; state = [string]$_.State; author = [string]$_.Author; actions = $acts }
}`),
  users: wrap(`
$admins = @()
try { $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { ([string]$_.Name).Split('\\')[-1] }) } catch { }
Get-LocalUser -ErrorAction Stop | ForEach-Object {
  @{ name = [string]$_.Name; enabled = [bool]$_.Enabled; last = ${iso('$_.LastLogon')}; desc = [string]$_.Description; admin = ($admins -contains [string]$_.Name) }
}`),
  software: wrap(`
$keys = @(
  @{ p = 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'; s = 'machine' },
  @{ p = 'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'; s = 'machine' },
  @{ p = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'; s = 'user' }
)
foreach ($k in $keys) {
  Get-ItemProperty -Path $k.p -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and -not $_.SystemComponent } | ForEach-Object {
    @{ name = [string]$_.DisplayName; version = [string]$_.DisplayVersion; publisher = [string]$_.Publisher; date = [string]$_.InstallDate; scope = $k.s }
  }
}`),
  usb: wrap(`
$root = 'HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR'
# No USBSTOR key simply means no USB storage device was ever attached: an empty result, not an error.
if (Test-Path -LiteralPath $root) { Get-ChildItem -LiteralPath $root -ErrorAction Stop | ForEach-Object {
  $vp = $_.PSChildName
  Get-ChildItem -Path $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
    $fn = (Get-ItemProperty -Path $_.PSPath -Name FriendlyName -ErrorAction SilentlyContinue).FriendlyName
    @{ name = [string]$fn; serial = [string]$_.PSChildName; vp = [string]$vp }
  }
} }`),
  // Parameters via env: log name (allow-listed in TS), max events, levels "1,2,3"
  events: wrap(`
$levels = @(([string]$env:BLAZMA_ARG_LEVELS).Split(',') | Where-Object { $_ } | ForEach-Object { [int]$_ })
$filter = @{ LogName = [string]$env:BLAZMA_ARG_LOG }
if ($levels.Count -gt 0) { $filter.Level = $levels }
Get-WinEvent -FilterHashtable $filter -MaxEvents ([int]$env:BLAZMA_ARG_MAX) -ErrorAction Stop | ForEach-Object {
  $msg = [string]$_.Message
  if ($msg.Length -gt 2000) { $msg = $msg.Substring(0, 2000) }
  @{ time = ${iso('$_.TimeCreated')}; id = [int]$_.Id; level = [string]$_.LevelDisplayName; provider = [string]$_.ProviderName; msg = $msg }
}`),
  // Batch Authenticode check: paths come from a temp file (one per line), never the script text.
  signatures: wrap(`
Get-Content -LiteralPath $env:BLAZMA_ARG_LIST -Encoding UTF8 -ErrorAction Stop | Where-Object { $_ } | ForEach-Object {
  $p = $_
  try {
    $s = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop
    $c = $s.SignerCertificate
    @{ path = $p; status = [string]$s.Status; subject = if ($c) { [string]$c.Subject } else { $null } }
  } catch { @{ path = $p; status = 'UnknownError'; subject = $null } }
}`),
};

interface Wrapped<T> {
  elevated: boolean;
  rows: T[] | T | null;
}

async function runScript<T>(script: string, args?: Record<string, string>, timeoutMs = 60_000): Promise<{ rows: T[]; elevated: boolean }> {
  if (!isWin()) throw new ForensicsError('unsupported_platform');
  const r = await runPowerShellJson<Wrapped<T>>(script, { args, timeoutMs });
  if (!r.ok) {
    if (r.error === 'powershell_failed' && /access.+denied|UnauthorizedAccess|privilege/i.test(r.detail ?? '')) throw new ForensicsError('access_denied');
    if (r.error === 'powershell_failed' && /No events were found/i.test(r.detail ?? '')) return { rows: [], elevated: false };
    throw new ForensicsError(r.error);
  }
  const rows = r.data.rows == null ? [] : Array.isArray(r.data.rows) ? r.data.rows : [r.data.rows];
  return { rows, elevated: !!r.data.elevated };
}

const s = (v: unknown): string | null => (typeof v === 'string' && v.trim() ? v.trim() : null);
const n = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);

function result<T>(rows: T[], source: ForensicsResult<T>['source'], elevated: boolean | null, partial?: string): ForensicsResult<T> {
  return { rows, collectedAt: now(), source, elevated, ...(partial ? { partial } : {}) };
}

// ---------------------------------------------------------------- Linux fallbacks (procfs)

async function linuxUsers(): Promise<Map<number, string>> {
  const m = new Map<number, string>();
  try {
    for (const line of (await readFile('/etc/passwd', 'utf8')).split('\n')) {
      const f = line.split(':');
      if (f.length > 2) m.set(Number(f[2]), f[0]!);
    }
  } catch {
    /* ignore */
  }
  return m;
}

async function linuxProcesses(): Promise<ForensicsResult<ProcessRow>> {
  const users = await linuxUsers();
  const pids = (await readdir('/proc')).filter((d) => /^\d+$/.test(d));
  let denied = 0;
  const bootTime = await readFile('/proc/stat', 'utf8').then((t) => Number(/btime (\d+)/.exec(t)?.[1] ?? 0)).catch(() => 0);
  const hz = 100;
  const rows = await Promise.all(
    pids.map(async (p): Promise<ProcessRow | null> => {
      try {
        const stat = await readFile(`/proc/${p}/stat`, 'utf8');
        const name = stat.slice(stat.indexOf('(') + 1, stat.lastIndexOf(')'));
        const rest = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
        const ppid = Number(rest[1]);
        const startTicks = Number(rest[19]);
        const status = await readFile(`/proc/${p}/status`, 'utf8').catch(() => '');
        const uid = Number(/^Uid:\s+(\d+)/m.exec(status)?.[1] ?? NaN);
        const cmd = (await readFile(`/proc/${p}/cmdline`, 'utf8').catch(() => '')).replace(/\0+$/, '').replace(/\0/g, ' ');
        let path: string | null = null;
        try {
          path = await readlink(`/proc/${p}/exe`);
        } catch {
          denied++;
        }
        return {
          pid: Number(p),
          ppid: Number.isFinite(ppid) ? ppid : null,
          name,
          path,
          commandLine: cmd || null,
          user: Number.isFinite(uid) ? users.get(uid) ?? String(uid) : null,
          started: bootTime && Number.isFinite(startTicks) ? new Date((bootTime + startTicks / hz) * 1000).toISOString() : null,
        };
      } catch {
        return null; // process exited while reading
      }
    }),
  );
  const list = rows.filter((r): r is ProcessRow => !!r).sort((a, b) => a.pid - b.pid);
  return result(list, 'procfs', process.getuid?.() === 0, denied > 0 ? 'forensics.partialAccess' : undefined);
}

/** Maps socket inode → pid by walking /proc/<pid>/fd (best effort; needs same-user or root). */
async function inodeToPid(): Promise<Map<number, number>> {
  const map = new Map<number, number>();
  const pids = (await readdir('/proc')).filter((d) => /^\d+$/.test(d));
  await Promise.all(
    pids.map(async (p) => {
      try {
        for (const fd of await readdir(`/proc/${p}/fd`)) {
          const l = await readlink(`/proc/${p}/fd/${fd}`).catch(() => '');
          const m = /^socket:\[(\d+)\]$/.exec(l);
          if (m) map.set(Number(m[1]), Number(p));
        }
      } catch {
        /* no access */
      }
    }),
  );
  return map;
}

async function linuxConnections(): Promise<ForensicsResult<ConnectionRow>> {
  const files: Array<[string, 'TCP' | 'UDP']> = [['/proc/net/tcp', 'TCP'], ['/proc/net/tcp6', 'TCP'], ['/proc/net/udp', 'UDP'], ['/proc/net/udp6', 'UDP']];
  const entries = (await Promise.all(files.map(async ([f, proto]) => parseProcNet(await readFile(f, 'utf8').catch(() => ''), proto)))).flat();
  const owners = await inodeToPid();
  const names = new Map<number, string>();
  await Promise.all(
    [...new Set(owners.values())].map(async (pid) => {
      const comm = await readFile(`/proc/${pid}/comm`, 'utf8').catch(() => '');
      if (comm) names.set(pid, comm.trim());
    }),
  );
  const rows: ConnectionRow[] = entries.map((e) => {
    const pid = owners.get(e.inode) ?? null;
    return { protocol: e.protocol, localAddress: e.localAddress, localPort: e.localPort, remoteAddress: e.remoteAddress, remotePort: e.remotePort, state: e.state, pid, process: pid !== null ? names.get(pid) ?? null : null };
  });
  const unknown = rows.filter((r) => r.pid === null).length;
  return result(rows, 'procfs', process.getuid?.() === 0, unknown > 0 ? 'forensics.partialAccess' : undefined);
}

// ---------------------------------------------------------------- public API

export async function processes(): Promise<ForensicsResult<ProcessRow>> {
  if (!isWin()) return linuxProcesses();
  const r = await runScript<Record<string, unknown>>(SCRIPTS.processes);
  const rows = r.rows.map((x) => ({
    pid: n(x.pid) ?? 0,
    ppid: n(x.ppid),
    name: s(x.name) ?? '?',
    path: s(x.path),
    commandLine: s(x.cmd),
    user: s(x.user),
    started: s(x.started),
  }));
  const noPath = rows.filter((x) => !x.path).length;
  return result(rows.sort((a, b) => a.pid - b.pid), 'powershell', r.elevated, !r.elevated && noPath > 0 ? 'forensics.needsAdminFull' : undefined);
}

export async function connections(): Promise<ForensicsResult<ConnectionRow>> {
  if (!isWin()) return linuxConnections();
  const r = await runScript<Record<string, unknown>>(SCRIPTS.connections);
  const rows: ConnectionRow[] = r.rows.map((x) => ({
    protocol: x.p === 'UDP' ? 'UDP' : 'TCP',
    localAddress: s(x.la) ?? '',
    localPort: n(x.lp) ?? 0,
    remoteAddress: s(x.ra),
    remotePort: n(x.rp),
    state: s(x.st),
    pid: n(x.pid),
    process: s(x.pn),
  }));
  return result(rows, 'powershell', r.elevated);
}

export async function services(): Promise<ForensicsResult<ServiceRow>> {
  const r = await runScript<Record<string, unknown>>(SCRIPTS.services);
  const root = process.env.SystemRoot || 'C:\\Windows';
  return result(
    r.rows.map((x) => ({
      name: s(x.name) ?? '?',
      displayName: s(x.display),
      state: s(x.state),
      startMode: s(x.mode),
      commandLine: s(x.path),
      binaryPath: parseServiceBinary(s(x.path), root),
      account: s(x.account),
      pid: n(x.pid) || null,
      description: s(x.desc),
      unquotedPath: isUnquotedServicePath(s(x.path)),
    })),
    'powershell',
    r.elevated,
  );
}

export async function drivers(): Promise<ForensicsResult<DriverRow>> {
  const r = await runScript<Record<string, unknown>>(SCRIPTS.drivers);
  const root = process.env.SystemRoot || 'C:\\Windows';
  return result(
    r.rows.map((x) => ({ name: s(x.name) ?? '?', displayName: s(x.display), state: s(x.state), startMode: s(x.mode), path: parseServiceBinary(s(x.path), root) })),
    'powershell',
    r.elevated,
  );
}

export async function startup(): Promise<ForensicsResult<StartupRow>> {
  const r = await runScript<Record<string, unknown>>(SCRIPTS.startup);
  return result(r.rows.map((x) => ({ name: s(x.name) ?? '?', command: s(x.command) ?? '', location: s(x.location) ?? '', user: s(x.user) })), 'powershell', r.elevated);
}

export async function tasks(): Promise<ForensicsResult<TaskRow>> {
  const r = await runScript<Record<string, unknown>>(SCRIPTS.tasks, undefined, 120_000);
  return result(
    r.rows.map((x) => {
      const path = s(x.path) ?? '\\';
      return {
        name: s(x.name) ?? '?',
        path,
        state: s(x.state),
        author: s(x.author),
        actions: Array.isArray(x.actions) ? x.actions.map(String).filter(Boolean) : typeof x.actions === 'string' ? [x.actions] : [],
        microsoft: /^\\Microsoft\\/i.test(path),
      };
    }),
    'powershell',
    r.elevated,
  );
}

export async function users(): Promise<ForensicsResult<UserRow>> {
  const r = await runScript<Record<string, unknown>>(SCRIPTS.users);
  return result(r.rows.map((x) => ({ name: s(x.name) ?? '?', enabled: typeof x.enabled === 'boolean' ? x.enabled : null, lastLogon: s(x.last), description: s(x.desc), admin: x.admin === true })), 'powershell', r.elevated);
}

export async function software(): Promise<ForensicsResult<SoftwareRow>> {
  const r = await runScript<Record<string, unknown>>(SCRIPTS.software);
  const seen = new Set<string>();
  const rows: SoftwareRow[] = [];
  for (const x of r.rows) {
    const key = `${s(x.name)}|${s(x.version)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const d = s(x.date);
    rows.push({
      name: s(x.name) ?? '?',
      version: s(x.version),
      publisher: s(x.publisher),
      installDate: d && /^\d{8}$/.test(d) ? `${d.slice(0, 4)}-${d.slice(4, 6)}-${d.slice(6, 8)}` : d,
      scope: x.scope === 'user' ? 'user' : 'machine',
    });
  }
  return result(rows.sort((a, b) => a.name.localeCompare(b.name)), 'powershell', r.elevated);
}

export async function usb(): Promise<ForensicsResult<UsbRow>> {
  const r = await runScript<Record<string, unknown>>(SCRIPTS.usb);
  return result(r.rows.map((x) => ({ name: s(x.name) ?? s(x.vp) ?? '?', serial: s(x.serial), vendorProduct: s(x.vp) })), 'powershell', r.elevated);
}

export const EVENT_LOGS: readonly EventLogName[] = [
  'System',
  'Application',
  'Security',
  'Windows PowerShell',
  'Microsoft-Windows-PowerShell/Operational',
  'Microsoft-Windows-Windows Defender/Operational',
];

export async function events(log: unknown, levels: unknown, max: unknown): Promise<ForensicsResult<EventRow>> {
  if (typeof log !== 'string' || !(EVENT_LOGS as readonly string[]).includes(log)) throw new ForensicsError('invalid_input');
  const lv = Array.isArray(levels) ? levels.filter((x): x is number => Number.isInteger(x) && x >= 1 && x <= 5) : [];
  const count = typeof max === 'number' && Number.isInteger(max) ? Math.min(Math.max(max, 1), 500) : 100;
  try {
    const r = await runScript<Record<string, unknown>>(SCRIPTS.events, { LOG: log, LEVELS: lv.join(','), MAX: String(count) }, 90_000);
    return result(
      r.rows.map((x) => ({ time: s(x.time), id: n(x.id) ?? 0, level: s(x.level), provider: s(x.provider), message: s(x.msg) ?? '' })),
      'powershell',
      r.elevated,
    );
  } catch (e) {
    // The Security log requires administrator rights: say exactly that.
    if (log === 'Security' && e instanceof ForensicsError && (e.code === 'access_denied' || e.code === 'powershell_failed')) throw new ForensicsError('security_log_needs_admin');
    throw e;
  }
}

/** Verifies Authenticode for many paths in one PowerShell run (paths passed via a temp file). */
export async function signatures(paths: unknown): Promise<SignatureRow[]> {
  if (!Array.isArray(paths)) throw new ForensicsError('invalid_input');
  const list = [...new Set(paths.filter((p): p is string => typeof p === 'string' && /^[a-zA-Z]:\\/.test(p) && !/[\r\n\0]/.test(p)))].slice(0, 2000);
  if (!isWin()) throw new ForensicsError('unsupported_platform');
  if (list.length === 0) return [];
  const tmp = join(subDir('temp'), `sig-list-${process.pid}-${Date.now()}.txt`);
  writeFileSync(tmp, list.join('\r\n'), { encoding: 'utf8', mode: 0o600 });
  try {
    const r = await runScript<Record<string, unknown>>(SCRIPTS.signatures, { LIST: tmp }, 300_000);
    const map: Record<string, SignatureRow['status']> = { Valid: 'valid', NotSigned: 'not_signed', HashMismatch: 'hash_mismatch', NotTrusted: 'not_trusted', UnknownError: 'unknown_error' };
    return r.rows.map((x) => {
      const subject = s(x.subject);
      return {
        path: s(x.path) ?? '',
        status: map[String(x.status)] ?? 'other',
        publisher: subject ? /CN=("?)([^,"]+)\1/.exec(subject)?.[2]?.trim() ?? subject : null,
      };
    });
  } finally {
    rmSync(tmp, { force: true });
  }
}

/** Current user's PSReadLine history (read directly, never logged). Shown only on explicit request. */
export async function powershellHistory(): Promise<{ path: string; lines: string[]; total: number }> {
  const base = isWin() ? process.env.APPDATA || join(homedir(), 'AppData', 'Roaming') : join(homedir(), '.local', 'share');
  const path = isWin()
    ? join(base, 'Microsoft', 'Windows', 'PowerShell', 'PSReadLine', 'ConsoleHost_history.txt')
    : join(base, 'powershell', 'PSReadLine', 'ConsoleHost_history.txt');
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    throw new ForensicsError(code === 'ENOENT' ? 'ps_history_missing' : 'access_denied');
  }
  const all = text.split(/\r?\n/).filter((l) => l.trim());
  return { path, lines: all.slice(-500), total: all.length };
}
