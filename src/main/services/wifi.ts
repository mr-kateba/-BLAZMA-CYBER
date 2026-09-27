// Wi-Fi Center (read-only): the current Wi-Fi connection, nearby networks and the saved networks.
//
// - Live facts come from the Windows WLAN API (wlanapi.dll) through a small C# reader compiled by
//   Windows PowerShell's Add-Type. The API returns numbers (auth/cipher algorithm ids, dBm, kHz), so
//   nothing depends on the Windows display language — unlike `netsh wlan show …` text.
// - Saved networks come from `netsh wlan export profile` WITHOUT key=clear; the <sharedKey> element
//   (which would hold the encrypted key) is removed before anything leaves PowerShell, and the
//   exported files are deleted immediately. Blazma never reads or shows a Wi-Fi password.
// - Windows 11 treats Wi-Fi scan results as location data: without location permission for desktop
//   apps the lists come back "access denied", which is reported as such (never as "no networks").

import { randomUUID } from 'node:crypto';
import { mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { buildWifiState, channelUsage, parseProfileXml, wifiFindings, type RawWlan, type SavedProfile } from '../../core/wifi';
import type { WifiReport } from '../../shared/api';
import { subDir } from './paths';
import { runPowerShellJson } from './powershell';

export class WifiError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

// C# 5 (the compiler Windows PowerShell 5.1 ships): no string interpolation, no ?. or nameof.
// Offsets follow the documented x64/x86 layouts of the WLAN structures (all 4-byte fields except
// where noted): WLAN_INTERFACE_INFO = 532, WLAN_AVAILABLE_NETWORK = 628, WLAN_BSS_ENTRY = 360.
export const WLAN_CSHARP = `
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public class BlazmaWlanConn { public string ssid; public string bssid; public string profile; public int quality; public int rx; public int tx; public int phy; public bool secEnabled; public int auth; public int cipher; }
public class BlazmaWlanNet { public string ssid; public int bssType; public int bssids; public int quality; public bool secEnabled; public int auth; public int cipher; public int flags; }
public class BlazmaWlanBss { public string ssid; public string bssid; public int rssi; public int quality; public int freq; public int phy; public int cap; }
public class BlazmaWlanIf { public string name; public int state; public BlazmaWlanConn conn; public int connError; public List<BlazmaWlanNet> nets; public int netsError; public List<BlazmaWlanBss> bss; public int bssError; }
public class BlazmaWlanResult { public int openError; public List<BlazmaWlanIf> interfaces = new List<BlazmaWlanIf>(); }

public static class BlazmaWlan {
  [DllImport("wlanapi.dll")] static extern int WlanOpenHandle(int ver, IntPtr r, out int neg, out IntPtr h);
  [DllImport("wlanapi.dll")] static extern int WlanCloseHandle(IntPtr h, IntPtr r);
  [DllImport("wlanapi.dll")] static extern int WlanEnumInterfaces(IntPtr h, IntPtr r, out IntPtr list);
  [DllImport("wlanapi.dll")] static extern int WlanQueryInterface(IntPtr h, ref Guid g, int op, IntPtr r, out int size, out IntPtr data, IntPtr vt);
  [DllImport("wlanapi.dll")] static extern int WlanGetAvailableNetworkList(IntPtr h, ref Guid g, int flags, IntPtr r, out IntPtr list);
  [DllImport("wlanapi.dll")] static extern int WlanGetNetworkBssList(IntPtr h, ref Guid g, IntPtr ssid, int type, bool sec, IntPtr r, out IntPtr list);
  [DllImport("wlanapi.dll")] static extern void WlanFreeMemory(IntPtr p);

  static string Ssid(IntPtr p) {
    int len = Marshal.ReadInt32(p);
    if (len <= 0 || len > 32) return "";
    byte[] b = new byte[len];
    Marshal.Copy(IntPtr.Add(p, 4), b, 0, len);
    return Encoding.UTF8.GetString(b);
  }
  static string Mac(IntPtr p) {
    byte[] b = new byte[6];
    Marshal.Copy(p, b, 0, 6);
    return BitConverter.ToString(b).Replace('-', ':');
  }
  static string WStr(IntPtr p, int chars) {
    string s = Marshal.PtrToStringUni(p, chars);
    int z = s.IndexOf('\\0');
    return z >= 0 ? s.Substring(0, z) : s;
  }

  public static BlazmaWlanResult Read() {
    BlazmaWlanResult res = new BlazmaWlanResult();
    IntPtr h; int neg;
    int e = WlanOpenHandle(2, IntPtr.Zero, out neg, out h);
    if (e != 0) { res.openError = e; return res; }
    try {
      IntPtr list;
      e = WlanEnumInterfaces(h, IntPtr.Zero, out list);
      if (e != 0) { res.openError = e; return res; }
      try {
        int n = Marshal.ReadInt32(list);
        for (int i = 0; i < n && i < 16; i++) {
          IntPtr item = IntPtr.Add(list, 8 + i * 532);
          Guid g = (Guid)Marshal.PtrToStructure(item, typeof(Guid));
          BlazmaWlanIf wi = new BlazmaWlanIf();
          wi.name = WStr(IntPtr.Add(item, 16), 256);
          wi.state = Marshal.ReadInt32(item, 528);

          int size; IntPtr data;
          e = WlanQueryInterface(h, ref g, 7, IntPtr.Zero, out size, out data, IntPtr.Zero);
          wi.connError = e;
          if (e == 0) {
            try {
              BlazmaWlanConn c = new BlazmaWlanConn();
              c.profile = WStr(IntPtr.Add(data, 8), 256);
              c.ssid = Ssid(IntPtr.Add(data, 520));
              c.bssid = Mac(IntPtr.Add(data, 560));
              c.phy = Marshal.ReadInt32(data, 568);
              c.quality = Marshal.ReadInt32(data, 576);
              c.rx = Marshal.ReadInt32(data, 580);
              c.tx = Marshal.ReadInt32(data, 584);
              c.secEnabled = Marshal.ReadInt32(data, 588) != 0;
              c.auth = Marshal.ReadInt32(data, 596);
              c.cipher = Marshal.ReadInt32(data, 600);
              wi.conn = c;
            } finally { WlanFreeMemory(data); }
          }

          IntPtr nl;
          e = WlanGetAvailableNetworkList(h, ref g, 3, IntPtr.Zero, out nl);
          wi.netsError = e;
          if (e == 0) {
            try {
              wi.nets = new List<BlazmaWlanNet>();
              int cnt = Marshal.ReadInt32(nl);
              for (int k = 0; k < cnt && k < 512; k++) {
                IntPtr it = IntPtr.Add(nl, 8 + k * 628);
                BlazmaWlanNet x = new BlazmaWlanNet();
                x.ssid = Ssid(IntPtr.Add(it, 512));
                x.bssType = Marshal.ReadInt32(it, 548);
                x.bssids = Marshal.ReadInt32(it, 552);
                x.quality = Marshal.ReadInt32(it, 604);
                x.secEnabled = Marshal.ReadInt32(it, 608) != 0;
                x.auth = Marshal.ReadInt32(it, 612);
                x.cipher = Marshal.ReadInt32(it, 616);
                x.flags = Marshal.ReadInt32(it, 620);
                wi.nets.Add(x);
              }
            } finally { WlanFreeMemory(nl); }
          }

          IntPtr bl;
          e = WlanGetNetworkBssList(h, ref g, IntPtr.Zero, 3, false, IntPtr.Zero, out bl);
          wi.bssError = e;
          if (e == 0) {
            try {
              wi.bss = new List<BlazmaWlanBss>();
              int cnt = Marshal.ReadInt32(bl, 4);
              for (int k = 0; k < cnt && k < 1024; k++) {
                IntPtr it = IntPtr.Add(bl, 8 + k * 360);
                BlazmaWlanBss b = new BlazmaWlanBss();
                b.ssid = Ssid(it);
                b.bssid = Mac(IntPtr.Add(it, 40));
                b.phy = Marshal.ReadInt32(it, 52);
                b.rssi = Marshal.ReadInt32(it, 56);
                b.quality = Marshal.ReadInt32(it, 60);
                b.cap = Marshal.ReadInt16(it, 88) & 0xffff;
                b.freq = Marshal.ReadInt32(it, 92);
                wi.bss.Add(b);
              }
            } finally { WlanFreeMemory(bl); }
          }
          res.interfaces.Add(wi);
        }
      } finally { WlanFreeMemory(list); }
    } finally { WlanCloseHandle(h, IntPtr.Zero); }
    return res;
  }
}
`;

export const WIFI_SCRIPT = `
$ErrorActionPreference = 'Stop'
$out = @{ wlan = $null; compileError = $false; readError = $null; profiles = @(); location = $null; profilesError = $false }
try { Add-Type -TypeDefinition $env:BLAZMA_ARG_SRC -Language CSharp } catch { $out.compileError = $true }
if (-not $out.compileError) {
  # DllNotFoundException = this Windows has no WLAN component (e.g. Windows Server without the feature).
  try { $out.wlan = [BlazmaWlan]::Read() } catch { $out.readError = [string]$_.Exception.GetBaseException().GetType().Name }
}
try {
  $cam = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location'
  $u = Get-ItemProperty -LiteralPath ('HKCU:\\' + $cam + '\\NonPackaged') -Name Value -ErrorAction SilentlyContinue
  $m = Get-ItemProperty -LiteralPath ('HKLM:\\' + $cam) -Name Value -ErrorAction SilentlyContinue
  $out.location = @{ user = [string]$u.Value; machine = [string]$m.Value }
} catch {}
$dir = $env:BLAZMA_ARG_DIR
try {
  $short = (New-Object -ComObject Scripting.FileSystemObject).GetFolder($dir).ShortPath
  $netsh = Join-Path $env:SystemRoot 'System32\\netsh.exe'
  $null = & $netsh wlan export profile ('folder=' + $short)
  $out.profiles = @(Get-ChildItem -LiteralPath $dir -Filter '*.xml' | ForEach-Object { (Get-Content -LiteralPath $_.FullName -Raw -Encoding UTF8) -replace '(?s)<sharedKey>.*?</sharedKey>', '' })
} catch { $out.profilesError = $true } finally {
  Get-ChildItem -LiteralPath $dir -Filter '*.xml' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
}
$out | ConvertTo-Json -Depth 8 -Compress
`;

export interface ScriptOut {
  wlan: RawWlan | null;
  compileError: boolean;
  readError?: string | null;
  profiles: string[] | string | null;
  location: { user: string; machine: string } | null;
  profilesError: boolean;
}

/** Windows error codes the WLAN API returns when there is nothing to read. */
const NO_WIFI = new Set([1062, 2, 1168]);

export function buildReport(out: ScriptOut, now = new Date()): WifiReport {
  const rawProfiles = Array.isArray(out.profiles) ? out.profiles : typeof out.profiles === 'string' ? [out.profiles] : [];
  const profiles = rawProfiles.map(parseProfileXml).filter((p): p is SavedProfile => !!p).sort((a, b) => a.name.localeCompare(b.name));
  const wlan = out.wlan;
  const noWifi = !wlan || NO_WIFI.has(wlan.openError) || (wlan.openError === 0 && (wlan.interfaces ?? []).length === 0);
  const state = wlan && !noWifi ? buildWifiState({ ...wlan, interfaces: wlan.interfaces ?? [] }) : { connections: [], networks: [], accessDenied: false };
  const locationOff = out.location ? /deny/i.test(out.location.user) || /deny/i.test(out.location.machine) : null;
  return {
    available: !out.compileError && !noWifi,
    reason: out.compileError ? 'wlan_unavailable' : noWifi ? 'no_wifi_adapter' : null,
    interfaces: (wlan?.interfaces ?? []).map((i) => i.name),
    connections: state.connections,
    networks: state.networks,
    channels: channelUsage(state.networks),
    // Access denied, or a connected adapter whose network name came back empty = location blocked.
    locationBlocked: state.accessDenied || (state.connections.length > 0 && state.connections.every((c) => !c.ssid) && locationOff !== false),
    locationSetting: locationOff === null ? null : locationOff ? 'off' : 'on',
    profiles,
    profilesReadable: !out.profilesError,
    findings: wifiFindings(state.connections, state.networks, profiles),
    collectedAt: now.toISOString(),
  };
}

export async function wifiReport(): Promise<WifiReport> {
  if (process.platform !== 'win32') throw new WifiError('unsupported_platform');
  const work = join(subDir('temp'), 'wifi', randomUUID());
  await mkdir(work, { recursive: true, mode: 0o700 });
  try {
    const r = await runPowerShellJson<ScriptOut>(WIFI_SCRIPT, { timeoutMs: 90_000, args: { SRC: WLAN_CSHARP, DIR: work } });
    if (!r.ok) throw new WifiError(r.error);
    return buildReport(r.data);
  } finally {
    await rm(work, { recursive: true, force: true }).catch(() => {});
  }
}
