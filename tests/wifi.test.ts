import { describe, expect, it, vi } from 'vitest';
import { buildWifiState, channelOf, channelUsage, parseProfileXml, securityFromAlgorithms, wifiFindings, type RawWlan } from '../src/core/wifi';

vi.mock('electron', () => ({}));
const { buildReport, WIFI_SCRIPT, WLAN_CSHARP } = await import('../src/main/services/wifi');
const { assertSafeScript } = await import('../src/main/services/powershell');

const profile = (o: { name: string; auth: string; enc: string; mode?: string; hidden?: boolean; oneX?: boolean; hex?: string }) => `<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>${o.name}</name>
  <SSIDConfig><SSID><hex>${o.hex ?? Buffer.from(o.name).toString('hex').toUpperCase()}</hex><name>${o.name}</name></SSID>${o.hidden ? '<nonBroadcast>true</nonBroadcast>' : ''}</SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>${o.mode ?? 'auto'}</connectionMode>
  <MSM><security><authEncryption><authentication>${o.auth}</authentication><encryption>${o.enc}</encryption><useOneX>${o.oneX ? 'true' : 'false'}</useOneX></authEncryption></security></MSM>
</WLANProfile>`;

describe('Wi-Fi security classification', () => {
  it('maps WLAN API algorithm ids to a security family', () => {
    expect(securityFromAlgorithms(9, 4)).toBe('wpa3');
    expect(securityFromAlgorithms(7, 4)).toBe('wpa2');
    expect(securityFromAlgorithms(6, 4)).toBe('wpa2');
    expect(securityFromAlgorithms(4, 2)).toBe('wpa');
    expect(securityFromAlgorithms(1, 0, false)).toBe('open');
    expect(securityFromAlgorithms(1, 1)).toBe('wep');
    expect(securityFromAlgorithms(10, 4)).toBe('owe');
    expect(securityFromAlgorithms(null, null)).toBe('unknown');
  });

  it('derives band and channel from the centre frequency', () => {
    expect(channelOf(2_437_000)).toEqual({ band: '2.4', channel: 6 });
    expect(channelOf(2_484_000)).toEqual({ band: '2.4', channel: 14 });
    expect(channelOf(5_180_000)).toEqual({ band: '5', channel: 36 });
    expect(channelOf(5_955_000)).toEqual({ band: '6', channel: 1 });
    expect(channelOf(null)).toEqual({ band: null, channel: null });
  });
});

describe('saved profiles (exported without keys)', () => {
  it('parses name, security, auto-connect and hidden', () => {
    expect(parseProfileXml(profile({ name: 'Home', auth: 'WPA3SAE', enc: 'AES' }))).toMatchObject({ name: 'Home', ssid: 'Home', security: 'wpa3', rating: 'good', autoConnect: true, hidden: false });
    expect(parseProfileXml(profile({ name: 'Cafe', auth: 'open', enc: 'none' }))).toMatchObject({ security: 'open', rating: 'bad', autoConnect: true });
    expect(parseProfileXml(profile({ name: 'Old', auth: 'WPA2PSK', enc: 'TKIP', mode: 'manual' }))).toMatchObject({ security: 'wpa', autoConnect: false });
    expect(parseProfileXml(profile({ name: 'Office', auth: 'WPA2', enc: 'AES', oneX: true }))).toMatchObject({ security: 'wpa2', enterprise: true });
    expect(parseProfileXml(profile({ name: 'Secret', auth: 'WPA2PSK', enc: 'AES', hidden: true }))?.hidden).toBe(true);
    // Arabic network names are stored as UTF-8 hex.
    expect(parseProfileXml(profile({ name: 'x', hex: Buffer.from('بيتي').toString('hex'), auth: 'WPA2PSK', enc: 'AES' }))?.ssid).toBe('بيتي');
    expect(parseProfileXml('<notAProfile/>')).toBeNull();
  });

  it('flags open networks that join automatically, weak ones and hidden ones', () => {
    const profiles = [
      parseProfileXml(profile({ name: 'Cafe', auth: 'open', enc: 'none' }))!,
      parseProfileXml(profile({ name: 'Old', auth: 'WPAPSK', enc: 'TKIP', mode: 'manual' }))!,
      parseProfileXml(profile({ name: 'Secret', auth: 'WPA2PSK', enc: 'AES', hidden: true }))!,
    ];
    const ids = wifiFindings([], [], profiles).map((f) => `${f.id}:${f.vars.name}`);
    expect(ids).toEqual(['saved_open_auto:Cafe', 'saved_weak:Old', 'saved_hidden:Secret']);
  });
});

const RAW: RawWlan = {
  openError: 0,
  interfaces: [{
    name: 'Intel(R) Wi-Fi 6 AX201',
    state: 1,
    connError: 0,
    conn: { ssid: 'Home', bssid: 'AA:BB:CC:00:00:01', profile: 'Home', quality: 35, rx: 866000, tx: 433000, phy: 10, secEnabled: true, auth: 7, cipher: 4 },
    netsError: 0,
    nets: [
      { ssid: 'Home', bssType: 1, bssids: 1, quality: 35, secEnabled: true, auth: 7, cipher: 4, flags: 3 },
      { ssid: 'Home', bssType: 1, bssids: 1, quality: 80, secEnabled: false, auth: 1, cipher: 0, flags: 0 },
      { ssid: '', bssType: 1, bssids: 1, quality: 20, secEnabled: true, auth: 7, cipher: 4, flags: 0 },
      ...Array.from({ length: 7 }, (_, i) => ({ ssid: `N${i}`, bssType: 1, bssids: 1, quality: 50, secEnabled: true, auth: 7, cipher: 4, flags: 0 })),
    ],
    bssError: 0,
    bss: [
      { ssid: 'Home', bssid: 'AA:BB:CC:00:00:01', rssi: -78, quality: 35, freq: 2_437_000, phy: 10, cap: 0x11 },
      { ssid: 'Home', bssid: 'DE:AD:00:00:00:02', rssi: -40, quality: 80, freq: 2_437_000, phy: 7, cap: 0x01 },
      ...Array.from({ length: 7 }, (_, i) => ({ ssid: `N${i}`, bssid: `00:11:22:33:44:5${i}`, rssi: -60, quality: 50, freq: 2_432_000 + (i % 3) * 5000, phy: 7, cap: 0x11 })),
    ],
  }],
};

describe('live WLAN facts', () => {
  const state = buildWifiState(RAW);

  it('describes the current connection', () => {
    expect(state.connections).toEqual([expect.objectContaining({
      ssid: 'Home', signal: 35, rssi: -78, band: '2.4', channel: 6, phy: 'Wi-Fi 6 (802.11ax)', authentication: 'WPA2-Personal', cipher: 'AES-CCMP', security: 'wpa2', rxMbps: 866, txMbps: 433,
    })]);
  });

  it('lists nearby networks once per name and security, connected first', () => {
    expect(state.networks[0]).toMatchObject({ ssid: 'Home', connected: true, saved: true, security: 'wpa2' });
    expect(state.networks.filter((n) => n.ssid === 'Home')).toHaveLength(2);
    expect(state.networks.find((n) => n.hidden)).toMatchObject({ ssid: null, security: 'wpa2' });
    expect(channelUsage(state.networks).find((c) => c.channel === 6)?.networks).toBeGreaterThan(1);
  });

  it('spots an evil-twin name, weak signal and a crowded channel', () => {
    const ids = wifiFindings(state.connections, state.networks, []).map((f) => f.id);
    expect(ids).toEqual(['evil_twin', 'current_weak_signal', 'crowded_channel']);
  });
});

describe('Wi-Fi report assembly', () => {
  it('reports "no Wi-Fi" honestly and location blocks as such', () => {
    expect(buildReport({ wlan: { openError: 1062, interfaces: [] }, compileError: false, profiles: [], location: null, profilesError: false })).toMatchObject({ available: false, reason: 'no_wifi_adapter' });
    expect(buildReport({ wlan: null, compileError: false, readError: 'DllNotFoundException', profiles: null, location: null, profilesError: true })).toMatchObject({ available: false, reason: 'no_wifi_adapter', profilesReadable: false });
    expect(buildReport({ wlan: null, compileError: true, profiles: [], location: null, profilesError: false }).reason).toBe('wlan_unavailable');
    const denied: RawWlan = { openError: 0, interfaces: [{ ...RAW.interfaces[0]!, nets: null, netsError: 5, bss: null, bssError: 5 }] };
    const r = buildReport({ wlan: denied, compileError: false, profiles: profile({ name: 'Home', auth: 'WPA2PSK', enc: 'AES' }), location: { user: 'Deny', machine: 'Allow' }, profilesError: false });
    expect(r).toMatchObject({ available: true, locationBlocked: true, locationSetting: 'off', networks: [] });
    expect(r.profiles.map((p) => p.name)).toEqual(['Home']);
  });

  it('keeps the PowerShell script safe and never asks for keys', () => {
    expect(() => assertSafeScript(WIFI_SCRIPT)).not.toThrow();
    expect(WIFI_SCRIPT).not.toMatch(/key=clear/i);
    expect(WIFI_SCRIPT).toContain('<sharedKey>');
    expect(WIFI_SCRIPT).not.toMatch(/\b(Set-|New-Item|Stop-|Start-Process|Restart-|Disable-|Enable-|Invoke-Expression|netsh[^\n]*(add|delete|set|connect|disconnect))/i);
    expect(WLAN_CSHARP).not.toMatch(/WlanSetInterface|WlanConnect|WlanDisconnect|WlanDeleteProfile|WlanSetProfile|WlanGetProfile/);
  });
});
