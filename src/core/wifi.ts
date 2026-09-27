// Wi-Fi security review (pure): the current connection, nearby networks and the Wi-Fi networks this
// computer has saved. Read-only — Blazma never connects, disconnects, or changes a Wi-Fi setting, and
// never reads a saved password (profiles are exported WITHOUT keys and the key element is dropped).
//
// Facts come from the Windows WLAN API (numbers, locale-independent) and from exported profile XML.

export type WifiSecurity = 'open' | 'owe' | 'wep' | 'wpa' | 'wpa2' | 'wpa3' | 'unknown';
export type WifiRating = 'good' | 'ok' | 'weak' | 'bad' | 'unknown';

/** DOT11_AUTH_ALGORITHM + DOT11_CIPHER_ALGORITHM → a security family. */
export function securityFromAlgorithms(auth: number | null, cipher: number | null, enabled = true): WifiSecurity {
  if (auth === null) return 'unknown';
  if (auth === 1) return !enabled || cipher === 0 ? 'open' : cipher === 1 || cipher === 5 || cipher === 0x101 ? 'wep' : 'open';
  if (auth === 2) return 'wep';
  if (auth === 3 || auth === 4 || auth === 5) return 'wpa';
  if (auth === 6 || auth === 7) return 'wpa2';
  if (auth === 8 || auth === 9 || auth === 11) return 'wpa3';
  if (auth === 10) return 'owe';
  return 'unknown';
}

export function authLabel(auth: number | null): string | null {
  const m: Record<number, string> = {
    1: 'Open', 2: 'Shared key (WEP)', 3: 'WPA-Enterprise', 4: 'WPA-Personal', 5: 'WPA-None', 6: 'WPA2-Enterprise',
    7: 'WPA2-Personal', 8: 'WPA3-Enterprise 192-bit', 9: 'WPA3-Personal (SAE)', 10: 'Enhanced Open (OWE)', 11: 'WPA3-Enterprise',
  };
  return auth === null ? null : (m[auth] ?? null);
}

export function cipherLabel(cipher: number | null): string | null {
  const m: Record<number, string> = { 0: 'None', 1: 'WEP-40', 2: 'TKIP', 4: 'AES-CCMP', 5: 'WEP-104', 8: 'GCMP', 9: 'GCMP-256', 10: 'CCMP-256', 0x101: 'WEP' };
  return cipher === null ? null : (m[cipher] ?? null);
}

export function phyLabel(phy: number | null): string | null {
  const m: Record<number, string> = { 4: '802.11a', 5: '802.11b', 6: '802.11g', 7: 'Wi-Fi 4 (802.11n)', 8: 'Wi-Fi 5 (802.11ac)', 10: 'Wi-Fi 6 (802.11ax)', 11: 'Wi-Fi 7 (802.11be)' };
  return phy === null ? null : (m[phy] ?? null);
}

export const SECURITY_RATING: Record<WifiSecurity, WifiRating> = { wpa3: 'good', wpa2: 'ok', owe: 'ok', wpa: 'weak', wep: 'bad', open: 'bad', unknown: 'unknown' };

/** Centre frequency (kHz) → band and channel. */
export function channelOf(khz: number | null): { band: '2.4' | '5' | '6' | null; channel: number | null } {
  if (!khz) return { band: null, channel: null };
  const mhz = Math.round(khz / 1000);
  if (mhz === 2484) return { band: '2.4', channel: 14 };
  if (mhz >= 2412 && mhz <= 2472) return { band: '2.4', channel: (mhz - 2407) / 5 };
  if (mhz >= 5955 && mhz <= 7115) return { band: '6', channel: (mhz - 5950) / 5 };
  if (mhz >= 5160 && mhz <= 5885) return { band: '5', channel: (mhz - 5000) / 5 };
  return { band: null, channel: null };
}

/** WLAN signal quality 0–100 (Windows maps −100 dBm → 0 and −50 dBm → 100). */
export function signalLevel(quality: number | null): 'excellent' | 'good' | 'fair' | 'weak' | null {
  if (quality === null) return null;
  return quality >= 80 ? 'excellent' : quality >= 60 ? 'good' : quality >= 40 ? 'fair' : 'weak';
}

// -------------------------------------------------------------------------------- saved profiles

export interface SavedProfile {
  name: string;
  ssid: string | null;
  /** auto = Windows joins it by itself whenever it is in range. */
  autoConnect: boolean;
  /** The network hides its name, so this computer calls out for it everywhere. */
  hidden: boolean;
  authentication: string | null;
  encryption: string | null;
  enterprise: boolean;
  security: WifiSecurity;
  rating: WifiRating;
}

const tag = (xml: string, name: string): string | null => {
  const m = new RegExp(`<${name}>([^<]*)</${name}>`, 'i').exec(xml);
  return m ? m[1]!.trim() : null;
};

function decodeXml(s: string): string {
  return s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&');
}

function ssidFromHex(hex: string | null): string | null {
  if (!hex || !/^[0-9a-f]+$/i.test(hex) || hex.length % 2) return null;
  const bytes = new Uint8Array(hex.match(/../g)!.map((b) => parseInt(b, 16)));
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
}

/** Parses one exported WLAN profile (netsh wlan export profile, WITHOUT key=clear). */
export function parseProfileXml(xml: string): SavedProfile | null {
  if (!/<WLANProfile\b/i.test(xml)) return null;
  const name = tag(xml, 'name');
  if (!name) return null;
  const ssidBlock = /<SSID>([\s\S]*?)<\/SSID>/i.exec(xml)?.[1] ?? '';
  const ssid = ssidFromHex(tag(ssidBlock, 'hex')) ?? (tag(ssidBlock, 'name') ? decodeXml(tag(ssidBlock, 'name')!) : null);
  const auth = tag(xml, 'authentication');
  const enc = tag(xml, 'encryption');
  const oneX = /<useOneX>\s*true\s*<\/useOneX>/i.test(xml) || /^(WPA|WPA2|WPA3|WPA3ENT|WPA3ENT192)$/i.test(auth ?? '');
  const a = (auth ?? '').toLowerCase();
  const e = (enc ?? '').toLowerCase();
  const security: WifiSecurity =
    a === 'open' ? (e === 'wep' ? 'wep' : 'open')
    : a === 'owe' ? 'owe'
    : a === 'shared' ? 'wep'
    : a.startsWith('wpa3') ? 'wpa3'
    : a.startsWith('wpa2') ? (e === 'tkip' ? 'wpa' : 'wpa2')
    : a.startsWith('wpa') ? 'wpa'
    : 'unknown';
  return {
    name: decodeXml(name),
    ssid,
    autoConnect: (tag(xml, 'connectionMode') ?? 'auto').toLowerCase() === 'auto',
    hidden: /<nonBroadcast>\s*true\s*<\/nonBroadcast>/i.test(xml),
    authentication: auth,
    encryption: enc,
    enterprise: oneX,
    security,
    rating: SECURITY_RATING[security],
  };
}

// ------------------------------------------------------------------------------- live WLAN facts

export interface WifiConnection {
  interfaceName: string;
  ssid: string | null;
  bssid: string | null;
  profile: string | null;
  signal: number | null;
  rssi: number | null;
  rxMbps: number | null;
  txMbps: number | null;
  phy: string | null;
  band: '2.4' | '5' | '6' | null;
  channel: number | null;
  authentication: string | null;
  cipher: string | null;
  security: WifiSecurity;
  rating: WifiRating;
}

export interface WifiNetwork {
  ssid: string | null;
  hidden: boolean;
  bssids: number;
  signal: number | null;
  security: WifiSecurity;
  rating: WifiRating;
  authentication: string | null;
  cipher: string | null;
  connected: boolean;
  saved: boolean;
  band: '2.4' | '5' | '6' | null;
  channel: number | null;
  rssi: number | null;
}

export type WifiFindingId = 'current_insecure' | 'current_weak_signal' | 'evil_twin' | 'saved_open_auto' | 'saved_weak' | 'saved_hidden' | 'crowded_channel';

export interface WifiFinding {
  id: WifiFindingId;
  severity: 'high' | 'medium' | 'low' | 'info';
  vars: Record<string, string | number>;
}

/** Raw numbers from the WLAN API script. */
export interface RawWlan {
  interfaces: Array<{
    name: string;
    state: number;
    conn: { ssid: string; bssid: string; profile: string; quality: number; rx: number; tx: number; phy: number; secEnabled: boolean; auth: number; cipher: number } | null;
    connError: number;
    nets: Array<{ ssid: string; bssType: number; bssids: number; quality: number; secEnabled: boolean; auth: number; cipher: number; flags: number }> | null;
    netsError: number;
    bss: Array<{ ssid: string; bssid: string; rssi: number; quality: number; freq: number; phy: number; cap: number }> | null;
    bssError: number;
  }>;
  openError: number;
}

const str = (v: unknown): string | null => (typeof v === 'string' && v.length > 0 ? v : null);

export function buildWifiState(raw: RawWlan): { connections: WifiConnection[]; networks: WifiNetwork[]; accessDenied: boolean } {
  const connections: WifiConnection[] = [];
  const networks: WifiNetwork[] = [];
  let accessDenied = false;
  for (const i of raw.interfaces ?? []) {
    if (i.netsError === 5 || i.bssError === 5 || i.connError === 5) accessDenied = true;
    const bss = i.bss ?? [];
    if (i.conn && i.state === 1) {
      const c = i.conn;
      const b = bss.find((x) => x.bssid.toLowerCase() === c.bssid.toLowerCase());
      const ch = channelOf(b?.freq ?? null);
      const security = securityFromAlgorithms(c.auth, c.cipher, c.secEnabled);
      connections.push({
        interfaceName: i.name,
        ssid: str(c.ssid),
        bssid: str(c.bssid),
        profile: str(c.profile),
        signal: c.quality,
        rssi: b ? b.rssi : null,
        rxMbps: c.rx ? Math.round(c.rx / 1000) : null,
        txMbps: c.tx ? Math.round(c.tx / 1000) : null,
        phy: phyLabel(c.phy),
        band: ch.band,
        channel: ch.channel,
        authentication: authLabel(c.auth),
        cipher: cipherLabel(c.cipher),
        security,
        rating: SECURITY_RATING[security],
      });
    }
    const seen = new Map<string, WifiNetwork>();
    for (const n of i.nets ?? []) {
      if (n.bssType !== 1) continue; // infrastructure networks only
      const key = `${n.ssid}|${n.auth}`;
      const security = securityFromAlgorithms(n.auth, n.cipher, n.secEnabled);
      const best = bss.filter((b) => b.ssid === n.ssid).sort((a, b) => b.rssi - a.rssi)[0];
      const ch = channelOf(best?.freq ?? null);
      const prev = seen.get(key);
      const entry: WifiNetwork = {
        ssid: str(n.ssid),
        hidden: !n.ssid,
        bssids: n.bssids,
        signal: n.quality,
        security,
        rating: SECURITY_RATING[security],
        authentication: authLabel(n.auth),
        cipher: cipherLabel(n.cipher),
        connected: (n.flags & 1) !== 0 || (prev?.connected ?? false),
        saved: (n.flags & 2) !== 0 || (prev?.saved ?? false),
        band: ch.band,
        channel: ch.channel,
        rssi: best ? best.rssi : null,
      };
      // Windows lists a network once per saved profile; keep one row per name + security.
      if (!prev || entry.signal! > (prev.signal ?? -1)) seen.set(key, entry);
    }
    networks.push(...seen.values());
  }
  networks.sort((a, b) => Number(b.connected) - Number(a.connected) || (b.signal ?? 0) - (a.signal ?? 0));
  return { connections, networks, accessDenied };
}

/** Channel usage on the 2.4 GHz band, where only 1, 6 and 11 don't overlap. */
export function channelUsage(networks: WifiNetwork[]): Array<{ band: '2.4' | '5' | '6'; channel: number; networks: number }> {
  const m = new Map<string, { band: '2.4' | '5' | '6'; channel: number; networks: number }>();
  for (const n of networks) {
    if (!n.band || !n.channel) continue;
    const k = `${n.band}|${n.channel}`;
    const e = m.get(k) ?? { band: n.band, channel: n.channel, networks: 0 };
    e.networks++;
    m.set(k, e);
  }
  return [...m.values()].sort((a, b) => a.band.localeCompare(b.band) || a.channel - b.channel);
}

export function wifiFindings(connections: WifiConnection[], networks: WifiNetwork[], profiles: SavedProfile[]): WifiFinding[] {
  const out: WifiFinding[] = [];
  for (const c of connections) {
    if (c.rating === 'bad' || c.rating === 'weak') out.push({ id: 'current_insecure', severity: c.rating === 'bad' ? 'high' : 'medium', vars: { ssid: c.ssid ?? '—', security: c.authentication ?? c.security } });
    if (c.signal !== null && c.signal < 40) out.push({ id: 'current_weak_signal', severity: 'low', vars: { ssid: c.ssid ?? '—', signal: c.signal } });
    // Same name nearby with weaker security than the network we trust: a classic "evil twin".
    const twin = networks.find((n) => n.ssid && n.ssid === c.ssid && !n.connected && rank(n.security) < rank(c.security));
    if (twin && c.ssid) out.push({ id: 'evil_twin', severity: 'high', vars: { ssid: c.ssid, security: twin.authentication ?? twin.security } });
    if (c.band === '2.4' && c.channel) {
      const same = networks.filter((n) => n.band === '2.4' && n.channel && Math.abs(n.channel - c.channel!) < 5 && !n.connected).length;
      if (same >= 6) out.push({ id: 'crowded_channel', severity: 'info', vars: { channel: c.channel, networks: same } });
    }
  }
  for (const p of profiles) {
    if ((p.security === 'open' || p.security === 'wep') && p.autoConnect) out.push({ id: 'saved_open_auto', severity: 'medium', vars: { name: p.name, security: p.authentication ?? p.security } });
    else if (p.rating === 'bad' || p.rating === 'weak') out.push({ id: 'saved_weak', severity: 'low', vars: { name: p.name, security: p.authentication ?? p.security } });
    if (p.hidden) out.push({ id: 'saved_hidden', severity: 'info', vars: { name: p.name } });
  }
  const order = { high: 0, medium: 1, low: 2, info: 3 };
  return out.sort((a, b) => order[a.severity] - order[b.severity]);
}

function rank(s: WifiSecurity): number {
  return { unknown: -1, open: 0, owe: 1, wep: 1, wpa: 2, wpa2: 3, wpa3: 4 }[s];
}
