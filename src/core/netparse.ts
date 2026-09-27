// Pure parsers for local system/network data (no I/O), unit-tested with fixtures.
// Linux: /proc/net/{tcp,tcp6,udp,udp6,route,arp}. Windows data arrives as JSON from fixed
// PowerShell scripts and only needs light normalization (see parseServiceBinary).

/** Linux TCP states from include/net/tcp_states.h */
const TCP_STATES: Record<string, string> = {
  '01': 'ESTABLISHED', '02': 'SYN_SENT', '03': 'SYN_RECV', '04': 'FIN_WAIT1', '05': 'FIN_WAIT2', '06': 'TIME_WAIT',
  '07': 'CLOSE', '08': 'CLOSE_WAIT', '09': 'LAST_ACK', '0A': 'LISTEN', '0B': 'CLOSING', '0C': 'NEW_SYN_RECV',
};

/** Decodes a little-endian hex IPv4 ("0100007F") or IPv6 (32 hex, 4 LE words) from /proc/net. */
export function decodeProcAddress(hex: string): string {
  if (hex.length === 8) {
    const b = hex.match(/../g)!.map((x) => Number.parseInt(x, 16)).reverse();
    return b.join('.');
  }
  if (hex.length === 32) {
    const words = hex.match(/.{8}/g)!.map((w) => w.match(/../g)!.reverse().join(''));
    const groups = words.join('').match(/.{4}/g)!.map((g) => g.replace(/^0+(?=.)/, '').toLowerCase());
    // IPv4-mapped IPv6 → show as IPv4 for readability
    if (groups.slice(0, 5).every((g) => g === '0') && groups[5] === 'ffff') {
      const v4 = `${groups[6]!.padStart(4, '0')}${groups[7]!.padStart(4, '0')}`.match(/../g)!.map((x) => Number.parseInt(x, 16));
      return v4.join('.');
    }
    return compressIPv6(groups);
  }
  return hex;
}

function compressIPv6(groups: string[]): string {
  // Replace the longest run of zero groups with "::"
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < groups.length; ) {
    if (groups[i] === '0') {
      let j = i;
      while (j < groups.length && groups[j] === '0') j++;
      if (j - i > bestLen && j - i > 1) {
        bestStart = i;
        bestLen = j - i;
      }
      i = j;
    } else i++;
  }
  if (bestStart < 0) return groups.join(':');
  const head = groups.slice(0, bestStart).join(':');
  const tail = groups.slice(bestStart + bestLen).join(':');
  return `${head}::${tail}`;
}

export interface ProcNetEntry {
  protocol: 'TCP' | 'UDP';
  localAddress: string;
  localPort: number;
  remoteAddress: string | null;
  remotePort: number | null;
  state: string | null;
  inode: number;
  uid: number;
}

export function parseProcNet(text: string, protocol: 'TCP' | 'UDP'): ProcNetEntry[] {
  const out: ProcNetEntry[] = [];
  for (const line of text.split('\n').slice(1)) {
    const f = line.trim().split(/\s+/);
    if (f.length < 10) continue;
    const [la, lp] = f[1]!.split(':') as [string, string];
    const [ra, rp] = f[2]!.split(':') as [string, string];
    const st = f[3]!.toUpperCase();
    const remotePort = Number.parseInt(rp, 16);
    const remote = decodeProcAddress(ra);
    const unconnected = remotePort === 0 && /^(0\.0\.0\.0|::)$/.test(remote);
    out.push({
      protocol,
      localAddress: decodeProcAddress(la),
      localPort: Number.parseInt(lp, 16),
      remoteAddress: unconnected ? null : remote,
      remotePort: unconnected ? null : remotePort,
      state: protocol === 'TCP' ? TCP_STATES[st] ?? st : unconnected ? null : 'CONNECTED',
      uid: Number(f[7]),
      inode: Number(f[9]),
    });
  }
  return out;
}

export interface RouteEntry {
  destination: string;
  gateway: string | null;
  interface: string | null;
  metric: number | null;
}

/** /proc/net/route (IPv4). Destination/Mask/Gateway are little-endian hex. */
export function parseProcRoute(text: string): RouteEntry[] {
  const out: RouteEntry[] = [];
  for (const line of text.split('\n').slice(1)) {
    const f = line.trim().split(/\s+/);
    if (f.length < 8) continue;
    const dest = decodeProcAddress(f[1]!);
    const gw = decodeProcAddress(f[2]!);
    const mask = decodeProcAddress(f[7]!);
    const prefix = mask.split('.').reduce((n, o) => n + (Number(o) >>> 0).toString(2).replace(/0/g, '').length, 0);
    out.push({ destination: `${dest}/${prefix}`, gateway: gw === '0.0.0.0' ? null : gw, interface: f[0] ?? null, metric: Number(f[6]) });
  }
  return out;
}

export interface NeighborEntry {
  address: string;
  mac: string | null;
  state: string | null;
  interface: string | null;
}

/** /proc/net/arp */
export function parseProcArp(text: string): NeighborEntry[] {
  const out: NeighborEntry[] = [];
  for (const line of text.split('\n').slice(1)) {
    const f = line.trim().split(/\s+/);
    if (f.length < 6) continue;
    const flags = Number.parseInt(f[2]!, 16);
    const mac = f[3]!.toLowerCase();
    out.push({
      address: f[0]!,
      mac: mac === '00:00:00:00:00:00' ? null : mac,
      state: flags & 0x2 ? 'REACHABLE' : 'INCOMPLETE',
      interface: f[5] ?? null,
    });
  }
  return out;
}

/** Parses Linux `ping -c N` output (LANG=C). Returns per-reply RTTs and counts. */
export function parsePingOutput(text: string): { sent: number; received: number; rtts: number[] } {
  const rtts = [...text.matchAll(/time[=<]([\d.]+)\s*ms/g)].map((m) => Number(m[1]));
  const summary = /(\d+)\s+packets transmitted,\s+(\d+)\s+(?:packets\s+)?received/.exec(text);
  return { sent: summary ? Number(summary[1]) : rtts.length, received: summary ? Number(summary[2]) : rtts.length, rtts };
}

/**
 * Extracts the executable path from a Windows service/driver ImagePath / PathName, e.g.
 *   "C:\Program Files\X\svc.exe" -k netsvcs   →  C:\Program Files\X\svc.exe
 *   C:\Windows\system32\svchost.exe -k LocalService → C:\Windows\system32\svchost.exe
 *   \SystemRoot\System32\drivers\x.sys        →  C:\Windows\System32\drivers\x.sys
 *   system32\DRIVERS\y.sys                    →  C:\Windows\system32\DRIVERS\y.sys
 *   \??\C:\Windows\x.sys                      →  C:\Windows\x.sys
 */
export function parseServiceBinary(pathName: string | null | undefined, systemRoot = 'C:\\Windows'): string | null {
  if (!pathName) return null;
  let s = pathName.trim();
  if (!s) return null;
  if (s.startsWith('"')) {
    const end = s.indexOf('"', 1);
    s = end > 0 ? s.slice(1, end) : s.slice(1);
  } else {
    const m = /^(.+?\.(?:exe|sys|dll|com|bat|cmd))(?=\s|$)/i.exec(s);
    if (m) s = m[1]!;
  }
  s = s.replace(/^\\\?\?\\/, '');
  if (/^\\SystemRoot\\/i.test(s)) s = systemRoot + s.slice('\\SystemRoot'.length);
  else if (/^%SystemRoot%\\/i.test(s)) s = systemRoot + s.slice('%SystemRoot%'.length);
  else if (/^system32\\/i.test(s)) s = `${systemRoot}\\${s}`;
  return s;
}

/**
 * Flags an unquoted service path that contains spaces before the executable
 * (the classic "unquoted service path" privilege-escalation weakness).
 */
export function isUnquotedServicePath(pathName: string | null | undefined): boolean {
  if (!pathName) return false;
  const s = pathName.trim();
  if (s.startsWith('"')) return false;
  const exe = /^(.+?\.exe)(?=\s|$)/i.exec(s)?.[1];
  return !!exe && exe.includes(' ');
}

const WELL_KNOWN: Record<number, string> = {
  20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns', 67: 'dhcp', 69: 'tftp', 80: 'http', 88: 'kerberos',
  110: 'pop3', 111: 'rpcbind', 123: 'ntp', 135: 'msrpc', 137: 'netbios-ns', 139: 'netbios-ssn', 143: 'imap', 161: 'snmp', 389: 'ldap',
  443: 'https', 445: 'smb', 465: 'smtps', 500: 'isakmp', 514: 'syslog', 515: 'printer', 548: 'afp', 587: 'submission', 631: 'ipp',
  636: 'ldaps', 873: 'rsync', 993: 'imaps', 995: 'pop3s', 1080: 'socks', 1433: 'mssql', 1521: 'oracle', 1723: 'pptp', 1883: 'mqtt',
  1900: 'ssdp', 2049: 'nfs', 3306: 'mysql', 3389: 'rdp', 5353: 'mdns', 5432: 'postgresql', 5900: 'vnc', 5985: 'winrm', 5986: 'winrm-https',
  6379: 'redis', 8000: 'http-alt', 8080: 'http-proxy', 8443: 'https-alt', 9100: 'jetdirect', 9200: 'elasticsearch', 11211: 'memcached', 27017: 'mongodb',
};

export function wellKnownService(port: number): string | null {
  return WELL_KNOWN[port] ?? null;
}

/** Common ports for a quick check of your own machines. */
export const COMMON_PORTS = '21,22,23,25,53,80,110,135,139,143,389,443,445,587,993,995,1433,3306,3389,5432,5900,5985,8080,8443';

/** Hosts in an IPv4 subnet (excluding network/broadcast), capped for safety. */
export function subnetHosts(cidr: string, max = 254): string[] {
  const [base, lenStr] = cidr.split('/');
  const len = Number(lenStr);
  if (!base || !Number.isInteger(len) || len < 24 || len > 30) throw new Error('subnet_too_large');
  const toInt = (ip: string) => ip.split('.').reduce((a, o) => a * 256 + Number(o), 0);
  const toIp = (n: number) => [24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.');
  const size = 2 ** (32 - len);
  const network = Math.floor(toInt(base) / size) * size;
  const out: string[] = [];
  for (let i = 1; i < size - 1 && out.length < max; i++) out.push(toIp(network + i));
  return out;
}

/** Converts an IPv4 address + netmask (e.g. from os.networkInterfaces) to its /N network. */
export function networkOf(address: string, netmask: string): string {
  const toInt = (ip: string) => ip.split('.').reduce((a, o) => a * 256 + Number(o), 0) >>> 0;
  const m = toInt(netmask);
  const prefix = netmask.split('.').reduce((n, o) => n + (Number(o) >>> 0).toString(2).replace(/0/g, '').length, 0);
  const net = (toInt(address) & m) >>> 0;
  return `${[24, 16, 8, 0].map((s) => (net >>> s) & 255).join('.')}/${prefix}`;
}
