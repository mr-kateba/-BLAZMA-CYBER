// Input validation shared by main process and renderer.
// Pure functions only: no Node or DOM APIs, so the renderer can give instant feedback
// while the main process re-validates everything it receives over IPC.

const IPV4_OCTET = '(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)';
const IPV4_RE = new RegExp(`^${IPV4_OCTET}(\\.${IPV4_OCTET}){3}$`);

export function isIPv4(value: string): boolean {
  return IPV4_RE.test(value);
}

export function isIPv6(value: string): boolean {
  if (value.length < 2 || value.length > 45) return false;
  let addr = value;
  // Allow an embedded IPv4 tail (e.g. ::ffff:192.0.2.1)
  const lastColon = addr.lastIndexOf(':');
  let groupsBudget = 8;
  if (addr.includes('.')) {
    const tail = addr.slice(lastColon + 1);
    if (!isIPv4(tail)) return false;
    addr = addr.slice(0, lastColon + 1) + '0:0';
    groupsBudget = 8;
  }
  const doubleColon = addr.split('::');
  if (doubleColon.length > 2) return false;
  const hex = /^[0-9a-fA-F]{1,4}$/;
  const parts = (s: string) => (s === '' ? [] : s.split(':'));
  if (doubleColon.length === 2) {
    const head = parts(doubleColon[0]!);
    const tail = parts(doubleColon[1]!);
    if (head.length + tail.length > groupsBudget - 1) return false;
    return [...head, ...tail].every((g) => hex.test(g));
  }
  const groups = addr.split(':');
  return groups.length === groupsBudget && groups.every((g) => hex.test(g));
}

export function isIP(value: string): boolean {
  return isIPv4(value) || isIPv6(value);
}

export type IpScope = 'private' | 'loopback' | 'link-local' | 'multicast' | 'reserved' | 'cgnat' | 'public';

/** Classifies an IP so the UI can explain why e.g. geolocation of 192.168.x.x is meaningless. */
export function classifyIP(value: string): IpScope | null {
  if (isIPv4(value)) {
    const [a, b] = value.split('.').map(Number) as [number, number];
    if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return 'private';
    if (a === 127) return 'loopback';
    if (a === 169 && b === 254) return 'link-local';
    if (a === 100 && b >= 64 && b <= 127) return 'cgnat';
    if (a >= 224 && a <= 239) return 'multicast';
    if (a === 0 || a >= 240) return 'reserved';
    return 'public';
  }
  if (isIPv6(value)) {
    const v = value.toLowerCase();
    if (v === '::1') return 'loopback';
    if (v === '::') return 'reserved';
    if (/^fe[89ab]/.test(v)) return 'link-local';
    if (/^f[cd]/.test(v)) return 'private';
    if (v.startsWith('ff')) return 'multicast';
    return 'public';
  }
  return null;
}

const LABEL_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;

/**
 * Validates a DNS hostname / domain (ASCII or punycode). Internationalized names must be
 * converted to punycode by the caller (URL API) before validation.
 */
export function isDomain(value: string, { requireTld = true } = {}): boolean {
  if (!value || value.length > 253) return false;
  const v = value.toLowerCase().replace(/\.$/, '');
  const labels = v.split('.');
  if (requireTld && labels.length < 2) return false;
  if (!labels.every((l) => LABEL_RE.test(l))) return false;
  const tld = labels[labels.length - 1]!;
  // TLDs are never all-numeric (prevents "1.2.3.4" passing as a domain)
  return !/^\d+$/.test(tld);
}

export function isHostname(value: string): boolean {
  return isIP(value) || isDomain(value, { requireTld: false });
}

export function isPort(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 1 && value <= 65535;
}

/** Parses "22,80,8000-8010" into a sorted unique list. Throws on invalid input or when above `max`. */
export function parsePortList(spec: string, max = 1024): number[] {
  const out = new Set<number>();
  for (const raw of spec.split(',')) {
    const part = raw.trim();
    if (!part) continue;
    const m = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(part);
    if (!m) throw new Error(`invalid_port_spec:${part}`);
    const start = Number(m[1]);
    const end = m[2] !== undefined ? Number(m[2]) : start;
    if (!isPort(start) || !isPort(end) || end < start) throw new Error(`invalid_port_spec:${part}`);
    for (let p = start; p <= end; p++) {
      out.add(p);
      if (out.size > max) throw new Error('too_many_ports');
    }
  }
  return [...out].sort((a, b) => a - b);
}

/** Characters that carry meaning to cmd.exe / PowerShell / POSIX shells. */
const SHELL_META = /[;&|`$<>(){}[\]'"\\\r\n\t\0*?!^%]/;

export function containsShellMetacharacters(value: string): boolean {
  return SHELL_META.test(value);
}

/**
 * Validates a user-supplied absolute path before the main process touches the filesystem.
 * Does not check existence (that is the caller's job, with proper error handling).
 */
export function validateAbsolutePath(value: unknown): { ok: true; path: string } | { ok: false; reason: string } {
  if (typeof value !== 'string' || value.length === 0) return { ok: false, reason: 'path_empty' };
  if (value.length > 32767) return { ok: false, reason: 'path_too_long' };
  if (value.includes('\0')) return { ok: false, reason: 'path_nul_byte' };
  const isWinAbs = /^[a-zA-Z]:[\\/]/.test(value) || /^\\\\[^\\/]+[\\/][^\\/]+/.test(value);
  const isPosixAbs = value.startsWith('/');
  if (!isWinAbs && !isPosixAbs) return { ok: false, reason: 'path_not_absolute' };
  // Win32 device namespace paths (\\?\ \\.\) are refused: they bypass normal path rules.
  if (/^\\\\[?.]\\/.test(value)) return { ok: false, reason: 'path_device_namespace' };
  return { ok: true, path: value };
}

/** Wraps an untrusted value so it can be shown in a table without breaking layout. */
export function truncateMiddle(value: string, max = 64): string {
  if (value.length <= max) return value;
  const half = Math.floor((max - 1) / 2);
  return `${value.slice(0, half)}…${value.slice(value.length - half)}`;
}
