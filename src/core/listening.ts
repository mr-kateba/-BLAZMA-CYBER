// "What's open on my PC" (pure): turns the connection table into the list of programs waiting for
// incoming connections, who can reach them (this computer only, or the network), and what each
// well-known port usually is. Facts, not verdicts: a listening port is normal for many programs, and
// Windows Firewall may still block it — the UI says so.

import type { ConnectionRow } from '../shared/api';

export type Reach = 'local' | 'network';
export type PortKind = 'windows' | 'file_sharing' | 'remote_desktop' | 'remote_admin' | 'database' | 'web' | 'dev' | 'media' | 'other';

export interface ListeningService {
  port: number;
  protocol: 'TCP' | 'UDP';
  process: string | null;
  pid: number | null;
  /** Local addresses it listens on (deduplicated). */
  addresses: string[];
  reach: Reach;
  kind: PortKind;
  /** i18n key suffix under ports.known.* for a well-known port, else null. */
  known: string | null;
  /** Worth a look: remote access, databases or file sharing reachable from the network. */
  attention: boolean;
}

const KNOWN: Record<number, { key: string; kind: PortKind }> = {
  21: { key: 'ftp', kind: 'remote_admin' },
  22: { key: 'ssh', kind: 'remote_admin' },
  23: { key: 'telnet', kind: 'remote_admin' },
  80: { key: 'http', kind: 'web' },
  135: { key: 'rpc', kind: 'windows' },
  139: { key: 'netbios', kind: 'file_sharing' },
  443: { key: 'https', kind: 'web' },
  445: { key: 'smb', kind: 'file_sharing' },
  1433: { key: 'mssql', kind: 'database' },
  2179: { key: 'hyperv', kind: 'windows' },
  3306: { key: 'mysql', kind: 'database' },
  3389: { key: 'rdp', kind: 'remote_desktop' },
  5040: { key: 'cdp', kind: 'windows' },
  5357: { key: 'wsd', kind: 'windows' },
  5432: { key: 'postgres', kind: 'database' },
  5900: { key: 'vnc', kind: 'remote_admin' },
  5985: { key: 'winrm', kind: 'remote_admin' },
  5986: { key: 'winrm', kind: 'remote_admin' },
  6379: { key: 'redis', kind: 'database' },
  7680: { key: 'delivery', kind: 'windows' },
  8080: { key: 'http_alt', kind: 'web' },
  27017: { key: 'mongodb', kind: 'database' },
};

const LOOPBACK = /^(127\.|::1$|::ffff:127\.)/;

function isListening(r: ConnectionRow): boolean {
  if (r.protocol === 'TCP') return (r.state ?? '').toLowerCase() === 'listen';
  // UDP has no state: an endpoint without a remote address is waiting for datagrams.
  return !r.remoteAddress || r.remoteAddress === '*' || r.remoteAddress === '0.0.0.0' || r.remoteAddress === '::';
}

function kindOf(port: number, process: string | null): { kind: PortKind; known: string | null } {
  const k = KNOWN[port];
  if (k) return { kind: k.kind, known: k.key };
  // Windows' dynamic RPC endpoints (lsass, wininit, services, spoolsv, svchost) live in 49152–65535.
  if (port >= 49152 && /^(lsass|wininit|services|spoolsv|svchost|system)$/i.test(process ?? '')) return { kind: 'windows', known: 'rpc_dynamic' };
  return { kind: 'other', known: null };
}

const ATTENTION_KINDS: PortKind[] = ['file_sharing', 'remote_desktop', 'remote_admin', 'database'];

/** TCP listeners (and optionally UDP endpoints), one row per port + program. */
export function listeningServices(rows: ConnectionRow[], includeUdp = false): ListeningService[] {
  const map = new Map<string, ListeningService>();
  for (const r of rows) {
    if (!isListening(r) || (r.protocol === 'UDP' && !includeUdp) || !r.localPort) continue;
    const key = `${r.protocol}:${r.localPort}:${r.pid ?? r.process ?? '?'}`;
    let s = map.get(key);
    if (!s) {
      const { kind, known } = kindOf(r.localPort, r.process);
      s = { port: r.localPort, protocol: r.protocol, process: r.process, pid: r.pid, addresses: [], reach: 'local', kind, known, attention: false };
      map.set(key, s);
    }
    if (!s.addresses.includes(r.localAddress)) s.addresses.push(r.localAddress);
    if (!LOOPBACK.test(r.localAddress)) s.reach = 'network';
  }
  const out = [...map.values()];
  for (const s of out) s.attention = s.reach === 'network' && ATTENTION_KINDS.includes(s.kind);
  // Worth-a-look first, then reachable from the network, then by port.
  return out.sort((a, b) => Number(b.attention) - Number(a.attention) || (a.reach === b.reach ? 0 : a.reach === 'network' ? -1 : 1) || a.port - b.port);
}
