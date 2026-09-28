import { describe, expect, it } from 'vitest';
import { listeningServices } from '../src/core/listening';
import { portsArea } from '../src/core/checkup';
import type { ConnectionRow } from '../src/shared/api';

const row = (p: Partial<ConnectionRow>): ConnectionRow => ({ protocol: 'TCP', localAddress: '0.0.0.0', localPort: 0, remoteAddress: '0.0.0.0', remotePort: 0, state: 'Listen', pid: 4, process: 'System', ...p });

const ROWS: ConnectionRow[] = [
  row({ localPort: 445, pid: 4, process: 'System' }),
  row({ localAddress: '::', localPort: 445, pid: 4, process: 'System' }),
  row({ localPort: 135, pid: 1000, process: 'svchost' }),
  row({ localAddress: '127.0.0.1', localPort: 3306, pid: 2000, process: 'mysqld' }),
  row({ localAddress: '192.168.1.10', localPort: 5432, pid: 2100, process: 'postgres' }),
  row({ localPort: 49664, pid: 700, process: 'lsass' }),
  row({ localAddress: '127.0.0.1', localPort: 9222, pid: 3000, process: 'chrome' }),
  // Not listening: an established connection and a UDP endpoint.
  row({ localAddress: '192.168.1.10', localPort: 50000, remoteAddress: '203.0.113.5', remotePort: 443, state: 'Established', pid: 3000, process: 'chrome' }),
  { protocol: 'UDP', localAddress: '0.0.0.0', localPort: 5353, remoteAddress: null, remotePort: null, state: null, pid: 1200, process: 'svchost' },
  // Linux spelling of the state.
  row({ localAddress: '::', localPort: 22, state: 'LISTEN', pid: 1, process: 'sshd' }),
];

describe('open ports on this PC', () => {
  const list = listeningServices(ROWS);

  it('lists TCP listeners once per port and program, with who can reach them', () => {
    expect(list.map((s) => s.port).sort((a, b) => a - b)).toEqual([22, 135, 445, 3306, 5432, 9222, 49664]);
    expect(list.find((s) => s.port === 445)).toMatchObject({ addresses: ['0.0.0.0', '::'], reach: 'network', kind: 'file_sharing', known: 'smb', attention: true });
    expect(list.find((s) => s.port === 3306)).toMatchObject({ reach: 'local', kind: 'database', attention: false });
    expect(list.find((s) => s.port === 5432)).toMatchObject({ reach: 'network', kind: 'database', attention: true });
    expect(list.find((s) => s.port === 49664)).toMatchObject({ kind: 'windows', known: 'rpc_dynamic', attention: false });
    expect(list.find((s) => s.port === 9222)).toMatchObject({ reach: 'local', known: null, kind: 'other' });
  });

  it('puts what deserves a look first, then network, then local', () => {
    expect(list.slice(0, 3).every((s) => s.attention)).toBe(true);
    const firstLocal = list.findIndex((s) => s.reach === 'local');
    expect(list.slice(firstLocal).every((s) => s.reach === 'local')).toBe(true);
  });

  it('can include UDP endpoints', () => {
    expect(listeningServices(ROWS, true).find((s) => s.protocol === 'UDP')).toMatchObject({ port: 5353, reach: 'network' });
  });

  it('feeds the full checkup', () => {
    expect(portsArea({ data: list })).toMatchObject({ state: 'attention', count: 3 });
    expect(portsArea({ data: listeningServices([row({ localPort: 135, process: 'svchost' })]) })).toMatchObject({ state: 'ok', vars: { network: 1 } });
    expect(portsArea({ error: 'powershell_failed' })).toMatchObject({ state: 'unavailable' });
  });
});
