import { describe, expect, it } from 'vitest';
import {
  decodeProcAddress, isUnquotedServicePath, networkOf, parsePingOutput, parseProcArp, parseProcNet, parseProcRoute,
  parseServiceBinary, subnetHosts, wellKnownService,
} from '../src/core/netparse';

// Real-format samples from a Linux /proc/net
const TCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:921F 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 3884 1 00000000c292aa80 100 0 0 10 0
   1: 0200A8C0:D3A2 0202000A:01BB 01 00000000:00000000 02:000005DC 00000000  1000        0 55123 2 0000000000000000 20 4 30 10 -1
`;
const TCP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1234 1
   1: 0000000000000000FFFF00000100007F:1F90 0000000000000000FFFF00000100007F:C350 01 00000000:00000000 00:00000000 00000000     0        0 5678 1
`;
const ROUTE = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	010200C0	0003	0	0	0	00000000	0	0	0
eth0	000200C0	00000000	0001	0	0	0	00FFFFFF	0	0	0
`;
const ARP = `IP address       HW type     Flags       HW address            Mask     Device
192.0.2.1        0x1         0x2         02:fc:00:00:00:05     *        eth0
192.0.2.9        0x1         0x0         00:00:00:00:00:00     *        eth0
`;

describe('/proc/net parsing', () => {
  it('decodes little-endian addresses', () => {
    expect(decodeProcAddress('0100007F')).toBe('127.0.0.1');
    expect(decodeProcAddress('0200A8C0')).toBe('192.168.0.2');
    expect(decodeProcAddress('00000000000000000000000000000000')).toBe('::');
    expect(decodeProcAddress('0000000000000000FFFF00000100007F')).toBe('127.0.0.1');
    expect(decodeProcAddress('B80D0120000000000000000001000000')).toBe('2001:db8::1');
  });
  it('parses TCP listen and established sockets', () => {
    const r = parseProcNet(TCP, 'TCP');
    expect(r[0]).toEqual({ protocol: 'TCP', localAddress: '127.0.0.1', localPort: 37407, remoteAddress: null, remotePort: null, state: 'LISTEN', uid: 0, inode: 3884 });
    expect(r[1]).toMatchObject({ localAddress: '192.168.0.2', localPort: 54178, remoteAddress: '10.0.2.2', remotePort: 443, state: 'ESTABLISHED', uid: 1000 });
  });
  it('parses TCP6 including IPv4-mapped addresses', () => {
    const r = parseProcNet(TCP6, 'TCP');
    expect(r[0]).toMatchObject({ localAddress: '::', localPort: 22, state: 'LISTEN' });
    expect(r[1]).toMatchObject({ localAddress: '127.0.0.1', localPort: 8080, remoteAddress: '127.0.0.1', remotePort: 50000, state: 'ESTABLISHED' });
  });
  it('parses routes and ARP', () => {
    expect(parseProcRoute(ROUTE)).toEqual([
      { destination: '0.0.0.0/0', gateway: '192.0.2.1', interface: 'eth0', metric: 0 },
      { destination: '192.0.2.0/24', gateway: null, interface: 'eth0', metric: 0 },
    ]);
    expect(parseProcArp(ARP)).toEqual([
      { address: '192.0.2.1', mac: '02:fc:00:00:00:05', state: 'REACHABLE', interface: 'eth0' },
      { address: '192.0.2.9', mac: null, state: 'INCOMPLETE', interface: 'eth0' },
    ]);
  });
});

describe('ping output', () => {
  it('parses LANG=C ping', () => {
    const out = `PING 192.0.2.1 (192.0.2.1) 56(84) bytes of data.
64 bytes from 192.0.2.1: icmp_seq=1 ttl=64 time=0.412 ms
64 bytes from 192.0.2.1: icmp_seq=3 ttl=64 time=1.05 ms

--- 192.0.2.1 ping statistics ---
3 packets transmitted, 2 received, 33.3333% packet loss, time 2003ms`;
    expect(parsePingOutput(out)).toEqual({ sent: 3, received: 2, rtts: [0.412, 1.05] });
  });
});

describe('Windows service paths', () => {
  it('extracts executable paths', () => {
    expect(parseServiceBinary('"C:\\Program Files\\Acme\\svc.exe" -run')).toBe('C:\\Program Files\\Acme\\svc.exe');
    expect(parseServiceBinary('C:\\Windows\\system32\\svchost.exe -k netsvcs -p')).toBe('C:\\Windows\\system32\\svchost.exe');
    expect(parseServiceBinary('\\SystemRoot\\System32\\drivers\\acpi.sys')).toBe('C:\\Windows\\System32\\drivers\\acpi.sys');
    expect(parseServiceBinary('system32\\DRIVERS\\x.sys')).toBe('C:\\Windows\\system32\\DRIVERS\\x.sys');
    expect(parseServiceBinary('\\??\\C:\\Windows\\y.sys')).toBe('C:\\Windows\\y.sys');
    expect(parseServiceBinary('')).toBeNull();
  });
  it('detects unquoted service paths with spaces', () => {
    expect(isUnquotedServicePath('C:\\Program Files\\Acme App\\svc.exe -k')).toBe(true);
    expect(isUnquotedServicePath('"C:\\Program Files\\Acme App\\svc.exe" -k')).toBe(false);
    expect(isUnquotedServicePath('C:\\Windows\\system32\\svchost.exe -k netsvcs')).toBe(false);
  });
});

describe('subnets and ports', () => {
  it('enumerates hosts and refuses large ranges', () => {
    const h = subnetHosts('192.168.1.77/24');
    expect(h).toHaveLength(254);
    expect(h[0]).toBe('192.168.1.1');
    expect(h[253]).toBe('192.168.1.254');
    expect(subnetHosts('10.0.0.8/30')).toEqual(['10.0.0.9', '10.0.0.10']);
    expect(() => subnetHosts('10.0.0.0/16')).toThrow('subnet_too_large');
  });
  it('computes the network of an interface', () => {
    expect(networkOf('192.168.1.77', '255.255.255.0')).toBe('192.168.1.0/24');
    expect(networkOf('10.1.2.3', '255.255.255.252')).toBe('10.1.2.0/30');
  });
  it('names well-known ports', () => {
    expect(wellKnownService(443)).toBe('https');
    expect(wellKnownService(3389)).toBe('rdp');
    expect(wellKnownService(1)).toBeNull();
  });
});
