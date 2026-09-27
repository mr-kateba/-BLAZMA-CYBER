import { describe, expect, it } from 'vitest';
import {
  classifyIP, containsShellMetacharacters, isDomain, isIPv4, isIPv6, isPort, parsePortList, validateAbsolutePath,
} from '../src/core/validation';

describe('IP validation', () => {
  it('accepts valid IPv4', () => {
    for (const ip of ['0.0.0.0', '8.8.8.8', '192.168.1.10', '255.255.255.255']) expect(isIPv4(ip)).toBe(true);
  });
  it('rejects invalid IPv4', () => {
    for (const ip of ['256.1.1.1', '1.2.3', '01.2.3.4', '1.2.3.4.5', '1.2.3.4 ', 'a.b.c.d', '1.2.3.4;ls']) expect(isIPv4(ip)).toBe(false);
  });
  it('accepts valid IPv6', () => {
    for (const ip of ['::1', '::', '2001:db8::1', 'fe80::1ff:fe23:4567:890a', '::ffff:192.0.2.1', '2001:0db8:0000:0000:0000:ff00:0042:8329']) {
      expect(isIPv6(ip), ip).toBe(true);
    }
  });
  it('rejects invalid IPv6', () => {
    for (const ip of ['2001:db8::1::1', '12345::', 'gggg::1', ':', '1:2:3:4:5:6:7:8:9']) expect(isIPv6(ip), ip).toBe(false);
  });
  it('classifies scopes', () => {
    expect(classifyIP('192.168.1.10')).toBe('private');
    expect(classifyIP('10.0.0.1')).toBe('private');
    expect(classifyIP('172.20.0.1')).toBe('private');
    expect(classifyIP('127.0.0.1')).toBe('loopback');
    expect(classifyIP('100.64.0.1')).toBe('cgnat');
    expect(classifyIP('8.8.8.8')).toBe('public');
    expect(classifyIP('::1')).toBe('loopback');
    expect(classifyIP('fe80::1')).toBe('link-local');
    expect(classifyIP('nope')).toBeNull();
  });
});

describe('domain validation', () => {
  it('accepts valid domains', () => {
    for (const d of ['example.com', 'sub.example.co.uk', 'xn--mgbh0fb.xn--kgbechtv', 'a-b.io', 'example.com.']) expect(isDomain(d), d).toBe(true);
  });
  it('rejects invalid domains', () => {
    for (const d of ['', 'localhost', '-bad.com', 'bad-.com', 'a..b', '1.2.3.4', 'exa mple.com', 'example.com;rm', 'x'.repeat(64) + '.com']) {
      expect(isDomain(d), d).toBe(false);
    }
  });
});

describe('ports', () => {
  it('validates ports', () => {
    expect(isPort(80)).toBe(true);
    expect(isPort(0)).toBe(false);
    expect(isPort(65536)).toBe(false);
    expect(isPort(80.5)).toBe(false);
    expect(isPort('80')).toBe(false);
  });
  it('parses port lists', () => {
    expect(parsePortList('443, 22,80-82,80')).toEqual([22, 80, 81, 82, 443]);
    expect(() => parsePortList('1-70000')).toThrow();
    expect(() => parsePortList('80;ls')).toThrow();
    expect(() => parsePortList('1-5000', 100)).toThrow('too_many_ports');
  });
});

describe('command injection prevention', () => {
  it('detects shell metacharacters', () => {
    for (const s of ['a;b', 'a&&b', 'a|b', '$(x)', '`x`', 'a\nb', "a'b", 'a"b', 'a>b']) expect(containsShellMetacharacters(s), s).toBe(true);
    for (const s of ['example.com', '8.8.8.8', 'host-name_1']) expect(containsShellMetacharacters(s)).toBe(false);
  });
});

describe('path validation', () => {
  it('accepts absolute paths', () => {
    expect(validateAbsolutePath('C:\\Users\\me\\file.exe').ok).toBe(true);
    expect(validateAbsolutePath('/home/me/file').ok).toBe(true);
    expect(validateAbsolutePath('\\\\server\\share\\f.txt').ok).toBe(true);
  });
  it('rejects unsafe paths', () => {
    expect(validateAbsolutePath('relative/file')).toEqual({ ok: false, reason: 'path_not_absolute' });
    expect(validateAbsolutePath('C:\\a\0b')).toEqual({ ok: false, reason: 'path_nul_byte' });
    expect(validateAbsolutePath('\\\\?\\C:\\x')).toEqual({ ok: false, reason: 'path_device_namespace' });
    expect(validateAbsolutePath('\\\\.\\PhysicalDrive0')).toEqual({ ok: false, reason: 'path_device_namespace' });
    expect(validateAbsolutePath(42)).toEqual({ ok: false, reason: 'path_empty' });
  });
});
