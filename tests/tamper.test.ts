import { describe, expect, it } from 'vitest';
import { evaluateDns, evaluateHosts, evaluateProxy, evaluateRootCerts, evaluateTamper, parseHosts } from '../src/core/tamper';
import { assertSafeScript } from '../src/main/services/powershell';
import { TAMPER_SCRIPT, tamperChecks } from '../src/main/services/tamper';

const DEFAULT_WINDOWS_HOSTS = `# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#      102.54.94.97     rhino.acme.com          # source server
# localhost name resolution is handled within DNS itself.
#	127.0.0.1       localhost
#	::1             localhost
`;

describe('Tamper checks — hosts file', () => {
  it('the default Windows hosts file (only comments) is clean', () => {
    expect(parseHosts(DEFAULT_WINDOWS_HOSTS)).toEqual([]);
    expect(evaluateHosts(DEFAULT_WINDOWS_HOSTS)).toMatchObject({ status: 'pass', items: [], detail: { vars: { hijacked: 0, redirected: 0, blocked: 0 } } });
  });

  it('blocking or redirecting security/update sites is suspicious', () => {
    const r = evaluateHosts('127.0.0.1 localhost\n0.0.0.0 update.microsoft.com\n203.0.113.9 www.virustotal.com   # evil\n');
    expect(r.status).toBe('fail');
    expect(r.items).toEqual([
      { value: '0.0.0.0 update.microsoft.com', note: 'hosts_blocks_security', tone: 'red' },
      { value: '203.0.113.9 www.virustotal.com', note: 'hosts_redirects_security', tone: 'red' },
    ]);
  });

  it('ad-block style entries are counted, not flagged; other redirects need a look', () => {
    expect(evaluateHosts('0.0.0.0 ads.example\n0.0.0.0 tracker.example\n').status).toBe('pass');
    const r = evaluateHosts('0.0.0.0 ads.example\n203.0.113.20 bank.example\n');
    expect(r.status).toBe('warn');
    expect(r.detail?.vars).toEqual({ hijacked: 0, redirected: 1, blocked: 1 });
    expect(r.items).toEqual([{ value: '203.0.113.20 bank.example', note: 'hosts_redirect', tone: 'amber' }]);
    // This PC's own name / devices on the local network (seen on a real Windows runner) are normal.
    const lan = evaluateHosts('10.1.0.134 runnervm99s1a\n192.168.1.20 nas.home\n');
    expect(lan.status).toBe('pass');
    expect(lan.items.map((i) => i.note)).toEqual(['hosts_local', 'hosts_local']);
    expect(evaluateHosts('evil.example 1.2.3.4\nnot-an-ip evil\n').status).toBe('pass');
    expect(evaluateHosts(null).status).toBe('unknown');
  });
});

describe('Tamper checks — proxy, DNS, root certificates', () => {
  it('proxy: none is fine; a local interceptor or server needs a look; a PAC over http is suspicious', () => {
    expect(evaluateProxy({ enabled: 0, server: '10.0.0.1:8080', pac: '' })).toMatchObject({ status: 'pass', items: [] });
    expect(evaluateProxy({ enabled: 1, server: '127.0.0.1:8888', pac: '' }).items).toEqual([{ value: '127.0.0.1:8888', note: 'proxy_local', tone: 'amber' }]);
    expect(evaluateProxy({ enabled: 1, server: 'http=proxy.corp.example:3128;https=proxy.corp.example:3128', pac: null }).items[0]!.note).toBe('proxy_server');
    expect(evaluateProxy({ enabled: 0, server: '', pac: 'http://203.0.113.5/wpad.dat' })).toMatchObject({ status: 'fail', items: [{ note: 'pac_insecure', tone: 'red' }] });
    expect(evaluateProxy({ enabled: 0, server: '', pac: 'https://pac.corp.example/proxy.pac' }).status).toBe('warn');
    expect(evaluateProxy(null).status).toBe('unknown');
  });

  it('DNS: router and well-known providers are fine; unknown public servers need a look', () => {
    const ok = evaluateDns([{ iface: 'Wi-Fi', server: '192.168.1.1' }, { iface: 'Wi-Fi', server: '1.1.1.1' }, { iface: 'Wi-Fi', server: 'fec0:0:0:ffff::1' }]);
    expect(ok.status).toBe('pass');
    expect(ok.items.map((i) => i.note)).toEqual(['dns_local', 'dns_known']);
    expect(ok.items[1]!.value).toBe('1.1.1.1 — Cloudflare (Wi-Fi)');
    expect(evaluateDns({ iface: 'Ethernet 3', server: '168.63.129.16' }).status).toBe('pass'); // Azure's resolver (real runner)
    const bad = evaluateDns({ iface: 'Ethernet', server: '203.0.113.53' });
    expect(bad).toMatchObject({ status: 'warn', items: [{ value: '203.0.113.53 (Ethernet)', note: 'dns_unknown', tone: 'amber' }] });
    expect(evaluateDns(null).status).toBe('unknown');
  });

  it('root certificates: user-added roots are listed with subject + thumbprint', () => {
    expect(evaluateRootCerts([]).status).toBe('pass');
    const r = evaluateRootCerts({ thumbprint: 'ab'.repeat(20), subject: 'CN=DO_NOT_TRUST_FiddlerRoot', notAfter: null });
    expect(r).toMatchObject({ status: 'warn', items: [{ value: `CN=DO_NOT_TRUST_FiddlerRoot · ${'AB'.repeat(20)}`, note: 'root_user_added' }] });
    expect(evaluateRootCerts([{ thumbprint: 'x', subject: null, notAfter: null }]).items).toEqual([]);
  });

  it('report shape', () => {
    const r = evaluateTamper({ hosts: '', proxy: { enabled: 0 }, dns: [], userRoots: [] }, new Date('2026-09-27T00:00:00Z'));
    expect(r.findings.map((f) => [f.id, f.status])).toEqual([['hosts', 'pass'], ['proxy', 'pass'], ['dns', 'pass'], ['root_certs', 'pass']]);
  });
});

describe('Tamper script', () => {
  it('is a fixed, query-only script', () => {
    expect(() => assertSafeScript(TAMPER_SCRIPT)).not.toThrow();
    expect(TAMPER_SCRIPT).not.toMatch(/\b(Set-|Remove-|New-|Stop-|Start-Process|Restart-|Disable-|Enable-|Invoke-Expression|Uninstall-|Register-|Unregister-|Import-Certificate|certutil)/i);
    expect(TAMPER_SCRIPT).not.toContain('BLAZMA_ARG_');
  });

  it.runIf(process.platform !== 'win32')('reads the real hosts file on this OS; Windows-only checks say so', async () => {
    const r = await tamperChecks();
    expect(r.findings.find((f) => f.id === 'hosts')!.status).not.toBe('unknown');
    for (const id of ['proxy', 'dns', 'root_certs']) expect(r.findings.find((f) => f.id === id)).toMatchObject({ status: 'unknown', reason: 'unsupported_platform' });
  });
});
