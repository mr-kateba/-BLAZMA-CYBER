import { describe, expect, it, vi } from 'vitest';
import { tmpdir } from 'node:os';

vi.mock('electron', () => ({ app: { getPath: () => tmpdir() }, safeStorage: {}, shell: { openExternal: vi.fn() } }));

import { evaluateDevice, SETTINGS_URIS, type RawDeviceFacts } from '../src/core/device-security';
import { DEVICE_SCRIPT, openSettingsPage } from '../src/main/services/device-security';
import { assertSafeScript } from '../src/main/services/powershell';

const NOW = new Date('2026-09-27T12:00:00Z');
const HARDENED: RawDeviceFacts = {
  elevated: false,
  defender: { available: true, rtp: true, age: 1, tamper: true },
  firewall: [{ name: 'Domain', enabled: true }, { name: 'Private', enabled: true }, { name: 'Public', enabled: true }],
  uac: { lua: 1, consent: 5 }, smb1Client: -1, rdp: { deny: 1, nla: 1 }, secureBoot: 1, bitlocker: 1,
  lastUpdate: '2026-09-20T00:00:00Z', autoLogon: '0', guestEnabled: false, lsaPpl: 1, vbs: 2, execPolicy: 'RemoteSigned', tpm: null,
};
const by = (r: ReturnType<typeof evaluateDevice>, id: string) => r.checks.find((c) => c.id === id)!;

describe('Device Security Score', () => {
  it('a hardened machine scores 100; the admin-only TPM check is unknown, not counted', () => {
    const r = evaluateDevice(HARDENED, NOW);
    expect(r.score).toBe(100);
    expect(r.grade).toBe('good');
    expect(by(r, 'tpm')).toMatchObject({ status: 'unknown', reason: 'needs_admin' });
    expect(r.unknown).toBe(1);
    expect(by(r, 'updates').detail).toEqual({ key: 'devsec.detail.days', vars: { days: 7 } });
  });

  it('flags real weaknesses with fail/warn', () => {
    const r = evaluateDevice({
      ...HARDENED,
      defender: { available: true, rtp: false, age: 12, tamper: false },
      firewall: [{ name: 'Domain', enabled: true }, { name: 'Public', enabled: false }],
      uac: { lua: 0, consent: 5 }, smb1Client: 3, rdp: { deny: 0, nla: 0 }, bitlocker: 2,
      lastUpdate: '2026-05-01T00:00:00Z', autoLogon: '1', guestEnabled: true, execPolicy: 'Unrestricted',
    }, NOW);
    for (const id of ['defender_realtime', 'defender_signatures', 'firewall', 'uac', 'smb1', 'rdp', 'encryption', 'updates', 'auto_logon', 'guest']) {
      expect(by(r, id).status, id).toBe('fail');
    }
    expect(by(r, 'tamper_protection').status).toBe('warn');
    expect(by(r, 'exec_policy').status).toBe('warn');
    expect(by(r, 'firewall').detail).toEqual({ key: 'devsec.detail.profilesOff', vars: { profiles: 'Public' } });
    expect(r.grade).toBe('poor');
  });

  it('never invents results: unreadable facts are unknown and excluded from the score', () => {
    const r = evaluateDevice({ elevated: false, defender: { available: false }, firewall: null }, NOW);
    expect(r.checks.every((c) => c.status === 'unknown')).toBe(true);
    expect(r.score).toBeNull();
    expect(r.grade).toBeNull();
    expect(by(r, 'defender_realtime').reason).toBe('defender_unavailable');
    expect(by(r, 'secure_boot').reason).toBe('not_supported');
  });

  it('treats unset registry values as the Windows default', () => {
    const r = evaluateDevice({ ...HARDENED, uac: { lua: -1, consent: -1 }, rdp: { deny: -1, nla: -1 }, autoLogon: 'absent', lsaPpl: -1 }, NOW);
    expect(by(r, 'uac').status).toBe('pass');
    expect(by(r, 'rdp').status).toBe('pass');
    expect(by(r, 'auto_logon').status).toBe('pass');
    expect(by(r, 'lsa_protection').status).toBe('warn');
  });

  it('the collector script is fixed, read-only and has no parameters', () => {
    expect(() => assertSafeScript(DEVICE_SCRIPT)).not.toThrow();
    expect(DEVICE_SCRIPT).not.toMatch(/\$\{/);
    expect(DEVICE_SCRIPT).not.toMatch(/\b(Set-|Remove-|New-|Stop-|Start-Process|Restart-|Disable-|Enable-|Invoke-Expression|Add-MpPreference|Set-MpPreference|Uninstall-|Register-|Unregister-)/i);
    expect(DEVICE_SCRIPT).not.toContain('BLAZMA_ARG_');
    expect(DEVICE_SCRIPT).toContain("'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'");
  });

  it('settings pages are a fixed allowlist of Windows URIs', async () => {
    for (const uri of Object.values(SETTINGS_URIS)) expect(uri).toMatch(/^(ms-settings:|windowsdefender:\/\/)[a-z]+$/);
    await expect(openSettingsPage('https://evil.example')).rejects.toMatchObject({ code: process.platform === 'win32' ? 'invalid_input' : 'unsupported_platform' });
  });
});
