import { describe, expect, it } from 'vitest';
import { reviewStartup, startupProgram } from '../src/core/startup-review';

const SID = 'HKU\\S-1-5-21-1-2-3-1001\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run';
const rows = [
  { name: 'OneDrive', command: '"C:\\Users\\sara\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background', location: SID, user: 'PC\\sara' },
  { name: 'SecurityHealth', command: '%windir%\\system32\\SecurityHealthSystray.exe', location: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', user: 'Public' },
  { name: 'updater', command: 'C:\\Users\\sara\\AppData\\Roaming\\upd\\svc.exe -q', location: 'Startup', user: 'PC\\sara' },
  { name: 'helper', command: 'rundll32.exe C:\\Users\\Public\\x.dll,Start', location: 'Common Startup', user: 'Public' },
  { name: 'ps', command: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -w hidden -c ...', location: SID, user: 'PC\\sara' },
];
const sigs = [
  { path: 'C:\\Users\\sara\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe', status: 'valid' as const, publisher: 'Microsoft Corporation' },
  { path: 'C:\\Windows\\system32\\SecurityHealthSystray.exe', status: 'valid' as const, publisher: 'Microsoft Windows' },
  { path: 'c:\\users\\sara\\appdata\\roaming\\upd\\svc.exe', status: 'not_signed' as const, publisher: null },
  { path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', status: 'valid' as const, publisher: 'Microsoft Windows' },
];

describe('what starts with Windows', () => {
  it('extracts the program from quoted, unquoted and %windir% commands', () => {
    expect(startupProgram('"C:\\A B\\x.exe" --flag')).toBe('C:\\A B\\x.exe');
    expect(startupProgram('%windir%\\system32\\a.exe')).toBe('C:\\Windows\\system32\\a.exe');
    expect(startupProgram('explorer.exe')).toBeNull();
  });

  it('marks unsigned programs in user folders and script hosts as worth a look — never signed Microsoft apps', () => {
    const r = reviewStartup(rows, sigs);
    const by = (n: string) => r.find((x) => x.name === n)!;
    expect(by('OneDrive')).toMatchObject({ scope: 'user', signature: 'valid', publisher: 'Microsoft Corporation', attention: false });
    expect(by('OneDrive').flags).toContain('hunt.flag.userFolder');
    expect(by('SecurityHealth')).toMatchObject({ scope: 'all_users', signature: 'valid', attention: false, flags: [] });
    expect(by('updater')).toMatchObject({ scope: 'user', signature: 'not_signed', attention: true });
    expect(by('helper')).toMatchObject({ scope: 'all_users', program: null, attention: true });
    expect(by('ps')).toMatchObject({ attention: true });
    expect(by('ps').flags).toContain('hunt.flag.scriptHost');
    // Worth-a-look entries first.
    expect(r.slice(0, 3).every((x) => x.attention)).toBe(true);
    expect(reviewStartup([{ name: 'x', command: '"C:\\Program Files\\cmdtool\\cmd.helper.exe"', location: 'HKLM', user: null }], [])[0]!.attention).toBe(false);
  });

  it('does not guess when the signature is unknown', () => {
    const r = reviewStartup([rows[2]!], []);
    expect(r[0]).toMatchObject({ signature: null, attention: false });
  });
});
