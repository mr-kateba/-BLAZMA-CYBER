import { EventEmitter } from 'node:events';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { openTerminal, terminalCandidates, terminalEnv } from '../src/main/services/terminal';

const ENV = {
  USERPROFILE: 'C:\\Users\\sara', LOCALAPPDATA: 'C:\\Users\\sara\\AppData\\Local', SystemRoot: 'C:\\Windows',
  PATH: 'C:\\Windows', BLAZMA_ARG_PATH: 'x', ELECTRON_RUN_AS_NODE: '1', PSModulePath: 'C:\\pwsh\\Modules', NODE_OPTIONS: '--inspect',
} as NodeJS.ProcessEnv;

/** Fake spawn: succeeds for the executables in `ok`, emits ENOENT for the rest. */
function fakeSpawn(ok: string[]) {
  const calls: Array<{ exe: string; args: string[]; opts: Record<string, unknown> }> = [];
  const fn = (exe: string, args: string[], opts: object) => {
    calls.push({ exe, args, opts: opts as Record<string, unknown> });
    const child = Object.assign(new EventEmitter(), { unref: () => {} });
    setImmediate(() => (ok.some((o) => exe.endsWith(o)) ? child.emit('spawn') : child.emit('error', Object.assign(new Error('nope'), { code: 'ENOENT' }))));
    return child as never;
  };
  return { fn, calls };
}

describe('Open terminal (regular Windows terminal, own window)', () => {
  it('prefers Windows Terminal, started in the user profile with fixed arguments', async () => {
    const s = fakeSpawn(['wt.exe', 'powershell.exe']);
    expect(await openTerminal({ platform: 'win32', env: ENV, spawnFn: s.fn })).toBe('windows-terminal');
    expect(s.calls).toHaveLength(1);
    expect(s.calls[0]).toMatchObject({ exe: join('C:\\Users\\sara\\AppData\\Local', 'Microsoft', 'WindowsApps', 'wt.exe'), args: ['-d', 'C:\\Users\\sara'] });
    expect(s.calls[0]!.opts).toMatchObject({ detached: true, stdio: 'ignore', cwd: 'C:\\Users\\sara' });
  });

  it('falls back to Windows PowerShell when Windows Terminal is not installed', async () => {
    const s = fakeSpawn(['powershell.exe']);
    expect(await openTerminal({ platform: 'win32', env: ENV, spawnFn: s.fn })).toBe('powershell');
    expect(s.calls.map((c) => c.exe.split(/[\\/]/).pop())).toEqual(['wt.exe', 'powershell.exe']);
    expect(s.calls[1]!.args).toEqual(['-NoLogo']);
  });

  it('reports honestly when nothing can be opened, and on other platforms', async () => {
    await expect(openTerminal({ platform: 'win32', env: ENV, spawnFn: fakeSpawn([]).fn })).rejects.toMatchObject({ code: 'terminal_unavailable' });
    await expect(openTerminal({ platform: 'linux', env: ENV, spawnFn: fakeSpawn(['wt.exe']).fn })).rejects.toMatchObject({ code: 'unsupported_platform' });
  });

  it('gives the terminal a clean environment', () => {
    const e = terminalEnv(ENV);
    expect(Object.keys(e).sort()).toEqual(['LOCALAPPDATA', 'PATH', 'SystemRoot', 'USERPROFILE']);
  });

  it('uses absolute paths only (no PATH lookup)', () => {
    for (const c of terminalCandidates(ENV)) expect(c.exe).toMatch(/^C:\\/);
    expect(terminalCandidates({ SystemRoot: 'C:\\Windows' } as NodeJS.ProcessEnv).map((c) => c.kind)).toEqual(['powershell']);
  });
});
