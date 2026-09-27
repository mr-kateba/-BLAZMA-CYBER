// Opens the user's regular Windows terminal in its own window. BLAZMA does not host a terminal:
// the GUI never builds or runs commands from user input, and a separate window keeps it that way.
//
// Order: Windows Terminal (wt.exe, when installed) → Windows PowerShell. Absolute paths, fixed
// arguments, unelevated, detached; the child gets a clean environment (no BLAZMA_/ELECTRON_ variables,
// no inherited PSModulePath — see powershell.ts).

import { spawn, type ChildProcess, type SpawnOptions } from 'node:child_process';
import { homedir } from 'node:os';
import { join } from 'node:path';

export class TerminalError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

export type TerminalKind = 'windows-terminal' | 'powershell';

export interface TerminalCandidate {
  kind: TerminalKind;
  exe: string;
  args: string[];
}

export function terminalCandidates(env: NodeJS.ProcessEnv): TerminalCandidate[] {
  const home = env.USERPROFILE || homedir();
  const root = env.SystemRoot || 'C:\\Windows';
  const list: TerminalCandidate[] = [];
  // wt.exe is an App Execution Alias; existence checks on aliases are unreliable, so we just try it.
  if (env.LOCALAPPDATA) list.push({ kind: 'windows-terminal', exe: join(env.LOCALAPPDATA, 'Microsoft', 'WindowsApps', 'wt.exe'), args: ['-d', home] });
  list.push({ kind: 'powershell', exe: join(root, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'), args: ['-NoLogo'] });
  return list;
}

export function terminalEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(env)) {
    const u = k.toUpperCase();
    if (u.startsWith('BLAZMA_') || u.startsWith('ELECTRON_') || u === 'PSMODULEPATH' || u === 'NODE_OPTIONS') continue;
    out[k] = v;
  }
  return out;
}

type SpawnFn = (exe: string, args: string[], opts: SpawnOptions) => ChildProcess;

function launch(c: TerminalCandidate, cwd: string, env: NodeJS.ProcessEnv, spawnFn: SpawnFn): Promise<void> {
  return new Promise((resolve, reject) => {
    // detached on Windows = the console program gets its own new window and outlives BLAZMA.
    const child = spawnFn(c.exe, c.args, { cwd, env, detached: true, stdio: 'ignore', windowsHide: false });
    child.once('error', reject);
    child.once('spawn', () => {
      child.unref();
      resolve();
    });
  });
}

export async function openTerminal(opts: { platform?: NodeJS.Platform; env?: NodeJS.ProcessEnv; spawnFn?: SpawnFn } = {}): Promise<TerminalKind> {
  const platform = opts.platform ?? process.platform;
  if (platform !== 'win32') throw new TerminalError('unsupported_platform');
  const env = opts.env ?? process.env;
  const cwd = env.USERPROFILE || homedir();
  const childEnv = terminalEnv(env);
  for (const c of terminalCandidates(env)) {
    try {
      await launch(c, cwd, childEnv, opts.spawnFn ?? (spawn as SpawnFn));
      return c.kind;
    } catch {
      // try the next candidate
    }
  }
  throw new TerminalError('terminal_unavailable');
}
