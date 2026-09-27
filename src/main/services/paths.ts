import { app } from 'electron';
import { existsSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';

/** A file with this name next to Blazma Cyber.exe turns on portable mode (the portable .zip ships it). */
export const PORTABLE_MARKER = 'portable.txt';

/** Where a portable copy keeps its data (next to the program), or null when this copy is not portable. */
export function portableDirFor(execPath: string, packaged: boolean): string | null {
  if (!packaged) return null;
  const base = dirname(execPath);
  return existsSync(join(base, PORTABLE_MARKER)) ? join(base, 'Blazma-data') : null;
}

let portable: string | null | undefined;

/** Portable data folder if active and writable; a read-only medium falls back to the normal location. */
export function portableDataDir(): string | null {
  if (portable !== undefined) return portable;
  const dir = portableDirFor(process.execPath, app.isPackaged);
  try {
    if (dir) mkdirSync(dir, { recursive: true });
    portable = dir;
  } catch {
    portable = null;
  }
  return portable;
}

/** All Blazma data lives under one local directory. Nothing is stored in the cloud. */
export function dataDir(): string {
  return process.env.BLAZMA_DATA_DIR || portableDataDir() || app.getPath('userData');
}

export function subDir(name: 'logs' | 'temp' | 'state' | 'secrets' | 'quarantine' | 'yara' | 'cases' | 'reports'): string {
  const dir = join(dataDir(), name);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}
