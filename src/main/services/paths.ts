import { app } from 'electron';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';

/** All Blazma data lives under one local directory. Nothing is stored in the cloud. */
export function dataDir(): string {
  return process.env.BLAZMA_DATA_DIR || app.getPath('userData');
}

export function subDir(name: 'logs' | 'temp' | 'state' | 'secrets'): string {
  const dir = join(dataDir(), name);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}
