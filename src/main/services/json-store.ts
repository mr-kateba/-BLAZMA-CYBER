import { readFileSync, renameSync, writeFileSync, existsSync } from 'node:fs';

/** Reads JSON, returning `fallback` when the file is missing or corrupt (corrupt files are kept aside). */
export function readJson<T>(file: string, fallback: T): T {
  if (!existsSync(file)) return fallback;
  try {
    return JSON.parse(readFileSync(file, 'utf8')) as T;
  } catch {
    try {
      renameSync(file, `${file}.corrupt-${Date.now()}`);
    } catch {
      /* ignore */
    }
    return fallback;
  }
}

/** Atomic write: write to a temp file then rename, so a crash never leaves half-written state. */
export function writeJson(file: string, value: unknown): void {
  const tmp = `${file}.tmp-${process.pid}`;
  writeFileSync(tmp, JSON.stringify(value, null, 2), { encoding: 'utf8', mode: 0o600 });
  renameSync(tmp, file);
}
