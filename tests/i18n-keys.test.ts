import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import en from '../locales/en.json';

// Every literal t('some.key') in the UI must exist — a missing key would show the raw key to users.
function files(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? files(p) : /\.tsx?$/.test(f) ? [p] : [];
  });
}

const has = (key: string) => key.split('.').reduce<unknown>((o, k) => (o && typeof o === 'object' ? (o as Record<string, unknown>)[k] : undefined), en) !== undefined;

describe('localization keys used in code', () => {
  it('exist in the locale files', () => {
    const missing: string[] = [];
    for (const file of files(join(__dirname, '..', 'src', 'renderer'))) {
      const src = readFileSync(file, 'utf8');
      for (const m of src.matchAll(/\bt\(\s*'([a-zA-Z][\w]*(?:\.[\w]+)+)'/g)) {
        if (!has(m[1]!)) missing.push(`${file.split('src')[1]}: ${m[1]}`);
      }
    }
    expect(missing).toEqual([]);
  });
});
