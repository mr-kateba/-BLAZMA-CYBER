import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

let dataDir: string;
vi.mock('electron', () => ({ app: { getPath: () => dataDir }, safeStorage: {} }));

import { YaraService } from '../src/main/services/yara';
import { yaraWeight } from '../src/main/services/file-analysis';

const PACK = join(__dirname, '..', 'engines', 'rules', 'reversinglabs.yar');
const LOCK = JSON.parse(readFileSync(join(__dirname, '..', 'engines.lock.json'), 'utf8'));

describe('Bundled rule pack & engines lock', () => {
  it('the vendored ReversingLabs pack is intact and licensed', () => {
    const text = readFileSync(PACK, 'utf8');
    expect(text).toContain('Commit e0a0be54aa1e11ccfd6854e4f19e9476f328fd84');
    expect((text.match(/^(private )?rule /gm) ?? []).length).toBe(LOCK.rules[0].rules);
    expect(existsSync(join(__dirname, '..', 'engines', 'rules', 'LICENSE-reversinglabs.txt'))).toBe(true);
    // Never ship the contiguous EICAR string (antivirus would flag BLAZMA itself).
    expect(text).not.toContain('X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR');
  });

  it('every bundled engine is pinned to an official https release with a SHA-256 and a license file', () => {
    for (const e of LOCK.engines) {
      expect(e.url, e.id).toMatch(/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/releases\/download\//);
      expect(e.sha256, e.id).toMatch(/^[a-f0-9]{64}$/);
      expect(e.size, e.id).toBeGreaterThan(1000);
      expect(existsSync(join(__dirname, '..', 'engines', 'licenses', `${e.id}.txt`)), e.id).toBe(true);
    }
  });

  it('ReversingLabs family rules are definitive; PUA is only strong evidence', () => {
    expect(yaraWeight({ tc_detection_type: 'Ransomware' })).toBe('malicious');
    expect(yaraWeight({ tc_detection_type: 'PUA' })).toBe('strong');
    expect(yaraWeight({ severity: 'info' })).toBe('weak');
    expect(yaraWeight({})).toBe('strong');
  });
});

const YR = process.env.BLAZMA_TEST_YR;
describe.skipIf(!YR || !existsSync(YR))('Rule pack with the REAL YARA-X engine', () => {
  let work: string;
  let packCopy: string;
  beforeAll(() => {
    dataDir = mkdtempSync(join(tmpdir(), 'blazma-pack-'));
    work = mkdtempSync(join(tmpdir(), 'blazma-pack-t-'));
    packCopy = join(work, 'pack.yar');
    copyFileSync(PACK, packCopy);
    writeFileSync(join(work, 'hello.txt'), 'hello world');
  });
  afterAll(() => {
    rmSync(dataDir, { recursive: true, force: true });
    rmSync(work, { recursive: true, force: true });
  });
  const svc = () => new YaraService(() => null, { exe: () => YR!, packs: () => [{ id: 'pack-reversinglabs', name: 'ReversingLabs', path: packCopy }] });

  it('uses the bundled engine when the user chose none', async () => {
    expect(await svc().engine()).toMatchObject({ available: true, bundled: true, version: '1.20.0' });
  });

  it('installs the pack enabled, validates it, and refuses to delete it', async () => {
    const s = svc();
    const pack = (await s.listRules()).find((r) => r.id === 'pack-reversinglabs');
    expect(pack).toMatchObject({ origin: 'pack', enabled: true });
    const validated = (await s.validateAll()).find((r) => r.id === 'pack-reversinglabs');
    expect(validated?.valid).toBe(true);
    await expect(s.remove('pack-reversinglabs')).rejects.toMatchObject({ code: 'yara_pack_readonly' });
    expect((await s.getSource('pack-reversinglabs')).length).toBeLessThan(260_000);
  }, 120_000);

  it('scans with the pack (no false positive on a benign file) and refreshes it when the app ships a new one', async () => {
    const s = svc();
    const r = await s.scan(join(work, 'hello.txt'), { recursive: false, signal: new AbortController().signal });
    expect(r.matchedFiles).toBe(0);
    expect(r.rulesUsed).toBeGreaterThan(0);
    writeFileSync(packCopy, readFileSync(PACK, 'utf8') + '\n// v2\n');
    await s.listRules();
    const installed = readFileSync(join(dataDir, 'yara', 'rules', 'pack-reversinglabs.yar'));
    expect(createHash('sha256').update(installed).digest('hex')).toBe(createHash('sha256').update(readFileSync(packCopy)).digest('hex'));
  }, 120_000);
});

describe.skipIf(!YR || !existsSync(YR))('Rule validation follows YARA-X verdicts', () => {
  it('warnings are valid, errors are not (even if the source contains the word "error")', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'blazma-chk-'));
    const s = new YaraService(() => YR!);
    const warn = join(dir, 'warn.yar');
    writeFileSync(warn, 'import "pe"\nimport "pe"\nrule error_strings { strings: $a = "error" condition: $a }\n');
    const bad = join(dir, 'bad.yar');
    writeFileSync(bad, 'rule bad { condition: foo }\n');
    expect(await s.checkFile(warn)).toBeNull();
    expect(await s.checkFile(bad)).toMatch(/E009|unknown identifier/);
    rmSync(dir, { recursive: true, force: true });
  });
});
