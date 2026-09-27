import { describe, expect, it, vi } from 'vitest';
import { tmpdir } from 'node:os';

vi.mock('electron', () => ({ app: { getPath: () => tmpdir() }, safeStorage: {} }));

import { buildEngineArgs, parseProgress, validateMode, RecoveryService } from '../src/main/services/recovery';
import { redact } from '../src/core/redact';

describe('recovery input validation', () => {
  it('requires absolute wordlist paths and safe masks', () => {
    expect(validateMode({ type: 'wordlist', path: '/tmp/list.txt' })).toEqual({ type: 'wordlist', path: '/tmp/list.txt' });
    expect(() => validateMode({ type: 'wordlist', path: 'relative.txt' })).toThrow('path_not_absolute');
    expect(validateMode({ type: 'mask', mask: '?u?l?l?l?d?d' })).toEqual({ type: 'mask', mask: '?u?l?l?l?d?d' });
    // A mask containing shell/command characters must be rejected outright.
    expect(() => validateMode({ type: 'mask', mask: '$(id)' })).toThrow('invalid_mask');
    expect(() => validateMode({ type: 'mask', mask: 'a;b|c`d' })).toThrow('invalid_mask');
    expect(() => validateMode({ type: 'nope' })).toThrow('invalid_mode');
  });

  it('builds argument arrays, never shell strings', () => {
    expect(buildEngineArgs('john', '/t/hash.txt', { type: 'wordlist', path: '/t/w.txt' })).toEqual(['--wordlist=/t/w.txt', '/t/hash.txt']);
    const hc = buildEngineArgs('hashcat', '/t/hash.txt', { type: 'mask', mask: '?d?d?d?d' });
    expect(hc[0]).toBe('-a');
    expect(hc).toContain('/t/hash.txt');
    // A path with shell metacharacters stays a single, unmodified argv element.
    const tricky = buildEngineArgs('hashcat', '/t/h', { type: 'wordlist', path: '/t/a b; ls.txt' });
    expect(tricky).toContain('/t/a b; ls.txt');
  });

  it('parses progress from hashcat JSON and John lines without leaking candidates', () => {
    expect(parseProgress('{"progress":[1000,5000],"devices":[{"speed":42}],"recovered_hashes":[0,1]}', 'hashcat')).toEqual({ tried: 1000, total: 5000, rate: 42 });
    expect(parseProgress('{"progress":[2,2],"recovered_hashes":[1,1]}', 'hashcat')).toMatchObject({ recovered: true });
    expect(parseProgress('0g 0:00:00:05 33% 2/3 1500p/s 1500c/s', 'john')).toMatchObject({ rate: 1500 });
    expect(parseProgress('any-line-with-a-candidate-value', 'john')).toBeNull();
  });
});

describe('recovery session runner', () => {
  it('requires explicit authorization before starting', async () => {
    const svc = new RecoveryService(() => process.execPath);
    await expect(svc.start('hashcat', '/tmp/x', { type: 'mask', mask: '?d' }, false, () => {})).rejects.toMatchObject({ code: 'authorization_required' });
  });

  it('reports engine availability honestly', async () => {
    expect(await new RecoveryService(() => null).engine('john')).toMatchObject({ available: false, reason: 'engine_not_configured' });
    expect(await new RecoveryService(() => '/no/such/engine').engine('hashcat')).toMatchObject({ available: false, reason: 'engine_path_missing' });
  });

  it('drives a stand-in engine end to end and reveals the result exactly once', async () => {
    if (process.platform === 'win32') return;
    const { mkdtempSync, writeFileSync, copyFileSync, chmodSync } = await import('node:fs');
    const { join } = await import('node:path');
    const dir = mkdtempSync(join(tmpdir(), 'rec-'));
    const engine = join(dir, 'engine.js');
    copyFileSync(join(__dirname, 'fixtures', 'fake-engine.js'), engine);
    chmodSync(engine, 0o755);
    const target = join(dir, 'target.zip');
    const wordlist = join(dir, 'w.txt');
    writeFileSync(target, 'data');
    writeFileSync(wordlist, 'a');
    const svc = new RecoveryService(() => engine);

    const events: any[] = [];
    await new Promise<void>((resolve) => {
      void svc.start('hashcat', target, { type: 'wordlist', path: wordlist }, true, (_id, ev) => {
        events.push(ev);
        if (ev.type === 'done' || ev.type === 'error') resolve();
      }).catch((e) => { events.push({ type: 'error', error: (e as Error).message }); resolve(); });
    });

    expect(events.some((e) => e.type === 'progress' && e.progress.rate === 500)).toBe(true);
    expect(events.find((e) => e.type === 'done')).toMatchObject({ found: true, password: 'REVEALED-SECRET' });
    expect(svc.list()).toEqual([]);
  });

  it('redaction strips a recovered password if it ever reached a log context', () => {
    const out = redact({ event: 'done', recovered: 'REVEALED-SECRET', note: 'x' }) as { recovered: string; note: string };
    expect(out.recovered).toBe('[REDACTED]');
    expect(out.note).toBe('x');
  });
});
