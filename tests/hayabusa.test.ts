import { existsSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { HuntAccumulator, hayabusaTime, parseHayabusaLine, type EventDetection } from '../src/core/hayabusa';
import { assertSafeScript } from '../src/main/services/powershell';
import { hayabusaArgs, LIVE_SCRIPT, parseOptions, parseSource, runEventHunt } from '../src/main/services/event-hunt';

// Shape of one `hayabusa dfir-timeline -t jsonl -p super-verbose -b` line (Hayabusa 4.1.0).
const LINE = '{ "Timestamp":"2021-10-20 13:39:12.731 +00:00","RuleTitle":"Log Cleared","Level":"high","Computer":"FS03.offsec.lan","Channel":"Security","EventID":1102,"RuleAuthor":"Zach Mathis","RuleModifiedDate":"2025-02-10","Status":"stable","RecordID":67099,"Details":{"SubjectDomainName":"OFFSEC","SubjectUserName":"admmig"},"ExtraFieldInfo":{},"MitreTactics":["Stealth"],"MitreTags":["T1070.001"],"Provider":"Microsoft-Windows-Eventlog","RuleCreationDate":"2020-11-08","RuleFile":"Sec_1102_High_SecLogCleared.yml","RuleID":"c2f690ac-53f8-4745-8cfe-7127dda28c74","EvtxFile":"C:\\\\logs\\\\Security.evtx" }';

describe('Hayabusa results', () => {
  it('parses a detection and keeps the rule author (DRL 1.1)', () => {
    expect(parseHayabusaLine(LINE)).toEqual({
      time: '2021-10-20T13:39:12.731Z', rule: 'Log Cleared', level: 'high', computer: 'FS03.offsec.lan', channel: 'Security', eventId: 1102, recordId: 67099,
      tactics: ['stealth'], techniques: ['T1070.001'], details: [['SubjectDomainName', 'OFFSEC'], ['SubjectUserName', 'admmig']],
      ruleAuthor: 'Zach Mathis', ruleFile: 'Sec_1102_High_SecLogCleared.yml', ruleId: 'c2f690ac-53f8-4745-8cfe-7127dda28c74', evtxFile: 'C:\\logs\\Security.evtx',
    });
    expect(parseHayabusaLine('{"RuleTitle":"x","Level":"crit","Details":"plain text"}')).toMatchObject({ level: 'critical', details: [['', 'plain text']], time: null });
    expect(parseHayabusaLine('not json')).toBeNull();
    expect(parseHayabusaLine('{"Level":"high"}')).toBeNull();
    expect(hayabusaTime('2022-02-22 22:00:00.1234567 +09:00')).toBe('2022-02-22T13:00:00.123Z');
    expect(hayabusaTime('yesterday')).toBeNull();
  });

  it('summarizes every detection and keeps the most severe rows first', () => {
    const acc = new HuntAccumulator(2);
    const d = (rule: string, level: EventDetection['level'], time: string, tactics: string[] = []) =>
      ({ ...parseHayabusaLine(LINE)!, rule, level, time, tactics, ruleAuthor: 'A' }) as EventDetection;
    acc.add(d('low1', 'low', '2026-01-01T00:00:00.000Z'));
    acc.add(d('low1', 'low', '2026-01-02T00:00:00.000Z'));
    acc.add(d('low1', 'low', '2026-01-03T00:00:00.000Z'));
    acc.add(d('crit', 'critical', '2026-01-04T00:00:00.000Z', ['execution']));
    acc.add(d('med', 'medium', '2026-01-05T00:00:00.000Z', ['execution', 'persistence']));
    const s = acc.summary();
    expect(s.total).toBe(5);
    expect(s.byLevel).toEqual({ critical: 1, high: 0, medium: 1, low: 3, informational: 0 });
    expect(s.topRules.map((r) => [r.rule, r.count])).toEqual([['crit', 1], ['med', 1], ['low1', 3]]);
    expect(s.tactics).toEqual([{ id: 'execution', count: 2 }, { id: 'persistence', count: 1 }]);
    expect([s.first, s.last]).toEqual(['2026-01-01T00:00:00.000Z', '2026-01-05T00:00:00.000Z']);
    expect(acc.sortedRows().map((r) => r.rule)).toEqual(['crit', 'med']);
  });
});

describe('Hayabusa runner', () => {
  it('builds a non-interactive, JSONL, rule-author-keeping command', () => {
    const a = hayabusaArgs(['-f', 'C:\\x.evtx'], 'out.jsonl', 'C:\\rules', { minLevel: 'high', days: 7 });
    expect(a.slice(0, 3)).toEqual(['dfir-timeline', '-f', 'C:\\x.evtx']);
    for (const f of ['-w', '-q', '-K', '-N', '-C', '-U', '-Q', '-b']) expect(a).toContain(f);
    expect(a.join(' ')).toContain('-t jsonl -p super-verbose');
    expect(a.join(' ')).toContain('-m high -r C:\\rules --time-offset 7d');
    expect(hayabusaArgs([], 'o', 'r', { minLevel: 'low', days: null })).not.toContain('--time-offset');
  });

  it('validates options and sources', async () => {
    expect(parseOptions({ minLevel: 'medium', days: 30 })).toEqual({ minLevel: 'medium', days: 30 });
    expect(() => parseOptions({ minLevel: 'informational', days: 30 })).toThrow();
    expect(() => parseOptions({ minLevel: 'high', days: 5 })).toThrow();
    expect(await parseSource({ kind: 'live' })).toEqual({ kind: 'live' });
    await expect(parseSource({ kind: 'file', path: 'relative.evtx' })).rejects.toMatchObject({ code: 'path_not_absolute' });
    await expect(parseSource({ kind: 'file', path: __filename })).rejects.toMatchObject({ code: 'evtx_expected' });
    await expect(parseSource({ kind: 'dir', path: __filename })).rejects.toMatchObject({ code: 'not_a_folder' });
    await expect(parseSource({ kind: 'shell', path: '/' })).rejects.toMatchObject({ code: 'invalid_input' });
  });

  it('the elevated script is a constant, quote-free, and only starts the engine', () => {
    expect(() => assertSafeScript(LIVE_SCRIPT)).not.toThrow();
    expect(LIVE_SCRIPT).toContain('-Verb RunAs');
    expect(LIVE_SCRIPT).not.toMatch(/Invoke-Expression|iex |Set-|Remove-|New-Item|-EncodedCommand|Bypass/i);
    expect(LIVE_SCRIPT).toContain("'-l'");
  });

  // Real engine: BLAZMA_TEST_HAYABUSA=<hayabusa binary with rules/ next to it>, BLAZMA_TEST_EVTX=<a .evtx file>.
  const exe = process.env.BLAZMA_TEST_HAYABUSA;
  const evtx = process.env.BLAZMA_TEST_EVTX;
  it.runIf(exe && evtx && existsSync(exe))('runs the real engine on an event log', async () => {
    process.env.BLAZMA_DATA_DIR ??= mkdtempSync(join(tmpdir(), 'blazma-hb-'));
    const r = await runEventHunt(exe!, { kind: 'file', path: evtx! }, { minLevel: 'low', days: null }, new AbortController().signal);
    console.log('Hayabusa:', JSON.stringify({ total: r.total, byLevel: r.byLevel, rules: r.topRules.slice(0, 5).map((x) => x.rule), ms: r.durationMs }));
    expect(r.total).toBeGreaterThan(0);
    expect(r.rows.every((x) => x.ruleAuthor !== undefined)).toBe(true);
  }, 300_000);
});
