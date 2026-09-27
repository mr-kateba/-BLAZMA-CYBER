import { describe, expect, it } from 'vitest';
import { parseCapa } from '../src/core/capa';
import { parseDie } from '../src/core/die';
import { buildSignals } from '../src/main/services/file-analysis';

// Shape of capa's JSON result document (`capa -j`), trimmed to the fields Blazma reads.
const CAPA = {
  meta: { version: '9.4.0' },
  rules: {
    'inject thread': { meta: { name: 'inject thread', namespace: 'host-interaction/process/inject', attack: [{ tactic: 'Defense Evasion', technique: 'Process Injection', subtechnique: 'Thread Execution Hijacking', id: 'T1055.003' }] } },
    'check for debugger via API': { meta: { name: 'check for debugger via API', namespace: 'anti-analysis/anti-debugging/debugger-detection', attack: [{ tactic: 'Defense Evasion', technique: 'Debugger Evasion', subtechnique: '', id: 'T1622' }] } },
    'read file on Windows': { meta: { name: 'read file on Windows', namespace: 'host-interaction/file-system/read', attack: [] } },
    'contain loop': { meta: { name: 'contain loop', namespace: 'internal/limitation', lib: true } },
    'sub': { meta: { name: 'sub', namespace: 'x', is_subscope_rule: true } },
    'weird attack': { meta: { name: 'weird attack', namespace: 'executable/pe', attack: [{ id: 'not-an-id' }] } },
  },
};

// Shape of `diec -j` output.
const DIE = {
  detects: [
    {
      filetype: 'PE64',
      parentfilepart: 'Header',
      values: [
        { info: '', name: 'Microsoft Visual C/C++', string: 'Compiler: Microsoft Visual C/C++(19.36)', type: 'Compiler', version: '19.36' },
        { info: 'brute', name: 'UPX', string: 'Packer: UPX(4.2.4)[brute]', type: 'Packer', version: '4.2.4' },
        { info: '', name: 'UPX', string: 'Packer: UPX(4.2.4)', type: 'Packer', version: '4.2.4' },
      ],
    },
  ],
};

describe('capa results', () => {
  it('keeps real capabilities, drops library/subscope rules, collects ATT&CK and risky groups', () => {
    const r = parseCapa(CAPA);
    expect(r.capabilities.map((c) => c.name)).toEqual(['check for debugger via API', 'weird attack', 'inject thread', 'read file on Windows']);
    expect(r.attack.map((a) => a.id)).toEqual(['T1055.003', 'T1622']);
    expect(r.attack[0]).toEqual({ id: 'T1055.003', tactic: 'Defense Evasion', technique: 'Process Injection: Thread Execution Hijacking' });
    expect(r.risky).toEqual(['injection', 'anti_analysis']);
    expect(parseCapa(null)).toEqual({ capabilities: [], attack: [], risky: [] });
  });
});

describe('Detect It Easy results', () => {
  it('lists unique detections and flags packers', () => {
    const r = parseDie(DIE);
    expect(r.fileType).toBe('PE64');
    expect(r.detections).toEqual([
      { type: 'Compiler', name: 'Microsoft Visual C/C++', version: '19.36', info: null },
      { type: 'Packer', name: 'UPX', version: '4.2.4', info: 'brute' },
    ]);
    expect(r.packers).toEqual(['UPX']);
    expect(parseDie({})).toEqual({ fileType: null, detections: [], packers: [] });
  });
});

describe('capa/DIE evidence is weighed conservatively', () => {
  const base = { typeId: 'pe', entropy: 5, packerHints: [] as string[], signature: { checked: false, reason: 'x' }, interestingCount: 0 };
  it('1–3 risky groups = weak; 4+ = strong; a packer = weak', () => {
    const risky = (n: number) => ({ ran: true as const, capabilities: [], attack: [], risky: ['injection', 'anti_analysis', 'keylogging', 'persistence', 'c2'].slice(0, n), durationMs: 1 });
    expect(buildSignals({ ...base, capa: risky(2) }).signals.find((s) => s.source === 'capa')?.weight).toBe('weak');
    expect(buildSignals({ ...base, capa: risky(4) }).signals.find((s) => s.source === 'capa')?.weight).toBe('strong');
    expect(buildSignals({ ...base, capa: risky(0) }).signals.some((s) => s.source === 'capa')).toBe(false);
    const die = { ran: true as const, fileType: 'PE64', detections: [], packers: ['UPX'] };
    expect(buildSignals({ ...base, die }).signals.find((s) => s.source === 'packer')).toMatchObject({ weight: 'weak', reasonArgs: { name: 'UPX' } });
  });
});
