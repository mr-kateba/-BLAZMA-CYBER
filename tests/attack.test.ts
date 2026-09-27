import { describe, expect, it } from 'vitest';
import { ATTACK_TACTICS, ATTACK_VERSION, attackMatrix, technique } from '../src/core/attack';
import { externalLinkHost } from '../src/core/intel';

describe('MITRE ATT&CK data', () => {
  it('is the official Enterprise dataset with the current tactics', () => {
    expect(ATTACK_VERSION).toBe('19.2');
    expect(ATTACK_TACTICS.map((t) => t.short)).toEqual([
      'reconnaissance', 'resource-development', 'initial-access', 'execution', 'persistence', 'privilege-escalation', 'stealth', 'defense-impairment',
      'credential-access', 'discovery', 'lateral-movement', 'collection', 'command-and-control', 'exfiltration', 'impact',
    ]);
  });

  it('looks up techniques and sub-techniques', () => {
    expect(technique('t1055.011')).toEqual({
      id: 'T1055.011', name: 'Extra Window Memory Injection', parentName: 'Process Injection', replaces: null, tactics: ['stealth', 'privilege-escalation'],
      url: 'https://attack.mitre.org/techniques/T1055/011/',
    });
    expect(technique('T1059')).toMatchObject({ name: 'Command and Scripting Interpreter', parentName: null, url: 'https://attack.mitre.org/techniques/T1059/' });
    expect(technique('T9999')).toBeNull();
    // Ids that detection rules still use but ATT&CK 19 replaced (MITRE "revoked-by").
    expect(technique('T1070.001')).toMatchObject({ id: 'T1685.005', name: 'Clear Windows Event Logs', replaces: 'T1070.001' });
    expect(technique('javascript:alert(1)')).toBeNull();
    expect(externalLinkHost(technique('T1059')!.url)).toBe('attack.mitre.org');
  });

  it('arranges observed techniques by tactic in kill-chain order', () => {
    const m = attackMatrix([{ id: 'T1070.001', count: 3 }, { id: 'T1059.001', count: 5 }, { id: 't1059.001', count: 1 }, { id: 'T0000', count: 9 }]);
    expect(m.map((c) => c.tactic.short)).toEqual(['execution', ...m.slice(1).map((c) => c.tactic.short)]);
    const exec = m.find((c) => c.tactic.short === 'execution')!;
    expect(exec.techniques).toEqual([expect.objectContaining({ id: 'T1059.001', count: 6, parentName: 'Command and Scripting Interpreter' })]);
    expect(m.flatMap((c) => c.techniques.map((x) => x.id))).toContain('T1685.005');
    expect(m.flatMap((c) => c.techniques.map((x) => x.id))).not.toContain('T0000');
  });
});
