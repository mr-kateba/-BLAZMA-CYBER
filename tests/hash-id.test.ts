import { describe, expect, it } from 'vitest';
import { identifyHash } from '../src/core/hash-id';

describe('hash identification', () => {
  it('returns multiple candidates for ambiguous 32-hex', () => {
    const r = identifyHash('5d41402abc4b2a76b9719d911017c592');
    expect(r.candidates.map((c) => c.id)).toEqual(['md5', 'ntlm', 'md4']);
    expect(r.candidates[0]!.confidence).toBe('medium');
  });
  it('identifies SHA family by length', () => {
    expect(identifyHash('a'.repeat(40)).candidates[0]!.id).toBe('sha1');
    expect(identifyHash('b'.repeat(64)).candidates[0]!.id).toBe('sha256');
    expect(identifyHash('c'.repeat(128)).candidates[0]!.id).toBe('sha512');
  });
  it('identifies structured formats with high confidence', () => {
    const bc = '$2b$12$' + 'a'.repeat(53);
    expect(identifyHash(bc).candidates).toEqual([{ id: 'bcrypt', name: 'bcrypt', confidence: 'high' }]);
  });
  it('returns no candidates for unknown input', () => {
    expect(identifyHash('hello world').candidates).toEqual([]);
    expect(identifyHash('z'.repeat(32)).candidates).toEqual([]);
  });
  it('trims whitespace', () => {
    expect(identifyHash('  ' + 'a'.repeat(40) + '\n').candidates[0]!.id).toBe('sha1');
  });
});
