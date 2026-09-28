import { describe, expect, it } from 'vitest';
import { safeHeaders, toByteString } from '../src/core/http-headers';

describe('safe response headers', () => {
  it('accepts emoji and Arabic header values instead of throwing', () => {
    const h = safeHeaders({ 'x-motd': '🚀 welcome', 'x-name': 'مرحبا', 'content-type': 'text/html', 'set-cookie': ['a=1', 'b=2'] });
    // The value is the UTF-8 bytes as sent, which decode back to the original text.
    expect(Buffer.from(h.get('x-motd')!, 'latin1').toString('utf8')).toBe('🚀 welcome');
    expect(Buffer.from(h.get('x-name')!, 'latin1').toString('utf8')).toBe('مرحبا');
    expect(h.get('content-type')).toBe('text/html');
    expect(h.get('set-cookie')).toBe('a=1, b=2');
    expect(toByteString('café')).toBe('café');
  });

  it('percent-encodes non-ASCII redirect targets so they can be followed', () => {
    const h = safeHeaders({ location: 'https://example.com/مستخدم/😀?q=1' });
    expect(h.get('location')).toBe(`https://example.com/${encodeURIComponent('مستخدم')}/${encodeURIComponent('😀')}?q=1`);
    expect(new URL(h.get('location')!).pathname).toBe(new URL('https://example.com/مستخدم/😀').pathname);
  });

  it('skips invalid headers instead of throwing', () => {
    const h = safeHeaders({ 'bad name': 'x', 'x-ctl': 'a\u0000b', 'x-ok': 'fine', 'x-undef': undefined });
    expect(h.get('x-ok')).toBe('fine');
    expect(h.has('x-ctl')).toBe(false);
    expect([...h.keys()]).toEqual(['x-ok']);
  });
});
