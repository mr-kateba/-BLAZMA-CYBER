import { describe, expect, it } from 'vitest';
import { classifyInput, refang } from '../src/core/smart-input';

const pages = (s: string) => classifyInput(s)?.actions.map((a) => a.page);

describe('smart search input', () => {
  it('recognises public and local IP addresses', () => {
    expect(classifyInput(' 8.8.8.8 ')).toMatchObject({ kind: 'ip', value: '8.8.8.8' });
    expect(pages('8.8.8.8')).toEqual(['ip-intel', 'reputation']);
    // Local addresses offer the service scan instead of internet reputation.
    expect(pages('192.168.1.20')).toEqual(['ip-intel', 'service-scan']);
    expect(classifyInput('2001:db8::1')?.kind).toBe('ip');
  });

  it('recognises hashes and lowercases them', () => {
    const sha = 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855';
    expect(classifyInput(sha)).toMatchObject({ kind: 'hash', value: sha.toLowerCase() });
    expect(pages(sha)).toEqual(['reputation', 'hash-lab']);
    expect(classifyInput(sha)?.actions[0]?.mode).toBe('hash');
    expect(pages('a'.repeat(128))).toEqual(['hash-lab']);
    expect(classifyInput('abc123')).toBeNull();
  });

  it('recognises domains, links, e-mail and @usernames', () => {
    expect(classifyInput('Example.COM.')).toMatchObject({ kind: 'domain', value: 'example.com' });
    expect(pages('example.com')).toEqual(['domain-intel', 'reputation', 'osint']);
    expect(classifyInput('https://example.com/login?x=1')).toMatchObject({ kind: 'url' });
    expect(classifyInput('someone@example.org')).toMatchObject({ kind: 'email', value: 'someone@example.org', actions: [{ page: 'osint', mode: 'email' }] });
    expect(classifyInput('@octocat')).toMatchObject({ kind: 'username', value: 'octocat', actions: [{ page: 'osint', mode: 'username' }] });
  });

  it('undoes common defanging', () => {
    expect(refang('hxxps://evil[.]example/a')).toBe('https://evil.example/a');
    expect(classifyInput('evil[.]example')).toMatchObject({ kind: 'domain', value: 'evil.example' });
    expect(classifyInput('1.2.3[.]4')).toMatchObject({ kind: 'ip', value: '1.2.3.4' });
    expect(classifyInput('bad[@]example[.]org')).toMatchObject({ kind: 'email', value: 'bad@example.org' });
  });

  it('recognises file paths (to analyze, never run)', () => {
    expect(classifyInput('C:\\Users\\me\\Downloads\\setup.exe')).toMatchObject({ kind: 'path', actions: [{ page: 'file-analyzer' }] });
    expect(classifyInput('"C:\\Program Files\\App\\app.exe"')?.value).toBe('C:\\Program Files\\App\\app.exe');
    expect(classifyInput('\\\\server\\share\\file.docx')?.kind).toBe('path');
  });

  it('ignores ordinary words and tool names', () => {
    for (const s of ['', '   ', 'hash lab', 'wifi', 'settings', 'نطاق', 'a b.com', 'x'.repeat(3000)]) expect(classifyInput(s)).toBeNull();
  });
});
