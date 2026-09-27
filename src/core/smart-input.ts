// "Paste anything" in the top search: recognise what the text is (IP, hash, domain, URL, e-mail,
// @username, local file path) and suggest the tools that can examine it. Pure and local: nothing is
// looked up here — the chosen tool only receives the value pre-filled, and the user starts it.

import { normalizeOsintTarget } from './osint';
import { classifyIP, isDomain, isIP } from './validation';

export type SmartKind = 'ip' | 'hash' | 'domain' | 'url' | 'email' | 'username' | 'path';

export interface SmartAction {
  /** Page id in the renderer's navigation. */
  page: 'ip-intel' | 'reputation' | 'hash-lab' | 'domain-intel' | 'osint' | 'file-analyzer' | 'service-scan';
  /** i18n key suffix under smart.action.* */
  action: string;
  value: string;
  /** Sub-mode the page should switch to (reputation kind, OSINT type, hash-lab tab). */
  mode?: string;
}

export interface SmartMatch {
  kind: SmartKind;
  value: string;
  actions: SmartAction[];
}

const HASH_RE = /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})$/i;
const WIN_PATH_RE = /^(?:[a-z]:\\|\\\\[^\\/:*?"<>|\s]+\\)[^\0<>|"*?]*$/i;
const POSIX_PATH_RE = /^\/[^\0]+$/;

/** Removes the "defanging" analysts use when sharing indicators: hxxp, [.], (.), [@]. */
export function refang(s: string): string {
  return s
    .replace(/^hxxp(s?):\/\//i, 'http$1://')
    .replace(/\[\.\]|\(\.\)|\{\.\}/g, '.')
    .replace(/\[@\]|\(@\)|\[at\]/gi, '@')
    .replace(/\[:\]/g, ':');
}

export function classifyInput(raw: string): SmartMatch | null {
  const trimmed = raw.trim().replace(/^["'<]+|["'>]+$/g, '');
  if (!trimmed || trimmed.length > 2048) return null;

  // File paths first: they may contain dots and look like domains.
  if (WIN_PATH_RE.test(trimmed) || (POSIX_PATH_RE.test(trimmed) && !trimmed.includes('//'))) {
    return { kind: 'path', value: trimmed, actions: [{ page: 'file-analyzer', action: 'analyzeFile', value: trimmed }] };
  }
  if (/\s/.test(trimmed)) return null;
  const v = refang(trimmed);

  if (isIP(v)) {
    const scope = classifyIP(v);
    const local = scope === 'private' || scope === 'link-local' || scope === 'loopback' || scope === 'cgnat';
    const actions: SmartAction[] = [{ page: 'ip-intel', action: 'ipIntel', value: v }];
    if (local) actions.push({ page: 'service-scan', action: 'serviceScan', value: v });
    else actions.push({ page: 'reputation', action: 'reputation', value: v, mode: 'ip' });
    return { kind: 'ip', value: v, actions };
  }
  if (HASH_RE.test(v)) {
    const h = v.toLowerCase();
    const actions: SmartAction[] = [{ page: 'hash-lab', action: 'identifyHash', value: h, mode: 'identify' }];
    if (h.length !== 128) actions.unshift({ page: 'reputation', action: 'reputation', value: h, mode: 'hash' });
    return { kind: 'hash', value: h, actions };
  }
  if (/^https?:\/\//i.test(v)) {
    const url = normalizeOsintTarget('url', v);
    if (!url) return null;
    return { kind: 'url', value: url, actions: [
      { page: 'domain-intel', action: 'checkLink', value: url },
      { page: 'osint', action: 'osint', value: url, mode: 'url' },
    ] };
  }
  if (v.includes('@') && !v.startsWith('@')) {
    const email = normalizeOsintTarget('email', v);
    return email ? { kind: 'email', value: email, actions: [{ page: 'osint', action: 'osint', value: email, mode: 'email' }] } : null;
  }
  if (v.startsWith('@')) {
    const user = normalizeOsintTarget('username', v);
    return user ? { kind: 'username', value: user, actions: [{ page: 'osint', action: 'accounts', value: user, mode: 'username' }] } : null;
  }
  const d = v.toLowerCase().replace(/\.$/, '');
  if (isDomain(d)) {
    return { kind: 'domain', value: d, actions: [
      { page: 'domain-intel', action: 'domainIntel', value: d },
      { page: 'reputation', action: 'reputation', value: d, mode: 'domain' },
      { page: 'osint', action: 'osint', value: d, mode: 'domain' },
    ] };
  }
  return null;
}
