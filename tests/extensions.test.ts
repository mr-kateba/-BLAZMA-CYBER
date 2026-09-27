import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { chromiumSettings, classify, parseFirefoxExtensions, resolveMessage } from '../src/core/extensions';
import { auditExtensions } from '../src/main/services/extensions';

const root = mkdtempSync(join(tmpdir(), 'blazma-ext-'));
afterAll(() => rmSync(root, { recursive: true, force: true }));

const ID_SIDELOADED = 'a'.repeat(32);
const ID_STORE = 'b'.repeat(32);
const ID_COMPONENT = 'c'.repeat(32);
const ID_EXTERNAL = 'd'.repeat(32);

function ext(profileDir: string, id: string, version: string, manifest: object, messages?: object) {
  const dir = join(profileDir, 'Extensions', id, version);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'manifest.json'), '﻿' + JSON.stringify(manifest));
  if (messages) {
    mkdirSync(join(dir, '_locales', 'en'), { recursive: true });
    writeFileSync(join(dir, '_locales', 'en', 'messages.json'), JSON.stringify(messages));
  }
}

// Chrome-style "User Data" with a Default profile
const chrome = join(root, 'Chrome', 'User Data');
const def = join(chrome, 'Default');
ext(def, ID_SIDELOADED, '1.0_0', { name: '__MSG_appName__', default_locale: 'en', version: '1.0', manifest_version: 3, permissions: ['webRequest', 'storage'], host_permissions: ['<all_urls>'] }, { AppName: { message: 'PDF Helper Pro' } });
ext(def, ID_STORE, '2.1_0', { name: 'Dark Reader Lite', version: '2.1', permissions: ['storage'] });
ext(def, ID_STORE, '2.10_0', { name: 'Dark Reader Lite', version: '2.10', permissions: ['storage', 'tabs'] }); // newer version folder wins
ext(def, ID_COMPONENT, '1_0', { name: 'Chrome Web Store Payments', version: '1', permissions: ['identity'] });
ext(def, ID_EXTERNAL, '3_0', { name: 'Coupon Finder', version: '3', content_scripts: [{ matches: ['https://*/*'], js: ['c.js'] }], permissions: ['cookies'] });
writeFileSync(join(def, 'Secure Preferences'), JSON.stringify({ extensions: { settings: {
  [ID_SIDELOADED]: { location: 4, state: 1 }, [ID_STORE]: { location: 1, from_webstore: true, disable_reasons: [] },
  [ID_COMPONENT]: { location: 5 }, [ID_EXTERNAL]: { location: 3, disable_reasons: [1] },
} } }));
mkdirSync(join(chrome, 'System Profile', 'Extensions'), { recursive: true }); // not a user profile: skipped

// Opera keeps a single profile in its root folder
const opera = join(root, 'Opera Stable');
ext(opera, ID_STORE, '1_0', { name: 'Opera Ad Blocker Plus', version: '1', permissions: ['declarativeNetRequestWithHostAccess'], host_permissions: ['*://*/*'] });

// Firefox profiles
const ff = join(root, 'Firefox', 'Profiles');
mkdirSync(join(ff, 'abcd.default-release'), { recursive: true });
writeFileSync(join(ff, 'abcd.default-release', 'extensions.json'), JSON.stringify({ addons: [
  { id: 'ublock@example', type: 'extension', location: 'app-profile', active: true, version: '1.60', signedState: 2, sourceURI: 'https://addons.mozilla.org/firefox/downloads/file/1/ublock.xpi', defaultLocale: { name: 'uBlock Origin' }, userPermissions: { permissions: ['webRequest', 'webRequestBlocking', 'storage'], origins: ['<all_urls>'] } },
  { id: 'formautofill@mozilla.org', type: 'extension', location: 'app-builtin', active: true, defaultLocale: { name: 'Form Autofill' } },
  { id: 'default-theme@mozilla.org', type: 'theme', location: 'app-builtin' },
] }));

describe('Browser extension audit', () => {
  it('reads Chromium profiles, resolves __MSG_ names, skips built-in components, follows install source', async () => {
    const a = await auditExtensions([
      { browser: 'chrome', dir: chrome },
      { browser: 'opera', dir: opera },
      { browser: 'firefox', dir: ff },
      { browser: 'edge', dir: join(root, 'missing') },
    ], new Date('2026-09-27T00:00:00Z'));
    expect(a.browsers).toEqual([{ browser: 'chrome', profiles: 1 }, { browser: 'opera', profiles: 1 }, { browser: 'firefox', profiles: 1 }]);
    const by = (name: string) => a.extensions.find((e) => e.name === name);
    expect(by('PDF Helper Pro')).toMatchObject({ browser: 'chrome', profile: 'Default', source: 'sideloaded', risk: 'high', enabled: true });
    expect(by('PDF Helper Pro')!.flags.sort()).toEqual(['all_sites', 'sideloaded', 'traffic']);
    expect(by('Dark Reader Lite')).toMatchObject({ version: '2.10', source: 'store', risk: 'low', enabled: true, flags: [] });
    expect(by('Coupon Finder')).toMatchObject({ source: 'external', enabled: false, risk: 'high' });
    expect(by('Chrome Web Store Payments')).toBeUndefined();
    expect(by('Opera Ad Blocker Plus')).toMatchObject({ browser: 'opera', risk: 'medium', flags: ['all_sites', 'traffic'] });
    expect(by('uBlock Origin')).toMatchObject({ browser: 'firefox', source: 'store', risk: 'medium', enabled: true });
    expect(by('Form Autofill')).toBeUndefined();
    // Sorted: needs-attention first
    expect(a.extensions[0]!.risk).toBe('high');
    expect(a.extensions.at(-1)!.risk).toBe('low');
  });

  it('classification rules', () => {
    expect(classify(['storage'], [], 'store')).toEqual({ flags: [], risk: 'low' });
    expect(classify(['tabs'], ['https://mail.example.com/*'], 'store')).toEqual({ flags: [], risk: 'low' });
    expect(classify([], ['<all_urls>'], 'store')).toEqual({ flags: ['all_sites'], risk: 'medium' });
    expect(classify(['cookies'], ['*://*/*'], 'store').risk).toBe('medium');
    expect(classify(['storage'], [], 'external').risk).toBe('high');
    expect(classify(['debugger'], [], 'store').risk).toBe('high');
    expect(classify(['storage'], [], 'policy')).toEqual({ flags: ['policy'], risk: 'low' });
    expect(classify([], [], 'store', true).flags).toEqual(['unsigned']);
  });

  it('helpers are defensive', () => {
    expect(resolveMessage('__MSG_Name__', { name: { message: 'X' } })).toBe('X');
    expect(resolveMessage('__MSG_missing__', {})).toBeNull();
    expect(resolveMessage('Plain', null)).toBe('Plain');
    expect(chromiumSettings('not json', null)).toEqual({});
    expect(parseFirefoxExtensions('p', '{broken')).toEqual([]);
  });
});
