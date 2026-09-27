// Browser extension audit (pure): what each installed extension is allowed to do, and how it got
// there. Input is the text of files the browser itself keeps (manifest.json, Preferences, Firefox's
// extensions.json). Broad access is a fact about the permissions, not a verdict: the UI says so.

export type BrowserId = 'chrome' | 'edge' | 'brave' | 'vivaldi' | 'opera' | 'chromium' | 'firefox';

export type ExtensionFlag =
  | 'all_sites' // can read and change every website
  | 'traffic' // can watch or block web requests
  | 'cookies'
  | 'history'
  | 'clipboard'
  | 'native' // talks to programs on the computer
  | 'debugger' // full control of pages through the debugger
  | 'proxy' // can route browsing through a proxy
  | 'management' // can manage other extensions
  | 'downloads'
  | 'sideloaded' // loaded from a folder / command line, not from the store
  | 'external' // installed by another program on the computer
  | 'policy' // installed by a policy
  | 'unsigned'; // Firefox: not signed by Mozilla

export type ExtensionRisk = 'high' | 'medium' | 'low';

export interface BrowserExtension {
  browser: BrowserId;
  profile: string;
  id: string;
  name: string;
  version: string | null;
  enabled: boolean | null;
  source: 'store' | 'sideloaded' | 'external' | 'policy' | 'unknown';
  flags: ExtensionFlag[];
  risk: ExtensionRisk;
  permissions: string[];
  hosts: string[];
}

export interface ExtensionAudit {
  extensions: BrowserExtension[];
  /** Browsers found for this user and how many profiles were read. */
  browsers: Array<{ browser: BrowserId; profiles: number }>;
  collectedAt: string;
}

const ALL_SITES = /^(<all_urls>|\*:\/\/\*\/\*|https?:\/\/\*\/\*|\*:\/\/\*\/|file:\/\/\/\*)$/;
const PERM_FLAGS: Record<string, ExtensionFlag> = {
  webRequest: 'traffic', webRequestBlocking: 'traffic', declarativeNetRequestWithHostAccess: 'traffic', declarativeNetRequestFeedback: 'traffic',
  cookies: 'cookies', history: 'history', clipboardRead: 'clipboard', nativeMessaging: 'native', debugger: 'debugger', proxy: 'proxy',
  management: 'management', downloads: 'downloads',
};

const obj = (v: unknown): Record<string, unknown> => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {});
const strs = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);
const s = (v: unknown): string | null => (typeof v === 'string' && v.trim() ? v.trim() : null);

export function classify(permissions: string[], hosts: string[], source: BrowserExtension['source'], unsigned = false): { flags: ExtensionFlag[]; risk: ExtensionRisk } {
  const flags = new Set<ExtensionFlag>();
  if (hosts.some((h) => ALL_SITES.test(h)) || permissions.some((p) => ALL_SITES.test(p))) flags.add('all_sites');
  for (const p of permissions) if (PERM_FLAGS[p]) flags.add(PERM_FLAGS[p]!);
  if (source === 'sideloaded') flags.add('sideloaded');
  if (source === 'external') flags.add('external');
  if (source === 'policy') flags.add('policy');
  if (unsigned) flags.add('unsigned');
  const f = [...flags];
  // "Needs attention" is about HOW it got there (outside the store, unsigned) or the debugger — not about
  // broad permissions alone: popular store extensions (ad-blockers, password managers) need those.
  const risk: ExtensionRisk =
    flags.has('sideloaded') || flags.has('external') || flags.has('unsigned') || flags.has('debugger') ? 'high'
    : f.some((x) => x !== 'policy' && x !== 'downloads') ? 'medium'
    : 'low';
  return { flags: f, risk };
}

/** Resolves "__MSG_name__" from the extension's messages.json (keys are case-insensitive). */
export function resolveMessage(value: string | null, messages: unknown): string | null {
  const m = value ? /^__MSG_(.+)__$/.exec(value) : null;
  if (!m) return value;
  const want = m[1]!.toLowerCase();
  for (const [k, v] of Object.entries(obj(messages))) if (k.toLowerCase() === want) return s(obj(v).message);
  return null;
}

/** Chromium stores install details per extension id in (Secure) Preferences → extensions.settings. */
export function chromiumSettings(...prefsTexts: Array<string | null>): Record<string, { location?: number; state?: number; disableReasons?: number[]; fromStore?: boolean }> {
  const out: Record<string, { location?: number; state?: number; disableReasons?: number[]; fromStore?: boolean }> = {};
  for (const text of prefsTexts) {
    if (!text) continue;
    let json: unknown;
    try {
      json = JSON.parse(text);
    } catch {
      continue;
    }
    for (const [id, raw] of Object.entries(obj(obj(obj(json).extensions).settings))) {
      const v = obj(raw);
      const cur = (out[id] ??= {});
      if (typeof v.location === 'number') cur.location = v.location;
      if (typeof v.state === 'number') cur.state = v.state;
      if (Array.isArray(v.disable_reasons)) cur.disableReasons = v.disable_reasons.filter((x): x is number => typeof x === 'number');
      else if (typeof v.disable_reasons === 'number') cur.disableReasons = v.disable_reasons ? [v.disable_reasons] : [];
      if (typeof v.from_webstore === 'boolean') cur.fromStore = v.from_webstore;
    }
  }
  return out;
}

/** Chromium ManifestLocation: 1 store, 2/3/6 external (another program), 4/8 unpacked / command line, 5/10 built-in, 7/9 policy. */
export function chromiumSource(location: number | undefined): BrowserExtension['source'] | 'component' {
  switch (location) {
    case 1: return 'store';
    case 4: case 8: return 'sideloaded';
    case 2: case 3: case 6: return 'external';
    case 7: case 9: return 'policy';
    case 5: case 10: return 'component';
    default: return 'unknown';
  }
}

export function parseChromiumExtension(browser: BrowserId, profile: string, id: string, manifestText: string, messages: unknown, setting: ReturnType<typeof chromiumSettings>[string] | undefined): BrowserExtension | null {
  let m: Record<string, unknown>;
  try {
    m = obj(JSON.parse(manifestText.replace(/^﻿/, '')));
  } catch {
    return null;
  }
  const source = chromiumSource(setting?.location);
  if (source === 'component') return null;
  // Themes and apps without permissions are not extensions in the sense that matters here.
  if (m.theme && !m.permissions) return null;
  const permissions = [...strs(m.permissions), ...strs(m.optional_permissions)].filter((p) => !p.includes('://') && p !== '<all_urls>');
  const hostLike = [...strs(m.permissions), ...strs(m.host_permissions), ...strs(m.optional_host_permissions)].filter((p) => p.includes('://') || p === '<all_urls>');
  const scripts = (Array.isArray(m.content_scripts) ? m.content_scripts : []).flatMap((c) => strs(obj(c).matches));
  const hosts = [...new Set([...hostLike, ...scripts])];
  const { flags, risk } = classify(permissions, hosts, source);
  const enabled = setting ? (setting.state !== undefined ? setting.state === 1 : setting.disableReasons ? setting.disableReasons.length === 0 : null) : null;
  return {
    browser, profile, id,
    name: resolveMessage(s(m.name), messages) ?? id,
    version: s(m.version),
    enabled,
    source,
    flags, risk,
    permissions: [...new Set(permissions)].slice(0, 100),
    hosts: hosts.slice(0, 100),
  };
}

/** Firefox keeps every add-on in <profile>/extensions.json. System/built-in add-ons are skipped. */
export function parseFirefoxExtensions(profile: string, text: string): BrowserExtension[] {
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    return [];
  }
  const out: BrowserExtension[] = [];
  for (const raw of Array.isArray(obj(json).addons) ? (obj(json).addons as unknown[]) : []) {
    const a = obj(raw);
    if (a.type !== 'extension') continue;
    const location = s(a.location) ?? '';
    if (/^app-(system|builtin)/.test(location) || a.isBuiltin === true) continue;
    const perms = obj(a.userPermissions);
    const permissions = strs(perms.permissions);
    const hosts = strs(perms.origins);
    const source: BrowserExtension['source'] =
      location === 'app-profile' ? (s(a.sourceURI)?.startsWith('https://addons.mozilla.org/') ? 'store' : 'external')
      : location === 'app-system-share' || location === 'app-global' || location === 'winreg-app-global' || location === 'winreg-app-user' ? 'external'
      : location === 'temporary' ? 'sideloaded'
      : 'unknown';
    const unsigned = typeof a.signedState === 'number' && a.signedState <= 0;
    const { flags, risk } = classify(permissions, hosts, source, unsigned);
    out.push({
      browser: 'firefox', profile,
      id: s(a.id) ?? '?',
      name: s(obj(a.defaultLocale).name) ?? s(a.id) ?? '?',
      version: s(a.version),
      enabled: typeof a.active === 'boolean' ? a.active : null,
      source, flags, risk,
      permissions: permissions.slice(0, 100),
      hosts: hosts.slice(0, 100),
    });
  }
  return out;
}

const RISK_ORDER: Record<ExtensionRisk, number> = { high: 0, medium: 1, low: 2 };
export function sortExtensions(list: BrowserExtension[]): BrowserExtension[] {
  return [...list].sort((a, b) => RISK_ORDER[a.risk] - RISK_ORDER[b.risk] || a.name.localeCompare(b.name));
}
