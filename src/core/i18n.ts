// Minimal, dependency-free translator shared by renderer and main (reports, dialogs).
// Keys are dotted paths into the locale JSON. Missing keys fall back to English, then to the key
// itself, so a missing translation is visible instead of crashing.

export type Lang = 'ar' | 'en';
export type Dir = 'rtl' | 'ltr';
export type Dict = { [key: string]: string | Dict };

export const SUPPORTED_LANGS: readonly Lang[] = ['ar', 'en'] as const;

export function isLang(value: unknown): value is Lang {
  return value === 'ar' || value === 'en';
}

export function directionOf(lang: Lang): Dir {
  return lang === 'ar' ? 'rtl' : 'ltr';
}

function lookup(dict: Dict, key: string): string | undefined {
  let node: string | Dict | undefined = dict;
  for (const part of key.split('.')) {
    if (typeof node !== 'object' || node === null) return undefined;
    node = node[part];
  }
  return typeof node === 'string' ? node : undefined;
}

export type Vars = Record<string, string | number>;

export function interpolate(template: string, vars?: Vars): string {
  if (!vars) return template;
  return template.replace(/\{\{\s*(\w+)\s*\}\}/g, (m, name: string) =>
    Object.prototype.hasOwnProperty.call(vars, name) ? String(vars[name]) : m,
  );
}

export function createTranslator(dict: Dict, fallback?: Dict) {
  return (key: string, vars?: Vars): string => {
    const hit = lookup(dict, key) ?? (fallback ? lookup(fallback, key) : undefined);
    return interpolate(hit ?? key, vars);
  };
}

/** Flattens a nested dict into dotted keys; used by the locale parity check and tests. */
export function flattenKeys(dict: Dict, prefix = ''): string[] {
  const keys: string[] = [];
  for (const [k, v] of Object.entries(dict)) {
    const full = prefix ? `${prefix}.${k}` : k;
    if (typeof v === 'string') keys.push(full);
    else keys.push(...flattenKeys(v, full));
  }
  return keys;
}

/** Returns placeholder names used in a template, for parity checks between languages. */
export function placeholders(template: string): string[] {
  return [...template.matchAll(/\{\{\s*(\w+)\s*\}\}/g)].map((m) => m[1]!).sort();
}
