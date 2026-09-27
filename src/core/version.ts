// Version comparison for the manual update check (pure). Semantic Versioning precedence:
// 1.2.0 > 1.2.0-rc.1 > 1.2.0-beta.2 > 1.2.0-beta.1; a leading "v" is ignored.

export interface Semver {
  major: number;
  minor: number;
  patch: number;
  pre: Array<string | number>;
}

export function parseSemver(v: string): Semver | null {
  const m = /^v?(\d{1,6})\.(\d{1,6})\.(\d{1,6})(?:-([0-9A-Za-z.-]{1,64}))?(?:\+[0-9A-Za-z.-]+)?$/.exec(v.trim());
  if (!m) return null;
  return { major: +m[1]!, minor: +m[2]!, patch: +m[3]!, pre: m[4] ? m[4].split('.').map((p) => (/^\d+$/.test(p) ? Number(p) : p)) : [] };
}

/** <0 when a is older than b, 0 when equal, >0 when newer. */
export function compareSemver(a: Semver, b: Semver): number {
  for (const k of ['major', 'minor', 'patch'] as const) if (a[k] !== b[k]) return a[k] - b[k];
  if (!a.pre.length || !b.pre.length) return (a.pre.length ? -1 : 0) - (b.pre.length ? -1 : 0);
  for (let i = 0; i < Math.max(a.pre.length, b.pre.length); i++) {
    const x = a.pre[i];
    const y = b.pre[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    if (x === y) continue;
    if (typeof x === 'number' && typeof y === 'number') return x - y;
    if (typeof x === 'number') return -1;
    if (typeof y === 'number') return 1;
    return x < y ? -1 : 1;
  }
  return 0;
}

export interface ReleaseInfo {
  tag: string;
  name: string | null;
  url: string;
  publishedAt: string | null;
  prerelease: boolean;
}

/** Newest published (non-draft) release from GitHub's /releases list whose tag is a valid version. */
export function newestRelease(json: unknown, repo: string): ReleaseInfo | null {
  let best: { r: ReleaseInfo; v: Semver } | null = null;
  for (const raw of Array.isArray(json) ? json : []) {
    const o = (raw ?? {}) as Record<string, unknown>;
    if (o.draft === true || typeof o.tag_name !== 'string') continue;
    const v = parseSemver(o.tag_name);
    if (!v) continue;
    // Only this repository's release page is ever opened.
    const url = `https://github.com/${repo}/releases/tag/${encodeURIComponent(o.tag_name)}`;
    const r: ReleaseInfo = {
      tag: o.tag_name,
      name: typeof o.name === 'string' && o.name.trim() ? o.name.trim().slice(0, 200) : null,
      url,
      publishedAt: typeof o.published_at === 'string' ? o.published_at : null,
      prerelease: o.prerelease === true,
    };
    if (!best || compareSemver(v, best.v) > 0) best = { r, v };
  }
  return best?.r ?? null;
}
