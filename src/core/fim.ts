// File integrity monitoring (pure part): compare two fingerprints of a folder.
//
// A fingerprint lists every regular file under the folder with its size, modification time and
// SHA-256. A file counts as "modified" only when its SHA-256 differs — a new timestamp with the same
// content is reported separately as "touched", and a changed file with an old timestamp is still
// caught (timestamps are easy to forge; content hashes are not).

export interface FimEntry {
  /** Path relative to the watched folder, with '/' separators. */
  path: string;
  size: number;
  mtimeMs: number;
  sha256: string;
}

export interface FimFingerprint {
  root: string;
  createdAt: string;
  files: FimEntry[];
  /** Files that could not be read (locked, access denied) — listed, never guessed. */
  unreadable: string[];
  /** True when the file limit was reached and the fingerprint is incomplete. */
  truncated: boolean;
}

export interface FimChange {
  path: string;
  change: 'added' | 'removed' | 'modified';
  before: Omit<FimEntry, 'path'> | null;
  after: Omit<FimEntry, 'path'> | null;
}

export interface FimDiff {
  changes: FimChange[];
  unchanged: number;
  /** Same content, different timestamp. */
  touched: number;
  /** Modified files whose timestamp did NOT change — a pattern of deliberate hiding. */
  hiddenEdits: string[];
}

const strip = ({ path: _p, ...rest }: FimEntry) => rest;

export function diffFingerprints(before: Pick<FimFingerprint, 'files'>, after: Pick<FimFingerprint, 'files'>): FimDiff {
  const old = new Map(before.files.map((f) => [f.path, f]));
  const changes: FimChange[] = [];
  let unchanged = 0;
  let touched = 0;
  const hiddenEdits: string[] = [];
  for (const f of after.files) {
    const o = old.get(f.path);
    old.delete(f.path);
    if (!o) {
      changes.push({ path: f.path, change: 'added', before: null, after: strip(f) });
    } else if (o.sha256 !== f.sha256) {
      changes.push({ path: f.path, change: 'modified', before: strip(o), after: strip(f) });
      if (Math.abs(o.mtimeMs - f.mtimeMs) < 1) hiddenEdits.push(f.path);
    } else {
      unchanged++;
      if (Math.abs(o.mtimeMs - f.mtimeMs) >= 1) touched++;
    }
  }
  for (const o of old.values()) changes.push({ path: o.path, change: 'removed', before: strip(o), after: null });
  const order = { modified: 0, added: 1, removed: 2 };
  changes.sort((a, b) => order[a.change] - order[b.change] || a.path.localeCompare(b.path));
  return { changes, unchanged, touched, hiddenEdits };
}

/** File types that run code when opened — changes to these deserve a closer look. */
export function isExecutableLike(path: string): boolean {
  return /\.(exe|dll|sys|scr|com|cpl|ocx|msi|msp|ps1|psm1|bat|cmd|vbs|vbe|js|jse|wsf|hta|lnk|jar|py)$/i.test(path);
}
