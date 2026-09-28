// Password recovery: turning an encrypted file into the "hash" the engine actually works on (pure).
//
// John the Ripper and hashcat do NOT read an archive/document directly — they need the small
// verifier ("hash") extracted from it first. John ships a family of `*2john` extractors for exactly
// this. Blazma runs the extractor the file's format needs, then feeds the result to the engine the
// user chose. This module only decides which extractor to use and reshapes its text output; it runs
// nothing and reads no files.

import type { EncryptedFormat } from './encrypted';

export interface ExtractorSpec {
  /** Candidate extractor filenames inside John's `run/` directory, most-preferred first. */
  files: string[];
  /** True when a compiled `.exe` extractor exists (runs on its own, no Perl/Python needed). */
  compiled: boolean;
}

// The extractors that ship in the official John "jumbo" Windows build. RAR and ZIP are compiled
// executables (work out of the box); 7z/PDF/Office are scripts that need Perl or Python installed.
const EXTRACTORS: Partial<Record<EncryptedFormat, ExtractorSpec>> = {
  rar: { files: ['rar2john.exe', 'rar2john'], compiled: true },
  zip: { files: ['zip2john.exe', 'zip2john'], compiled: true },
  '7z': { files: ['7z2john.pl'], compiled: false },
  pdf: { files: ['pdf2john.pl'], compiled: false },
  'office-ooxml': { files: ['office2john.py'], compiled: false },
  'office-legacy': { files: ['office2john.py'], compiled: false },
};

export function extractorFor(format: EncryptedFormat): ExtractorSpec | null {
  return EXTRACTORS[format] ?? null;
}

/** The first line of a `*2john` tool's output that actually carries a hash (`…$…`). */
export function firstHashLine(output: string): string | null {
  for (const raw of output.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.includes('$') && line.length > line.indexOf('$') + 1) return line;
  }
  return null;
}

/** The bare hash: `*2john` prefixes the source file name (which on Windows contains `C:` colons),
 *  so the hash simply starts at the first `$`. */
export function bareHash(line: string): string {
  const i = line.indexOf('$');
  return i >= 0 ? line.slice(i) : line;
}

/** A John hash-file line with a fixed login, so parsing `john --show` output is unambiguous even
 *  when the original file name contained colons. */
export function johnHashLine(line: string): string {
  return `target:${bareHash(line)}`;
}

/** The hash string for hashcat: the bare hash without any trailing `*2john` metadata (paths etc.
 *  some extractors append after a `:`). */
export function hashcatHash(line: string): string {
  const h = bareHash(line);
  const c = h.indexOf(':');
  return c >= 0 ? h.slice(0, c) : h;
}

/** hashcat `-m` mode for an extracted hash, or null when Blazma can't map it confidently (then the
 *  recovery uses John, which autodetects the type from the same hash). */
export function hashcatMode(hash: string): number | null {
  if (hash.startsWith('$rar5$')) return 13000;
  if (/^\$RAR3\$\*0\*/.test(hash)) return 12500; // RAR3 with encrypted headers
  if (hash.startsWith('$zip2$')) return 13600;
  if (hash.startsWith('$7z$')) return 11600;
  const office = /^\$office\$\*?(\d{4})/.exec(hash);
  if (office) return office[1] === '2007' ? 9400 : office[1] === '2010' ? 9500 : 9600;
  return null;
}
