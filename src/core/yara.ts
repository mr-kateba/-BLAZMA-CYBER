// Pure YARA helpers (no Electron / filesystem): the builtin starter rule pack and the
// parser for YARA-X `yr scan --output-format ndjson` output.

import type { YaraFileResult, YaraMatch } from '../shared/api';

// Starter pack authored for BLAZMA CYBER. Kept deliberately small and well-explained.
// NOTE: the EICAR rule matches only the name portion, so this source file itself is never
// detected as the EICAR test file by antivirus engines.
export const BUILTIN_RULES: Array<{ id: string; name: string; source: string }> = [
  {
    id: 'blazma-eicar',
    name: 'EICAR test file',
    source: `rule Blazma_EICAR_Test_File
{
  meta:
    description = "EICAR antivirus test file (harmless, used to check that scanners work)"
    author = "BLAZMA CYBER"
    severity = "test"
  strings:
    $name = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"
  condition:
    filesize < 256 and $name
}
`,
  },
  {
    id: 'blazma-ps-download-exec',
    name: 'PowerShell download-and-execute',
    source: `rule Blazma_PowerShell_Download_And_Execute
{
  meta:
    description = "Script text that downloads content and executes it in memory. Common in malicious droppers, but also used by some admin scripts."
    author = "BLAZMA CYBER"
    severity = "suspicious"
  strings:
    $d1 = "DownloadString" nocase
    $d2 = "DownloadData" nocase
    $d3 = "Invoke-WebRequest" nocase
    $x1 = "Invoke-Expression" nocase
    $x2 = "IEX" nocase fullword
  condition:
    filesize < 5MB and any of ($d*) and any of ($x*)
}
`,
  },
  {
    id: 'blazma-upx-pe',
    name: 'UPX-packed executable',
    source: `rule Blazma_UPX_Packed_PE
{
  meta:
    description = "Windows executable packed with UPX. Packing hides code from analysis; it is used by malware and by many legitimate tools."
    author = "BLAZMA CYBER"
    severity = "info"
  strings:
    $s0 = "UPX0"
    $s1 = "UPX1"
  condition:
    uint16(0) == 0x5A4D and all of them
}
`,
  },
];

/** Parses `yr scan --output-format ndjson` lines into per-file results. */
export function parseNdjson(stdout: string): YaraFileResult[] {
  const out: YaraFileResult[] = [];
  for (const line of stdout.split(/\r?\n/)) {
    const s = line.trim();
    if (!s.startsWith('{')) continue;
    let obj: unknown;
    try {
      obj = JSON.parse(s);
    } catch {
      continue;
    }
    const o = obj as { path?: unknown; rules?: unknown };
    if (typeof o.path !== 'string' || !Array.isArray(o.rules)) continue;
    const matches: YaraMatch[] = o.rules.map((r) => {
      const x = r as { identifier?: unknown; namespace?: unknown; tags?: unknown; meta?: unknown };
      const meta: Record<string, string | number | boolean> = {};
      // YARA-X emits meta as an array of [key, value] pairs (or an object in some versions).
      if (Array.isArray(x.meta)) {
        for (const pair of x.meta) {
          if (Array.isArray(pair) && typeof pair[0] === 'string') meta[pair[0]] = normalizeMeta(pair[1]);
        }
      } else if (x.meta && typeof x.meta === 'object') {
        for (const [k, v] of Object.entries(x.meta)) meta[k] = normalizeMeta(v);
      }
      return {
        rule: String(x.identifier ?? ''),
        namespace: String(x.namespace ?? 'default'),
        tags: Array.isArray(x.tags) ? x.tags.map(String) : [],
        meta,
      };
    });
    out.push({ path: o.path, matches });
  }
  return out;
}

function normalizeMeta(v: unknown): string | number | boolean {
  if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') return v;
  return JSON.stringify(v);
}

