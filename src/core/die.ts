// Detect It Easy result parsing: compiler / linker / packer / protector / installer identification.
// Input: the JSON from `diec -j <file>`. DIE reads the file statically; nothing is executed.

export interface DieDetection {
  /** DIE category as reported, e.g. Compiler, Linker, Packer, Protector, Installer, Library. */
  type: string;
  name: string;
  version: string | null;
  info: string | null;
}

export interface DieSummary {
  fileType: string | null;
  detections: DieDetection[];
  /** Packers/protectors/cryptors found (these hide code and are evidence worth noting). */
  packers: string[];
}

const PACKING = /^(packer|protector|cryptor|obfuscator|joiner)$/i;
const s = (v: unknown): string | null => (typeof v === 'string' && v.trim() ? v.trim() : null);

export function parseDie(json: unknown): DieSummary {
  const detects = (json as { detects?: unknown } | null)?.detects;
  const out: DieDetection[] = [];
  let fileType: string | null = null;
  for (const d of Array.isArray(detects) ? detects : []) {
    const o = d as Record<string, unknown>;
    fileType ??= s(o.filetype);
    for (const v of Array.isArray(o.values) ? o.values : []) {
      const x = v as Record<string, unknown>;
      const name = s(x.name);
      const type = s(x.type);
      if (!name || !type) continue;
      if (!out.some((e) => e.type === type && e.name === name)) out.push({ type, name, version: s(x.version), info: s(x.info) });
    }
  }
  return { fileType, detections: out, packers: out.filter((d) => PACKING.test(d.type)).map((d) => d.name) };
}
