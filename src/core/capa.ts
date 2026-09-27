// capa (Mandiant) result parsing: "what can this program do?" with MITRE ATT&CK mapping.
// capa reads the file statically (it never runs it). Input: the JSON result document from `capa -j`.

export interface AttackRef {
  id: string; // e.g. T1055
  tactic: string;
  technique: string;
}

export interface Capability {
  name: string;
  namespace: string;
  /** Top-level group, e.g. "host-interaction" (i18n: capa.group.*). */
  group: string;
  attack: AttackRef[];
}

export interface CapaSummary {
  capabilities: Capability[];
  attack: AttackRef[];
  /** Risky behaviour groups present (i18n: capa.risk.*), used as analysis evidence. */
  risky: string[];
}

const RISKY: Array<[string, RegExp]> = [
  ['injection', /^host-interaction\/process\/inject/],
  ['anti_analysis', /^anti-analysis\//],
  ['keylogging', /^collection\/keylog/],
  ['persistence', /^persistence\//],
  ['c2', /^communication\/c2/],
  ['impact', /^impact\//],
  ['credential_access', /^(collection\/credential|host-interaction\/credential)/],
];

const str = (v: unknown): string => (typeof v === 'string' ? v : '');

export function parseCapa(json: unknown): CapaSummary {
  const rules = (json as { rules?: Record<string, unknown> } | null)?.rules;
  const caps: Capability[] = [];
  const attack = new Map<string, AttackRef>();
  if (rules && typeof rules === 'object') {
    for (const [key, v] of Object.entries(rules)) {
      const meta = (v as { meta?: Record<string, unknown> } | null)?.meta ?? {};
      // Library and subscope rules are building blocks, not capabilities.
      if (meta.lib === true || meta.is_subscope_rule === true) continue;
      const name = str(meta.name) || key;
      const namespace = str(meta.namespace);
      const refs: AttackRef[] = [];
      for (const a of Array.isArray(meta.attack) ? meta.attack : []) {
        const o = a as Record<string, unknown>;
        const id = str(o.id);
        if (!/^T\d{4}(\.\d{3})?$/.test(id)) continue;
        const ref = { id, tactic: str(o.tactic), technique: [str(o.technique), str(o.subtechnique)].filter(Boolean).join(': ') };
        refs.push(ref);
        attack.set(id, ref);
      }
      caps.push({ name, namespace, group: namespace.split('/')[0] || 'other', attack: refs });
    }
  }
  caps.sort((a, b) => a.group.localeCompare(b.group) || a.name.localeCompare(b.name));
  const risky = RISKY.filter(([, re]) => caps.some((c) => re.test(c.namespace))).map(([k]) => k);
  return { capabilities: caps, attack: [...attack.values()].sort((a, b) => a.id.localeCompare(b.id)), risky };
}
