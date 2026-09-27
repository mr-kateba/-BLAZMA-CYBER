// Builds src/core/attack-data.json (technique id → name + tactics) from MITRE's official STIX bundle.
// Usage: node scripts/make-attack-data.mjs <path to enterprise-attack.json> <attack-stix-data commit>
// Source: https://github.com/mitre-attack/attack-stix-data — © The MITRE Corporation (see engines/licenses/mitre-attack.txt).
import { readFileSync, writeFileSync } from 'node:fs';

const [src, commit] = process.argv.slice(2);
if (!src || !commit) throw new Error('usage: make-attack-data.mjs <enterprise-attack.json> <commit>');
const objects = JSON.parse(readFileSync(src, 'utf8')).objects;
const collection = objects.find((o) => o.type === 'x-mitre-collection');
const tactics = objects
  .filter((o) => o.type === 'x-mitre-tactic' && !o.revoked && !o.x_mitre_deprecated)
  .map((o) => ({ id: o.external_references.find((r) => r.source_name === 'mitre-attack').external_id, short: o.x_mitre_shortname, name: o.name }));
// Kill-chain order of the Enterprise matrix.
const matrix = objects.find((o) => o.type === 'x-mitre-matrix' && !o.revoked);
const order = matrix.tactic_refs.map((ref) => objects.find((o) => o.id === ref).x_mitre_shortname);
const techniques = {};
for (const o of objects) {
  if (o.type !== 'attack-pattern' || o.revoked || o.x_mitre_deprecated) continue;
  const id = o.external_references.find((r) => r.source_name === 'mitre-attack')?.external_id;
  if (!id) continue;
  techniques[id] = [o.name, (o.kill_chain_phases ?? []).filter((k) => k.kill_chain_name === 'mitre-attack').map((k) => k.phase_name)];
}
// Older ids (still used by many detection rules) → the technique that replaced them, from MITRE's own
// "revoked-by" relationships.
const extId = (o) => o?.external_references?.find((r) => r.source_name === 'mitre-attack')?.external_id;
const byStixId = new Map(objects.filter((o) => o.type === 'attack-pattern').map((o) => [o.id, o]));
const revoked = {};
for (const r of objects) {
  if (r.type !== 'relationship' || r.relationship_type !== 'revoked-by') continue;
  const from = extId(byStixId.get(r.source_ref));
  const to = extId(byStixId.get(r.target_ref));
  if (from && to && techniques[to] && !techniques[from]) revoked[from] = to;
}
const out = { version: collection?.x_mitre_version ?? null, source: `mitre-attack/attack-stix-data@${commit}`, tactics: order.map((s) => tactics.find((t) => t.short === s)), techniques, revoked };
writeFileSync(new URL('../src/core/attack-data.json', import.meta.url), `${JSON.stringify(out)}\n`);
console.log(`ATT&CK ${out.version}: ${Object.keys(techniques).length} techniques, ${out.tactics.length} tactics, ${Object.keys(revoked).length} revoked ids mapped`);
