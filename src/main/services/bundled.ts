// Locates engines and rule packs that ship inside Blazma (see engines.lock.json).
// Packaged: <resources>/engines/<id>/… and <resources>/rules/…; development: build/engines and engines/rules.
// Bundled engines were SHA-256-verified at build time; nothing here downloads anything.

import { app } from 'electron';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

export type BundledEngineId = 'yara-x' | 'capa' | 'die' | 'hayabusa' | 'hollows-hunter';

export interface BundledEngine {
  id: BundledEngineId;
  name: string;
  version: string;
  license: string;
  path: string;
}

function resources(): string {
  return app.isPackaged ? process.resourcesPath : join(app.getAppPath(), 'build');
}

export function enginesDir(): string {
  return join(resources(), 'engines');
}

export function rulesDir(): string {
  return app.isPackaged ? join(process.resourcesPath, 'rules') : join(app.getAppPath(), 'engines', 'rules');
}

let manifest: Record<string, { name: string; version: string; license: string; exe: string }> | null = null;

function readManifest(): typeof manifest {
  if (manifest) return manifest;
  try {
    const raw = JSON.parse(readFileSync(join(enginesDir(), 'manifest.json'), 'utf8')) as { engines?: typeof manifest };
    manifest = raw.engines ?? {};
  } catch {
    manifest = {};
  }
  return manifest;
}

/** The bundled engine, if this build ships it and its executable exists. */
export function bundledEngine(id: BundledEngineId): BundledEngine | null {
  const m = readManifest()?.[id];
  if (!m) return null;
  const path = join(enginesDir(), id, ...m.exe.split('/'));
  return existsSync(path) ? { id, name: m.name, version: m.version, license: m.license, path } : null;
}

/** A rule pack shipped with Blazma (e.g. reversinglabs.yar), if present. */
export function bundledRulePack(file: string): string | null {
  const p = join(rulesDir(), file);
  return existsSync(p) ? p : null;
}
