// Safe local quarantine.
//
// Design goals (see SECURITY.md):
//  - A quarantined file must not be runnable by accident. We store it with a neutral extension
//    (.blazmaq) in a protected directory, with 0o600 permissions, AND byte-obfuscated (XOR 0xFF)
//    so a stored blob is never a valid PE/script that could be double-clicked into execution.
//  - Enough metadata is kept to restore the exact original bytes (verified by SHA-256).
//  - Nothing is ever permanently deleted automatically; delete is an explicit user action.
//
// The XOR is obfuscation for safety, not encryption; it is a deliberate, reversible neutralization.

import { createHash } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { chmod, mkdir, rename, rm, stat, unlink } from 'node:fs/promises';
import { pipeline } from 'node:stream/promises';
import { Transform } from 'node:stream';
import { basename, join } from 'node:path';
import { validateAbsolutePath } from '../../core/validation';
import { detectFileType } from '../../core/filetype';
import { readJson, writeJson } from './json-store';
import { subDir } from './paths';

import type { QuarantineEntry } from '../../shared/api';
export type { QuarantineEntry };

export class QuarantineError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

const NEUTRALIZE = 0xff;
function xorTransform(): Transform {
  return new Transform({
    transform(chunk: Buffer, _enc, cb) {
      const out = Buffer.allocUnsafe(chunk.length);
      for (let i = 0; i < chunk.length; i++) out[i] = chunk[i]! ^ NEUTRALIZE;
      cb(null, out);
    },
  });
}

const ID_RE = /^[a-z0-9-]{6,64}$/;

export class QuarantineService {
  private readonly dir = subDir('quarantine');
  private readonly indexFile = join(this.dir, 'index.json');

  private read(): QuarantineEntry[] {
    const raw = readJson<unknown>(this.indexFile, []);
    return Array.isArray(raw) ? (raw as QuarantineEntry[]) : [];
  }
  private write(entries: QuarantineEntry[]): void {
    writeJson(this.indexFile, entries);
  }
  private blobPath(id: string): string {
    return join(this.dir, `${id}.blazmaq`);
  }

  list(): QuarantineEntry[] {
    return this.read().sort((a, b) => b.quarantinedAt.localeCompare(a.quarantinedAt));
  }

  get(id: string): QuarantineEntry | null {
    return this.read().find((e) => e.id === id) ?? null;
  }

  /** Moves a file into quarantine (neutralized), records metadata, and removes the original. */
  async quarantine(rawPath: unknown, reason: string): Promise<QuarantineEntry> {
    const v = validateAbsolutePath(rawPath);
    if (!v.ok) throw new QuarantineError(v.reason);

    let st;
    try {
      st = await stat(v.path);
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      throw new QuarantineError(code === 'ENOENT' ? 'file_not_found' : 'access_denied');
    }
    if (!st.isFile()) throw new QuarantineError('not_a_file');

    const id = `q-${Date.now().toString(36)}-${createHash('sha1').update(v.path).digest('hex').slice(0, 10)}`;
    const dest = this.blobPath(id);
    await mkdir(this.dir, { recursive: true, mode: 0o700 });

    // Stream original -> hash + neutralized copy, then remove the original.
    const hash = createHash('sha256');
    const head: Buffer[] = [];
    let headLen = 0;
    const tap = new Transform({
      transform(chunk: Buffer, _e, cb) {
        hash.update(chunk);
        if (headLen < 4096) {
          const take = chunk.subarray(0, 4096 - headLen);
          head.push(Buffer.from(take));
          headLen += take.length;
        }
        cb(null, chunk);
      },
    });
    try {
      await pipeline(createReadStream(v.path), tap, xorTransform(), createWriteStream(dest, { mode: 0o600 }));
    } catch {
      await rm(dest, { force: true });
      throw new QuarantineError('quarantine_failed');
    }
    await chmod(dest, 0o600).catch(() => undefined);

    const type = detectFileType(Buffer.concat(head));
    const entry: QuarantineEntry = {
      id,
      originalPath: v.path,
      originalName: basename(v.path),
      sizeBytes: st.size,
      sha256: hash.digest('hex'),
      typeId: type.id,
      typeDescription: type.description,
      quarantinedAt: new Date().toISOString(),
      reason,
    };

    // Only remove the original once the neutralized copy is safely written.
    try {
      await unlink(v.path);
    } catch (e) {
      await rm(dest, { force: true });
      const code = (e as NodeJS.ErrnoException).code;
      throw new QuarantineError(code === 'EACCES' || code === 'EPERM' ? 'access_denied' : 'quarantine_failed');
    }

    this.write([entry, ...this.read()]);
    return entry;
  }

  /** Restores the exact original bytes (verified) to the original path or a chosen target. */
  async restore(id: unknown, targetPath?: unknown): Promise<{ path: string }> {
    if (typeof id !== 'string' || !ID_RE.test(id)) throw new QuarantineError('invalid_input');
    const entry = this.get(id);
    if (!entry) throw new QuarantineError('quarantine_not_found');

    let dest = entry.originalPath;
    if (targetPath !== undefined) {
      const v = validateAbsolutePath(targetPath);
      if (!v.ok) throw new QuarantineError(v.reason);
      dest = v.path;
    }
    // Refuse to overwrite an existing file at the destination.
    try {
      await stat(dest);
      throw new QuarantineError('restore_target_exists');
    } catch (e) {
      if (e instanceof QuarantineError) throw e;
      // ENOENT is what we want.
    }

    const tmp = `${dest}.blazma-restore-${process.pid}`;
    const hash = createHash('sha256');
    const verify = new Transform({
      transform(chunk: Buffer, _e, cb) {
        hash.update(chunk);
        cb(null, chunk);
      },
    });
    try {
      await pipeline(createReadStream(this.blobPath(id)), xorTransform(), verify, createWriteStream(tmp, { mode: 0o600 }));
    } catch {
      await rm(tmp, { force: true });
      throw new QuarantineError('restore_failed');
    }
    if (hash.digest('hex') !== entry.sha256) {
      await rm(tmp, { force: true });
      throw new QuarantineError('restore_hash_mismatch');
    }
    try {
      await rename(tmp, dest);
    } catch {
      await rm(tmp, { force: true });
      throw new QuarantineError('restore_failed');
    }

    this.write(this.read().filter((e) => e.id !== id));
    await rm(this.blobPath(id), { force: true });
    return { path: dest };
  }

  /** Permanently deletes a quarantined item (explicit user action only). */
  async remove(id: unknown): Promise<void> {
    if (typeof id !== 'string' || !ID_RE.test(id)) throw new QuarantineError('invalid_input');
    if (!this.get(id)) throw new QuarantineError('quarantine_not_found');
    await rm(this.blobPath(id), { force: true });
    this.write(this.read().filter((e) => e.id !== id));
  }

  /** Decodes a quarantined blob to a temp file for re-analysis, runs `work`, then deletes the temp. */
  async withDecoded<T>(id: string, work: (tempPath: string) => Promise<T>): Promise<T> {
    if (!ID_RE.test(id)) throw new QuarantineError('invalid_input');
    if (!this.get(id)) throw new QuarantineError('quarantine_not_found');
    const tmpDir = subDir('temp');
    const tmp = join(tmpDir, `rescan-${id}-${process.pid}.tmp`);
    try {
      await pipeline(createReadStream(this.blobPath(id)), xorTransform(), createWriteStream(tmp, { mode: 0o600 }));
      return await work(tmp);
    } finally {
      await rm(tmp, { force: true });
    }
  }
}
