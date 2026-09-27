// Phishing email check: reads a local .eml file (or pasted source) and analyzes it with src/core/email.ts.
// Entirely local — the message never leaves the machine. Attachments can be handed to File Analyzer:
// they are written, never opened, into BLAZMA's temp folder with a non-executable extension.

import { randomUUID } from 'node:crypto';
import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { analyzeEmail, attachmentBytes, MAX_EMAIL_BYTES, type EmailAnalysis } from '../../core/email';
import { validateAbsolutePath } from '../../core/validation';
import { subDir } from './paths';

export class EmailError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

const TTL = 15 * 60_000;
const cache = new Map<string, { at: number; raw: Buffer }>();

function remember(raw: Buffer): string {
  const now = Date.now();
  for (const [k, v] of cache) if (now - v.at > TTL) cache.delete(k);
  while (cache.size >= 3) cache.delete(cache.keys().next().value!);
  const token = randomUUID();
  cache.set(token, { at: now, raw });
  return token;
}

function analyze(raw: Buffer): EmailAnalysis & { token: string } {
  // Outlook .msg files are OLE compound documents, not MIME text.
  if (raw.subarray(0, 8).equals(Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]))) throw new EmailError('email_msg_unsupported');
  try {
    return { ...analyzeEmail(raw), token: remember(raw) };
  } catch (e) {
    const code = (e as { code?: string }).code;
    throw new EmailError(code === 'email_too_large' || code === 'not_an_email' ? code : 'invalid_input');
  }
}

export async function analyzeEmailFile(rawPath: unknown) {
  const v = validateAbsolutePath(rawPath);
  if (!v.ok) throw new EmailError(v.reason);
  const st = await stat(v.path).catch(() => null);
  if (!st || !st.isFile()) throw new EmailError('file_not_found');
  if (st.size > MAX_EMAIL_BYTES) throw new EmailError('email_too_large');
  return analyze(await readFile(v.path));
}

export function analyzeEmailText(text: unknown) {
  if (typeof text !== 'string' || !text.trim()) throw new EmailError('invalid_input');
  if (Buffer.byteLength(text) > MAX_EMAIL_BYTES) throw new EmailError('email_too_large');
  return analyze(Buffer.from(text, 'utf8'));
}

/** Writes one attachment into BLAZMA's temp folder (non-executable name) and returns its path. */
export async function extractAttachment(token: unknown, index: unknown): Promise<string> {
  if (typeof token !== 'string' || !cache.has(token)) throw new EmailError('email_expired');
  if (typeof index !== 'number' || !Number.isInteger(index) || index < 0 || index > 500) throw new EmailError('invalid_input');
  const att = attachmentBytes(cache.get(token)!.raw, index);
  if (!att) throw new EmailError('invalid_input');
  const dir = join(subDir('temp'), 'email-attachments');
  await mkdir(dir, { recursive: true, mode: 0o700 });
  // Keep a readable name for the analysis, but never an executable extension.
  const safe = att.name.replace(/[\u0000-\u001f‪-‮\\/:*?"<>|]/g, '_').slice(0, 120) || 'attachment';
  const path = join(dir, `${randomUUID().slice(0, 8)}-${safe}.blazma-attachment`);
  await writeFile(path, att.bytes, { mode: 0o600 });
  return path;
}
