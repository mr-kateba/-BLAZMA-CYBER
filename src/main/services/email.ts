// Phishing email check: reads a local .eml / Outlook .msg file (or pasted source) and analyzes it with src/core/email.ts.
// Entirely local — the message never leaves the machine. Attachments can be handed to File Analyzer:
// they are written, never opened, into Blazma's temp folder with a non-executable extension.

import { randomUUID } from 'node:crypto';
import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { isCfb } from '../../core/cfb';
import { analyzeEmail, attachmentBytes, MAX_EMAIL_BYTES, type EmailAnalysis } from '../../core/email';
import { msgToMime } from '../../core/msg';
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

const KNOWN = new Set(['email_too_large', 'not_an_email', 'email_msg_invalid']);

function analyze(input: Buffer): EmailAnalysis & { token: string; format: 'eml' | 'msg' } {
  try {
    // Outlook .msg files are OLE compound documents: rebuilt as MIME, then analyzed the same way.
    const msg = isCfb(input);
    const raw = msg ? msgToMime(input) : input;
    const analysis = analyzeEmail(raw, msg ? Math.ceil(MAX_EMAIL_BYTES * 1.4) : MAX_EMAIL_BYTES);
    return { ...analysis, format: msg ? 'msg' : 'eml', token: remember(raw) };
  } catch (e) {
    const code = (e as { code?: string }).code;
    throw new EmailError(code && KNOWN.has(code) ? code : 'invalid_input');
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

/** Writes one attachment into Blazma's temp folder (non-executable name) and returns its path. */
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
