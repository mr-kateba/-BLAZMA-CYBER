import { appendFileSync, existsSync, renameSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { redact } from '../../core/redact';
import { subDir } from './paths';

export type LogLevel = 'DEBUG' | 'INFO' | 'WARNING' | 'ERROR' | 'SECURITY';
const ORDER: Record<LogLevel, number> = { DEBUG: 0, INFO: 1, WARNING: 2, ERROR: 3, SECURITY: 4 };
const MAX_BYTES = 5 * 1024 * 1024;

let minLevel: LogLevel = 'INFO';

export function setLogLevel(level: LogLevel): void {
  minLevel = level;
}

function logFile(): string {
  return join(subDir('logs'), 'blazma.log.jsonl');
}

/**
 * Structured JSONL logging. Every context object passes through redact() so API keys,
 * tokens and passwords can never be written, even by mistake.
 */
export function log(level: LogLevel, event: string, context?: Record<string, unknown>): void {
  if (ORDER[level] < ORDER[minLevel] && level !== 'SECURITY') return;
  const entry = { ts: new Date().toISOString(), level, event, ...(context ? { ctx: redact(context) } : {}) };
  try {
    const file = logFile();
    if (existsSync(file) && statSync(file).size > MAX_BYTES) renameSync(file, `${file}.1`);
    appendFileSync(file, JSON.stringify(entry) + '\n', { encoding: 'utf8', mode: 0o600 });
  } catch {
    // Logging must never crash the app.
  }
  if (process.env.BLAZMA_DEV === '1') console.log(`[${level}] ${event}`, entry.ctx ?? '');
}

export const logger = {
  debug: (e: string, c?: Record<string, unknown>) => log('DEBUG', e, c),
  info: (e: string, c?: Record<string, unknown>) => log('INFO', e, c),
  warn: (e: string, c?: Record<string, unknown>) => log('WARNING', e, c),
  error: (e: string, c?: Record<string, unknown>) => log('ERROR', e, c),
  security: (e: string, c?: Record<string, unknown>) => log('SECURITY', e, c),
};
