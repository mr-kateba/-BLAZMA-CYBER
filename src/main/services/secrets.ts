import { safeStorage } from 'electron';
import { join } from 'node:path';
import type { ApiKeyService } from '../../shared/api';
import { readJson, writeJson } from './json-store';
import { subDir } from './paths';

export const API_KEY_SERVICES: readonly ApiKeyService[] = ['virustotal', 'abuseipdb', 'shodan', 'censys'];

export function isApiKeyService(v: unknown): v is ApiKeyService {
  return typeof v === 'string' && (API_KEY_SERVICES as readonly string[]).includes(v);
}

/**
 * API keys are encrypted with the OS credential protection (DPAPI on Windows) through
 * Electron safeStorage. If encryption is unavailable we REFUSE to store, rather than
 * silently writing plaintext.
 */
export class SecretStore {
  private readonly file = join(subDir('secrets'), 'api-keys.json');

  available(): boolean {
    return safeStorage.isEncryptionAvailable();
  }

  status(): Record<ApiKeyService, boolean> {
    const data = readJson<Record<string, string>>(this.file, {});
    return Object.fromEntries(API_KEY_SERVICES.map((s) => [s, typeof data[s] === 'string'])) as Record<ApiKeyService, boolean>;
  }

  set(service: ApiKeyService, value: string): void {
    if (!this.available()) throw new Error('secure_storage_unavailable');
    const data = readJson<Record<string, string>>(this.file, {});
    data[service] = safeStorage.encryptString(value).toString('base64');
    writeJson(this.file, data);
  }

  get(service: ApiKeyService): string | null {
    const data = readJson<Record<string, string>>(this.file, {});
    const enc = data[service];
    if (!enc || !this.available()) return null;
    return safeStorage.decryptString(Buffer.from(enc, 'base64'));
  }

  remove(service: ApiKeyService): void {
    const data = readJson<Record<string, string>>(this.file, {});
    delete data[service];
    writeJson(this.file, data);
  }
}
