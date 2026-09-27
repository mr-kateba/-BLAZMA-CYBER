import { describe, expect, it, vi } from 'vitest';
import { tmpdir } from 'node:os';

vi.mock('electron', () => ({ app: { getPath: () => tmpdir() }, safeStorage: {} }));

import { sanitizeSettings } from '../src/main/services/settings';
import { DEFAULT_SETTINGS } from '../src/shared/api';

describe('settings validation', () => {
  it('defaults to Offline Mode on (privacy-first) and no language chosen', () => {
    expect(DEFAULT_SETTINGS.offlineMode).toBe(true);
    expect(DEFAULT_SETTINGS.language).toBeNull();
  });
  it('accepts valid values and drops unknown keys', () => {
    const s = sanitizeSettings({ language: 'ar', offlineMode: false, evil: '<script>', __proto__: { x: 1 } }, DEFAULT_SETTINGS);
    expect(s.language).toBe('ar');
    expect(s.offlineMode).toBe(false);
    expect(s).not.toHaveProperty('evil');
  });
  it('rejects invalid values, keeping the previous ones', () => {
    const s = sanitizeSettings({ language: 'fr', theme: 'pink', offlineMode: 'no', logLevel: 'TRACE' }, DEFAULT_SETTINGS);
    expect(s).toEqual(DEFAULT_SETTINGS);
  });
  it('handles garbage input', () => {
    expect(sanitizeSettings(null, DEFAULT_SETTINGS)).toEqual(DEFAULT_SETTINGS);
    expect(sanitizeSettings('x', DEFAULT_SETTINGS)).toEqual(DEFAULT_SETTINGS);
  });
});
