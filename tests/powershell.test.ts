import { describe, expect, it, vi } from 'vitest';

vi.mock('electron', () => ({ app: { getPath: () => '/tmp' }, safeStorage: {} }));

import { assertSafeScript } from '../src/main/services/powershell';
import { __scriptsForTest } from '../src/main/services/windows-security';

describe('PowerShell script safety', () => {
  it('fixed scripts contain no double quotes (argv quoting safety)', () => {
    for (const s of Object.values(__scriptsForTest)) expect(() => assertSafeScript(s)).not.toThrow();
  });
  it('user data is passed via environment variables, never interpolated', () => {
    expect(__scriptsForTest.SIGNATURE_SCRIPT).toContain('$env:BLAZMA_ARG_PATH');
    expect(__scriptsForTest.SIGNATURE_SCRIPT).toContain('-LiteralPath');
    // No template interpolation markers left in any script
    for (const s of Object.values(__scriptsForTest)) expect(s).not.toMatch(/\$\{/);
  });
  it('rejects scripts with double quotes', () => {
    expect(() => assertSafeScript('Write-Output "x"')).toThrow('script_contains_double_quote');
  });
});
