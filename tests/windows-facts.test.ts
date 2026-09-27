import { beforeEach, describe, expect, it, vi } from 'vitest';
import { tmpdir } from 'node:os';

vi.mock('electron', () => ({ app: { getPath: () => tmpdir() }, safeStorage: {} }));
const runMock = vi.fn();
vi.mock('../src/main/services/powershell', () => ({ runPowerShellJson: (...a: unknown[]) => runMock(...a), assertSafeScript: () => {} }));

import { __resetWindowsFactsCache, getWindowsFacts, peekWindowsFacts } from '../src/main/services/windows-security';

const platform = Object.getOwnPropertyDescriptor(process, 'platform')!;

describe('Windows facts cache (no PowerShell storms)', () => {
  beforeEach(() => {
    __resetWindowsFactsCache();
    runMock.mockReset();
    Object.defineProperty(process, 'platform', { value: 'win32' });
    return () => Object.defineProperty(process, 'platform', platform);
  });

  it('runs a single PowerShell process for concurrent callers', async () => {
    let release!: (v: unknown) => void;
    runMock.mockReturnValue(new Promise((r) => (release = r)));
    const calls = [getWindowsFacts(), getWindowsFacts(), getWindowsFacts()];
    release({ ok: true, data: { os: null, cores: 4, processes: 100, defender: { available: false }, firewall: null } });
    const results = await Promise.all(calls);
    expect(runMock).toHaveBeenCalledTimes(1);
    expect(results[0]!.processCount).toBe(100);
  });

  it('caches failures instead of re-spawning on every poll', async () => {
    runMock.mockResolvedValue({ ok: false, error: 'timeout' });
    const a = await getWindowsFacts();
    await getWindowsFacts();
    await getWindowsFacts();
    expect(runMock).toHaveBeenCalledTimes(1);
    expect(a.security.defender).toEqual({ available: false, reason: 'timeout' });
  });

  it('peek never blocks and returns null before the first result', () => {
    runMock.mockReturnValue(new Promise(() => {}));
    expect(peekWindowsFacts()).toBeNull();
    expect(peekWindowsFacts()).toBeNull();
    expect(runMock).toHaveBeenCalledTimes(1);
  });
});
