// "What starts with Windows" (pure): the autostart entries Windows lists, the program each one
// runs, whether that program is signed and by whom, and where it lives. Unsigned programs that
// start from a user or temporary folder are "worth a look" — a common malware habit, but also
// what some small legitimate tools do, so it is never called malicious.

import { persistenceFlags } from './hunt';
import { parseServiceBinary } from './netparse';

export interface StartupInput {
  name: string;
  command: string;
  location: string;
  user: string | null;
}

export interface SignatureFact {
  path: string;
  status: 'valid' | 'not_signed' | 'hash_mismatch' | 'not_trusted' | 'unknown_error' | 'other';
  publisher: string | null;
}

export interface StartupItem extends StartupInput {
  /** Program path extracted from the command, or null (e.g. a shell command without a path). */
  program: string | null;
  scope: 'user' | 'all_users';
  signature: SignatureFact['status'] | null;
  publisher: string | null;
  /** i18n keys under hunt.flag.* */
  flags: string[];
  attention: boolean;
}

/** Windows' own launcher programs: the real program is in the arguments. */
const HOSTS = /^"?(?:[^"\s]*\\|[a-z]:\\[^"]*\\)?(rundll32|regsvr32|cmd|powershell|pwsh|wscript|cscript|mshta)(\.exe)?"?(\s|$)/i;

export function startupProgram(command: string, systemRoot = 'C:\\Windows'): string | null {
  const p = parseServiceBinary(command.replace(/%windir%/gi, systemRoot), systemRoot);
  return p && /^([a-z]:\\|\\\\)/i.test(p) ? p : null;
}

export function reviewStartup(rows: StartupInput[], signatures: SignatureFact[], systemRoot = 'C:\\Windows'): StartupItem[] {
  const sig = new Map(signatures.map((s) => [s.path.toLowerCase(), s]));
  const items = rows.map((r) => {
    const program = startupProgram(r.command, systemRoot);
    const s = program ? sig.get(program.toLowerCase()) : undefined;
    const flags = persistenceFlags(r.command);
    // A script host started at logon deserves a look whatever its own signature says.
    const viaHost = HOSTS.test(r.command.trim());
    if (viaHost) flags.push('hunt.flag.scriptHost');
    const unsigned = !!s && s.status !== 'valid';
    // Win32_StartupCommand locations: HKU\<sid>\…\Run, HKLM\…\Run, "Startup", "Common Startup".
    const scope: StartupItem['scope'] = /^(HKU|HKCU)\\/i.test(r.location) || /^Startup$/i.test(r.location.trim()) ? 'user' : 'all_users';
    return {
      ...r,
      program,
      scope,
      signature: s?.status ?? null,
      publisher: s?.publisher ?? null,
      flags,
      attention: viaHost || (unsigned && flags.includes('hunt.flag.userFolder')) || s?.status === 'hash_mismatch',
    };
  });
  return items.sort((a, b) => Number(b.attention) - Number(a.attention) || a.name.localeCompare(b.name));
}
