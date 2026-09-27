// Device Security Score (pure): turns read-only Windows facts into explained checks and a score.
//
// Honesty rules: a check whose fact could not be read is `unknown` (with a reason) and is left out of
// the score — it never counts as passed or failed. Blazma never changes these settings; each check
// explains why it matters and how the user can fix it, optionally opening the right Windows page.

export type CheckStatus = 'pass' | 'warn' | 'fail' | 'unknown';

/** Fixed Windows settings pages a check may open (resolved to URIs in the main process). */
export type SettingsLink = 'virus' | 'firewall' | 'update' | 'encryption' | 'remote' | 'deviceSecurity';

export interface DeviceCheck {
  id: string;
  status: CheckStatus;
  weight: number;
  /** i18n key + vars describing what was found (e.g. "signatures are 12 days old"). */
  detail: { key: string; vars?: Record<string, string | number> } | null;
  /** i18n error code when status is unknown. */
  reason?: string;
  link: SettingsLink | null;
}

export interface DeviceSecurityReport {
  /** 0–100 over the checks that could be evaluated; null when none could. */
  score: number | null;
  grade: 'good' | 'fair' | 'poor' | null;
  checks: DeviceCheck[];
  evaluated: number;
  unknown: number;
  elevated: boolean;
  collectedAt: string;
}

/**
 * Facts gathered by the (query-only) PowerShell script. null = could not be read.
 * For registry values, -1 / 'absent' = the value is not set, i.e. the Windows default applies.
 */
export interface RawDeviceFacts {
  elevated?: boolean;
  defender?: { available: boolean; rtp?: boolean | null; age?: number | null; tamper?: boolean | null } | null;
  firewall?: Array<{ name: string; enabled: boolean }> | { name: string; enabled: boolean } | null;
  uac?: { lua?: number | null; consent?: number | null } | null;
  smb1Client?: number | null; // mrxsmb10 service Start value; -1 = driver not installed
  rdp?: { deny?: number | null; nla?: number | null } | null;
  secureBoot?: number | null;
  bitlocker?: number | null; // Shell property System.Volume.BitLockerProtection of the system drive
  lastUpdate?: string | null; // ISO date of the newest successful update
  autoLogon?: string | null;
  guestEnabled?: boolean | null;
  lsaPpl?: number | null;
  vbs?: number | null; // Win32_DeviceGuard.VirtualizationBasedSecurityStatus
  execPolicy?: string | null;
  tpm?: { present: boolean; ready: boolean } | null;
}

const DAY = 86_400_000;

function check(id: string, weight: number, link: SettingsLink | null, status: CheckStatus, detail: DeviceCheck['detail'] = null, reason?: string): DeviceCheck {
  return { id, weight, link, status, detail, ...(reason ? { reason } : {}) };
}

const unknown = (id: string, weight: number, link: SettingsLink | null, reason = 'not_readable') => check(id, weight, link, 'unknown', null, reason);

export function evaluateDevice(raw: RawDeviceFacts, now: Date): DeviceSecurityReport {
  const c: DeviceCheck[] = [];
  const d = raw.defender;

  // Microsoft Defender
  if (!d || !d.available) {
    c.push(unknown('defender_realtime', 3, 'virus', 'defender_unavailable'));
    c.push(unknown('defender_signatures', 2, 'virus', 'defender_unavailable'));
  } else {
    c.push(d.rtp == null ? unknown('defender_realtime', 3, 'virus') : check('defender_realtime', 3, 'virus', d.rtp ? 'pass' : 'fail'));
    c.push(
      d.age == null || d.age < 0
        ? unknown('defender_signatures', 2, 'virus')
        : check('defender_signatures', 2, 'virus', d.age <= 3 ? 'pass' : d.age <= 7 ? 'warn' : 'fail', { key: 'devsec.detail.days', vars: { days: d.age } }),
    );
  }
  c.push(d?.available && d.tamper != null ? check('tamper_protection', 1, 'virus', d.tamper ? 'pass' : 'warn') : unknown('tamper_protection', 1, 'virus', d?.available ? 'not_readable' : 'defender_unavailable'));

  // Firewall: every profile must be on.
  const fw = raw.firewall == null ? null : Array.isArray(raw.firewall) ? raw.firewall : [raw.firewall];
  if (!fw || fw.length === 0) c.push(unknown('firewall', 3, 'firewall'));
  else {
    const off = fw.filter((p) => !p.enabled).map((p) => p.name);
    c.push(check('firewall', 3, 'firewall', off.length === 0 ? 'pass' : 'fail', off.length ? { key: 'devsec.detail.profilesOff', vars: { profiles: off.join(', ') } } : null));
  }

  // Windows Update: the newest successful update.
  if (!raw.lastUpdate || Number.isNaN(new Date(raw.lastUpdate).getTime())) c.push(unknown('updates', 3, 'update'));
  else {
    const days = Math.max(0, Math.floor((now.getTime() - new Date(raw.lastUpdate).getTime()) / DAY));
    c.push(check('updates', 3, 'update', days <= 45 ? 'pass' : days <= 90 ? 'warn' : 'fail', { key: 'devsec.detail.days', vars: { days } }));
  }

  // User Account Control
  const uac = raw.uac;
  // Defaults when not set: EnableLUA = 1, ConsentPromptBehaviorAdmin = 5 (prompt).
  if (!uac || uac.lua == null) c.push(unknown('uac', 2, null));
  else c.push(check('uac', 2, null, uac.lua === 0 ? 'fail' : uac.consent === 0 ? 'warn' : 'pass'));

  // SMBv1 client (a worm vector: WannaCry). -1 = not installed.
  c.push(raw.smb1Client == null ? unknown('smb1', 2, null) : check('smb1', 2, null, raw.smb1Client === -1 || raw.smb1Client === 4 ? 'pass' : 'fail'));

  // Remote Desktop: off is best; on requires Network Level Authentication.
  const rdp = raw.rdp;
  // Default when not set: connections denied.
  if (!rdp || rdp.deny == null) c.push(unknown('rdp', 2, 'remote'));
  else c.push(check('rdp', 2, 'remote', rdp.deny === 1 || rdp.deny === -1 ? 'pass' : rdp.nla === 1 ? 'warn' : 'fail'));

  // Secure Boot (missing key = legacy BIOS / not supported)
  c.push(raw.secureBoot == null ? unknown('secure_boot', 2, null, 'not_supported') : check('secure_boot', 2, null, raw.secureBoot === 1 ? 'pass' : 'fail'));

  // Drive encryption of the system drive. 1/6 on, 3 encrypting, 5 suspended, 2 off; 0/null unavailable.
  const bl = raw.bitlocker;
  if (bl == null || bl === 0) c.push(unknown('encryption', 2, 'encryption', 'encryption_unavailable'));
  else c.push(check('encryption', 2, 'encryption', bl === 1 || bl === 6 ? 'pass' : bl === 3 || bl === 5 ? 'warn' : 'fail'));

  // Automatic sign-in stores a password in the registry.
  c.push(raw.autoLogon == null ? unknown('auto_logon', 1, null) : check('auto_logon', 1, null, raw.autoLogon === '1' ? 'fail' : 'pass'));

  // Guest account
  c.push(raw.guestEnabled == null ? unknown('guest', 1, null) : check('guest', 1, null, raw.guestEnabled ? 'fail' : 'pass'));

  // LSA protection (credential theft hardening)
  c.push(raw.lsaPpl == null ? unknown('lsa_protection', 1, 'deviceSecurity') : check('lsa_protection', 1, 'deviceSecurity', raw.lsaPpl === 1 || raw.lsaPpl === 2 ? 'pass' : 'warn'));

  // Virtualization-based security / memory integrity
  c.push(raw.vbs == null ? unknown('vbs', 1, 'deviceSecurity') : check('vbs', 1, 'deviceSecurity', raw.vbs === 2 ? 'pass' : 'warn'));

  // PowerShell execution policy
  const ep = raw.execPolicy?.trim();
  c.push(!ep ? unknown('exec_policy', 1, null) : check('exec_policy', 1, null, /^(Unrestricted|Bypass)$/i.test(ep) ? 'warn' : 'pass', { key: 'devsec.detail.value', vars: { value: ep } }));

  // TPM (readable only as administrator)
  if (raw.tpm) c.push(check('tpm', 1, 'deviceSecurity', raw.tpm.present && raw.tpm.ready ? 'pass' : 'warn'));
  else c.push(unknown('tpm', 1, 'deviceSecurity', raw.elevated ? 'not_readable' : 'needs_admin'));

  const known = c.filter((x) => x.status !== 'unknown');
  const total = known.reduce((s, x) => s + x.weight, 0);
  const got = known.reduce((s, x) => s + x.weight * (x.status === 'pass' ? 1 : x.status === 'warn' ? 0.5 : 0), 0);
  const score = total > 0 ? Math.round((got / total) * 100) : null;
  return {
    score,
    grade: score == null ? null : score >= 80 ? 'good' : score >= 50 ? 'fair' : 'poor',
    checks: c,
    evaluated: known.length,
    unknown: c.length - known.length,
    elevated: raw.elevated === true,
    collectedAt: now.toISOString(),
  };
}

/** Windows settings pages, keyed by the fixed link ids above. Never built from input. */
export const SETTINGS_URIS: Record<SettingsLink, string> = {
  virus: 'windowsdefender://threatsettings',
  firewall: 'windowsdefender://network',
  update: 'ms-settings:windowsupdate',
  encryption: 'ms-settings:deviceencryption',
  remote: 'ms-settings:remotedesktop',
  deviceSecurity: 'windowsdefender://devicesecurity',
};
