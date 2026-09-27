import {
  Activity, BadgeCheck, Crosshair, Earth, FileClock, MemoryStick, MailWarning, FileSearch, FolderOpen, Hash, KeyRound, KeySquare, Languages, Link2, MonitorCog, Network, Palette, Plug,
  Puzzle, ScanSearch, ScrollText, ShieldCheck, ShieldHalf, SquareTerminal, UserSearch, LayoutDashboard, Cpu, Scale, type LucideIcon,
} from 'lucide-react';

export type PageId =
  | 'dashboard' | 'device-security'
  | 'ip-intel' | 'domain-intel' | 'email-check' | 'password-check' | 'osint' | 'reputation'
  | 'security-center' | 'file-analyzer' | 'browser-extensions' | 'yara' | 'hash-lab'
  | 'password-recovery'
  | 'network-traffic'
  | 'windows-forensics' | 'network-toolkit' | 'threat-hunting' | 'event-logs' | 'memory-scan' | 'terminal'
  | 'cases' | 'reports'
  | 'privacy'
  | 'settings-api' | 'settings-engines' | 'settings-appearance' | 'settings-language';

export interface NavItem {
  id: PageId;
  labelKey: string;
  icon: LucideIcon;
  /** Present only for modules that do not exist yet; the UI labels them honestly as planned. */
  planned?: { phase: number; itemsKey: string };
  /** Opens something outside Blazma (e.g. the Windows terminal) instead of a page. */
  external?: boolean;
  /** Shown in simple mode (everyday users). */
  simple?: boolean;
  /** Friendlier label used in simple mode. */
  simpleLabelKey?: string;
}

export interface NavSection {
  titleKey?: string;
  items: NavItem[];
}

const p = (phase: number, key: string) => ({ phase, itemsKey: `planned.modules.${key}` });

export const NAV: NavSection[] = [
  {
    items: [
      { id: 'dashboard', simple: true, labelKey: 'nav.dashboard', icon: LayoutDashboard },
      { id: 'device-security', simple: true, labelKey: 'nav.deviceSecurity', icon: BadgeCheck },
    ],
  },
  {
    titleKey: 'nav.section.intelligence',
    items: [
      { id: 'ip-intel', labelKey: 'nav.ipIntel', icon: Earth },
      { id: 'domain-intel', simple: true, simpleLabelKey: 'nav.simple.checkLink', labelKey: 'nav.domainIntel', icon: Link2 },
      { id: 'email-check', simple: true, labelKey: 'nav.emailCheck', icon: MailWarning },
      { id: 'password-check', simple: true, labelKey: 'nav.passwordCheck', icon: KeySquare },
      { id: 'osint', labelKey: 'nav.osint', icon: UserSearch },
      { id: 'reputation', labelKey: 'nav.reputation', icon: Scale },
    ],
  },
  {
    titleKey: 'nav.section.analysis',
    items: [
      { id: 'security-center', simple: true, labelKey: 'nav.securityCenter', icon: ShieldHalf },
      { id: 'file-analyzer', simple: true, simpleLabelKey: 'nav.simple.scanFile', labelKey: 'nav.fileAnalyzer', icon: FileSearch },
      { id: 'browser-extensions', simple: true, labelKey: 'nav.extensions', icon: Puzzle },
      { id: 'yara', labelKey: 'nav.yara', icon: ScanSearch },
      { id: 'hash-lab', labelKey: 'nav.hashLab', icon: Hash },
    ],
  },
  {
    titleKey: 'nav.section.recovery',
    items: [{ id: 'password-recovery', labelKey: 'nav.passwordRecovery', icon: KeyRound }],
  },
  {
    titleKey: 'nav.section.network',
    items: [
      { id: 'network-traffic', labelKey: 'nav.networkTraffic', icon: Activity },
      { id: 'network-toolkit', labelKey: 'nav.networkToolkit', icon: Network },
    ],
  },
  {
    titleKey: 'nav.section.forensics',
    items: [
      { id: 'windows-forensics', labelKey: 'nav.windowsForensics', icon: MonitorCog },
      { id: 'threat-hunting', labelKey: 'nav.threatHunting', icon: Crosshair },
      { id: 'event-logs', labelKey: 'nav.eventLogs', icon: FileClock },
      { id: 'memory-scan', labelKey: 'nav.memoryScan', icon: MemoryStick },
      { id: 'terminal', labelKey: 'nav.terminal', icon: SquareTerminal, external: true },
    ],
  },
  {
    titleKey: 'nav.section.investigations',
    items: [
      { id: 'cases', labelKey: 'nav.cases', icon: FolderOpen },
      { id: 'reports', labelKey: 'nav.reports', icon: ScrollText },
    ],
  },
  { titleKey: 'nav.section.privacy', items: [{ id: 'privacy', simple: true, labelKey: 'nav.privacyCenter', icon: ShieldCheck }] },
  {
    titleKey: 'nav.section.settings',
    items: [
      { id: 'settings-api', labelKey: 'nav.apiKeys', icon: Plug },
      { id: 'settings-engines', labelKey: 'nav.engines', icon: Cpu },
      { id: 'settings-appearance', simple: true, labelKey: 'nav.appearance', icon: Palette },
      { id: 'settings-language', simple: true, labelKey: 'nav.language', icon: Languages },
    ],
  },
];

export const ALL_ITEMS: NavItem[] = NAV.flatMap((s) => s.items);

/** The sidebar for a mode: simple mode keeps only the essentials (sections without items disappear). */
export function visibleNav(mode: 'simple' | 'expert'): NavSection[] {
  if (mode === 'expert') return NAV;
  return NAV.map((s) => ({ ...s, items: s.items.filter((i) => i.simple) })).filter((s) => s.items.length > 0);
}

export function labelKeyFor(item: NavItem, mode: 'simple' | 'expert'): string {
  return mode === 'simple' && item.simpleLabelKey ? item.simpleLabelKey : item.labelKey;
}

export function findItem(id: PageId): NavItem {
  return ALL_ITEMS.find((i) => i.id === id) ?? ALL_ITEMS[0]!;
}
