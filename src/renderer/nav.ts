import {
  Crosshair, Earth, FileSearch, FolderOpen, Hash, KeyRound, Languages, Link2, MonitorCog, Network, Palette, Plug,
  ScanSearch, ScrollText, ShieldCheck, ShieldHalf, UserSearch, LayoutDashboard, Cpu, Scale, type LucideIcon,
} from 'lucide-react';

export type PageId =
  | 'dashboard'
  | 'ip-intel' | 'domain-intel' | 'osint' | 'reputation'
  | 'security-center' | 'file-analyzer' | 'yara' | 'hash-lab'
  | 'password-recovery'
  | 'windows-forensics' | 'network-toolkit' | 'threat-hunting'
  | 'cases' | 'reports'
  | 'privacy'
  | 'settings-api' | 'settings-engines' | 'settings-appearance' | 'settings-language';

export interface NavItem {
  id: PageId;
  labelKey: string;
  icon: LucideIcon;
  /** Present only for modules that do not exist yet; the UI labels them honestly as planned. */
  planned?: { phase: number; itemsKey: string };
}

export interface NavSection {
  titleKey?: string;
  items: NavItem[];
}

const p = (phase: number, key: string) => ({ phase, itemsKey: `planned.modules.${key}` });

export const NAV: NavSection[] = [
  { items: [{ id: 'dashboard', labelKey: 'nav.dashboard', icon: LayoutDashboard }] },
  {
    titleKey: 'nav.section.intelligence',
    items: [
      { id: 'ip-intel', labelKey: 'nav.ipIntel', icon: Earth },
      { id: 'domain-intel', labelKey: 'nav.domainIntel', icon: Link2 },
      { id: 'osint', labelKey: 'nav.osint', icon: UserSearch, planned: p(6, 'osint') },
      { id: 'reputation', labelKey: 'nav.reputation', icon: Scale },
    ],
  },
  {
    titleKey: 'nav.section.analysis',
    items: [
      { id: 'security-center', labelKey: 'nav.securityCenter', icon: ShieldHalf },
      { id: 'file-analyzer', labelKey: 'nav.fileAnalyzer', icon: FileSearch },
      { id: 'yara', labelKey: 'nav.yara', icon: ScanSearch },
      { id: 'hash-lab', labelKey: 'nav.hashLab', icon: Hash },
    ],
  },
  {
    titleKey: 'nav.section.recovery',
    items: [{ id: 'password-recovery', labelKey: 'nav.passwordRecovery', icon: KeyRound }],
  },
  {
    titleKey: 'nav.section.forensics',
    items: [
      { id: 'windows-forensics', labelKey: 'nav.windowsForensics', icon: MonitorCog },
      { id: 'network-toolkit', labelKey: 'nav.networkToolkit', icon: Network },
      { id: 'threat-hunting', labelKey: 'nav.threatHunting', icon: Crosshair, planned: p(6, 'threatHunting') },
    ],
  },
  {
    titleKey: 'nav.section.investigations',
    items: [
      { id: 'cases', labelKey: 'nav.cases', icon: FolderOpen, planned: p(6, 'cases') },
      { id: 'reports', labelKey: 'nav.reports', icon: ScrollText, planned: p(6, 'reports') },
    ],
  },
  { titleKey: 'nav.section.privacy', items: [{ id: 'privacy', labelKey: 'nav.privacyCenter', icon: ShieldCheck }] },
  {
    titleKey: 'nav.section.settings',
    items: [
      { id: 'settings-api', labelKey: 'nav.apiKeys', icon: Plug },
      { id: 'settings-engines', labelKey: 'nav.engines', icon: Cpu },
      { id: 'settings-appearance', labelKey: 'nav.appearance', icon: Palette },
      { id: 'settings-language', labelKey: 'nav.language', icon: Languages },
    ],
  },
];

export const ALL_ITEMS: NavItem[] = NAV.flatMap((s) => s.items);

export function findItem(id: PageId): NavItem {
  return ALL_ITEMS.find((i) => i.id === id) ?? ALL_ITEMS[0]!;
}
