import { lazy, Suspense, useEffect, useMemo, useRef, useState } from 'react';
import { ExternalLink, Search, Settings as SettingsIcon, type LucideIcon } from 'lucide-react';
import { Ltr, Skeleton } from './components/ui';
import { classifyInput } from '../core/smart-input';
import { Logo } from './components/Logo';
import { useApp } from './components/AppContext';
import { useI18n } from './i18n/I18nProvider';
import { findItem, labelKeyFor, visibleNav, type PageId } from './nav';
import { DownloadsOpenListener } from './components/DownloadsWatch';
import { Dashboard } from './pages/Dashboard';
import { APP_AUTHOR } from '../shared/api';

// Every page except the dashboard is loaded on first visit (smaller startup bundle).
const FileAnalyzer = lazy(() => import('./pages/FileAnalyzer').then((m) => ({ default: m.FileAnalyzer })));
const HashLab = lazy(() => import('./pages/HashLab').then((m) => ({ default: m.HashLab })));
const PrivacyCenter = lazy(() => import('./pages/PrivacyCenter').then((m) => ({ default: m.PrivacyCenter })));
const SettingsPage = lazy(() => import('./pages/Settings').then((m) => ({ default: m.SettingsPage })));
const PlannedModule = lazy(() => import('./pages/PlannedModule').then((m) => ({ default: m.PlannedModule })));
const SecurityCenter = lazy(() => import('./pages/SecurityCenter').then((m) => ({ default: m.SecurityCenter })));
const YaraScanner = lazy(() => import('./pages/YaraScanner').then((m) => ({ default: m.YaraScanner })));
const IpIntel = lazy(() => import('./pages/IpIntel').then((m) => ({ default: m.IpIntel })));
const DomainIntel = lazy(() => import('./pages/DomainIntel').then((m) => ({ default: m.DomainIntel })));
const ReputationCenter = lazy(() => import('./pages/ReputationCenter').then((m) => ({ default: m.ReputationCenter })));
const WindowsForensics = lazy(() => import('./pages/WindowsForensics').then((m) => ({ default: m.WindowsForensics })));
const NetworkToolkit = lazy(() => import('./pages/NetworkToolkit').then((m) => ({ default: m.NetworkToolkit })));
const PasswordRecovery = lazy(() => import('./pages/PasswordRecovery').then((m) => ({ default: m.PasswordRecovery })));
const Cases = lazy(() => import('./pages/Cases').then((m) => ({ default: m.Cases })));
const Reports = lazy(() => import('./pages/Reports').then((m) => ({ default: m.Reports })));
const ThreatHunting = lazy(() => import('./pages/ThreatHunting').then((m) => ({ default: m.ThreatHunting })));
const DeviceSecurity = lazy(() => import('./pages/DeviceSecurity').then((m) => ({ default: m.DeviceSecurity })));
const EmailCheck = lazy(() => import('./pages/EmailCheck').then((m) => ({ default: m.EmailCheck })));
const BrowserExtensions = lazy(() => import('./pages/BrowserExtensions').then((m) => ({ default: m.BrowserExtensions })));
const MemoryScan = lazy(() => import('./pages/MemoryScan').then((m) => ({ default: m.MemoryScan })));
const WifiCenter = lazy(() => import('./pages/WifiCenter').then((m) => ({ default: m.WifiCenter })));
const FileIntegrity = lazy(() => import('./pages/FileIntegrity').then((m) => ({ default: m.FileIntegrity })));
const ServiceScan = lazy(() => import('./pages/ServiceScan').then((m) => ({ default: m.ServiceScan })));
const NetworkTraffic = lazy(() => import('./pages/NetworkTraffic').then((m) => ({ default: m.NetworkTraffic })));
const EventLogs = lazy(() => import('./pages/EventLogs').then((m) => ({ default: m.EventLogs })));
const PasswordCheck = lazy(() => import('./pages/PasswordCheck').then((m) => ({ default: m.PasswordCheck })));
const Osint = lazy(() => import('./pages/Osint').then((m) => ({ default: m.Osint })));

function Page({ id }: { id: PageId }) {
  switch (id) {
    case 'dashboard':
      return <Dashboard />;
    case 'device-security':
      return <DeviceSecurity />;
    case 'file-analyzer':
      return <FileAnalyzer />;
    case 'hash-lab':
      return <HashLab />;
    case 'privacy':
      return <PrivacyCenter />;
    case 'security-center':
      return <SecurityCenter />;
    case 'yara':
      return <YaraScanner />;
    case 'ip-intel':
      return <IpIntel />;
    case 'domain-intel':
      return <DomainIntel />;
    case 'email-check':
      return <EmailCheck />;
    case 'password-check':
      return <PasswordCheck />;
    case 'browser-extensions':
      return <BrowserExtensions />;
    case 'event-logs':
      return <EventLogs />;
    case 'memory-scan':
      return <MemoryScan />;
    case 'network-traffic':
      return <NetworkTraffic />;
    case 'wifi':
      return <WifiCenter />;
    case 'service-scan':
      return <ServiceScan />;
    case 'file-integrity':
      return <FileIntegrity />;
    case 'osint':
      return <Osint />;
    case 'reputation':
      return <ReputationCenter />;
    case 'windows-forensics':
      return <WindowsForensics />;
    case 'network-toolkit':
      return <NetworkToolkit />;
    case 'password-recovery':
      return <PasswordRecovery />;
    case 'cases':
      return <Cases />;
    case 'reports':
      return <Reports />;
    case 'threat-hunting':
      return <ThreatHunting />;
    case 'settings-api':
      return <SettingsPage tab="apiKeys" />;
    case 'settings-engines':
      return <SettingsPage tab="engines" />;
    case 'settings-appearance':
    case 'settings-language':
      return <SettingsPage tab="general" />;
    default:
      return <PlannedModule item={findItem(id)} />;
  }
}

function TopSearch() {
  const { t } = useI18n();
  const { navigate, settings, openWith, analyzeFile } = useApp();
  const mode = settings.uiMode;
  const [q, setQ] = useState('');
  const [open, setOpen] = useState(false);
  const [idx, setIdx] = useState(0);
  const ref = useRef<HTMLInputElement>(null);

  // Ctrl+K (or "/" outside a text field) jumps to the search from anywhere.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const typing = e.target instanceof HTMLElement && (e.target.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName));
      if (((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') || (e.key === '/' && !typing)) {
        e.preventDefault();
        ref.current?.focus();
        ref.current?.select();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const results = useMemo(() => {
    const s = q.trim().toLowerCase();
    if (!s) return [];
    const visible = visibleNav(mode).flatMap((sec) => sec.items);
    const out: Array<{ key: string; icon: LucideIcon; label: string; hint?: string; value?: string; planned?: boolean; go: () => void }> = [];
    // "Paste anything": an indicator or a file path becomes direct actions on the tools that examine it.
    const m = classifyInput(q);
    if (m) {
      for (const a of m.actions) {
        const item = visible.find((i) => i.id === a.page);
        if (!item) continue;
        out.push({
          key: `smart:${a.page}:${a.action}`,
          icon: item.icon,
          label: t(`smart.action.${a.action}`),
          hint: t(`smart.kind.${m.kind}`),
          value: m.value,
          go: () => (a.page === 'file-analyzer' ? analyzeFile(a.value) : openWith(a.page, a.value, a.mode)),
        });
      }
    }
    for (const i of visible) {
      if (!(t(labelKeyFor(i, mode)).toLowerCase().includes(s) || i.id.includes(s))) continue;
      out.push({ key: i.id, icon: i.icon, label: t(labelKeyFor(i, mode)), planned: !!i.planned, go: () => navigate(i.id) });
      if (out.length >= 10) break;
    }
    return out;
  }, [q, t, mode, navigate, openWith, analyzeFile]);

  const go = (r: (typeof results)[number]) => {
    r.go();
    setQ('');
    setOpen(false);
    ref.current?.blur();
  };

  return (
    <div className="search">
      <Search className="search-icon" size={16} />
      <input
        ref={ref}
        value={q}
        placeholder={t('topbar.search')}
        aria-label={t('topbar.search')}
        spellCheck={false}
        onChange={(e) => {
          setQ(e.target.value);
          setOpen(true);
          setIdx(0);
        }}
        onFocus={() => setOpen(true)}
        onBlur={() => setTimeout(() => setOpen(false), 150)}
        onKeyDown={(e) => {
          if (e.key === 'ArrowDown') setIdx((i) => Math.min(i + 1, results.length - 1));
          if (e.key === 'ArrowUp') setIdx((i) => Math.max(i - 1, 0));
          if (e.key === 'Enter' && results[idx]) go(results[idx]!);
          if (e.key === 'Escape') {
            setOpen(false);
            ref.current?.blur();
          }
        }}
      />
      {!q && <kbd className="search-kbd" aria-hidden>{t('topbar.shortcut')}</kbd>}
      {open && q.trim() && (
        <div className="search-results">
          {results.length === 0 && <div className="empty small">{t('topbar.searchEmpty')}</div>}
          {results.map((r, i) => {
            const Icon = r.icon;
            return (
              <button key={r.key} className={`${i === idx ? 'active' : ''}${r.value ? ' smart' : ''}`} onMouseDown={() => go(r)}>
                <Icon size={16} color="var(--primary)" />
                <span style={{ flex: 1, minWidth: 0 }}>
                  {r.label}
                  {r.value && <span className="search-value"><Ltr mono>{r.value}</Ltr></span>}
                </span>
                {r.hint && <span className="nav-soon">{r.hint}</span>}
                {r.planned && <span className="nav-soon">{t('nav.planned')}</span>}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

/**
 * Drop a file anywhere in the window to analyze it. Drops already handled by a page's own drop zone
 * (which call preventDefault) are left alone. Files are only read, never opened.
 */
function GlobalDrop() {
  const { t } = useI18n();
  const { analyzeFile, toast } = useApp();
  const [over, setOver] = useState(false);
  useEffect(() => {
    let depth = 0;
    const hasFiles = (e: DragEvent) => Array.from(e.dataTransfer?.types ?? []).includes('Files');
    const enter = (e: DragEvent) => {
      if (!hasFiles(e)) return;
      depth += 1;
      setOver(true);
    };
    const leave = (e: DragEvent) => {
      if (!hasFiles(e)) return;
      depth = Math.max(0, depth - 1);
      if (depth === 0) setOver(false);
    };
    const dragOver = (e: DragEvent) => {
      if (hasFiles(e)) e.preventDefault();
    };
    const drop = (e: DragEvent) => {
      depth = 0;
      setOver(false);
      if (!hasFiles(e) || e.defaultPrevented) return;
      e.preventDefault();
      const f = e.dataTransfer?.files?.[0];
      if (!f) return;
      const p = window.blazma.files.pathForFile(f);
      if (p) analyzeFile(p);
      else toast('red', t('errors.path_empty'));
    };
    window.addEventListener('dragenter', enter);
    window.addEventListener('dragleave', leave);
    window.addEventListener('dragover', dragOver);
    window.addEventListener('drop', drop);
    return () => {
      window.removeEventListener('dragenter', enter);
      window.removeEventListener('dragleave', leave);
      window.removeEventListener('dragover', dragOver);
      window.removeEventListener('drop', drop);
    };
  }, [analyzeFile, toast, t]);
  if (!over) return null;
  return (
    <div className="global-drop" aria-hidden="true">
      <div className="global-drop-label">{t('file.dropAnywhere')}</div>
    </div>
  );
}

export function Shell() {
  const { t, lang } = useI18n();
  const [version, setVersion] = useState<string | null>(null);
  useEffect(() => void window.blazma.app.info().then((i) => setVersion(i.version)), []);
  const { page, navigate, settings, updateSettings, viewSeq } = useApp();

  return (
    <>
      <div className="app-bg" />
      <GlobalDrop />
      <DownloadsOpenListener />
      <div className="shell">
        <header className="topbar">
          <div className="brand">
            <Logo />
            <div>
              <div className="brand-name">{t('app.name')}</div>
              <div className="brand-tag">{t('app.tagline')}</div>
            </div>
          </div>
          <TopSearch />
          <div className="topbar-actions">
            <div className="lang-switch no-drag" role="group" aria-label={t('topbar.language')}>
              <button className={lang === 'ar' ? 'active' : ''} onClick={() => void updateSettings({ language: 'ar' })}>
                العربية
              </button>
              <button className={lang === 'en' ? 'active' : ''} onClick={() => void updateSettings({ language: 'en' })}>
                English
              </button>
            </div>
            <button className="icon-btn" title={t('topbar.settings')} aria-label={t('topbar.settings')} onClick={() => navigate('settings-appearance')}>
              <SettingsIcon size={18} />
            </button>
            <button
              className={`mode-pill ${settings.offlineMode ? 'local' : 'online'}`}
              title={t(settings.offlineMode ? 'topbar.localOnlyTooltip' : 'topbar.onlineTooltip')}
              onClick={() => navigate('privacy')}
            >
              <span className="dot" />
              {t(settings.offlineMode ? 'topbar.localOnly' : 'topbar.online')}
            </button>
          </div>
        </header>

        <aside className="sidebar">
          <nav aria-label="Main">
            {visibleNav(settings.uiMode).map((section, si) => (
              <div key={si}>
                {section.titleKey && <div className="nav-section">{t(section.titleKey)}</div>}
                {section.items.map((item) => {
                  const Icon = item.icon;
                  return (
                    <button
                      key={item.id}
                      className={`nav-item ${page === item.id ? 'active' : ''} ${item.planned ? 'planned' : ''}`}
                      title={item.planned ? t('nav.plannedTooltip', { phase: item.planned.phase }) : item.external ? t('nav.externalTooltip') : undefined}
                      aria-current={page === item.id ? 'page' : undefined}
                      onClick={() => navigate(item.id)}
                    >
                      <Icon size={17} strokeWidth={1.8} />
                      <span className="nav-label">{t(labelKeyFor(item, settings.uiMode))}</span>
                      {item.planned && <span className="nav-soon">{t('nav.planned')}</span>}
                      {item.external && <ExternalLink size={13} className="nav-external" aria-hidden="true" />}
                    </button>
                  );
                })}
              </div>
            ))}
          </nav>
          <div className="sidebar-footer">
            <button
              className="btn sm mode-switch"
              onClick={() => {
                const next = settings.uiMode === 'simple' ? 'expert' : 'simple';
                void updateSettings({ uiMode: next });
                // Leaving expert mode on a page that simple mode hides → back to the dashboard.
                if (next === 'simple' && !visibleNav('simple').some((s) => s.items.some((i) => i.id === page))) navigate('dashboard');
              }}
            >
              {t(settings.uiMode === 'simple' ? 'mode.switchToExpert' : 'mode.switchToSimple')}
            </button>
            <div>
              <span className="ltr">Blazma Cyber{version && ` v${version}`}</span>
            </div>
            <div>{t('app.byline', { author: APP_AUTHOR })}</div>
            <div>{t('app.footer')}</div>
          </div>
        </aside>

        <main className="main">
          <Suspense fallback={<div className="page" aria-busy="true"><Skeleton w={260} h={28} /></div>}>
            <Page key={`${page}:${viewSeq}`} id={page} />
          </Suspense>
        </main>
      </div>
    </>
  );
}
