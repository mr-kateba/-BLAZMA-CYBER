import { useMemo, useRef, useState } from 'react';
import { Search, Settings as SettingsIcon } from 'lucide-react';
import { Logo } from './components/Logo';
import { useApp } from './components/AppContext';
import { useI18n } from './i18n/I18nProvider';
import { ALL_ITEMS, NAV, findItem, type PageId } from './nav';
import { Dashboard } from './pages/Dashboard';
import { FileAnalyzer } from './pages/FileAnalyzer';
import { HashLab } from './pages/HashLab';
import { PrivacyCenter } from './pages/PrivacyCenter';
import { SettingsPage } from './pages/Settings';
import { PlannedModule } from './pages/PlannedModule';

function Page({ id }: { id: PageId }) {
  switch (id) {
    case 'dashboard':
      return <Dashboard />;
    case 'file-analyzer':
      return <FileAnalyzer />;
    case 'hash-lab':
      return <HashLab />;
    case 'privacy':
      return <PrivacyCenter />;
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
  const { navigate } = useApp();
  const [q, setQ] = useState('');
  const [open, setOpen] = useState(false);
  const [idx, setIdx] = useState(0);
  const ref = useRef<HTMLInputElement>(null);

  const results = useMemo(() => {
    const s = q.trim().toLowerCase();
    if (!s) return [];
    return ALL_ITEMS.filter((i) => t(i.labelKey).toLowerCase().includes(s) || i.id.includes(s)).slice(0, 8);
  }, [q, t]);

  const go = (id: PageId) => {
    navigate(id);
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
          if (e.key === 'Enter' && results[idx]) go(results[idx]!.id);
          if (e.key === 'Escape') setOpen(false);
        }}
      />
      {open && q.trim() && (
        <div className="search-results">
          {results.length === 0 && <div className="empty small">{t('topbar.searchEmpty')}</div>}
          {results.map((r, i) => {
            const Icon = r.icon;
            return (
              <button key={r.id} className={i === idx ? 'active' : ''} onMouseDown={() => go(r.id)}>
                <Icon size={16} color="var(--primary)" />
                <span style={{ flex: 1 }}>{t(r.labelKey)}</span>
                {r.planned && <span className="nav-soon">{t('nav.planned')}</span>}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

export function Shell() {
  const { t, lang } = useI18n();
  const { page, navigate, settings, updateSettings } = useApp();

  return (
    <>
      <div className="app-bg" />
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
            {NAV.map((section, si) => (
              <div key={si}>
                {section.titleKey && <div className="nav-section">{t(section.titleKey)}</div>}
                {section.items.map((item) => {
                  const Icon = item.icon;
                  return (
                    <button
                      key={item.id}
                      className={`nav-item ${page === item.id ? 'active' : ''} ${item.planned ? 'planned' : ''}`}
                      title={item.planned ? t('nav.plannedTooltip', { phase: item.planned.phase }) : undefined}
                      aria-current={page === item.id ? 'page' : undefined}
                      onClick={() => navigate(item.id)}
                    >
                      <Icon size={17} strokeWidth={1.8} />
                      <span className="nav-label">{t(item.labelKey)}</span>
                      {item.planned && <span className="nav-soon">{t('nav.planned')}</span>}
                    </button>
                  );
                })}
              </div>
            ))}
          </nav>
          <div className="sidebar-footer">
            <div>
              <span className="ltr">BLAZMA CYBER v0.1.0</span>
            </div>
            <div>{t('app.footer')}</div>
          </div>
        </aside>

        <main className="main">
          <Page key={page} id={page} />
        </main>
      </div>
    </>
  );
}
