import { useEffect, useState } from 'react';
import type { Settings } from '../shared/api';
import type { Lang } from '../core/i18n';
import { I18nProvider } from './i18n/I18nProvider';
import { AppProvider } from './components/AppContext';
import { LanguagePicker } from './pages/LanguagePicker';
import { Shell } from './Shell';
import type { PageId } from './nav';

const START: Record<Settings['startPage'], PageId> = {
  dashboard: 'dashboard',
  'file-analyzer': 'file-analyzer',
  'hash-lab': 'hash-lab',
  privacy: 'privacy',
};

export function App() {
  const [settings, setSettings] = useState<Settings | null>(null);

  useEffect(() => {
    void window.blazma.settings.get().then(setSettings);
  }, []);

  useEffect(() => {
    if (settings) document.documentElement.dataset.theme = settings.theme;
  }, [settings?.theme]);

  if (!settings) return <div className="app-bg" />;

  if (!settings.language) {
    return (
      <LanguagePicker
        onPick={async (lang: Lang) => {
          const r = await window.blazma.settings.update({ language: lang, reportLanguage: lang });
          if (r.ok) setSettings(r.data);
        }}
      />
    );
  }

  return (
    <I18nProvider lang={settings.language}>
      <AppProvider settings={settings} setSettings={setSettings} initialPage={START[settings.startPage]}>
        <Shell />
      </AppProvider>
    </I18nProvider>
  );
}
