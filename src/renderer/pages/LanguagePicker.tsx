import { useState } from 'react';
import { Languages } from 'lucide-react';
import type { Lang } from '../../core/i18n';
import { Logo } from '../components/Logo';
import { translatorFor } from '../i18n/I18nProvider';

/** First launch: bilingual by design, since no language has been chosen yet. */
export function LanguagePicker({ onPick }: { onPick: (l: Lang) => void }) {
  const [sel, setSel] = useState<Lang>('ar');
  const ar = translatorFor('ar');
  const en = translatorFor('en');
  const t = sel === 'ar' ? ar : en;
  return (
    <>
      <div className="app-bg" />
      <div className="picker" dir={sel === 'ar' ? 'rtl' : 'ltr'}>
        <div className="card picker-card">
          <Logo size={72} className="brand-logo" />
          <div className="brand-name" style={{ fontSize: 26, marginTop: 14 }}>BLAZMA CYBER</div>
          <div className="brand-tag" style={{ marginTop: 4 }}>{t('app.tagline')}</div>
          <h1 style={{ marginTop: 26, fontSize: 22, display: 'flex', gap: 10, justifyContent: 'center', alignItems: 'center' }}>
            <Languages size={22} color="var(--cyan)" />
            <span>{ar('langPicker.title')}</span>
            <span className="dim">|</span>
            <span>{en('langPicker.title')}</span>
          </h1>
          <div className="picker-options">
            <button className={`lang-option ${sel === 'ar' ? 'selected' : ''}`} onClick={() => setSel('ar')} dir="rtl">
              <div className="lang-name">{ar('langPicker.arabic')}</div>
              <div className="muted small">{ar('langPicker.arabicHint')}</div>
            </button>
            <button className={`lang-option ${sel === 'en' ? 'selected' : ''}`} onClick={() => setSel('en')} dir="ltr">
              <div className="lang-name">{en('langPicker.english')}</div>
              <div className="muted small">{en('langPicker.englishHint')}</div>
            </button>
          </div>
          <button className="btn primary" style={{ marginTop: 24, minWidth: 180 }} onClick={() => onPick(sel)}>
            {t('langPicker.continue')}
          </button>
          <p className="dim small" style={{ marginTop: 18, marginBottom: 0 }}>{t('langPicker.privacyNote')}</p>
          <p className="dim tiny" style={{ margin: 0 }}>{t('langPicker.subtitle')}</p>
        </div>
      </div>
    </>
  );
}
