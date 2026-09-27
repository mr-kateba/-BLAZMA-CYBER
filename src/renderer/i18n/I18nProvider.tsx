import { createContext, useContext, useLayoutEffect, useMemo, type ReactNode } from 'react';
import en from '@locales/en.json';
import ar from '@locales/ar.json';
import { createTranslator, directionOf, type Dict, type Dir, type Lang, type Vars } from '../../core/i18n';

interface I18n {
  lang: Lang;
  dir: Dir;
  t: (key: string, vars?: Vars) => string;
  /** Intl locale: Arabic keeps Latin digits, which are more readable for technical values. */
  locale: string;
}

const Ctx = createContext<I18n | null>(null);
const DICTS: Record<Lang, Dict> = { en: en as Dict, ar: ar as Dict };

export function I18nProvider({ lang, children }: { lang: Lang; children: ReactNode }) {
  const value = useMemo<I18n>(
    () => ({
      lang,
      dir: directionOf(lang),
      t: createTranslator(DICTS[lang], DICTS.en),
      locale: lang === 'ar' ? 'ar-u-nu-latn' : 'en-GB',
    }),
    [lang],
  );

  // Direction is applied at the document root so every component (and native controls) follows it.
  useLayoutEffect(() => {
    document.documentElement.lang = lang;
    document.documentElement.dir = value.dir;
  }, [lang, value.dir]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useI18n(): I18n {
  const v = useContext(Ctx);
  if (!v) throw new Error('useI18n outside provider');
  return v;
}

/** Standalone translator for screens rendered before a language is chosen. */
export function translatorFor(lang: Lang) {
  return createTranslator(DICTS[lang], DICTS.en);
}
