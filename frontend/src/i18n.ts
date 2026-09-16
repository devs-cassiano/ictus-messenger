import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import LanguageDetector from 'i18next-browser-languagedetector';

import ar from './locales/ar.json';
import en from './locales/en.json';
import es from './locales/es.json';
import pt from './locales/pt.json';

export const SUPPORTED_LANGS = ['en', 'pt', 'es', 'ar'] as const;
export type SupportedLang = (typeof SUPPORTED_LANGS)[number];

export function updateHtmlDirection(lang: string): void {
  const base = lang.split('-')[0] ?? lang;
  const isRtl = base === 'ar';
  document.documentElement.dir = isRtl ? 'rtl' : 'ltr';
  document.documentElement.lang = base;
}

void i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources: {
      en: { translation: en },
      pt: { translation: pt },
      es: { translation: es },
      ar: { translation: ar },
    },
    fallbackLng: 'en',
    supportedLngs: [...SUPPORTED_LANGS],
    nonExplicitSupportedLngs: true,
    interpolation: { escapeValue: false },
    detection: {
      order: ['localStorage', 'navigator'],
      lookupLocalStorage: 'ictus.lang',
      caches: ['localStorage'],
    },
  });

updateHtmlDirection(i18n.language || 'en');
i18n.on('languageChanged', updateHtmlDirection);

export default i18n;
