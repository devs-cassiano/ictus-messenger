import { useEffect, useId, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { SUPPORTED_LANGS, type SupportedLang } from '../i18n';
import { IconGlobe } from './ui/Icons';

const STORAGE_KEY = 'ictus.lang';

const LANGUAGES: ReadonlyArray<{ code: SupportedLang; label: string }> = [
  { code: 'pt', label: 'PT' },
  { code: 'en', label: 'EN' },
  { code: 'es', label: 'ES' },
  { code: 'ar', label: 'عربي' },
];

function resolveLang(raw: string | undefined): SupportedLang {
  const base = (raw ?? 'en').split('-')[0] as SupportedLang;
  return SUPPORTED_LANGS.includes(base) ? base : 'en';
}

function labelFor(code: SupportedLang): string {
  return LANGUAGES.find((entry) => entry.code === code)?.label ?? 'EN';
}

export function LanguageSelector() {
  const { t, i18n } = useTranslation();
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement | null>(null);
  const menuId = useId();
  const current = resolveLang(i18n.resolvedLanguage ?? i18n.language);
  const currentLabel = labelFor(current);
  const currentIsArabic = current === 'ar';

  useEffect(() => {
    if (!open) {
      return;
    }

    function onPointerDown(event: MouseEvent | TouchEvent): void {
      const root = rootRef.current;
      if (!root) {
        return;
      }
      const target = event.target;
      if (target instanceof Node && !root.contains(target)) {
        setOpen(false);
      }
    }

    function onKeyDown(event: KeyboardEvent): void {
      if (event.key === 'Escape') {
        setOpen(false);
      }
    }

    document.addEventListener('mousedown', onPointerDown);
    document.addEventListener('touchstart', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('mousedown', onPointerDown);
      document.removeEventListener('touchstart', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [open]);

  function selectLang(lang: SupportedLang): void {
    void i18n.changeLanguage(lang);
    try {
      localStorage.setItem(STORAGE_KEY, lang);
    } catch {
      // ignore quota / private mode
    }
    setOpen(false);
  }

  return (
    <div className="language-selector" ref={rootRef}>
      <button
        type="button"
        className={`icon-btn language-trigger${open ? ' active' : ''}`}
        aria-label={t('settings.languageAria')}
        title={t('settings.language')}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={menuId}
        onClick={() => setOpen((value) => !value)}
      >
        <IconGlobe size="nav" />
        <span
          className={`language-code${currentIsArabic ? ' is-arabic' : ''}`}
          lang={currentIsArabic ? 'ar' : undefined}
          dir={currentIsArabic ? 'rtl' : undefined}
          aria-hidden="true"
        >
          {currentLabel}
        </span>
      </button>

      {open && (
        <div
          id={menuId}
          className="language-popover"
          role="menu"
          aria-label={t('settings.language')}
        >
          {LANGUAGES.map(({ code, label }) => {
            const active = code === current;
            const isArabic = code === 'ar';
            return (
              <button
                key={code}
                type="button"
                role="menuitemradio"
                aria-checked={active}
                className={`language-option${active ? ' active' : ''}${
                  isArabic ? ' is-arabic' : ''
                }`}
                lang={isArabic ? 'ar' : undefined}
                dir={isArabic ? 'rtl' : undefined}
                title={t(`langs.${code}`)}
                onClick={() => selectLang(code)}
              >
                {label}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
