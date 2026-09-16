import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  IconEye,
  IconEyeOff,
  IconLockExport,
  IconLockImport,
  IconX,
} from './ui/Icons';

interface PinVaultModalProps {
  mode: 'export' | 'import';
  busy?: boolean;
  error?: string | null;
  onCancel: () => void;
  onConfirm: (pin: string) => void | Promise<void>;
}

export function PinVaultModal({
  mode,
  busy = false,
  error = null,
  onCancel,
  onConfirm,
}: PinVaultModalProps) {
  const { t } = useTranslation();
  const [pin, setPin] = useState('');
  const [pinVisible, setPinVisible] = useState(false);

  async function handleSubmit(event?: {
    preventDefault(): void;
  }): Promise<void> {
    event?.preventDefault();
    const trimmed = pin.replace(/\D/g, '').slice(0, 6);
    if (trimmed.length !== 6) {
      return;
    }
    setPin('');
    setPinVisible(false);
    await onConfirm(trimmed);
  }

  const isExport = mode === 'export';

  return (
    <div
      className="share-modal-backdrop"
      role="presentation"
      onClick={onCancel}
    >
      <div
        className="share-modal"
        role="dialog"
        aria-modal="true"
        aria-label={
          isExport ? t('backup.exportTitle') : t('backup.importTitle')
        }
        onClick={(e) => e.stopPropagation()}
      >
        <header className="share-modal-head">
          <h2>
            {isExport ? (
              <IconLockExport size="sm" />
            ) : (
              <IconLockImport size="sm" />
            )}
            {isExport ? t('backup.exportShort') : t('backup.importShort')}
          </h2>
          <button
            type="button"
            className="icon-btn"
            aria-label={t('backup.close')}
            onClick={onCancel}
            disabled={busy}
          >
            <IconX size="sm" />
          </button>
        </header>

        <p className="share-status">
          {isExport ? t('backup.exportHint') : t('backup.importHint')}
        </p>

        <div className="lock-form">
          <label htmlFor="vault_token_seed">{t('backup.pinLabel')}</label>
          <div className="pin-input-wrap">
            <input
              id="vault_token_seed"
              name="vault_token_seed"
              type={pinVisible ? 'text' : 'password'}
              inputMode="numeric"
              maxLength={6}
              autoComplete="current-password"
              autoCorrect="off"
              autoCapitalize="off"
              spellCheck={false}
              data-form-type="other"
              data-lpignore="true"
              data-bwignore="true"
              data-1p-ignore="true"
              value={pin}
              onChange={(e) => {
                const next = e.target.value;
                if (!/^\d*$/.test(next) || next.length > 6) {
                  return;
                }
                setPin(next);
              }}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  void handleSubmit();
                }
              }}
              placeholder={t('auth.pinPlaceholder')}
              disabled={busy}
              autoFocus
            />
            <button
              type="button"
              className="pin-visibility-toggle"
              aria-label={pinVisible ? t('auth.hidePin') : t('auth.showPin')}
              aria-pressed={pinVisible}
              onClick={() => setPinVisible((v) => !v)}
              disabled={busy}
            >
              {pinVisible ? <IconEyeOff size="sm" /> : <IconEye size="sm" />}
            </button>
          </div>
          <button
            type="button"
            disabled={busy || pin.length !== 6}
            onClick={() => void handleSubmit()}
          >
            {busy
              ? t('auth.busy')
              : isExport
                ? t('backup.exportAction')
                : t('backup.importAction')}
          </button>
        </div>

        {error && <p className="error">{error}</p>}
      </div>
    </div>
  );
}
