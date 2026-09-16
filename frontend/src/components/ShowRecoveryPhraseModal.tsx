import { useEffect, useState, type CSSProperties } from 'react';
import { useTranslation } from 'react-i18next';
import {
  ACCOUNT_PIN_MAX,
  ACCOUNT_PIN_MIN,
  deriveVaultKey,
  isValidAccountPin,
  normalizeAccountPin,
} from '../crypto/vault';
import { ensureSodium } from '../crypto/identity';
import {
  loadSealedMnemonic,
  loadVaultSalt,
  vaultHasMnemonic,
} from '../storage/db';
import { IconX } from './ui/Icons';

interface ShowRecoveryPhraseModalProps {
  onClose: () => void;
}

export function ShowRecoveryPhraseModal({
  onClose,
}: ShowRecoveryPhraseModalProps) {
  const { t } = useTranslation();
  const [pin, setPin] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [phrase, setPhrase] = useState<string | null>(null);
  const [available, setAvailable] = useState<boolean | null>(null);

  useEffect(() => {
    let cancelled = false;
    void vaultHasMnemonic().then((has) => {
      if (!cancelled) {
        setAvailable(has);
      }
    });
    return () => {
      cancelled = true;
    };
  }, []);

  async function reveal(): Promise<void> {
    const accountPin = normalizeAccountPin(pin);
    if (!isValidAccountPin(accountPin)) {
      setError(t('auth.pinRequired'));
      return;
    }
    setBusy(true);
    setError(null);
    setPin('');
    try {
      const has = await vaultHasMnemonic();
      if (!has) {
        setError(t('auth.noMnemonicStored'));
        return;
      }
      const s = await ensureSodium();
      const salt = await loadVaultSalt();
      if (!salt || salt.length !== s.crypto_pwhash_SALTBYTES) {
        setError(t('auth.vaultCorrupt'));
        return;
      }
      const vaultKey = await deriveVaultKey(accountPin, salt);
      try {
        const mnemonic = await loadSealedMnemonic(vaultKey);
        if (!mnemonic) {
          setError(t('auth.pinIncorrect'));
          return;
        }
        setPhrase(mnemonic);
      } finally {
        s.memzero(vaultKey);
      }
    } catch (err) {
      setError(
        err instanceof Error ? err.message : t('auth.sessionPrepareFail'),
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <div
      className="share-modal-backdrop"
      role="presentation"
      onClick={onClose}
    >
      <div
        className="share-modal"
        role="dialog"
        aria-modal="true"
        aria-label={t('auth.showRecoveryPhrase')}
        onClick={(e) => e.stopPropagation()}
      >
        <header className="share-modal-head">
          <h2>{t('auth.showRecoveryPhrase')}</h2>
          <button
            type="button"
            className="icon-btn"
            aria-label={t('chat.close')}
            onClick={onClose}
          >
            <IconX size="sm" />
          </button>
        </header>

        {available === false && (
          <p className="share-status">{t('auth.noMnemonicStored')}</p>
        )}

        {!phrase && available !== false && (
          <div className="lock-form">
            <p className="share-status">{t('auth.confirmPinToView')}</p>
            <input
              type="tel"
              inputMode="numeric"
              maxLength={ACCOUNT_PIN_MAX}
              autoComplete="off"
              value={pin}
              disabled={busy}
              placeholder={t('auth.pinPlaceholder')}
              className={
                error ? 'lock-seed-input pin-invalid' : 'lock-seed-input'
              }
              style={
                {
                  WebkitTextSecurity: 'disc',
                  textSecurity: 'disc',
                } as CSSProperties
              }
              onChange={(e) => {
                const next = e.target.value;
                if (!/^\d*$/.test(next) || next.length > ACCOUNT_PIN_MAX) {
                  return;
                }
                setPin(next);
                if (error) {
                  setError(null);
                }
              }}
            />
            <button
              type="button"
              disabled={busy || pin.length < ACCOUNT_PIN_MIN}
              onClick={() => void reveal()}
            >
              {busy ? t('auth.busy') : t('auth.revealPhrase')}
            </button>
          </div>
        )}

        {phrase && (
          <div className="auth-mnemonic-block">
            <p className="share-status">{t('auth.writeDownMnemonic')}</p>
            <ol className="mnemonic-grid">
              {phrase.split(' ').map((word, index) => (
                <li key={`${word}-${index}`}>
                  <span className="mnemonic-index">{index + 1}.</span>
                  <span className="mnemonic-word">{word}</span>
                </li>
              ))}
            </ol>
            <button type="button" onClick={onClose}>
              {t('chat.close')}
            </button>
          </div>
        )}

        {error && <p className="error">{error}</p>}
      </div>
    </div>
  );
}
