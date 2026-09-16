import { useEffect, useState, type CSSProperties } from 'react';
import { useTranslation } from 'react-i18next';
import {
  identityFromMnemonic,
  isValidMnemonic,
  normalizeMnemonic,
} from '../crypto/mnemonic';
import {
  ACCOUNT_PIN_MAX,
  ACCOUNT_PIN_MIN,
  deriveVaultKey,
  isValidAccountPin,
  normalizeAccountPin,
} from '../crypto/vault';
import { ensureSodium, type IdentityKeyPair } from '../crypto/identity';
import {
  destroyAllUserData,
  hasExistingVault,
  loadEncryptedIdentity,
  loadVaultSalt,
  purgeInconsistentVault,
  saveMnemonicVault,
  clearLocalDataStores,
} from '../storage/db';
import { clearTabSession } from '../session/tabSession';
import { LanguageSelector } from './LanguageSelector';
import { CreateAccountModal } from './CreateAccountModal';

export type AuthUnlockResult = {
  sessionId: string;
  keyPair: IdentityKeyPair;
  vaultKey: Uint8Array;
};

type AuthStep =
  | 'probe'
  | 'welcome'
  | 'restore'
  | 'set-pin'
  | 'unlock'
  | 'forgot';

interface AuthLockPanelProps {
  onUnlocked: (result: AuthUnlockResult) => void | Promise<void>;
}

export function AuthLockPanel({ onUnlocked }: AuthLockPanelProps) {
  const { t } = useTranslation();
  const [step, setStep] = useState<AuthStep>('probe');
  const [hasVault, setHasVault] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pin, setPin] = useState('');
  const [pinConfirm, setPinConfirm] = useState('');
  const [mnemonicDraft, setMnemonicDraft] = useState('');
  const [pendingMnemonic, setPendingMnemonic] = useState<string | null>(null);
  const [showCreateWizard, setShowCreateWizard] = useState(false);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        await purgeInconsistentVault();
        const exists = await hasExistingVault();
        if (cancelled) {
          return;
        }
        setHasVault(exists);
        if (exists) {
          setStep('unlock');
          setShowCreateWizard(false);
        } else {
          // Empty / legacy / corrupt storage → landing only (never auto-open create).
          setStep('welcome');
          setShowCreateWizard(false);
        }
      } catch {
        if (!cancelled) {
          setHasVault(false);
          setStep('welcome');
          setShowCreateWizard(false);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  function clearPins(): void {
    setPin('');
    setPinConfirm('');
  }

  function clearAuthError(): void {
    if (error) {
      setError(null);
    }
  }

  async function finishUnlock(
    vaultKey: Uint8Array,
    identity: { sessionId: string; keyPair: IdentityKeyPair },
  ): Promise<void> {
    clearPins();
    setPendingMnemonic(null);
    setMnemonicDraft('');
    setShowCreateWizard(false);
    setHasVault(true);
    await onUnlocked({
      sessionId: identity.sessionId,
      keyPair: identity.keyPair,
      vaultKey,
    });
  }

  async function sealAndEnter(mnemonic: string, accountPin: string): Promise<void> {
    const s = await ensureSodium();
    const salt = s.randombytes_buf(s.crypto_pwhash_SALTBYTES);
    const vaultKey = await deriveVaultKey(accountPin, salt);
    try {
      const identity = await identityFromMnemonic(mnemonic);
      await clearLocalDataStores();
      await saveMnemonicVault(mnemonic, vaultKey, salt, identity);
      await finishUnlock(vaultKey, identity);
    } catch (err) {
      s.memzero(vaultKey);
      throw err;
    }
  }

  async function handleRestoreSubmit(): Promise<void> {
    setError(null);
    const phrase = normalizeMnemonic(mnemonicDraft);
    if (!isValidMnemonic(phrase)) {
      setError(t('auth.mnemonicInvalid'));
      return;
    }
    setPendingMnemonic(phrase);
    clearPins();
    setStep('set-pin');
  }

  async function handleSetPin(): Promise<void> {
    const a = normalizeAccountPin(pin);
    const b = normalizeAccountPin(pinConfirm);
    if (!isValidAccountPin(a)) {
      setError(t('auth.pinCreateHint'));
      return;
    }
    if (a !== b) {
      setError(t('auth.pinMismatch'));
      return;
    }
    if (!pendingMnemonic) {
      setError(t('auth.mnemonicMissing'));
      return;
    }

    setBusy(true);
    setError(null);
    try {
      await sealAndEnter(pendingMnemonic, a);
    } catch (err) {
      const message =
        err instanceof Error ? err.message : t('auth.sessionPrepareFail');
      setError(t('auth.errorPrefix', { message }));
    } finally {
      setBusy(false);
    }
  }

  async function handleUnlockPin(): Promise<void> {
    const accountPin = normalizeAccountPin(pin);
    if (!isValidAccountPin(accountPin)) {
      setError(t('auth.pinRequired'));
      return;
    }

    setBusy(true);
    setError(null);
    try {
      const s = await ensureSodium();
      await purgeInconsistentVault();
      const stillValid = await hasExistingVault();
      if (!stillValid) {
        setHasVault(false);
        setStep('welcome');
        setShowCreateWizard(false);
        setError(t('auth.vaultCorrupt'));
        return;
      }

      const salt = await loadVaultSalt();
      if (
        !salt ||
        !(salt instanceof Uint8Array) ||
        salt.length !== s.crypto_pwhash_SALTBYTES
      ) {
        setHasVault(false);
        setError(t('auth.vaultCorrupt'));
        setStep('welcome');
        setShowCreateWizard(false);
        return;
      }

      const vaultKey = await deriveVaultKey(accountPin, salt);
      const identity = await loadEncryptedIdentity(vaultKey);
      if (!identity) {
        s.memzero(vaultKey);
        setError(t('auth.pinIncorrect'));
        return;
      }
      clearPins();
      await finishUnlock(vaultKey, identity);
    } catch (err) {
      const message =
        err instanceof Error ? err.message : t('auth.sessionPrepareFail');
      setError(t('auth.errorPrefix', { message }));
    } finally {
      setBusy(false);
    }
  }

  async function handleForgotRestore(): Promise<void> {
    const phrase = normalizeMnemonic(mnemonicDraft);
    const accountPin = normalizeAccountPin(pin);
    const confirm = normalizeAccountPin(pinConfirm);
    if (!isValidMnemonic(phrase)) {
      setError(t('auth.mnemonicInvalid'));
      return;
    }
    if (!isValidAccountPin(accountPin)) {
      setError(t('auth.pinCreateHint'));
      return;
    }
    if (accountPin !== confirm) {
      setError(t('auth.pinMismatch'));
      return;
    }

    setBusy(true);
    setError(null);
    try {
      await sealAndEnter(phrase, accountPin);
    } catch (err) {
      const message =
        err instanceof Error ? err.message : t('auth.sessionPrepareFail');
      setError(t('auth.errorPrefix', { message }));
    } finally {
      setBusy(false);
    }
  }

  async function handleWipeAndCreateNew(): Promise<void> {
    setBusy(true);
    setError(null);
    try {
      clearTabSession();
      await destroyAllUserData();
      clearPins();
      setMnemonicDraft('');
      setPendingMnemonic(null);
      setHasVault(false);
      setStep('welcome');
      setShowCreateWizard(true);
    } catch (err) {
      const message =
        err instanceof Error ? err.message : t('auth.sessionPrepareFail');
      setError(t('auth.errorPrefix', { message }));
    } finally {
      setBusy(false);
    }
  }

  const pinInputStyle = {
    WebkitTextSecurity: 'disc',
    textSecurity: 'disc',
  } as CSSProperties;

  function renderPinField(
    value: string,
    onChange: (next: string) => void,
    opts: { id: string; label: string; autoFocus?: boolean },
  ) {
    return (
      <>
        <label className="auth-label" htmlFor={opts.id}>
          {opts.label}
        </label>
        <input
          id={opts.id}
          name={opts.id}
          type="tel"
          inputMode="numeric"
          maxLength={ACCOUNT_PIN_MAX}
          autoComplete="off"
          autoCorrect="off"
          autoCapitalize="off"
          spellCheck={false}
          data-form-type="other"
          data-lpignore="true"
          value={value}
          onChange={(e) => {
            const next = e.target.value;
            if (!/^\d*$/.test(next) || next.length > ACCOUNT_PIN_MAX) {
              return;
            }
            onChange(next);
            clearAuthError();
          }}
          placeholder={t('auth.pinPlaceholder')}
          disabled={busy}
          autoFocus={opts.autoFocus}
          aria-label={opts.label}
          className={error ? 'lock-seed-input pin-invalid' : 'lock-seed-input'}
          style={pinInputStyle}
        />
      </>
    );
  }

  return (
    <div className="app shell-locked">
      <div className="atmosphere" aria-hidden="true" />
      <main className="lock-panel">
        <p className="brand">{t('auth.brand')}</p>
        <h1>{t('auth.title')}</h1>
        <LanguageSelector />

        {step === 'probe' && (
          <p className="share-status" aria-live="polite">
            {t('auth.restoring')}
          </p>
        )}

        {step === 'welcome' && (
          <div className="auth-actions">
            <button
              type="button"
              disabled={busy}
              onClick={() => {
                setError(null);
                setShowCreateWizard(true);
              }}
            >
              {t('auth.createIdentity')}
            </button>
            <button
              type="button"
              className="ghost"
              disabled={busy}
              onClick={() => {
                setError(null);
                setMnemonicDraft('');
                setShowCreateWizard(false);
                setStep('restore');
              }}
            >
              {t('auth.restoreIdentity')}
            </button>
          </div>
        )}

        {step === 'restore' && (
          <div className="auth-restore-block">
            <p className="share-status">{t('auth.enterMnemonic')}</p>
            <textarea
              className="mnemonic-input"
              rows={3}
              value={mnemonicDraft}
              spellCheck={false}
              autoCapitalize="off"
              autoCorrect="off"
              disabled={busy}
              placeholder={t('auth.mnemonicPlaceholder')}
              onChange={(e) => {
                setMnemonicDraft(e.target.value);
                clearAuthError();
              }}
            />
            <button
              type="button"
              disabled={busy}
              onClick={() => void handleRestoreSubmit()}
            >
              {t('auth.continue')}
            </button>
            <button
              type="button"
              className="ghost"
              disabled={busy}
              onClick={() => {
                setError(null);
                setStep(hasVault ? 'unlock' : 'welcome');
              }}
            >
              {t('auth.back')}
            </button>
          </div>
        )}

        {step === 'set-pin' && (
          <div className="lock-form auth-set-pin">
            <p className="share-status">{t('auth.createPinTitle')}</p>
            {renderPinField(pin, setPin, {
              id: 'create_pin',
              label: t('auth.pinLabel'),
              autoFocus: true,
            })}
            {renderPinField(pinConfirm, setPinConfirm, {
              id: 'create_pin_confirm',
              label: t('auth.confirmPinLabel'),
            })}
            <button
              type="button"
              disabled={
                busy ||
                pin.length < ACCOUNT_PIN_MIN ||
                pinConfirm.length < ACCOUNT_PIN_MIN
              }
              onClick={() => void handleSetPin()}
            >
              {busy ? t('auth.busy') : t('auth.enter')}
            </button>
            <button
              type="button"
              className="ghost"
              disabled={busy}
              onClick={() => {
                setError(null);
                clearPins();
                setStep(hasVault ? 'forgot' : 'restore');
              }}
            >
              {t('auth.back')}
            </button>
          </div>
        )}

        {step === 'unlock' && hasVault && (
          <div className="lock-form" data-access="unlock">
            <p className="share-status">{t('auth.unlockPinTitle')}</p>
            {renderPinField(pin, setPin, {
              id: 'unlock_pin',
              label: t('auth.pinLabel'),
              autoFocus: true,
            })}
            <button
              type="button"
              disabled={busy || pin.length < ACCOUNT_PIN_MIN}
              onClick={() => void handleUnlockPin()}
            >
              {busy ? t('auth.busy') : t('auth.enter')}
            </button>
            <button
              type="button"
              className="ghost auth-forgot-link"
              disabled={busy}
              onClick={() => {
                setError(null);
                clearPins();
                setMnemonicDraft('');
                setStep('forgot');
              }}
            >
              {t('auth.forgotPin')}
            </button>
            <button
              type="button"
              className="ghost auth-wipe-link"
              disabled={busy}
              onClick={() => void handleWipeAndCreateNew()}
            >
              {t('auth.createFromScratch')}
            </button>
          </div>
        )}

        {step === 'forgot' && (
          <div className="auth-forgot-block">
            <p className="share-status">{t('auth.forgotPin')}</p>
            <textarea
              className="mnemonic-input"
              rows={3}
              value={mnemonicDraft}
              spellCheck={false}
              autoCapitalize="off"
              autoCorrect="off"
              disabled={busy}
              placeholder={t('auth.mnemonicPlaceholder')}
              onChange={(e) => {
                setMnemonicDraft(e.target.value);
                clearAuthError();
              }}
            />
            <p className="share-status">{t('auth.createPinTitle')}</p>
            {renderPinField(pin, setPin, {
              id: 'forgot_pin',
              label: t('auth.pinLabel'),
            })}
            {renderPinField(pinConfirm, setPinConfirm, {
              id: 'forgot_pin_confirm',
              label: t('auth.confirmPinLabel'),
            })}
            <button
              type="button"
              disabled={
                busy ||
                pin.length < ACCOUNT_PIN_MIN ||
                pinConfirm.length < ACCOUNT_PIN_MIN
              }
              onClick={() => void handleForgotRestore()}
            >
              {busy ? t('auth.busy') : t('auth.resetPin')}
            </button>
            <button
              type="button"
              className="ghost"
              disabled={busy}
              onClick={() => {
                setError(null);
                clearPins();
                setStep('unlock');
              }}
            >
              {t('auth.back')}
            </button>
          </div>
        )}

        {error && <p className="error">{error}</p>}
      </main>

      {showCreateWizard && (
        <CreateAccountModal
          onCancel={() => {
            setShowCreateWizard(false);
            setStep('welcome');
          }}
          onComplete={async (result) => {
            await finishUnlock(result.vaultKey, {
              sessionId: result.sessionId,
              keyPair: result.keyPair,
            });
          }}
        />
      )}
    </div>
  );
}
