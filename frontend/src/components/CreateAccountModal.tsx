import {
  useEffect,
  useRef,
  useState,
  type CSSProperties,
} from 'react';
import { useTranslation } from 'react-i18next';
import {
  createMnemonic,
  downloadRecoveryBackupFile,
  identityFromMnemonic,
  MNEMONIC_WORD_COUNT,
  normalizeMnemonic,
  shuffleWords,
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
  clearLocalDataStores,
  saveMnemonicVault,
} from '../storage/db';
import { scheduleClipboardClear } from '../crypto/clipboardGuard';
import { IconCopy, IconCheck, IconX } from './ui/Icons';

export type CreateAccountResult = {
  sessionId: string;
  keyPair: IdentityKeyPair;
  vaultKey: Uint8Array;
};

type WizardStep = 1 | 2 | 3 | 4;

interface CreateAccountModalProps {
  onCancel: () => void;
  onComplete: (result: CreateAccountResult) => void | Promise<void>;
}

interface PreparedIdentity {
  sessionId: string;
  keyPair: IdentityKeyPair;
}

export function CreateAccountModal({
  onCancel,
  onComplete,
}: CreateAccountModalProps) {
  const { t, i18n } = useTranslation();
  const [step, setStep] = useState<WizardStep>(1);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const mnemonicRef = useRef<string | null>(null);
  const [displayWords, setDisplayWords] = useState<string[] | null>(null);
  const [prepared, setPrepared] = useState<PreparedIdentity | null>(null);

  const [hasDownloaded, setHasDownloaded] = useState(false);
  const [confirmedSaved, setConfirmedSaved] = useState(false);

  const [shuffled, setShuffled] = useState<string[]>([]);
  const [picked, setPicked] = useState<string[]>([]);
  const [verifyMode, setVerifyMode] = useState<'chips' | 'type'>('chips');
  const [typedPhrase, setTypedPhrase] = useState('');

  const [pin, setPin] = useState('');
  const [pinConfirm, setPinConfirm] = useState('');

  const [unlockPayload, setUnlockPayload] = useState<CreateAccountResult | null>(
    null,
  );
  const [copied, setCopied] = useState(false);

  const isRtl = i18n.dir() === 'rtl';

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const phrase = createMnemonic();
        const identity = await identityFromMnemonic(phrase);
        if (cancelled) {
          return;
        }
        mnemonicRef.current = identity.mnemonic;
        setDisplayWords(identity.mnemonic.split(' '));
        setPrepared({
          sessionId: identity.sessionId,
          keyPair: identity.keyPair,
        });
      } catch (err) {
        if (!cancelled) {
          setError(
            err instanceof Error ? err.message : t('auth.sessionPrepareFail'),
          );
        }
      }
    })();
    return () => {
      cancelled = true;
      wipeMnemonicMemory();
    };
    // Intentional mount-only identity bootstrap.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function wipeMnemonicMemory(): void {
    mnemonicRef.current = null;
    setDisplayWords(null);
    setShuffled([]);
    setPicked([]);
    setTypedPhrase('');
  }

  const canAdvanceFromStep1 = hasDownloaded || confirmedSaved;

  function handleDownload(): void {
    const phrase = mnemonicRef.current;
    if (!phrase || !prepared) {
      setError(t('auth.mnemonicMissing'));
      return;
    }
    downloadRecoveryBackupFile(prepared.sessionId, phrase);
    setHasDownloaded(true);
    setError(null);
  }

  function goToVerification(): void {
    if (!canAdvanceFromStep1 || !mnemonicRef.current) {
      return;
    }
    const words = mnemonicRef.current.split(' ');
    setDisplayWords(null);
    setShuffled(shuffleWords(words));
    setPicked([]);
    setTypedPhrase('');
    setVerifyMode('chips');
    setError(null);
    setStep(2);
  }

  function pickChip(word: string, indexInPool: number): void {
    if (picked.length >= MNEMONIC_WORD_COUNT) {
      return;
    }
    setPicked((prev) => [...prev, word]);
    setShuffled((prev) => prev.filter((_, i) => i !== indexInPool));
    setError(null);
  }

  function undoLastPick(): void {
    setPicked((prev) => {
      if (prev.length === 0) {
        return prev;
      }
      const last = prev[prev.length - 1]!;
      setShuffled((pool) => [...pool, last]);
      return prev.slice(0, -1);
    });
    setError(null);
  }

  function resetVerification(): void {
    const phrase = mnemonicRef.current;
    if (!phrase) {
      return;
    }
    setShuffled(shuffleWords(phrase.split(' ')));
    setPicked([]);
    setTypedPhrase('');
    setError(null);
  }

  function handleVerifyContinue(): void {
    const expected = mnemonicRef.current;
    if (!expected) {
      setError(t('auth.mnemonicMissing'));
      return;
    }

    let candidate: string;
    if (verifyMode === 'chips') {
      if (picked.length !== MNEMONIC_WORD_COUNT) {
        setError(t('createAccount.verifyMismatchDetail'));
        return;
      }
      candidate = picked.join(' ');
    } else {
      candidate = normalizeMnemonic(typedPhrase);
    }

    if (candidate !== expected) {
      setError(t('createAccount.verifyMismatchDetail'));
      return;
    }

    setError(null);
    setPin('');
    setPinConfirm('');
    setStep(3);
  }

  async function handleSealPin(): Promise<void> {
    const accountPin = normalizeAccountPin(pin);
    const confirm = normalizeAccountPin(pinConfirm);
    const phrase = mnemonicRef.current;

    if (!isValidAccountPin(accountPin)) {
      setError(t('auth.pinCreateHint'));
      return;
    }
    if (accountPin !== confirm) {
      setError(t('auth.pinMismatch'));
      return;
    }
    if (!phrase || !prepared) {
      setError(t('auth.mnemonicMissing'));
      return;
    }

    setBusy(true);
    setError(null);
    const s = await ensureSodium();
    const salt = s.randombytes_buf(s.crypto_pwhash_SALTBYTES);
    const vaultKey = await deriveVaultKey(accountPin, salt);
    try {
      await clearLocalDataStores();
      await saveMnemonicVault(phrase, vaultKey, salt, prepared);
      wipeMnemonicMemory();
      setPin('');
      setPinConfirm('');
      setUnlockPayload({
        sessionId: prepared.sessionId,
        keyPair: prepared.keyPair,
        vaultKey,
      });
      setStep(4);
    } catch (err) {
      s.memzero(vaultKey);
      const message =
        err instanceof Error ? err.message : t('auth.sessionPrepareFail');
      setError(t('auth.errorPrefix', { message }));
    } finally {
      setBusy(false);
    }
  }

  async function handleEnterChat(): Promise<void> {
    if (!unlockPayload) {
      return;
    }
    setBusy(true);
    try {
      await onComplete(unlockPayload);
    } catch (err) {
      const message =
        err instanceof Error ? err.message : t('auth.sessionPrepareFail');
      setError(t('auth.errorPrefix', { message }));
      setBusy(false);
    }
  }

  async function copySessionId(): Promise<void> {
    if (!prepared?.sessionId) {
      return;
    }
    try {
      await navigator.clipboard.writeText(prepared.sessionId);
      scheduleClipboardClear();
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setError(t('errors.copySessionFail'));
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
          disabled={busy}
          autoFocus={opts.autoFocus}
          aria-label={opts.label}
          placeholder={t('auth.pinPlaceholder')}
          className={error ? 'lock-seed-input pin-invalid' : 'lock-seed-input'}
          style={pinInputStyle}
          onChange={(e) => {
            const next = e.target.value;
            if (!/^\d*$/.test(next) || next.length > ACCOUNT_PIN_MAX) {
              return;
            }
            onChange(next);
            if (error) {
              setError(null);
            }
          }}
        />
      </>
    );
  }

  return (
    <div
      className="share-modal-backdrop create-account-backdrop"
      role="presentation"
      onClick={step === 4 ? undefined : onCancel}
    >
      <div
        className="share-modal create-account-modal"
        role="dialog"
        aria-modal="true"
        aria-label={t('createAccount.title')}
        dir={isRtl ? 'rtl' : 'ltr'}
        onClick={(e) => e.stopPropagation()}
      >
        <header className="share-modal-head">
          <div className="create-account-head-text">
            <p className="create-account-step">
              {t('createAccount.stepOf', { current: step, total: 4 })}
            </p>
            <h2>{t('createAccount.title')}</h2>
          </div>
          {step < 4 && (
            <button
              type="button"
              className="icon-btn"
              aria-label={t('chat.close')}
              disabled={busy}
              onClick={onCancel}
            >
              <IconX size="sm" />
            </button>
          )}
        </header>

        <ol className="create-account-progress" aria-hidden="true">
          {[1, 2, 3, 4].map((n) => (
            <li
              key={n}
              className={
                n === step ? 'is-active' : n < step ? 'is-done' : undefined
              }
            />
          ))}
        </ol>

        {step === 1 && (
          <div className="create-account-step-body">
            <h3>{t('createAccount.oneTimeTitle')}</h3>
            <p className="create-account-critical" role="alert">
              {t('createAccount.oneTimeCritical')}
            </p>
            <p className="share-status">{t('createAccount.oneTimeHint')}</p>

            {displayWords && displayWords.length === MNEMONIC_WORD_COUNT ? (
              <ol className="mnemonic-grid mnemonic-grid-contrast">
                {displayWords.map((word, index) => (
                  <li key={`${index}-${word}`}>
                    <span className="mnemonic-index">{index + 1}.</span>
                    <span className="mnemonic-word">{word}</span>
                  </li>
                ))}
              </ol>
            ) : (
              <p className="share-status">{t('auth.busy')}</p>
            )}

            <button
              type="button"
              className="create-account-primary"
              disabled={busy || !prepared || !mnemonicRef.current}
              onClick={handleDownload}
            >
              {t('createAccount.downloadRecoveryKey')}
            </button>

            <label className="create-account-check">
              <input
                type="checkbox"
                checked={confirmedSaved}
                disabled={busy || !displayWords}
                onChange={(e) => {
                  setConfirmedSaved(e.target.checked);
                  setError(null);
                }}
              />
              <span>{t('createAccount.confirmSaved')}</span>
            </label>

            <button
              type="button"
              disabled={busy || !canAdvanceFromStep1}
              onClick={goToVerification}
            >
              {t('createAccount.advanceVerify')}
            </button>
          </div>
        )}

        {step === 2 && (
          <div className="create-account-step-body">
            <h3>{t('createAccount.confirmTitle')}</h3>
            <p className="share-status">{t('createAccount.confirmHint')}</p>

            <div className="create-account-mode-toggle">
              <button
                type="button"
                className={verifyMode === 'chips' ? undefined : 'ghost'}
                disabled={busy}
                onClick={() => {
                  setVerifyMode('chips');
                  resetVerification();
                }}
              >
                {t('createAccount.modeChips')}
              </button>
              <button
                type="button"
                className={verifyMode === 'type' ? undefined : 'ghost'}
                disabled={busy}
                onClick={() => {
                  setVerifyMode('type');
                  setError(null);
                }}
              >
                {t('createAccount.modeType')}
              </button>
            </div>

            {verifyMode === 'chips' ? (
              <>
                <ol className="mnemonic-slots">
                  {Array.from({ length: MNEMONIC_WORD_COUNT }, (_, i) => (
                    <li key={i} className={picked[i] ? 'is-filled' : undefined}>
                      <span className="mnemonic-index">{i + 1}.</span>
                      <span className="mnemonic-word">
                        {picked[i] ?? '—'}
                      </span>
                    </li>
                  ))}
                </ol>
                <div className="mnemonic-chip-pool">
                  {shuffled.map((word, index) => (
                    <button
                      key={`${word}-${index}`}
                      type="button"
                      className="mnemonic-chip"
                      disabled={busy}
                      onClick={() => pickChip(word, index)}
                    >
                      {word}
                    </button>
                  ))}
                </div>
                <div className="create-account-row">
                  <button
                    type="button"
                    className="ghost"
                    disabled={busy || picked.length === 0}
                    onClick={undoLastPick}
                  >
                    {t('createAccount.undoWord')}
                  </button>
                  <button
                    type="button"
                    className="ghost"
                    disabled={busy}
                    onClick={resetVerification}
                  >
                    {t('createAccount.resetWords')}
                  </button>
                </div>
              </>
            ) : (
              <textarea
                className="mnemonic-input"
                rows={3}
                value={typedPhrase}
                spellCheck={false}
                autoCapitalize="off"
                autoCorrect="off"
                disabled={busy}
                placeholder={t('auth.mnemonicPlaceholder')}
                onChange={(e) => {
                  setTypedPhrase(e.target.value);
                  if (error) {
                    setError(null);
                  }
                }}
              />
            )}

            <button
              type="button"
              disabled={
                busy ||
                (verifyMode === 'chips'
                  ? picked.length !== MNEMONIC_WORD_COUNT
                  : typedPhrase.trim().length === 0)
              }
              onClick={handleVerifyContinue}
            >
              {t('auth.continue')}
            </button>
          </div>
        )}

        {step === 3 && (
          <div className="create-account-step-body auth-set-pin">
            <h3>{t('createAccount.setPinTitle')}</h3>
            <p className="share-status">{t('createAccount.setPinHint')}</p>
            {renderPinField(pin, setPin, {
              id: 'create_account_pin',
              label: t('auth.pinLabel'),
              autoFocus: true,
            })}
            {renderPinField(pinConfirm, setPinConfirm, {
              id: 'create_account_pin_confirm',
              label: t('auth.confirmPinLabel'),
            })}
            <button
              type="button"
              disabled={
                busy ||
                pin.length < ACCOUNT_PIN_MIN ||
                pinConfirm.length < ACCOUNT_PIN_MIN
              }
              onClick={() => void handleSealPin()}
            >
              {busy ? t('auth.busy') : t('auth.continue')}
            </button>
          </div>
        )}

        {step === 4 && prepared && (
          <div className="create-account-step-body create-account-done">
            <h3>{t('createAccount.successTitle')}</h3>
            <p className="share-status">{t('createAccount.successHint')}</p>
            <div className="create-account-session-id">
              <code dir="ltr">{prepared.sessionId}</code>
              <button
                type="button"
                className="icon-btn"
                title={t('sidebar.copySessionId')}
                aria-label={t('sidebar.copySessionId')}
                onClick={() => void copySessionId()}
              >
                {copied ? <IconCheck size="sm" /> : <IconCopy size="sm" />}
              </button>
            </div>
            <button
              type="button"
              className="create-account-primary"
              disabled={busy || !unlockPayload}
              onClick={() => void handleEnterChat()}
            >
              {busy ? t('auth.busy') : t('createAccount.enterChat')}
            </button>
          </div>
        )}

        {error && <p className="error">{error}</p>}
      </div>
    </div>
  );
}
