import { useEffect, useRef, useState, type ChangeEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { Html5Qrcode } from 'html5-qrcode';
import { extractSessionId } from '../crypto/identity';
import { IconCamera, IconUpload, IconX } from './ui/Icons';

const SCANNER_ELEMENT_ID = 'session-qr-reader';

interface QrScannerModalProps {
  onClose: () => void;
  onDetected: (sessionId: string) => void;
}

export function QrScannerModal({ onClose, onDetected }: QrScannerModalProps) {
  const { t } = useTranslation();
  const scannerRef = useRef<Html5Qrcode | null>(null);
  const runningRef = useRef(false);
  const handledRef = useRef(false);
  const onDetectedRef = useRef(onDetected);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [status, setStatus] = useState(() => t('scanner.starting'));
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    onDetectedRef.current = onDetected;
  }, [onDetected]);

  async function stopScanner(): Promise<void> {
    const scanner = scannerRef.current;
    if (!scanner) {
      return;
    }
    try {
      if (runningRef.current) {
        await scanner.stop();
        runningRef.current = false;
      }
    } catch {
      // already stopped
    }
    try {
      scanner.clear();
    } catch {
      // ignore
    }
  }

  useEffect(() => {
    handledRef.current = false;
    setStatus(t('scanner.starting'));
    const scanner = new Html5Qrcode(SCANNER_ELEMENT_ID, {
      verbose: false,
    });
    scannerRef.current = scanner;
    let cancelled = false;

    void (async () => {
      try {
        await scanner.start(
          { facingMode: 'environment' },
          { fps: 8, qrbox: { width: 220, height: 220 } },
          (decoded) => {
            if (handledRef.current || cancelled) {
              return;
            }
            const sessionId = extractSessionId(decoded);
            if (!sessionId) {
              setError(t('scanner.invalidQr'));
              return;
            }
            handledRef.current = true;
            void (async () => {
              await stopScanner();
              onDetectedRef.current(sessionId);
            })();
          },
          () => {
            // frame miss — ignore
          },
        );
        if (cancelled) {
          await stopScanner();
          return;
        }
        runningRef.current = true;
        setStatus(t('scanner.point'));
        setError(null);
      } catch {
        if (!cancelled) {
          setStatus(t('scanner.cameraUnavailable'));
          setError(null);
        }
      }
    })();

    return () => {
      cancelled = true;
      void stopScanner().finally(() => {
        scannerRef.current = null;
      });
    };
    // Camera lifecycle is mount-only; status strings use t from first render.
  }, []);

  async function handleFilePicked(
    event: ChangeEvent<HTMLInputElement>,
  ): Promise<void> {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file) {
      return;
    }

    setError(null);
    setStatus(t('scanner.reading'));

    try {
      await stopScanner();
      const scanner =
        scannerRef.current ??
        new Html5Qrcode(SCANNER_ELEMENT_ID, { verbose: false });
      scannerRef.current = scanner;

      const decoded = await scanner.scanFile(file, false);
      const sessionId = extractSessionId(decoded);
      if (!sessionId) {
        setError(t('scanner.invalidImage'));
        setStatus(t('scanner.tryAnother'));
        return;
      }
      handledRef.current = true;
      onDetected(sessionId);
    } catch {
      setError(t('scanner.readFail'));
      setStatus(t('scanner.tryAnother'));
    }
  }

  return (
    <div
      className="share-modal-backdrop"
      role="presentation"
      onClick={() => {
        void stopScanner().then(onClose);
      }}
    >
      <div
        className="share-modal scanner-modal"
        role="dialog"
        aria-modal="true"
        aria-label={t('scanner.aria')}
        onClick={(e) => e.stopPropagation()}
      >
        <header className="share-modal-head">
          <h2>
            <IconCamera size="sm" /> {t('scanner.title')}
          </h2>
          <button
            type="button"
            className="icon-btn"
            aria-label={t('scanner.close')}
            onClick={() => {
              void stopScanner().then(onClose);
            }}
          >
            <IconX size="sm" />
          </button>
        </header>

        <div id={SCANNER_ELEMENT_ID} className="qr-reader-host" />

        <p className="share-status">{status}</p>
        {error && <p className="error">{error}</p>}

        <div className="share-actions">
          <label className="share-action-btn primary file-pick">
            <IconUpload size="sm" />
            <span>{t('scanner.upload')}</span>
            <input
              ref={fileInputRef}
              type="file"
              accept="image/png,image/jpeg,image/webp,image/gif"
              onChange={(e) => void handleFilePicked(e)}
            />
          </label>
        </div>
      </div>
    </div>
  );
}
