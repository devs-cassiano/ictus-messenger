import { useCallback, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { QRCodeCanvas } from 'qrcode.react';
import { scheduleClipboardClear } from '../crypto/clipboardGuard';
import { IconCheck, IconCopy, IconDownload, IconQrCode, IconX } from './ui/Icons';

interface IdentityShareModalProps {
  sessionId: string;
  onClose: () => void;
}

type CopyState = 'idle' | 'hash' | 'qr';

export function IdentityShareModal({
  sessionId,
  onClose,
}: IdentityShareModalProps) {
  const { t } = useTranslation();
  const canvasWrapRef = useRef<HTMLDivElement | null>(null);
  const [copyState, setCopyState] = useState<CopyState>('idle');
  const [error, setError] = useState<string | null>(null);

  const flash = useCallback((kind: CopyState) => {
    setCopyState(kind);
    window.setTimeout(() => setCopyState('idle'), 1600);
  }, []);

  async function handleCopyHash(): Promise<void> {
    setError(null);
    try {
      await navigator.clipboard.writeText(sessionId);
      scheduleClipboardClear(30_000);
      flash('hash');
    } catch {
      setError(t('share.copyHashFail'));
    }
  }

  function getCanvas(): HTMLCanvasElement | null {
    return canvasWrapRef.current?.querySelector('canvas') ?? null;
  }

  function downloadPng(canvas: HTMLCanvasElement): void {
    canvas.toBlob((blob) => {
      if (!blob) {
        setError(t('share.pngFail'));
        return;
      }
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = 'session-id-qr.png';
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
      flash('qr');
    }, 'image/png');
  }

  async function handleCopyQr(): Promise<void> {
    setError(null);
    const canvas = getCanvas();
    if (!canvas) {
      setError(t('share.qrNotReady'));
      return;
    }

    const blob = await new Promise<Blob | null>((resolve) => {
      canvas.toBlob((b) => resolve(b), 'image/png');
    });
    if (!blob) {
      setError(t('share.qrImageFail'));
      return;
    }

    try {
      if (
        typeof ClipboardItem !== 'undefined' &&
        navigator.clipboard &&
        typeof navigator.clipboard.write === 'function'
      ) {
        await navigator.clipboard.write([
          new ClipboardItem({ 'image/png': blob }),
        ]);
        scheduleClipboardClear(30_000);
        flash('qr');
        return;
      }
    } catch {
      // fall through to download
    }

    downloadPng(canvas);
  }

  return (
    <div
      className="share-modal-backdrop"
      role="presentation"
      onClick={onClose}
    >
      <div
        className="share-modal identity-share-modal"
        role="dialog"
        aria-modal="true"
        aria-label={t('share.aria')}
        onClick={(e) => e.stopPropagation()}
      >
        <header className="share-modal-head">
          <h2>{t('share.title')}</h2>
          <button
            type="button"
            className="icon-btn share-modal-close"
            aria-label={t('share.close')}
            onClick={onClose}
          >
            <IconX size="sm" />
          </button>
        </header>

        <div className="share-hash-row">
          <input
            id="session-hash"
            className="share-hash-input"
            value={sessionId}
            readOnly
            spellCheck={false}
            aria-label={t('share.sessionId')}
          />
          <button
            type="button"
            className="share-action-btn"
            onClick={() => void handleCopyHash()}
            title={t('share.copyHash')}
            aria-label={t('share.copyHash')}
          >
            {copyState === 'hash' ? <IconCheck size="sm" /> : <IconCopy size="sm" />}
            <span>
              {copyState === 'hash' ? t('share.copied') : t('share.copyHash')}
            </span>
          </button>
        </div>

        <div className="share-qr-block" ref={canvasWrapRef}>
          <QRCodeCanvas
            value={sessionId}
            size={200}
            bgColor="#0d1b1e"
            fgColor="#2dd4bf"
            level="M"
            marginSize={2}
            title="Session ID QR"
          />
        </div>

        <div className="share-actions">
          <button
            type="button"
            className="share-action-btn primary"
            onClick={() => void handleCopyQr()}
            title={t('share.copyQr')}
            aria-label={t('share.copyQr')}
          >
            {copyState === 'qr' ? (
              <IconCheck size="sm" />
            ) : (
              <IconQrCode size="sm" />
            )}
            <span>
              {copyState === 'qr' ? t('share.qrSaved') : t('share.copyQr')}
            </span>
          </button>
          <button
            type="button"
            className="share-action-btn"
            onClick={() => {
              const canvas = getCanvas();
              if (canvas) {
                downloadPng(canvas);
              }
            }}
            title={t('share.downloadPng')}
            aria-label={t('share.downloadPng')}
          >
            <IconDownload size="sm" />
            <span>{t('share.downloadPng')}</span>
          </button>
        </div>

        {error && <p className="error">{error}</p>}
      </div>
    </div>
  );
}
