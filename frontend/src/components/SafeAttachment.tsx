import { useEffect, useState, type MouseEvent } from 'react';
import { ensureSodium } from '../crypto/identity';
import type { MessageAttachment } from '../crypto/envelope';
import {
  extensionOf,
  isImageMime,
  neutralDownloadName,
  sanitizeFilename,
  validateFileHeader,
} from '../crypto/fileSecurity';
import { IconDownload, IconEye, IconFile, IconImage } from './ui/Icons';

type RenderMode = 'image' | 'document' | 'rejected' | 'loading';

interface SafeAttachmentProps {
  attachment: MessageAttachment;
  protectedMedia?: boolean;
  onOpenImage?: (attachment: MessageAttachment) => void;
  onDownload?: () => void | Promise<void>;
}

/**
 * Build a short-lived Blob URL for an attachment (caller must revoke).
 */
export async function createAttachmentBlobUrl(
  attachment: MessageAttachment,
): Promise<{ blobUrl: string; mimeType: string; downloadName: string }> {
  const s = await ensureSodium();
  const fileName = sanitizeFilename(attachment.fileName);
  const buffer = s.from_base64(attachment.dataBase64);
  const check = validateFileHeader(buffer, extensionOf(fileName));
  if (!check.valid || !check.mimeType || check.mimeType !== attachment.mimeType) {
    throw new Error('Anexo rejeitado na revalidação de segurança');
  }
  const bytes = new Uint8Array(buffer);
  const blob = new Blob([bytes], { type: check.mimeType });
  try {
    return {
      blobUrl: URL.createObjectURL(blob),
      mimeType: check.mimeType,
      downloadName: neutralDownloadName(check.mimeType),
    };
  } finally {
    s.memzero(buffer);
    s.memzero(bytes);
  }
}

export function SafeAttachment({
  attachment,
  protectedMedia: _protectedMedia = false,
  onOpenImage,
  onDownload,
}: SafeAttachmentProps) {
  const [mode, setMode] = useState<RenderMode>('loading');
  const [blobUrl, setBlobUrl] = useState<string | null>(null);
  const [downloadName, setDownloadName] = useState('documento.bin');

  useEffect(() => {
    let revoked = false;
    let objectUrl: string | null = null;

    void (async () => {
      const s = await ensureSodium();
      const fileName = sanitizeFilename(attachment.fileName);
      let buffer: Uint8Array;
      try {
        buffer = s.from_base64(attachment.dataBase64);
      } catch {
        if (!revoked) {
          setMode('rejected');
        }
        return;
      }

      const check = validateFileHeader(buffer, extensionOf(fileName));
      if (
        !check.valid ||
        !check.mimeType ||
        check.mimeType !== attachment.mimeType
      ) {
        s.memzero(buffer);
        if (!revoked) {
          setMode('rejected');
        }
        return;
      }

      if (revoked) {
        s.memzero(buffer);
        return;
      }

      setDownloadName(neutralDownloadName(check.mimeType));

      if (isImageMime(check.mimeType)) {
        s.memzero(buffer);
        setMode('image');
        return;
      }

      const bytes = new Uint8Array(buffer);
      const blob = new Blob([bytes], { type: check.mimeType });
      s.memzero(buffer);
      s.memzero(bytes);
      objectUrl = URL.createObjectURL(blob);

      if (revoked) {
        URL.revokeObjectURL(objectUrl);
        return;
      }

      setBlobUrl(objectUrl);
      setMode('document');
    })();

    return () => {
      revoked = true;
      if (objectUrl) {
        URL.revokeObjectURL(objectUrl);
      }
    };
  }, [attachment]);

  async function runProtectedHook(): Promise<void> {
    if (onDownload) {
      await onDownload();
    }
  }

  async function handleDocumentDownloadClick(
    event: MouseEvent<HTMLAnchorElement>,
  ): Promise<void> {
    if (onDownload) {
      event.preventDefault();
      await onDownload();
      if (blobUrl) {
        const anchor = document.createElement('a');
        anchor.href = blobUrl;
        anchor.download = downloadName;
        anchor.click();
      }
    }
  }

  async function handleImageDownloadClick(
    event: MouseEvent<HTMLAnchorElement>,
  ): Promise<void> {
    event.preventDefault();
    try {
      await runProtectedHook();
      const built = await createAttachmentBlobUrl(attachment);
      const anchor = document.createElement('a');
      anchor.href = built.blobUrl;
      anchor.download = built.downloadName;
      anchor.rel = 'noopener';
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(built.blobUrl);
    } catch {
      // download aborted / rejected
    }
  }

  if (mode === 'loading') {
    return (
      <div className="attachment-card">
        <span className="attachment-caption">…</span>
      </div>
    );
  }

  if (mode === 'rejected') {
    return (
      <div className="attachment-card rejected">Anexo rejeitado.</div>
    );
  }

  if (mode === 'image') {
    return (
      <div className="image-attach-card">
        <span className="image-attach-icon" aria-hidden="true">
          <IconImage size="md" />
        </span>
        <span className="image-attach-meta">
          <strong>Imagem</strong>
        </span>
        <div className="image-attach-actions">
          <button
            type="button"
            className="image-attach-action"
            aria-label="Visualizar"
            title="Visualizar"
            onClick={() => onOpenImage?.(attachment)}
          >
            <IconEye size="sm" />
          </button>
          <a
            href="#download"
            download={downloadName}
            className="image-attach-action download-inline"
            aria-label="Baixar"
            title="Baixar"
            onClick={(e) => void handleImageDownloadClick(e)}
          >
            <IconDownload size="sm" />
          </a>
        </div>
      </div>
    );
  }

  if (mode === 'document' && blobUrl) {
    return (
      <div className="image-attach-card document-attach-card">
        <span className="image-attach-icon" aria-hidden="true">
          <IconFile size="md" />
        </span>
        <span className="image-attach-meta">
          <strong>Documento</strong>
        </span>
        <a
          href={blobUrl}
          download={downloadName}
          className="image-attach-action download-inline"
          aria-label="Baixar"
          title="Baixar"
          onClick={(e) => void handleDocumentDownloadClick(e)}
        >
          <IconDownload size="sm" />
        </a>
      </div>
    );
  }

  return null;
}
