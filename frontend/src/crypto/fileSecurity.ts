import { ensureSodium } from './identity';

/** Maximum attachment size: 5 MiB. */
export const MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024;

const BLOCKED_EXTENSIONS = new Set([
  'svg',
  'svgz',
  'html',
  'htm',
  'xhtml',
  'js',
  'mjs',
  'cjs',
  'exe',
  'dll',
  'bat',
  'cmd',
  'com',
  'msi',
  'scr',
  'ps1',
  'vbs',
  'wsf',
  'jar',
  'apk',
  'wasm',
]);

const DANGEROUS_TEXT_PATTERNS = [
  /<\s*script\b/i,
  /<\s*html\b/i,
  /<\s*svg\b/i,
  /javascript\s*:/i,
];

type MagicRule = {
  mimeType: string;
  extensions: string[];
  test: (buffer: Uint8Array) => boolean;
};

function startsWithBytes(buffer: Uint8Array, magic: number[]): boolean {
  if (buffer.length < magic.length) {
    return false;
  }
  return magic.every((byte, index) => buffer[index] === byte);
}

function bytesEqualAt(
  buffer: Uint8Array,
  offset: number,
  magic: number[],
): boolean {
  if (buffer.length < offset + magic.length) {
    return false;
  }
  return magic.every((byte, index) => buffer[offset + index] === byte);
}

const MAGIC_RULES: MagicRule[] = [
  {
    mimeType: 'image/png',
    extensions: ['png'],
    test: (buffer) => startsWithBytes(buffer, [0x89, 0x50, 0x4e, 0x47]),
  },
  {
    mimeType: 'image/jpeg',
    extensions: ['jpg', 'jpeg'],
    test: (buffer) => startsWithBytes(buffer, [0xff, 0xd8, 0xff]),
  },
  {
    mimeType: 'image/webp',
    extensions: ['webp'],
    test: (buffer) =>
      bytesEqualAt(buffer, 0, [0x52, 0x49, 0x46, 0x46]) &&
      bytesEqualAt(buffer, 8, [0x57, 0x45, 0x42, 0x50]),
  },
  {
    mimeType: 'application/pdf',
    extensions: ['pdf'],
    test: (buffer) => startsWithBytes(buffer, [0x25, 0x50, 0x44, 0x46]),
  },
  {
    mimeType:
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    extensions: ['docx'],
    test: (buffer) => startsWithBytes(buffer, [0x50, 0x4b, 0x03, 0x04]),
  },
  {
    mimeType:
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    extensions: ['xlsx'],
    test: (buffer) => startsWithBytes(buffer, [0x50, 0x4b, 0x03, 0x04]),
  },
];

function normalizeExtension(extension: string): string {
  return extension.replace(/^\./, '').trim().toLowerCase();
}

/**
 * Reject null bytes and executable/markup patterns in plain text payloads.
 */
export function isSafePlainText(buffer: Uint8Array): boolean {
  for (let i = 0; i < buffer.length; i += 1) {
    if (buffer[i] === 0x00) {
      return false;
    }
  }

  let decoded: string;
  try {
    decoded = new TextDecoder('utf-8', { fatal: false }).decode(buffer);
  } catch {
    return false;
  }

  for (const pattern of DANGEROUS_TEXT_PATTERNS) {
    if (pattern.test(decoded)) {
      return false;
    }
  }

  return true;
}

/**
 * Strict whitelist validation using magic bytes (+ plain-text rules).
 */
export function validateFileHeader(
  buffer: Uint8Array,
  extension: string,
): { valid: boolean; mimeType: string | null } {
  if (buffer.byteLength === 0 || buffer.byteLength > MAX_ATTACHMENT_BYTES) {
    return { valid: false, mimeType: null };
  }

  const ext = normalizeExtension(extension);
  if (!ext || BLOCKED_EXTENSIONS.has(ext)) {
    return { valid: false, mimeType: null };
  }

  if (ext === 'txt' || ext === 'csv') {
    if (!isSafePlainText(buffer)) {
      return { valid: false, mimeType: null };
    }
    return {
      valid: true,
      mimeType: ext === 'csv' ? 'text/csv' : 'text/plain',
    };
  }

  const rule = MAGIC_RULES.find((candidate) =>
    candidate.extensions.includes(ext),
  );
  if (!rule || !rule.test(buffer)) {
    return { valid: false, mimeType: null };
  }

  return { valid: true, mimeType: rule.mimeType };
}

/**
 * Strip path traversal and control characters (kept for inbound validation).
 */
export function sanitizeFilename(name: string): string {
  const base = name.split(/[/\\]/).pop() ?? 'file';
  const withoutTraversal = base.replace(/\.\./g, '');
  const withoutControls = withoutTraversal.replace(
    /[\u0000-\u001f\u007f<>:"|?*\u0000]/g,
    '',
  );
  const trimmed = withoutControls.trim().replace(/^\.+/, '') || 'file';
  return trimmed.slice(0, 180);
}

export function formatFileSize(bytes: number): string {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function extensionOf(fileName: string): string {
  const sanitized = sanitizeFilename(fileName);
  const dot = sanitized.lastIndexOf('.');
  if (dot <= 0 || dot === sanitized.length - 1) {
    return '';
  }
  return sanitized.slice(dot + 1).toLowerCase();
}

export function extensionFromMime(mimeType: string): string {
  switch (mimeType) {
    case 'image/png':
      return 'png';
    case 'image/jpeg':
      return 'jpg';
    case 'image/webp':
      return 'webp';
    case 'application/pdf':
      return 'pdf';
    case 'text/plain':
      return 'txt';
    case 'text/csv':
      return 'csv';
    case 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
      return 'docx';
    case 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet':
      return 'xlsx';
    default:
      return 'bin';
  }
}

export function isImageMime(mimeType: string): boolean {
  return (
    mimeType === 'image/png' ||
    mimeType === 'image/jpeg' ||
    mimeType === 'image/webp'
  );
}

/** Neutral download aliases shown to the OS — never the original name. */
export function neutralDownloadName(mimeType: string): string {
  const ext = extensionFromMime(mimeType);
  return isImageMime(mimeType) ? `imagem.${ext}` : `documento.${ext}`;
}

export async function randomAnonymousFileName(ext: string): Promise<string> {
  const s = await ensureSodium();
  const hex = s.to_hex(s.randombytes_buf(16));
  const cleanExt = normalizeExtension(ext) || 'bin';
  return `${hex}.${cleanExt}`;
}

/**
 * Recreate image raster via canvas to strip all EXIF / metadata.
 */
export async function stripImageMetadata(
  file: File,
): Promise<{ buffer: Uint8Array; mimeType: string }> {
  const originalExt = extensionOf(file.name);
  const originalBuffer = new Uint8Array(await file.arrayBuffer());
  const check = validateFileHeader(originalBuffer, originalExt);
  if (!check.valid || !check.mimeType || !isImageMime(check.mimeType)) {
    throw new Error('Arquivo de imagem inválido para higienização.');
  }

  const bitmap = await createImageBitmap(file);
  try {
    const canvas = document.createElement('canvas');
    canvas.width = bitmap.width;
    canvas.height = bitmap.height;
    const ctx = canvas.getContext('2d', { alpha: true });
    if (!ctx) {
      throw new Error('Canvas indisponível para remoção de metadados.');
    }
    ctx.drawImage(bitmap, 0, 0);

    // Prefer PNG for lossless wipe; keep JPEG/WebP when source was that type.
    const exportMime =
      check.mimeType === 'image/jpeg'
        ? 'image/jpeg'
        : check.mimeType === 'image/webp'
          ? 'image/webp'
          : 'image/png';

    const blob = await new Promise<Blob>((resolve, reject) => {
      canvas.toBlob(
        (result) => {
          if (!result) {
            reject(new Error('Falha ao exportar imagem higienizada.'));
            return;
          }
          resolve(result);
        },
        exportMime,
        exportMime === 'image/jpeg' ? 0.92 : undefined,
      );
    });

    if (blob.size > MAX_ATTACHMENT_BYTES) {
      throw new Error('Imagem higienizada excede o limite de 5 MB.');
    }

    const buffer = new Uint8Array(await blob.arrayBuffer());
    const outExt = extensionFromMime(exportMime);
    const recheck = validateFileHeader(buffer, outExt);
    if (!recheck.valid || recheck.mimeType !== exportMime) {
      throw new Error('Imagem higienizada falhou na revalidação de magic bytes.');
    }

    return { buffer, mimeType: exportMime };
  } finally {
    bitmap.close();
  }
}

export interface PreparedAttachmentBytes {
  buffer: Uint8Array;
  mimeType: string;
  fileName: string;
}

/**
 * Validate, strip image EXIF when needed, and assign an anonymous filename.
 */
export async function prepareOutgoingFile(
  file: File,
): Promise<PreparedAttachmentBytes> {
  const originalExt = extensionOf(file.name);
  if (!originalExt) {
    throw new Error('Extensão de arquivo não suportada.');
  }

  const peek = new Uint8Array(await file.arrayBuffer());
  const peekCheck = validateFileHeader(peek, originalExt);
  if (!peekCheck.valid || !peekCheck.mimeType) {
    throw new Error(
      'Arquivo rejeitado: tipo não permitido ou magic bytes inválidos.',
    );
  }

  let buffer: Uint8Array;
  let mimeType: string;

  if (isImageMime(peekCheck.mimeType)) {
    const cleaned = await stripImageMetadata(file);
    buffer = cleaned.buffer;
    mimeType = cleaned.mimeType;
  } else {
    buffer = peek;
    mimeType = peekCheck.mimeType;
  }

  if (buffer.byteLength > MAX_ATTACHMENT_BYTES) {
    throw new Error('Arquivo excede o limite de 5 MB.');
  }

  const fileName = await randomAnonymousFileName(extensionFromMime(mimeType));
  return { buffer, mimeType, fileName };
}

const TEXT_PREVIEW_LIMIT = 8 * 1024;

export function buildTextPreview(
  buffer: Uint8Array,
  mimeType: string,
): string | undefined {
  if (mimeType !== 'text/plain' && mimeType !== 'text/csv') {
    return undefined;
  }
  if (!isSafePlainText(buffer)) {
    return undefined;
  }
  const slice =
    buffer.byteLength > TEXT_PREVIEW_LIMIT
      ? buffer.subarray(0, TEXT_PREVIEW_LIMIT)
      : buffer;
  return new TextDecoder('utf-8', { fatal: false }).decode(slice);
}
