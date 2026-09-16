import sodium from 'libsodium-wrappers-sumo';
import { ensureSodium, type IdentityKeyPair } from './identity';
import {
  extensionOf,
  sanitizeFilename,
  validateFileHeader,
} from './fileSecurity';
import type {
  DeleteMessageNotice,
  GroupControlMessage,
} from './groupSecurity';
import {
  isDeleteMessageNotice,
  isGroupControlMessage,
} from './groupSecurity';

/** Hybrid E2EE envelope: sealed ephemeral key + secretbox body (all Base64). */
export interface HybridEnvelope {
  wrappedKey: string;
  bodyCiphertext: string;
  nonce: string;
}

export interface MessageAttachment {
  fileName: string;
  mimeType: string;
  dataBase64: string;
  size: number;
  textPreview?: string;
}

export interface GroupSealedPayload {
  ciphertext: string;
  nonce: string;
}

export type { DeleteMessageNotice };

/** Plaintext payload sealed inside the hybrid envelope. */
export type ViewPolicy = 'PERMANENT' | 'VIEW_ONCE' | 'VIEW_TWICE';

export interface InnerMessage {
  id: string;
  senderSessionId: string;
  text: string;
  sentAt: number;
  viewPolicy: ViewPolicy;
  isBurned?: boolean;
  ttlDays?: number;
  attachment?: MessageAttachment;
  groupId?: string;
  /** Group-key ciphertext carrier (Base64) for closed-group fan-out. */
  groupCiphertext?: string;
  groupNonce?: string;
  /** Closed-group membership / key control plane. */
  control?: GroupControlMessage;
  /** Silent delete-for-all notice. */
  deleteNotice?: DeleteMessageNotice;
}

export function normalizeViewPolicy(value: unknown): ViewPolicy {
  if (value === 'VIEW_ONCE' || value === 'VIEW_TWICE' || value === 'PERMANENT') {
    return value;
  }
  return 'PERMANENT';
}

export { isDeleteMessageNotice };

function sessionIdToEd25519Pk(sessionId: string, s: typeof sodium): Uint8Array {
  const hex = sessionId.startsWith('05') ? sessionId.slice(2) : sessionId;
  return s.from_hex(hex);
}

function parseAttachment(value: unknown): MessageAttachment | undefined {
  if (typeof value !== 'object' || value === null) {
    return undefined;
  }
  const record = value as Record<string, unknown>;
  if (
    typeof record.fileName !== 'string' ||
    typeof record.mimeType !== 'string' ||
    typeof record.dataBase64 !== 'string' ||
    typeof record.size !== 'number'
  ) {
    return undefined;
  }

  const fileName = sanitizeFilename(record.fileName);
  const attachment: MessageAttachment = {
    fileName,
    mimeType: record.mimeType,
    dataBase64: record.dataBase64,
    size: record.size,
  };
  if (typeof record.textPreview === 'string') {
    attachment.textPreview = record.textPreview;
  }
  return attachment;
}

function parseInnerMessage(raw: string): InnerMessage {
  const parsed: unknown = JSON.parse(raw);
  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error('InnerMessage inválido');
  }
  const record = parsed as Record<string, unknown>;
  if (
    typeof record.id !== 'string' ||
    typeof record.senderSessionId !== 'string' ||
    typeof record.text !== 'string' ||
    typeof record.sentAt !== 'number'
  ) {
    throw new Error('InnerMessage com campos obrigatórios ausentes');
  }

  const inner: InnerMessage = {
    id: record.id,
    senderSessionId: record.senderSessionId,
    text: record.text,
    sentAt: record.sentAt,
    viewPolicy: normalizeViewPolicy(record.viewPolicy),
  };

  if (record.isBurned === true) {
    inner.isBurned = true;
  }

  if (typeof record.ttlDays === 'number') {
    inner.ttlDays = record.ttlDays;
  }

  if (typeof record.groupId === 'string') {
    inner.groupId = record.groupId;
  }
  if (typeof record.groupCiphertext === 'string') {
    inner.groupCiphertext = record.groupCiphertext;
  }
  if (typeof record.groupNonce === 'string') {
    inner.groupNonce = record.groupNonce;
  }
  if (isGroupControlMessage(record.control)) {
    inner.control = record.control;
  }
  if (isDeleteMessageNotice(record.deleteNotice)) {
    const notice: DeleteMessageNotice = {
      type: 'DELETE_FOR_ALL',
      targetMessageId: record.deleteNotice.targetMessageId,
      deletedBy: record.deleteNotice.deletedBy,
      timestamp: record.deleteNotice.timestamp,
    };
    if (typeof record.deleteNotice.groupId === 'string') {
      notice.groupId = record.deleteNotice.groupId;
    }
    inner.deleteNotice = notice;
  }

  const attachment = parseAttachment(record.attachment);
  if (attachment) {
    // Re-validate magic bytes before accepting attachment into memory model.
    const s = sodium;
    let buffer: Uint8Array;
    try {
      buffer = s.from_base64(attachment.dataBase64);
    } catch {
      throw new Error('Anexo com Base64 inválido');
    }
    const check = validateFileHeader(buffer, extensionOf(attachment.fileName));
    if (!check.valid || check.mimeType !== attachment.mimeType) {
      throw new Error('Anexo rejeitado na revalidação de segurança');
    }
    inner.attachment = attachment;
  }

  return inner;
}

/**
 * Seal an InnerMessage (includes senderSessionId / optional attachment).
 */
export async function sealMessageEnvelope(
  message: InnerMessage,
  recipientSessionId: string,
): Promise<HybridEnvelope> {
  const s = await ensureSodium();

  if (message.attachment) {
    const buffer = s.from_base64(message.attachment.dataBase64);
    const check = validateFileHeader(
      buffer,
      extensionOf(message.attachment.fileName),
    );
    if (!check.valid || check.mimeType !== message.attachment.mimeType) {
      throw new Error('Anexo inválido: falha na validação de magic bytes');
    }
  }

  const ephemeralKey = s.randombytes_buf(s.crypto_secretbox_KEYBYTES);
  const nonce = s.randombytes_buf(s.crypto_secretbox_NONCEBYTES);
  let payload: Uint8Array | undefined;

  try {
    payload = s.from_string(JSON.stringify(message));
    const bodyCiphertext = s.crypto_secretbox_easy(payload, nonce, ephemeralKey);

    const recipientEdPk = sessionIdToEd25519Pk(recipientSessionId, s);
    const recipientCurvePk = s.crypto_sign_ed25519_pk_to_curve25519(recipientEdPk);
    const wrappedKey = s.crypto_box_seal(ephemeralKey, recipientCurvePk);

    return {
      wrappedKey: s.to_base64(wrappedKey),
      bodyCiphertext: s.to_base64(bodyCiphertext),
      nonce: s.to_base64(nonce),
    };
  } finally {
    s.memzero(ephemeralKey);
    if (payload) {
      s.memzero(payload);
    }
  }
}

/**
 * Open a hybrid envelope and return the structured InnerMessage (with sender).
 */
export async function openMessageEnvelope(
  envelope: HybridEnvelope,
  myKeyPair: IdentityKeyPair,
): Promise<InnerMessage> {
  const s = await ensureSodium();

  const curvePk = s.crypto_sign_ed25519_pk_to_curve25519(myKeyPair.publicKey);
  const curveSk = s.crypto_sign_ed25519_sk_to_curve25519(myKeyPair.privateKey);

  let ephemeralKey: Uint8Array | undefined;
  let plaintext: Uint8Array | undefined;

  try {
    ephemeralKey = s.crypto_box_seal_open(
      s.from_base64(envelope.wrappedKey),
      curvePk,
      curveSk,
    );

    plaintext = s.crypto_secretbox_open_easy(
      s.from_base64(envelope.bodyCiphertext),
      s.from_base64(envelope.nonce),
      ephemeralKey,
    );

    return parseInnerMessage(s.to_string(plaintext));
  } finally {
    s.memzero(curveSk);
    if (ephemeralKey) {
      s.memzero(ephemeralKey);
    }
    if (plaintext) {
      s.memzero(plaintext);
    }
  }
}

/**
 * Encrypt an InnerMessage with the closed-group symmetric key.
 */
export async function sealGroupMessage(
  inner: InnerMessage,
  groupKey: Uint8Array,
): Promise<GroupSealedPayload> {
  const s = await ensureSodium();
  const nonce = s.randombytes_buf(s.crypto_secretbox_NONCEBYTES);
  const payload = s.from_string(JSON.stringify(inner));
  try {
    const ciphertext = s.crypto_secretbox_easy(payload, nonce, groupKey);
    return {
      ciphertext: s.to_base64(ciphertext),
      nonce: s.to_base64(nonce),
    };
  } finally {
    s.memzero(payload);
  }
}

/**
 * Decrypt a closed-group payload with the current group key.
 */
export async function openGroupMessage(
  ciphertext: string,
  nonce: string,
  groupKey: Uint8Array,
): Promise<InnerMessage> {
  const s = await ensureSodium();
  const plaintext = s.crypto_secretbox_open_easy(
    s.from_base64(ciphertext),
    s.from_base64(nonce),
    groupKey,
  );
  try {
    return parseInnerMessage(s.to_string(plaintext));
  } finally {
    s.memzero(plaintext);
  }
}
