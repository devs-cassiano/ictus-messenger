import { ensureSodium, type IdentityKeyPair, isValidSessionId } from './identity';
import type { MessageAttachment, ViewPolicy } from './envelope';
import { normalizeViewPolicy } from './envelope';
import { deriveVaultKey } from './vault';
import {
  loadEncryptedIdentity,
  loadVaultSalt,
  type DecryptedMessage,
} from '../storage/db';
import {
  VAULT_SCHEMA_ERROR,
  vaultDecryptedPayloadSchema,
  vaultFileEnvelopeSchema,
} from '../utils/vaultSchema';
import { clampMessageText } from '../utils/validators';

export type ConversationVaultType = 'DIRECT' | 'GROUP';

/** Decrypted message snapshot stored inside the vault payload. */
export interface StoredMessageDecrypted {
  id: string;
  conversationWith: string;
  senderSessionId: string;
  plainText: string;
  timestamp: number;
  expiresAt?: number;
  attachment?: MessageAttachment;
  viewPolicy: ViewPolicy;
  viewCount: number;
  isBurned: boolean;
}

export interface VaultBackupPayload {
  magic: 'SESSION_VAULT_BACKUP_V1';
  conversationId: string;
  conversationType: ConversationVaultType;
  exportedAt: number;
  participants: string[];
  messages: StoredMessageDecrypted[];
}

export interface VaultFileEnvelope {
  format: 'SESSION_CONVERSATION_VAULT';
  /** v2 adds Ed25519 author signature over salt|nonce|ciphertext. */
  version: 2;
  salt: string;
  nonce: string;
  ciphertext: string;
  authorSessionId: string;
  signature: string;
}

const MAGIC = 'SESSION_VAULT_BACKUP_V1' as const;
const FORMAT = 'SESSION_CONVERSATION_VAULT' as const;
const VAULT_VERSION = 2 as const;

function toStoredMessage(msg: DecryptedMessage): StoredMessageDecrypted {
  const item: StoredMessageDecrypted = {
    id: msg.id,
    conversationWith: msg.conversationWith,
    senderSessionId: msg.senderSessionId,
    plainText: msg.plainText,
    timestamp: msg.timestamp,
    viewPolicy: normalizeViewPolicy(msg.viewPolicy),
    viewCount: msg.viewCount,
    isBurned: msg.isBurned,
  };
  if (typeof msg.expiresAt === 'number') {
    item.expiresAt = msg.expiresAt;
  }
  if (msg.attachment) {
    item.attachment = msg.attachment;
  }
  return item;
}

/**
 * Confirm the account PIN by deriving the vault key and opening identity.
 * Failure is cryptographic (MAC), not a login “wrong password” signal.
 */
export async function verifyAccountPin(pin: string): Promise<Uint8Array> {
  const salt = await loadVaultSalt();
  if (!salt) {
    throw new Error('Cofre local não encontrado.');
  }
  const vaultKey = await deriveVaultKey(pin, salt);
  const identity = await loadEncryptedIdentity(vaultKey);
  if (!identity) {
    const s = await ensureSodium();
    s.memzero(vaultKey);
    throw new Error('Não foi possível abrir o cofre local com esta semente.');
  }
  return vaultKey;
}

async function deriveBackupKey(
  pin: string,
  salt: Uint8Array,
): Promise<Uint8Array> {
  const s = await ensureSodium();
  if (salt.length !== s.crypto_pwhash_SALTBYTES) {
    throw new Error('Salt de backup inválido.');
  }
  const pinBytes = s.from_string(pin);
  try {
    return s.crypto_pwhash(
      32,
      pinBytes,
      salt,
      s.crypto_pwhash_OPSLIMIT_MODERATE,
      s.crypto_pwhash_MEMLIMIT_MODERATE,
      s.crypto_pwhash_ALG_ARGON2ID13,
    );
  } finally {
    s.memzero(pinBytes);
  }
}

/** Blake2b digest of salt || nonce || ciphertext for Ed25519 signing. */
function vaultIntegrityDigest(
  s: Awaited<ReturnType<typeof ensureSodium>>,
  salt: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  const material = new Uint8Array(salt.length + nonce.length + ciphertext.length);
  material.set(salt, 0);
  material.set(nonce, salt.length);
  material.set(ciphertext, salt.length + nonce.length);
  try {
    return s.crypto_generichash(32, material, null);
  } finally {
    s.memzero(material);
  }
}

function authorPublicKeyFromSessionId(
  s: Awaited<ReturnType<typeof ensureSodium>>,
  sessionId: string,
): Uint8Array {
  if (!isValidSessionId(sessionId)) {
    throw new Error('Autor do vault inválido');
  }
  return s.from_hex(sessionId.slice(2));
}

/**
 * Build and seal a conversation vault file (hex-encoded JSON envelope)
 * with Argon2id-moderate secretbox + Ed25519 author signature.
 */
export async function sealConversationVault(options: {
  pin: string;
  conversationId: string;
  conversationType: ConversationVaultType;
  participants: string[];
  messages: DecryptedMessage[];
  localSessionId: string;
  authorKeyPair: IdentityKeyPair;
}): Promise<VaultFileEnvelope> {
  const {
    pin,
    conversationId,
    conversationType,
    participants,
    messages,
    localSessionId,
    authorKeyPair,
  } = options;

  if (!participants.includes(localSessionId)) {
    throw new Error(
      'Acesso negado: o usuário atual não é participante deste registro',
    );
  }

  const accountKey = await verifyAccountPin(pin);
  const s = await ensureSodium();
  s.memzero(accountKey);

  const salt = s.randombytes_buf(s.crypto_pwhash_SALTBYTES);
  const backupKey = await deriveBackupKey(pin, salt);
  const nonce = s.randombytes_buf(s.crypto_secretbox_NONCEBYTES);

  const payload: VaultBackupPayload = {
    magic: MAGIC,
    conversationId,
    conversationType,
    exportedAt: Date.now(),
    participants: [...participants],
    messages: messages.map(toStoredMessage),
  };

  let plaintext: Uint8Array | undefined;
  let digest: Uint8Array | undefined;
  try {
    plaintext = s.from_string(JSON.stringify(payload));
    const ciphertext = s.crypto_secretbox_easy(plaintext, nonce, backupKey);
    digest = vaultIntegrityDigest(s, salt, nonce, ciphertext);
    const signature = s.crypto_sign_detached(digest, authorKeyPair.privateKey);

    const envelope: VaultFileEnvelope = {
      format: FORMAT,
      version: VAULT_VERSION,
      salt: s.to_hex(salt),
      nonce: s.to_hex(nonce),
      ciphertext: s.to_hex(ciphertext),
      authorSessionId: localSessionId,
      signature: s.to_hex(signature),
    };
    return envelope;
  } finally {
    s.memzero(backupKey);
    if (plaintext) {
      s.memzero(plaintext);
    }
    if (digest) {
      s.memzero(digest);
    }
  }
}

/** Structured import failures for UI messaging. */
export type VaultImportErrorCode =
  | 'empty'
  | 'not_json'
  | 'bad_envelope'
  | 'bad_crypto_fields'
  | 'bad_signature'
  | 'bad_pin'
  | 'not_participant'
  | 'unknown';

export class VaultImportError extends Error {
  readonly code: VaultImportErrorCode;

  constructor(code: VaultImportErrorCode, message: string) {
    super(message);
    this.name = 'VaultImportError';
    this.code = code;
  }
}

/**
 * Parse and validate the outer vault file JSON (no PIN / decrypt yet).
 */
export function parseVaultFileEnvelope(fileContent: string): VaultFileEnvelope {
  const trimmed = fileContent.trim();
  if (!trimmed) {
    throw new VaultImportError(
      'empty',
      'Selecione um arquivo de backup válido.',
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    throw new VaultImportError(
      'not_json',
      'Formato do arquivo inválido (JSON esperado)',
    );
  }

  const result = vaultFileEnvelopeSchema.safeParse(parsed);
  if (!result.success) {
    throw new VaultImportError('bad_envelope', VAULT_SCHEMA_ERROR);
  }

  if (result.data.version !== VAULT_VERSION) {
    throw new VaultImportError('bad_envelope', VAULT_SCHEMA_ERROR);
  }

  return result.data as VaultFileEnvelope;
}

function parsePayload(raw: string): VaultBackupPayload {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new VaultImportError('bad_envelope', VAULT_SCHEMA_ERROR);
  }

  const result = vaultDecryptedPayloadSchema.safeParse(parsed);
  if (!result.success) {
    throw new VaultImportError('bad_envelope', VAULT_SCHEMA_ERROR);
  }

  const record = result.data;
  const messages: StoredMessageDecrypted[] = [];
  for (const m of record.messages) {
    const stored: StoredMessageDecrypted = {
      id: m.id,
      conversationWith: m.conversationWith,
      senderSessionId: m.senderSessionId,
      plainText: clampMessageText(m.plainText),
      timestamp: m.timestamp,
      viewPolicy: normalizeViewPolicy(m.viewPolicy),
      viewCount: typeof m.viewCount === 'number' ? m.viewCount : 0,
      isBurned: m.isBurned === true,
    };
    if (typeof m.expiresAt === 'number') {
      stored.expiresAt = m.expiresAt;
    }
    if (typeof m.attachment === 'object' && m.attachment !== null) {
      stored.attachment = m.attachment as MessageAttachment;
    }
    messages.push(stored);
  }

  return {
    magic: MAGIC,
    conversationId: record.conversationId,
    conversationType: record.conversationType,
    exportedAt: record.exportedAt,
    participants: record.participants,
    messages,
  };
}

/**
 * Open a vault file with the user PIN, verify Ed25519 authorship, and enforce
 * participant membership.
 */
export async function openConversationVault(
  envelopeJson: string,
  pin: string,
  localSessionId: string,
): Promise<VaultBackupPayload> {
  const parsed = parseVaultFileEnvelope(envelopeJson);

  const s = await ensureSodium();
  let salt: Uint8Array;
  let nonce: Uint8Array;
  let ciphertext: Uint8Array;
  let signature: Uint8Array;
  let digest: Uint8Array | undefined;
  try {
    salt = s.from_hex(parsed.salt);
    nonce = s.from_hex(parsed.nonce);
    ciphertext = s.from_hex(parsed.ciphertext);
    signature = s.from_hex(parsed.signature);
  } catch {
    throw new VaultImportError(
      'bad_crypto_fields',
      'Arquivo de backup incompatível ou corrompido.',
    );
  }

  if (
    salt.length !== s.crypto_pwhash_SALTBYTES ||
    nonce.length !== s.crypto_secretbox_NONCEBYTES ||
    signature.length !== s.crypto_sign_BYTES
  ) {
    throw new VaultImportError(
      'bad_crypto_fields',
      'Arquivo de backup incompatível ou corrompido.',
    );
  }

  try {
    const authorPk = authorPublicKeyFromSessionId(s, parsed.authorSessionId);
    digest = vaultIntegrityDigest(s, salt, nonce, ciphertext);
    const valid = s.crypto_sign_verify_detached(signature, digest, authorPk);
    if (!valid) {
      throw new VaultImportError(
        'bad_signature',
        'Assinatura do vault inválida ou arquivo adulterado',
      );
    }
  } catch (err) {
    if (err instanceof VaultImportError) {
      throw err;
    }
    throw new VaultImportError(
      'bad_signature',
      'Assinatura do vault inválida ou arquivo adulterado',
    );
  } finally {
    if (digest) {
      s.memzero(digest);
    }
  }

  const backupKey = await deriveBackupKey(pin, salt);
  let plain: Uint8Array | undefined;
  try {
    try {
      plain = s.crypto_secretbox_open_easy(ciphertext, nonce, backupKey);
    } catch {
      throw new VaultImportError(
        'bad_pin',
        'PIN incorreto ou dados corrompidos.',
      );
    }

    let payload: VaultBackupPayload;
    try {
      payload = parsePayload(s.to_string(plain));
    } catch {
      throw new VaultImportError(
        'bad_envelope',
        'Arquivo de backup incompatível ou corrompido.',
      );
    }

    if (!payload.participants.includes(localSessionId)) {
      throw new VaultImportError(
        'not_participant',
        'Acesso negado: o usuário atual não é participante deste registro',
      );
    }
    if (!payload.participants.includes(parsed.authorSessionId)) {
      throw new VaultImportError(
        'bad_signature',
        'Assinatura do vault inválida ou arquivo adulterado',
      );
    }

    return payload;
  } finally {
    s.memzero(backupKey);
    if (plain) {
      s.memzero(plain);
    }
  }
}

export function downloadVaultFile(envelope: VaultFileEnvelope): void {
  const blob = new Blob([JSON.stringify(envelope)], {
    type: 'application/octet-stream',
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `conversa_backup_${Date.now()}.vault`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}
