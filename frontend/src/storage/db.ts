import { openDB, type DBSchema, type IDBPDatabase } from 'idb';
import type {
  InnerMessage,
  MessageAttachment,
  ViewPolicy,
} from '../crypto/envelope';
import { normalizeViewPolicy } from '../crypto/envelope';
import type {
  DeleteMessageNotice,
  GroupMeta,
} from '../crypto/groupSecurity';
import { conversationKeyForGroup } from '../crypto/groupSecurity';
import {
  ensureSodium,
  type IdentityKeyPair,
} from '../crypto/identity';
import { identityFromMnemonic } from '../crypto/mnemonic';
import {
  extensionOf,
  sanitizeFilename,
  validateFileHeader,
} from '../crypto/fileSecurity';

interface StoredConversation {
  peerSessionId: string;
  /** Encrypted preview: `nonceB64.ciphertextB64` (never plaintext). */
  lastMessage: string;
  updatedAt: number;
  ttlDays?: number;
  isGroup?: boolean;
  groupId?: string;
}

interface StoredMessage {
  id: string;
  conversationWith: string;
  senderSessionId: string;
  ciphertext: string;
  nonce: string;
  timestamp: number;
  expiresAt?: number;
  viewPolicy: ViewPolicy;
  viewCount: number;
  isBurned: boolean;
  /** Outgoing delivery pipeline against real SNodes. */
  deliveryStatus?: DeliveryStatus;
}

export type DeliveryStatus = 'pending' | 'sent' | 'failed';

/** Group key material is stored encrypted under the vault key. */
interface StoredGroup {
  groupId: string;
  name: string;
  admins: string[];
  /** @deprecated legacy single-admin field — migrated on read */
  adminSessionId?: string;
  members: string[];
  keyVersion: number;
  groupKeyCiphertext: string;
  groupKeyNonce: string;
}

interface VaultRecord {
  id: 'primary';
  salt: string;
  /** Legacy sealed identity blob (pre-mnemonic vaults). */
  identityCiphertext?: string;
  identityNonce?: string;
  /** PIN-sealed BIP39 mnemonic (never store plaintext). */
  mnemonicCiphertext?: string;
  mnemonicNonce?: string;
  /** Present on vaults sealed with Argon2id moderate; absent = legacy/orphan. */
  kdf?: 'argon2id-moderate';
  /** Vault schema marker. */
  kind?: 'mnemonic-v1' | 'identity-legacy';
}

const VAULT_KDF = 'argon2id-moderate' as const;

interface MessengerDB extends DBSchema {
  conversations: {
    key: string;
    value: StoredConversation;
  };
  messages: {
    key: string;
    value: StoredMessage;
    indexes: {
      conversationWith: string;
      expiresAt: number;
    };
  };
  groups: {
    key: string;
    value: StoredGroup;
  };
  vault: {
    key: string;
    value: VaultRecord;
  };
}

export interface DecryptedMessage {
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
  deliveryStatus?: DeliveryStatus;
}

export interface ConversationPreview {
  peerSessionId: string;
  lastMessage: string;
  updatedAt: number;
  ttlDays?: number;
  isGroup?: boolean;
  groupId?: string;
  groupName?: string;
}

const DB_NAME = 'session-messenger-db';
const DB_VERSION = 3;

let dbPromise: Promise<IDBPDatabase<MessengerDB>> | null = null;

function getDb(): Promise<IDBPDatabase<MessengerDB>> {
  if (!dbPromise) {
    dbPromise = openDB<MessengerDB>(DB_NAME, DB_VERSION, {
      upgrade(db) {
        if (!db.objectStoreNames.contains('conversations')) {
          db.createObjectStore('conversations', { keyPath: 'peerSessionId' });
        }
        if (!db.objectStoreNames.contains('messages')) {
          const messages = db.createObjectStore('messages', { keyPath: 'id' });
          messages.createIndex('conversationWith', 'conversationWith');
          messages.createIndex('expiresAt', 'expiresAt');
        }
        if (!db.objectStoreNames.contains('groups')) {
          db.createObjectStore('groups', { keyPath: 'groupId' });
        }
        if (!db.objectStoreNames.contains('vault')) {
          db.createObjectStore('vault', { keyPath: 'id' });
        }
      },
    });
  }
  return dbPromise;
}

async function encryptUtf8(
  plainText: string,
  vaultKey: Uint8Array,
): Promise<{ ciphertext: string; nonce: string }> {
  const s = await ensureSodium();
  const nonce = s.randombytes_buf(s.crypto_secretbox_NONCEBYTES);
  const plain = s.from_string(plainText);
  try {
    const ciphertext = s.crypto_secretbox_easy(plain, nonce, vaultKey);
    return {
      ciphertext: s.to_base64(ciphertext),
      nonce: s.to_base64(nonce),
    };
  } finally {
    s.memzero(plain);
  }
}

async function decryptUtf8(
  ciphertext: string,
  nonce: string,
  vaultKey: Uint8Array,
): Promise<string> {
  const s = await ensureSodium();
  const plain = s.crypto_secretbox_open_easy(
    s.from_base64(ciphertext),
    s.from_base64(nonce),
    vaultKey,
  );
  try {
    return s.to_string(plain);
  } finally {
    s.memzero(plain);
  }
}

function packPreview(nonce: string, ciphertext: string): string {
  return `${nonce}.${ciphertext}`;
}

function unpackPreview(packed: string): { nonce: string; ciphertext: string } {
  const sep = packed.indexOf('.');
  if (sep <= 0 || sep === packed.length - 1) {
    throw new Error('Preview cifrado inválido');
  }
  return {
    nonce: packed.slice(0, sep),
    ciphertext: packed.slice(sep + 1),
  };
}

function computeExpiresAt(msg: InnerMessage): number | undefined {
  if (typeof msg.ttlDays !== 'number' || msg.ttlDays <= 0) {
    return undefined;
  }
  return msg.sentAt + msg.ttlDays * 86_400_000;
}

interface PersistedIdentity {
  sessionId: string;
  publicKey: string;
  privateKey: string;
  keyType: string;
}

export async function loadVaultSalt(): Promise<Uint8Array | null> {
  const db = await getDb();
  const record = await db.get('vault', 'primary');
  if (!record) {
    return null;
  }
  const s = await ensureSodium();
  try {
    const salt = s.from_base64(record.salt);
    if (salt.length !== s.crypto_pwhash_SALTBYTES) {
      return null;
    }
    return salt;
  } catch {
    return null;
  }
}

/**
 * True ONLY when a complete mnemonic sealed vault exists.
 * Legacy identity-only rows, partial/malformed fields, or wrong KDF → false.
 */
export async function hasExistingVault(): Promise<boolean> {
  try {
    const db = await getDb();
    const record = await db.get('vault', 'primary');
    if (!record) {
      return false;
    }
    if (record.kdf !== VAULT_KDF) {
      return false;
    }
    // Explicit legacy identity vault without a sealed mnemonic → onboarding.
    if (
      record.kind === 'identity-legacy' &&
      (!record.mnemonicCiphertext || !record.mnemonicNonce)
    ) {
      return false;
    }
    if (typeof record.salt !== 'string' || record.salt.length === 0) {
      return false;
    }
    if (
      typeof record.mnemonicCiphertext !== 'string' ||
      record.mnemonicCiphertext.length === 0 ||
      typeof record.mnemonicNonce !== 'string' ||
      record.mnemonicNonce.length === 0
    ) {
      return false;
    }

    const s = await ensureSodium();
    try {
      const salt = s.from_base64(record.salt);
      const nonce = s.from_base64(record.mnemonicNonce);
      const ciphertext = s.from_base64(record.mnemonicCiphertext);
      return (
        salt.length === s.crypto_pwhash_SALTBYTES &&
        nonce.length === s.crypto_secretbox_NONCEBYTES &&
        ciphertext.length > s.crypto_secretbox_MACBYTES
      );
    } catch {
      return false;
    }
  } catch {
    return false;
  }
}

export async function vaultHasMnemonic(): Promise<boolean> {
  return hasExistingVault();
}

/** @deprecated Prefer hasExistingVault — kept as alias for older call sites. */
export async function hasInitializedVault(): Promise<boolean> {
  return hasExistingVault();
}

/**
 * Remove orphan / incomplete / legacy vault rows so first-access can proceed.
 * Any non-mnemonic-v1 residue is deleted (hasVault forced to false).
 */
export async function purgeInconsistentVault(): Promise<void> {
  try {
    const db = await getDb();
    const record = await db.get('vault', 'primary');
    if (!record) {
      return;
    }
    const valid = await hasExistingVault();
    if (!valid) {
      await db.delete('vault', 'primary');
    }
  } catch {
    // best-effort hygiene
  }
}

/**
 * Wipe local messenger stores so a new deterministic identity can be sealed.
 * Used when the provided PIN cannot authenticate the current vault MAC.
 */
export async function clearLocalDataStores(): Promise<void> {
  const db = await getDb();
  const storeNames = Array.from(db.objectStoreNames);
  if (storeNames.length === 0) {
    return;
  }
  const tx = db.transaction(storeNames, 'readwrite');
  await Promise.all([
    ...storeNames.map((name) => tx.objectStore(name).clear()),
    tx.done,
  ]);
}

export async function saveEncryptedIdentity(
  sessionId: string,
  keyPair: IdentityKeyPair,
  vaultKey: Uint8Array,
  salt: Uint8Array,
  mnemonic?: string,
): Promise<void> {
  const s = await ensureSodium();
  const payload: PersistedIdentity = {
    sessionId,
    publicKey: s.to_base64(keyPair.publicKey),
    privateKey: s.to_base64(keyPair.privateKey),
    keyType: keyPair.keyType,
  };

  const identityNonce = s.randombytes_buf(s.crypto_secretbox_NONCEBYTES);
  const identityPlain = s.from_string(JSON.stringify(payload));
  let mnemonicPlain: Uint8Array | undefined;
  try {
    const identityCiphertext = s.crypto_secretbox_easy(
      identityPlain,
      identityNonce,
      vaultKey,
    );

    const record: VaultRecord = {
      id: 'primary',
      salt: s.to_base64(salt),
      identityCiphertext: s.to_base64(identityCiphertext),
      identityNonce: s.to_base64(identityNonce),
      kdf: VAULT_KDF,
      kind: mnemonic ? 'mnemonic-v1' : 'identity-legacy',
    };

    if (mnemonic) {
      const mnemonicNonce = s.randombytes_buf(s.crypto_secretbox_NONCEBYTES);
      mnemonicPlain = s.from_string(mnemonic);
      const mnemonicCiphertext = s.crypto_secretbox_easy(
        mnemonicPlain,
        mnemonicNonce,
        vaultKey,
      );
      record.mnemonicCiphertext = s.to_base64(mnemonicCiphertext);
      record.mnemonicNonce = s.to_base64(mnemonicNonce);
      record.kind = 'mnemonic-v1';
    }

    const db = await getDb();
    await db.put('vault', record);
  } finally {
    s.memzero(identityPlain);
    if (mnemonicPlain) {
      s.memzero(mnemonicPlain);
    }
  }
}

/**
 * Persist a mnemonic-backed vault (PIN seals only the phrase; keys are derived).
 */
export async function saveMnemonicVault(
  mnemonic: string,
  vaultKey: Uint8Array,
  salt: Uint8Array,
  identity: { sessionId: string; keyPair: IdentityKeyPair },
): Promise<void> {
  await saveEncryptedIdentity(
    identity.sessionId,
    identity.keyPair,
    vaultKey,
    salt,
    mnemonic,
  );
}

/**
 * Decrypt the sealed mnemonic with the vault key. Null on wrong PIN / missing.
 */
export async function loadSealedMnemonic(
  vaultKey: Uint8Array,
): Promise<string | null> {
  const db = await getDb();
  const record = await db.get('vault', 'primary');
  if (
    !record?.mnemonicCiphertext ||
    !record.mnemonicNonce ||
    typeof record.mnemonicCiphertext !== 'string' ||
    typeof record.mnemonicNonce !== 'string'
  ) {
    return null;
  }

  const s = await ensureSodium();
  let plain: Uint8Array | undefined;
  try {
    plain = s.crypto_secretbox_open_easy(
      s.from_base64(record.mnemonicCiphertext),
      s.from_base64(record.mnemonicNonce),
      vaultKey,
    );
    return s.to_string(plain);
  } catch {
    return null;
  } finally {
    if (plain) {
      s.memzero(plain);
    }
  }
}

export async function loadEncryptedIdentity(
  vaultKey: Uint8Array,
): Promise<{ sessionId: string; keyPair: IdentityKeyPair } | null> {
  const db = await getDb();
  const record = await db.get('vault', 'primary');
  if (!record) {
    return null;
  }

  const s = await ensureSodium();

  // Mnemonic vaults: open phrase → derive keys. Wrong PIN / MAC fail → null
  // (do not fall through to legacy identity blob).
  if (record.mnemonicCiphertext && record.mnemonicNonce) {
    let mnemonicPlain: Uint8Array | undefined;
    try {
      mnemonicPlain = s.crypto_secretbox_open_easy(
        s.from_base64(record.mnemonicCiphertext),
        s.from_base64(record.mnemonicNonce),
        vaultKey,
      );
      const mnemonic = s.to_string(mnemonicPlain);
      const derived = await identityFromMnemonic(mnemonic);
      return {
        sessionId: derived.sessionId,
        keyPair: derived.keyPair,
      };
    } catch {
      return null;
    } finally {
      if (mnemonicPlain) {
        s.memzero(mnemonicPlain);
      }
    }
  }

  if (!record.identityCiphertext || !record.identityNonce) {
    return null;
  }

  let plain: Uint8Array | undefined;
  try {
    plain = s.crypto_secretbox_open_easy(
      s.from_base64(record.identityCiphertext),
      s.from_base64(record.identityNonce),
      vaultKey,
    );
    const parsed = JSON.parse(s.to_string(plain)) as PersistedIdentity;
    return {
      sessionId: parsed.sessionId,
      keyPair: {
        keyType: parsed.keyType,
        publicKey: s.from_base64(parsed.publicKey),
        privateKey: s.from_base64(parsed.privateKey),
      },
    };
  } catch {
    return null;
  } finally {
    if (plain) {
      s.memzero(plain);
    }
  }
}

interface StoredMessageBody {
  text: string;
  attachment?: MessageAttachment;
}

async function revalidateStoredAttachment(
  attachment: MessageAttachment,
): Promise<MessageAttachment | undefined> {
  const s = await ensureSodium();
  let buffer: Uint8Array;
  try {
    buffer = s.from_base64(attachment.dataBase64);
  } catch {
    return undefined;
  }
  const fileName = sanitizeFilename(attachment.fileName);
  const check = validateFileHeader(buffer, extensionOf(fileName));
  if (!check.valid || check.mimeType !== attachment.mimeType) {
    return undefined;
  }
  const safe: MessageAttachment = {
    fileName,
    mimeType: attachment.mimeType,
    dataBase64: attachment.dataBase64,
    size: attachment.size,
  };
  if (typeof attachment.textPreview === 'string') {
    safe.textPreview = attachment.textPreview;
  }
  return safe;
}

function parseStoredBody(raw: string): StoredMessageBody {
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed === 'object' && parsed !== null) {
      const record = parsed as Record<string, unknown>;
      if (typeof record.text === 'string') {
        const body: StoredMessageBody = { text: record.text };
        if (typeof record.attachment === 'object' && record.attachment !== null) {
          body.attachment = record.attachment as MessageAttachment;
        }
        return body;
      }
    }
  } catch {
    // legacy plaintext rows
  }
  return { text: raw };
}

export async function saveIncomingOrOutgoingMessage(
  msg: InnerMessage,
  conversationWith: string,
  vaultKey: Uint8Array,
  options?: { deliveryStatus?: DeliveryStatus },
): Promise<void> {
  const viewPolicy = normalizeViewPolicy(msg.viewPolicy);
  const isBurned = msg.isBurned === true;
  const body: StoredMessageBody = {
    text: isBurned
      ? '[Mensagem destruída após visualização]'
      : msg.text,
  };
  if (!isBurned && msg.attachment) {
    body.attachment = msg.attachment;
  }

  const previewSource = isBurned
    ? 'Mensagem expirada'
    : msg.attachment
      ? msg.text.trim() || 'Anexo'
      : msg.text;

  const { ciphertext, nonce } = await encryptUtf8(
    JSON.stringify(body),
    vaultKey,
  );
  const preview = await encryptUtf8(previewSource, vaultKey);
  const expiresAt = computeExpiresAt(msg);

  const isGroup = Boolean(msg.groupId);
  const peerSessionId = isGroup
    ? conversationKeyForGroup(msg.groupId as string)
    : conversationWith;

  const db = await getDb();
  const existingMsg = await db.get('messages', msg.id);

  const stored: StoredMessage = {
    id: msg.id,
    conversationWith: peerSessionId,
    senderSessionId: msg.senderSessionId,
    ciphertext,
    nonce,
    timestamp: msg.sentAt,
    viewPolicy,
    viewCount: existingMsg?.viewCount ?? 0,
    isBurned: existingMsg?.isBurned === true || isBurned,
  };
  if (expiresAt !== undefined) {
    stored.expiresAt = expiresAt;
  }
  const deliveryStatus =
    options?.deliveryStatus ?? existingMsg?.deliveryStatus;
  if (deliveryStatus) {
    stored.deliveryStatus = deliveryStatus;
  }

  const existing = await db.get('conversations', peerSessionId);

  const conversation: StoredConversation = {
    peerSessionId,
    lastMessage: packPreview(preview.nonce, preview.ciphertext),
    updatedAt: msg.sentAt,
  };
  if (typeof msg.ttlDays === 'number') {
    conversation.ttlDays = msg.ttlDays;
  }
  if (isGroup && msg.groupId) {
    conversation.isGroup = true;
    conversation.groupId = msg.groupId;
  } else if (existing?.isGroup) {
    conversation.isGroup = true;
    if (existing.groupId) {
      conversation.groupId = existing.groupId;
    }
  }

  const tx = db.transaction(['messages', 'conversations'], 'readwrite');
  await tx.objectStore('messages').put(stored);
  await tx.objectStore('conversations').put(conversation);
  await tx.done;
}

export async function getConversationList(
  vaultKey: Uint8Array,
): Promise<ConversationPreview[]> {
  const db = await getDb();
  const rows = await db.getAll('conversations');
  const previews: ConversationPreview[] = [];

  for (const row of rows) {
    try {
      const { nonce, ciphertext } = unpackPreview(row.lastMessage);
      const lastMessage = await decryptUtf8(ciphertext, nonce, vaultKey);
      const preview: ConversationPreview = {
        peerSessionId: row.peerSessionId,
        lastMessage,
        updatedAt: row.updatedAt,
      };
      if (typeof row.ttlDays === 'number') {
        preview.ttlDays = row.ttlDays;
      }
      if (row.isGroup) {
        preview.isGroup = true;
      }
      if (row.groupId) {
        preview.groupId = row.groupId;
        const group = await getGroupMeta(row.groupId, vaultKey);
        if (group) {
          preview.groupName = group.name;
        }
      }
      previews.push(preview);
    } catch {
      // skip undecryptable conversation previews
    }
  }

  previews.sort((a, b) => b.updatedAt - a.updatedAt);
  return previews;
}

export async function getMessages(
  conversationWith: string,
  vaultKey: Uint8Array,
): Promise<DecryptedMessage[]> {
  const db = await getDb();
  const records = await db.getAllFromIndex(
    'messages',
    'conversationWith',
    conversationWith,
  );

  const messages: DecryptedMessage[] = [];
  const now = Date.now();

  for (const record of records) {
    if (typeof record.expiresAt === 'number' && record.expiresAt <= now) {
      continue;
    }
    try {
      const raw = await decryptUtf8(
        record.ciphertext,
        record.nonce,
        vaultKey,
      );
      const body = parseStoredBody(raw);
      const viewPolicy = normalizeViewPolicy(record.viewPolicy);
      const isBurned = record.isBurned === true;
      const item: DecryptedMessage = {
        id: record.id,
        conversationWith: record.conversationWith,
        senderSessionId: record.senderSessionId,
        plainText: isBurned
          ? '[Mensagem destruída após visualização]'
          : body.text,
        timestamp: record.timestamp,
        viewPolicy,
        viewCount: record.viewCount ?? 0,
        isBurned,
      };
      if (typeof record.expiresAt === 'number') {
        item.expiresAt = record.expiresAt;
      }
      if (!isBurned && body.attachment) {
        const safe = await revalidateStoredAttachment(body.attachment);
        if (safe) {
          item.attachment = safe;
        }
      }
      if (record.deliveryStatus) {
        item.deliveryStatus = record.deliveryStatus;
      }
      messages.push(item);
    } catch {
      // skip undecryptable rows
    }
  }

  messages.sort((a, b) => a.timestamp - b.timestamp);
  return messages;
}

export async function updateMessageDeliveryStatus(
  messageId: string,
  deliveryStatus: DeliveryStatus,
): Promise<void> {
  const db = await getDb();
  const record = await db.get('messages', messageId);
  if (!record) {
    return;
  }
  await db.put('messages', { ...record, deliveryStatus });
}

function viewsAllowed(policy: ViewPolicy): number {
  if (policy === 'VIEW_ONCE') {
    return 1;
  }
  if (policy === 'VIEW_TWICE') {
    return 2;
  }
  return Number.POSITIVE_INFINITY;
}

/**
 * Anti-forensic shred: overwrite ciphertext/nonce with random bytes via put(),
 * then physically delete the message row.
 */
async function shredThenDeleteMessage(messageId: string): Promise<StoredMessage | null> {
  const db = await getDb();
  const record = await db.get('messages', messageId);
  if (!record) {
    return null;
  }

  const s = await ensureSodium();
  const cipherLen = Math.max(64, Math.ceil((record.ciphertext.length * 3) / 4));
  const shreddedCipher = new Uint8Array(cipherLen);
  const shreddedNonce = new Uint8Array(s.crypto_secretbox_NONCEBYTES);
  crypto.getRandomValues(shreddedCipher);
  crypto.getRandomValues(shreddedNonce);

  await db.put('messages', {
    ...record,
    ciphertext: s.to_base64(shreddedCipher),
    nonce: s.to_base64(shreddedNonce),
    isBurned: true,
  });
  await db.delete('messages', messageId);
  return record;
}

/**
 * Consume one local view of a protected message; burn ciphertext when exhausted.
 * Exhausted ephemeral messages are shredded then physically deleted.
 */
export async function consumeMessageView(
  messageId: string,
  vaultKey: Uint8Array,
): Promise<DecryptedMessage | null> {
  const db = await getDb();
  const record = await db.get('messages', messageId);
  if (!record) {
    return null;
  }

  const viewPolicy = normalizeViewPolicy(record.viewPolicy);
  if (viewPolicy === 'PERMANENT' || record.isBurned === true) {
    const list = await getMessages(record.conversationWith, vaultKey);
    return list.find((m) => m.id === messageId) ?? null;
  }

  const nextCount = (record.viewCount ?? 0) + 1;
  let isBurned = false;
  if (
    (viewPolicy === 'VIEW_ONCE' && nextCount >= 1) ||
    (viewPolicy === 'VIEW_TWICE' && nextCount >= 2)
  ) {
    isBurned = true;
  }

  let body: StoredMessageBody;
  try {
    const raw = await decryptUtf8(record.ciphertext, record.nonce, vaultKey);
    body = parseStoredBody(raw);
  } catch {
    body = { text: '' };
  }

  if (isBurned) {
    revokeMessageBlobUrls(messageId);
    await shredThenDeleteMessage(messageId);
    await refreshConversationPreview(record.conversationWith, vaultKey);
    return {
      id: record.id,
      conversationWith: record.conversationWith,
      senderSessionId: record.senderSessionId,
      plainText: '[Mensagem destruída após visualização]',
      timestamp: record.timestamp,
      viewPolicy,
      viewCount: nextCount,
      isBurned: true,
    };
  }

  const { ciphertext, nonce } = await encryptUtf8(
    JSON.stringify(body),
    vaultKey,
  );

  const updated: StoredMessage = {
    ...record,
    ciphertext,
    nonce,
    viewPolicy,
    viewCount: nextCount,
    isBurned: false,
  };

  await db.put('messages', updated);

  const decrypted: DecryptedMessage = {
    id: updated.id,
    conversationWith: updated.conversationWith,
    senderSessionId: updated.senderSessionId,
    plainText: body.text,
    timestamp: updated.timestamp,
    viewPolicy,
    viewCount: nextCount,
    isBurned: false,
  };
  if (typeof updated.expiresAt === 'number') {
    decrypted.expiresAt = updated.expiresAt;
  }
  if (body.attachment) {
    const safe = await revalidateStoredAttachment(body.attachment);
    if (safe) {
      decrypted.attachment = safe;
    }
  }
  return decrypted;
}

export function remainingViews(msg: {
  viewPolicy: ViewPolicy;
  viewCount: number;
  isBurned: boolean;
}): number {
  if (msg.isBurned || msg.viewPolicy === 'PERMANENT') {
    return Number.POSITIVE_INFINITY;
  }
  return Math.max(0, viewsAllowed(msg.viewPolicy) - msg.viewCount);
}

/** Tracks Blob URLs tied to a message id so silent deletes can revoke them. */
const messageBlobUrls = new Map<string, Set<string>>();

export function registerMessageBlobUrl(
  messageId: string,
  blobUrl: string,
): void {
  let set = messageBlobUrls.get(messageId);
  if (!set) {
    set = new Set();
    messageBlobUrls.set(messageId, set);
  }
  set.add(blobUrl);
}

export function revokeMessageBlobUrls(messageId: string): void {
  const set = messageBlobUrls.get(messageId);
  if (!set) {
    return;
  }
  for (const url of set) {
    try {
      URL.revokeObjectURL(url);
    } catch {
      // ignore revoke errors
    }
  }
  messageBlobUrls.delete(messageId);
}

/** Revoke every tracked Blob URL (panic / full wipe). */
export function revokeAllMessageBlobUrls(): void {
  for (const messageId of [...messageBlobUrls.keys()]) {
    revokeMessageBlobUrls(messageId);
  }
}

/**
 * Close any open idb handle so deleteDatabase is not blocked by live connections.
 */
async function closeOpenDatabase(): Promise<void> {
  if (!dbPromise) {
    return;
  }
  try {
    const db = await dbPromise;
    db.close();
  } catch {
    // ignore close errors
  }
  dbPromise = null;
}

/**
 * Fallback: reopen and wipe every object store when deleteDatabase is blocked.
 * Store names match the live schema (messages, conversations, groups, vault).
 */
async function clearAllObjectStoresFallback(): Promise<void> {
  try {
    const db = await openDB<MessengerDB>(DB_NAME, DB_VERSION, {
      upgrade(database) {
        if (!database.objectStoreNames.contains('conversations')) {
          database.createObjectStore('conversations', {
            keyPath: 'peerSessionId',
          });
        }
        if (!database.objectStoreNames.contains('messages')) {
          const messages = database.createObjectStore('messages', {
            keyPath: 'id',
          });
          messages.createIndex('conversationWith', 'conversationWith');
          messages.createIndex('expiresAt', 'expiresAt');
        }
        if (!database.objectStoreNames.contains('groups')) {
          database.createObjectStore('groups', { keyPath: 'groupId' });
        }
        if (!database.objectStoreNames.contains('vault')) {
          database.createObjectStore('vault', { keyPath: 'id' });
        }
      },
    });

    const storeNames = Array.from(db.objectStoreNames);
    if (storeNames.length > 0) {
      const tx = db.transaction(storeNames, 'readwrite');
      await Promise.all([
        ...storeNames.map((name) => tx.objectStore(name).clear()),
        tx.done,
      ]);
    }
    db.close();
  } catch {
    // ignore fallback errors — best effort wipe
  } finally {
    dbPromise = null;
  }
}

async function deleteIndexedDatabase(): Promise<'deleted' | 'blocked' | 'error'> {
  return new Promise((resolve) => {
    const request = indexedDB.deleteDatabase(DB_NAME);
    let settled = false;
    const finish = (result: 'deleted' | 'blocked' | 'error') => {
      if (settled) {
        return;
      }
      settled = true;
      resolve(result);
    };
    // Some browsers stall after onblocked without onsuccess — never hang forever.
    const watchdog = window.setTimeout(() => finish('blocked'), 2500);
    request.onsuccess = () => {
      window.clearTimeout(watchdog);
      finish('deleted');
    };
    request.onerror = () => {
      window.clearTimeout(watchdog);
      finish('error');
    };
    request.onblocked = () => {
      console.warn(
        'IndexedDB delete blocked — fechando conexões e limpando stores…',
      );
      window.clearTimeout(watchdog);
      finish('blocked');
    };
  });
}

/**
 * Physically destroy the IndexedDB database and reset the connection handle.
 */
export async function destroyLocalDatabase(): Promise<void> {
  await closeOpenDatabase();

  let result = await deleteIndexedDatabase();
  if (result !== 'deleted') {
    await clearAllObjectStoresFallback();
    await closeOpenDatabase();
    result = await deleteIndexedDatabase();
    if (result !== 'deleted') {
      await clearAllObjectStoresFallback();
      await closeOpenDatabase();
    }
  }
}

async function clearWebStorage(): Promise<void> {
  try {
    localStorage.clear();
  } catch {
    // ignore
  }
  try {
    sessionStorage.clear();
  } catch {
    // ignore
  }
}

async function clearCacheStorage(): Promise<void> {
  if (!('caches' in globalThis)) {
    return;
  }
  try {
    const keys = await caches.keys();
    await Promise.all(keys.map((key) => caches.delete(key)));
  } catch {
    // ignore
  }
}

async function unregisterServiceWorkers(): Promise<void> {
  if (!('serviceWorker' in navigator)) {
    return;
  }
  try {
    const registrations = await navigator.serviceWorker.getRegistrations();
    await Promise.all(registrations.map((reg) => reg.unregister()));
  } catch {
    // ignore
  }
}

/**
 * Radical local wipe: close IDB, delete the database (with store-clear fallback),
 * clear web storage, Cache Storage, and unregister service workers.
 * Guarantees hasExistingVault() === false afterwards (best-effort, never hangs).
 */
export async function destroyAllUserData(): Promise<void> {
  revokeAllMessageBlobUrls();
  await destroyLocalDatabase();
  await clearWebStorage();

  try {
    await Promise.race([
      clearCacheStorage(),
      new Promise<void>((resolve) => {
        window.setTimeout(resolve, 1500);
      }),
    ]);
  } catch {
    // ignore
  }

  try {
    await Promise.race([
      unregisterServiceWorkers(),
      new Promise<void>((resolve) => {
        window.setTimeout(resolve, 1500);
      }),
    ]);
  } catch {
    // ignore
  }

  // Final hygiene without blocking redirect callers.
  try {
    dbPromise = null;
    await Promise.race([
      (async () => {
        await clearAllObjectStoresFallback();
        await closeOpenDatabase();
      })(),
      new Promise<void>((resolve) => {
        window.setTimeout(resolve, 2000);
      }),
    ]);
  } catch {
    dbPromise = null;
  }
}

/**
 * Panic purge: wipe IndexedDB, revoke blobs, clear web storage and caches.
 * Caller must memzero in-memory keys and force a hard navigation reset in finally.
 */
export async function triggerPanicPurge(): Promise<void> {
  await destroyAllUserData();
}


async function previewTextFromStoredMessage(
  record: StoredMessage,
  vaultKey: Uint8Array,
): Promise<string> {
  if (record.isBurned) {
    return 'Mensagem expirada';
  }
  try {
    const raw = await decryptUtf8(record.ciphertext, record.nonce, vaultKey);
    const body = parseStoredBody(raw);
    if (body.attachment) {
      return body.text.trim() || 'Anexo';
    }
    return body.text;
  } catch {
    return '';
  }
}

/**
 * After a physical message wipe, refresh the conversation preview from the
 * newest remaining message (or empty). Never writes a "deleted" placeholder.
 */
async function refreshConversationPreview(
  conversationWith: string,
  vaultKey: Uint8Array,
): Promise<void> {
  const db = await getDb();
  const existing = await db.get('conversations', conversationWith);
  if (!existing) {
    return;
  }

  const records = await db.getAllFromIndex(
    'messages',
    'conversationWith',
    conversationWith,
  );
  records.sort((a, b) => b.timestamp - a.timestamp);

  let previewSource = '';
  let updatedAt = existing.updatedAt;
  if (records.length > 0) {
    const latest = records[0];
    previewSource = await previewTextFromStoredMessage(latest, vaultKey);
    updatedAt = latest.timestamp;
  }

  const preview = await encryptUtf8(previewSource, vaultKey);
  await db.put('conversations', {
    ...existing,
    lastMessage: packPreview(preview.nonce, preview.ciphertext),
    updatedAt,
  });
}

/**
 * Physical local wipe — no tombstone / "mensagem apagada" row.
 * Overwrites ciphertext with random bytes before delete.
 */
export async function deleteMessageForMe(
  messageId: string,
  vaultKey: Uint8Array,
): Promise<{ conversationWith: string } | null> {
  const record = await shredThenDeleteMessage(messageId);
  if (!record) {
    return null;
  }

  revokeMessageBlobUrls(messageId);
  await refreshConversationPreview(record.conversationWith, vaultKey);
  return { conversationWith: record.conversationWith };
}

/**
 * Local physical wipe used when the user chooses "Apagar para todos"
 * (network fan-out is handled separately by sessionClient).
 */
export async function deleteMessageForAll(
  messageId: string,
  vaultKey: Uint8Array,
): Promise<{ conversationWith: string } | null> {
  return deleteMessageForMe(messageId, vaultKey);
}

/**
 * Apply a remote DELETE_FOR_ALL notice after authorization checks.
 * Authorized wipe leaves zero residual UI/DB traces.
 */
export async function handleRemoteDeleteNotice(
  notice: DeleteMessageNotice,
  vaultKey: Uint8Array,
): Promise<{ deleted: boolean; conversationWith?: string }> {
  const db = await getDb();
  const record = await db.get('messages', notice.targetMessageId);
  if (!record) {
    return { deleted: false };
  }

  const isAuthor = record.senderSessionId === notice.deletedBy;
  let authorized = isAuthor;

  if (!authorized) {
    const groupId =
      notice.groupId ??
      (record.conversationWith.startsWith('group:')
        ? record.conversationWith.slice('group:'.length)
        : undefined);
    if (groupId) {
      const meta = await getGroupMeta(groupId, vaultKey);
      if (meta?.admins.includes(notice.deletedBy)) {
        authorized = true;
      }
    }
  }

  if (!authorized) {
    return { deleted: false };
  }

  revokeMessageBlobUrls(notice.targetMessageId);
  await shredThenDeleteMessage(notice.targetMessageId);
  await refreshConversationPreview(record.conversationWith, vaultKey);
  return { deleted: true, conversationWith: record.conversationWith };
}

export async function deleteConversation(
  conversationWith: string,
): Promise<void> {
  const db = await getDb();
  const records = await db.getAllFromIndex(
    'messages',
    'conversationWith',
    conversationWith,
  );
  for (const record of records) {
    revokeMessageBlobUrls(record.id);
    await shredThenDeleteMessage(record.id);
  }
  await db.delete('conversations', conversationWith);
}

export async function purgeExpiredMessages(): Promise<number> {
  const db = await getDb();
  const now = Date.now();
  const index = db.transaction('messages', 'readonly').store.index('expiresAt');
  const expired: string[] = [];
  let cursor = await index.openCursor(IDBKeyRange.upperBound(now));

  while (cursor) {
    expired.push(cursor.value.id);
    cursor = await cursor.continue();
  }

  for (const messageId of expired) {
    revokeMessageBlobUrls(messageId);
    await shredThenDeleteMessage(messageId);
  }
  return expired.length;
}

export async function saveGroupMeta(
  meta: GroupMeta,
  vaultKey: Uint8Array,
  options?: { syncTitle?: boolean },
): Promise<void> {
  if (!meta.groupKeyHex) {
    throw new Error('Não é possível persistir grupo sem chave.');
  }

  const s = await ensureSodium();
  const keyBytes = s.from_hex(meta.groupKeyHex);
  const { ciphertext, nonce } = await encryptUtf8(
    s.to_base64(keyBytes),
    vaultKey,
  );
  s.memzero(keyBytes);

  const stored: StoredGroup = {
    groupId: meta.groupId,
    name: meta.name,
    admins: [...meta.admins],
    members: [...meta.members],
    keyVersion: meta.keyVersion,
    groupKeyCiphertext: ciphertext,
    groupKeyNonce: nonce,
  };

  const db = await getDb();
  const titlePreview = await encryptUtf8(`Grupo: ${meta.name}`, vaultKey);
  const conversation: StoredConversation = {
    peerSessionId: conversationKeyForGroup(meta.groupId),
    lastMessage: packPreview(titlePreview.nonce, titlePreview.ciphertext),
    updatedAt: Date.now(),
    isGroup: true,
    groupId: meta.groupId,
  };

  const tx = db.transaction(['groups', 'conversations'], 'readwrite');
  await tx.objectStore('groups').put(stored);
  const existing = await tx
    .objectStore('conversations')
    .get(conversation.peerSessionId);
  if (existing && !options?.syncTitle) {
    conversation.lastMessage = existing.lastMessage;
    conversation.updatedAt = Math.max(
      existing.updatedAt,
      conversation.updatedAt,
    );
  }
  await tx.objectStore('conversations').put(conversation);
  await tx.done;
}

export async function getGroupMeta(
  groupId: string,
  vaultKey: Uint8Array,
): Promise<GroupMeta | null> {
  const db = await getDb();
  const stored = await db.get('groups', groupId);
  if (!stored) {
    return null;
  }

  const s = await ensureSodium();
  try {
    const keyB64 = await decryptUtf8(
      stored.groupKeyCiphertext,
      stored.groupKeyNonce,
      vaultKey,
    );
    const keyBytes = s.from_base64(keyB64);
    const admins =
      Array.isArray(stored.admins) && stored.admins.length > 0
        ? [...stored.admins]
        : stored.adminSessionId
          ? [stored.adminSessionId]
          : [];

    const meta: GroupMeta = {
      groupId: stored.groupId,
      name: stored.name,
      admins,
      members: [...stored.members],
      groupKeyHex: s.to_hex(keyBytes),
      keyVersion: stored.keyVersion,
    };
    s.memzero(keyBytes);
    return meta;
  } catch {
    return null;
  }
}

export async function updateGroupMembers(
  groupId: string,
  newMembers: string[],
  vaultKey: Uint8Array,
): Promise<GroupMeta | null> {
  const meta = await getGroupMeta(groupId, vaultKey);
  if (!meta) {
    return null;
  }
  const updated: GroupMeta = {
    ...meta,
    members: Array.from(new Set(newMembers.map((m) => m.trim()).filter(Boolean))),
  };
  await saveGroupMeta(updated, vaultKey);
  return updated;
}

export async function deleteGroup(groupId: string): Promise<void> {
  const db = await getDb();
  const conversationId = conversationKeyForGroup(groupId);
  await deleteConversation(conversationId);
  await db.delete('groups', groupId);
}

/**
 * Merge decrypted backup messages into IndexedDB, skipping duplicate IDs.
 * Returns the number of newly inserted messages.
 */
export async function mergeImportedMessages(
  messages: DecryptedMessage[],
  conversationWith: string,
  vaultKey: Uint8Array,
  options?: { isGroup?: boolean; groupId?: string },
): Promise<number> {
  const db = await getDb();
  const sorted = [...messages].sort((a, b) => a.timestamp - b.timestamp);
  let imported = 0;

  for (const msg of sorted) {
    const existing = await db.get('messages', msg.id);
    if (existing) {
      continue;
    }

    const inner: InnerMessage = {
      id: msg.id,
      senderSessionId: msg.senderSessionId,
      text: msg.isBurned
        ? '[Mensagem destruída após visualização]'
        : msg.plainText,
      sentAt: msg.timestamp,
      viewPolicy: normalizeViewPolicy(msg.viewPolicy),
      isBurned: msg.isBurned,
    };
    if (msg.attachment && !msg.isBurned) {
      inner.attachment = msg.attachment;
    }
    if (options?.groupId) {
      inner.groupId = options.groupId;
    }
    if (typeof msg.expiresAt === 'number' && msg.expiresAt > msg.timestamp) {
      const ttlDays = Math.max(
        1,
        Math.round((msg.expiresAt - msg.timestamp) / 86_400_000),
      );
      inner.ttlDays = ttlDays;
    }

    await saveIncomingOrOutgoingMessage(inner, conversationWith, vaultKey);

    // Preserve view counters from the backup snapshot.
    const stored = await db.get('messages', msg.id);
    if (stored) {
      stored.viewCount = msg.viewCount;
      stored.isBurned = msg.isBurned || stored.isBurned;
      await db.put('messages', stored);
    }
    imported += 1;
  }

  return imported;
}
