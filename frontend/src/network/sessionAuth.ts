/**
 * Session storage_rpc authentication helpers.
 *
 * Canonical signatures (namespace 0): UTF-8 of `{method}{timestamp_ms}`
 * e.g. "retrieve1726420149000" / "store1726420149000"
 * (namespace 0 contributes an empty segment in the signed string, but we
 * still send `namespace: 0` explicitly in JSON params).
 */

import { ensureSodium } from '../crypto/identity';
import {
  normalizeSessionPubkey,
  type SessionAuthHeaders,
} from './snodePool';

/** Default private-message namespace on oxen-storage-server. */
export const DEFAULT_NAMESPACE = 0;

/** Alias — Session storage pubkey is always `05` + 64 hex (66 chars). */
export function formatSessionPubkey(key: string): string {
  return normalizeSessionPubkey(key);
}

/** Ed25519 public key hex (64 chars) embedded in a Session ID. */
export function ed25519HexFromSessionId(sessionId: string): string {
  const full = formatSessionPubkey(sessionId);
  if (full.startsWith('05') && full.length === 66) {
    return full.slice(2);
  }
  return full;
}

/** Standard padded Base64 required by oxen-storage-server for signatures. */
export async function toSessionBase64(bytes: Uint8Array): Promise<string> {
  const s = await ensureSodium();
  return s.to_base64(bytes, s.base64_variants.ORIGINAL);
}

/**
 * Normalize to libsodium 64-byte secret key (seed‖pubkey) and assert it
 * matches the Ed25519 pubkey embedded in the Session ID.
 */
export async function normalizeSigningSecretKey(
  ed25519PrivateKey: Uint8Array,
  sessionId: string,
): Promise<Uint8Array> {
  const s = await ensureSodium();
  const expectedPkHex = ed25519HexFromSessionId(sessionId);

  let secretKey: Uint8Array;
  if (ed25519PrivateKey.length === 64) {
    secretKey = ed25519PrivateKey;
  } else if (ed25519PrivateKey.length === 32) {
    const kp = s.crypto_sign_seed_keypair(ed25519PrivateKey);
    secretKey = kp.privateKey;
  } else {
    throw new Error(
      `Ed25519 secret key must be 32 or 64 bytes (got ${ed25519PrivateKey.length})`,
    );
  }

  const derivedPk = s.crypto_sign_ed25519_sk_to_pk(secretKey);
  const derivedHex = s.to_hex(derivedPk);
  if (derivedHex !== expectedPkHex) {
    throw new Error(
      `Signing key pubkey ${derivedHex.slice(0, 8)}… does not match Session ID ${expectedPkHex.slice(0, 8)}…`,
    );
  }
  return secretKey;
}

/**
 * Sign retrieve/store/delete: UTF-8(`{method}{namespace?}{timestamp_ms}`).
 * Namespace 0 → empty segment in the signed string.
 */
export async function signStorageRequest(
  method: string,
  timestampMs: number,
  ed25519PrivateKey: Uint8Array,
  sessionId: string,
  namespace = DEFAULT_NAMESPACE,
): Promise<string> {
  const s = await ensureSodium();
  const ts = Math.floor(timestampMs);
  const secretKey = await normalizeSigningSecretKey(
    ed25519PrivateKey,
    sessionId,
  );

  const message = new TextEncoder().encode(
    namespace === 0 ? `${method}${ts}` : `${method}${namespace}${ts}`,
  );
  const sigBytes = s.crypto_sign_detached(message, secretKey);
  try {
    const publicKey = s.crypto_sign_ed25519_sk_to_pk(secretKey);
    if (!s.crypto_sign_verify_detached(sigBytes, message, publicKey)) {
      throw new Error('Local Ed25519 self-verify failed for storage auth');
    }
    return s.to_base64(sigBytes, s.base64_variants.ORIGINAL);
  } finally {
    s.memzero(sigBytes);
  }
}

export type { SessionAuthHeaders };

export type RetrieveAuthBundle = {
  params: {
    pubkey: string;
    timestamp: number;
    signature: string;
    last_hash: string;
    namespace: number;
  };
  headers: SessionAuthHeaders;
};

/**
 * Authenticated retrieve params (explicit namespace 0).
 */
export async function buildRetrieveParams(options: {
  sessionId: string;
  ed25519SecretKey: Uint8Array;
  lastHash?: string;
  timestampMs?: number;
  namespace?: number;
}): Promise<RetrieveAuthBundle> {
  const timestamp = Math.floor(options.timestampMs ?? Date.now());
  const namespace = options.namespace ?? DEFAULT_NAMESPACE;
  const pubkey = formatSessionPubkey(options.sessionId);
  const signature = await signStorageRequest(
    'retrieve',
    timestamp,
    options.ed25519SecretKey,
    pubkey,
    namespace,
  );

  const params = {
    pubkey,
    timestamp,
    signature,
    last_hash: options.lastHash ?? '',
    namespace,
  };

  const headers: SessionAuthHeaders = {
    'X-Session-Timestamp': String(timestamp),
    'X-Session-Signature': signature,
    'X-Session-Pubkey': pubkey,
  };

  return { params, headers };
}

/**
 * Store params for destination inbox (namespace 0).
 * When signer is provided, attaches authenticated store signature (sender key).
 */
export async function buildStoreParams(options: {
  destinationSessionId: string;
  dataBase64: string;
  ttlSeconds: number;
  timestampMs?: number;
  namespace?: number;
  /** Sender Session ID + secret — enables authenticated store. */
  signerSessionId?: string;
  signerSecretKey?: Uint8Array;
}): Promise<Record<string, unknown>> {
  const timestamp = Math.floor(options.timestampMs ?? Date.now());
  const namespace = options.namespace ?? DEFAULT_NAMESPACE;
  const pubkey = formatSessionPubkey(options.destinationSessionId);

  const params: Record<string, unknown> = {
    pubkey,
    ttl: Math.floor(options.ttlSeconds),
    timestamp,
    data: options.dataBase64,
    namespace,
  };

  if (options.signerSecretKey && options.signerSessionId) {
    const signerId = formatSessionPubkey(options.signerSessionId);
    const signature = await signStorageRequest(
      'store',
      timestamp,
      options.signerSecretKey,
      signerId,
      namespace,
    );
    params.signature = signature;
    params.pubkey_ed25519 = ed25519HexFromSessionId(signerId);
    params.sig_timestamp = timestamp;
  }

  return params;
}

/** @deprecated use signStorageRequest */
export function canonicalSignMessage(
  method: string,
  timestampMs: number,
  namespace = 0,
): Uint8Array {
  const ts = Math.floor(timestampMs);
  const nsFragment = namespace === 0 ? '' : String(namespace);
  return new TextEncoder().encode(`${method}${nsFragment}${ts}`);
}
