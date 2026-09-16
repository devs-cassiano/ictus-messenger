/**
 * Ephemeral tab session — survives F5 via sessionStorage, cleared on tab close
 * and on explicit Lock / Panic.
 *
 * Material is Base64-encoded working keys (not plaintext PIN). XSS can still
 * read sessionStorage; this is an intentional UX trade-off for refresh survival.
 */

import { ensureSodium, type IdentityKeyPair } from '../crypto/identity';

const TAB_SESSION_KEY = 'ictus.tabSession.v1';

export type TabSessionPayload = {
  v: 1;
  sessionId: string;
  vaultKeyB64: string;
  publicKeyB64: string;
  privateKeyB64: string;
  keyType: string;
  savedAt: number;
};

export type RestoredTabSession = {
  sessionId: string;
  vaultKey: Uint8Array;
  keyPair: IdentityKeyPair;
};

function canUseSessionStorage(): boolean {
  try {
    const probe = '__ictus_ss_probe__';
    sessionStorage.setItem(probe, '1');
    sessionStorage.removeItem(probe);
    return true;
  } catch {
    return false;
  }
}

/** Persist unlocked vault + identity for this browser tab only. */
export async function saveTabSession(options: {
  sessionId: string;
  vaultKey: Uint8Array;
  keyPair: IdentityKeyPair;
}): Promise<void> {
  if (!canUseSessionStorage()) {
    return;
  }
  const s = await ensureSodium();
  const payload: TabSessionPayload = {
    v: 1,
    sessionId: options.sessionId.trim().toLowerCase(),
    vaultKeyB64: s.to_base64(
      options.vaultKey,
      s.base64_variants.ORIGINAL,
    ),
    publicKeyB64: s.to_base64(
      options.keyPair.publicKey,
      s.base64_variants.ORIGINAL,
    ),
    privateKeyB64: s.to_base64(
      options.keyPair.privateKey,
      s.base64_variants.ORIGINAL,
    ),
    keyType: options.keyPair.keyType || 'ed25519',
    savedAt: Date.now(),
  };
  sessionStorage.setItem(TAB_SESSION_KEY, JSON.stringify(payload));
}

/** Clear tab session (Lock / Sair / Panic). */
export function clearTabSession(): void {
  try {
    sessionStorage.removeItem(TAB_SESSION_KEY);
  } catch {
    // ignore
  }
}

/**
 * Restore working keys from sessionStorage.
 * Returns null if missing, corrupt, or cryptographic material is invalid.
 */
export async function loadTabSession(): Promise<RestoredTabSession | null> {
  if (!canUseSessionStorage()) {
    return null;
  }

  let raw: string | null;
  try {
    raw = sessionStorage.getItem(TAB_SESSION_KEY);
  } catch {
    return null;
  }
  if (!raw) {
    return null;
  }

  const s = await ensureSodium();
  try {
    const parsed = JSON.parse(raw) as Partial<TabSessionPayload>;
    if (
      parsed.v !== 1 ||
      typeof parsed.sessionId !== 'string' ||
      typeof parsed.vaultKeyB64 !== 'string' ||
      typeof parsed.publicKeyB64 !== 'string' ||
      typeof parsed.privateKeyB64 !== 'string'
    ) {
      clearTabSession();
      return null;
    }

    const vaultKey = s.from_base64(
      parsed.vaultKeyB64,
      s.base64_variants.ORIGINAL,
    );
    const publicKey = s.from_base64(
      parsed.publicKeyB64,
      s.base64_variants.ORIGINAL,
    );
    const privateKey = s.from_base64(
      parsed.privateKeyB64,
      s.base64_variants.ORIGINAL,
    );

    if (
      vaultKey.length !== 32 ||
      publicKey.length !== s.crypto_sign_PUBLICKEYBYTES ||
      (privateKey.length !== s.crypto_sign_SECRETKEYBYTES &&
        privateKey.length !== 32)
    ) {
      s.memzero(vaultKey);
      s.memzero(publicKey);
      s.memzero(privateKey);
      clearTabSession();
      return null;
    }

    // Ensure secret key matches Session ID (05 + ed25519 pk).
    let secretKey = privateKey;
    if (privateKey.length === 32) {
      const kp = s.crypto_sign_seed_keypair(privateKey);
      s.memzero(privateKey);
      secretKey = kp.privateKey;
    }
    const derivedPk = s.crypto_sign_ed25519_sk_to_pk(secretKey);
    const expectedId = `05${s.to_hex(derivedPk)}`;
    const sessionId = parsed.sessionId.trim().toLowerCase();
    if (expectedId !== sessionId) {
      s.memzero(vaultKey);
      s.memzero(publicKey);
      s.memzero(secretKey);
      s.memzero(derivedPk);
      clearTabSession();
      return null;
    }
    // Prefer derived public key for consistency.
    s.memzero(publicKey);

    return {
      sessionId,
      vaultKey,
      keyPair: {
        keyType: parsed.keyType || 'ed25519',
        publicKey: derivedPk,
        privateKey: secretKey,
      },
    };
  } catch {
    clearTabSession();
    return null;
  }
}
