import sodium from 'libsodium-wrappers-sumo';
import { ensureSodium } from './identity';

/** Fixed 16-byte salt (hex) used when no salt is provided. */
const FALLBACK_SALT_HEX = '0123456789abcdef0123456789abcdef';

export const ACCOUNT_PIN_MIN = 4;
/** Local account PIN: 4–6 digits (Argon2id vault seal). */
export const ACCOUNT_PIN_MAX = 6;

/**
 * Derive a 32-byte vault key from a PIN using Argon2id (moderate limits).
 * Mitigates offline dictionary/GPU attacks against low-entropy numeric PINs.
 * PIN bytes are zeroed immediately after derivation.
 */
export async function deriveVaultKey(
  pin: string,
  salt?: Uint8Array | null,
): Promise<Uint8Array> {
  await sodium.ready;

  if (typeof pin !== 'string' || pin.length === 0) {
    throw new Error('PIN inválido: informe um PIN não vazio.');
  }

  const expectedSaltBytes = sodium.crypto_pwhash_SALTBYTES;
  let resolvedSalt: Uint8Array;

  if (salt == null) {
    resolvedSalt = sodium.from_hex(FALLBACK_SALT_HEX);
  } else if (!(salt instanceof Uint8Array)) {
    throw new Error('Salt inválido: esperado Uint8Array.');
  } else if (salt.length !== expectedSaltBytes) {
    throw new Error(
      `Salt inválido: esperado exatamente ${expectedSaltBytes} bytes, recebido ${salt.length}.`,
    );
  } else {
    resolvedSalt = salt;
  }

  if (resolvedSalt.length !== expectedSaltBytes) {
    throw new Error(
      `Salt inválido: esperado exatamente ${expectedSaltBytes} bytes.`,
    );
  }

  const pinBytes = sodium.from_string(pin);
  try {
    return sodium.crypto_pwhash(
      32,
      pinBytes,
      resolvedSalt,
      sodium.crypto_pwhash_OPSLIMIT_MODERATE,
      sodium.crypto_pwhash_MEMLIMIT_MODERATE,
      sodium.crypto_pwhash_ALG_ARGON2ID13,
    );
  } finally {
    sodium.memzero(pinBytes);
  }
}

export function normalizeAccountPin(raw: string): string {
  return raw.replace(/\D/g, '').slice(0, ACCOUNT_PIN_MAX);
}

export function isValidAccountPin(pin: string): boolean {
  return /^\d+$/.test(pin) && pin.length >= ACCOUNT_PIN_MIN && pin.length <= ACCOUNT_PIN_MAX;
}

/**
 * Seal the mnemonic string under the PIN-derived vault key (ChaCha20-Poly1305).
 */
export async function sealMnemonic(
  mnemonic: string,
  vaultKey: Uint8Array,
): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array }> {
  const s = await ensureSodium();
  const nonce = s.randombytes_buf(s.crypto_secretbox_NONCEBYTES);
  const plain = s.from_string(mnemonic);
  try {
    const ciphertext = s.crypto_secretbox_easy(plain, nonce, vaultKey);
    return { ciphertext, nonce };
  } finally {
    s.memzero(plain);
  }
}

/**
 * Open a PIN-sealed mnemonic. Returns null when the MAC fails (wrong PIN).
 */
export async function openMnemonic(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  vaultKey: Uint8Array,
): Promise<string | null> {
  const s = await ensureSodium();
  let plain: Uint8Array | undefined;
  try {
    plain = s.crypto_secretbox_open_easy(ciphertext, nonce, vaultKey);
    return s.to_string(plain);
  } catch {
    return null;
  } finally {
    if (plain) {
      s.memzero(plain);
    }
  }
}
