import sodium from 'libsodium-wrappers-sumo';
import { sanitizeSessionId } from '../utils/validators';

/** Ed25519 identity key pair produced by `crypto_sign_keypair`. */
export type IdentityKeyPair = {
  keyType: string;
  publicKey: Uint8Array;
  privateKey: Uint8Array;
};

export async function ensureSodium(): Promise<typeof sodium> {
  await sodium.ready;
  return sodium;
}

export async function generateIdentity(): Promise<{
  sessionId: string;
  keyPair: IdentityKeyPair;
}> {
  const s = await ensureSodium();
  const keyPair = s.crypto_sign_keypair() as IdentityKeyPair;
  const sessionId = `05${s.to_hex(keyPair.publicKey)}`;
  return { sessionId, keyPair };
}

/** Session ID: '05' + 64 hex chars (Ed25519 pubkey). */
export function isValidSessionId(value: string): boolean {
  return sanitizeSessionId(value) !== null;
}

/** Extract a Session ID from raw QR / paste text. */
export function extractSessionId(raw: string): string | null {
  const direct = sanitizeSessionId(raw);
  if (direct) {
    return direct;
  }
  const match = raw.match(/05[0-9a-fA-F]{64}/);
  if (!match) {
    return null;
  }
  return sanitizeSessionId(match[0]);
}
