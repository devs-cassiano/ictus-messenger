/**
 * BIP39 mnemonic → deterministic Ed25519 identity (Session ID `05` + pubkey hex).
 * Mnemonic plaintext is never persisted — only PIN-sealed ciphertext reaches IndexedDB.
 */

import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { ensureSodium, type IdentityKeyPair } from './identity';

export const MNEMONIC_WORD_COUNT = 12;

/** Normalize user input to lowercase single-spaced words. */
export function normalizeMnemonic(raw: string): string {
  return raw
    .normalize('NFKC')
    .trim()
    .toLowerCase()
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, '')
    .split(/\s+/)
    .filter(Boolean)
    .join(' ');
}

export function isValidMnemonic(raw: string): boolean {
  const phrase = normalizeMnemonic(raw);
  const words = phrase.split(' ');
  if (words.length !== MNEMONIC_WORD_COUNT) {
    return false;
  }
  return validateMnemonic(phrase, wordlist);
}

/** Create a new English BIP39 12-word recovery phrase. */
export function createMnemonic(): string {
  return generateMnemonic(wordlist, 128);
}

/**
 * Derive Session Ed25519 identity from a BIP39 mnemonic.
 * Uses the first 32 bytes of the BIP39 seed as `crypto_sign_seed_keypair` seed.
 */
export async function identityFromMnemonic(raw: string): Promise<{
  sessionId: string;
  keyPair: IdentityKeyPair;
  mnemonic: string;
}> {
  const mnemonic = normalizeMnemonic(raw);
  if (!isValidMnemonic(mnemonic)) {
    throw new Error('Frase de recuperação inválida.');
  }

  const s = await ensureSodium();
  const seed64 = mnemonicToSeedSync(mnemonic);
  const seed32 = seed64.slice(0, 32);
  try {
    const keyPair = s.crypto_sign_seed_keypair(seed32) as IdentityKeyPair;
    const sessionId = `05${s.to_hex(keyPair.publicKey)}`;
    return { sessionId, keyPair, mnemonic };
  } finally {
    seed32.fill(0);
    seed64.fill(0);
  }
}

/** Fisher–Yates shuffle (copy); used for recovery-phrase verification chips. */
export function shuffleWords(words: readonly string[]): string[] {
  const next = [...words];
  for (let i = next.length - 1; i > 0; i -= 1) {
    const j = Math.floor(Math.random() * (i + 1));
    const tmp = next[i]!;
    next[i] = next[j]!;
    next[j] = tmp;
  }
  return next;
}

/**
 * Build a plain-text recovery backup for one-time download.
 * Caller must never persist this string in IndexedDB / localStorage.
 */
export function formatRecoveryBackupFile(
  sessionId: string,
  mnemonic: string,
): string {
  const phrase = normalizeMnemonic(mnemonic);
  const lines = [
    'Ictus Session — Recovery Key Backup',
    '====================================',
    '',
    'WARNING: Anyone with this file can take over your identity.',
    'Store it offline. Never share it. Never upload it to cloud sync.',
    'This phrase will not be shown again during account creation.',
    '',
    `Session ID:`,
    sessionId,
    '',
    'Recovery Phrase (12 words, BIP-39 English):',
    phrase,
    '',
    'Keep this file in a safe place. Delete copies you no longer need.',
    '',
  ];
  return lines.join('\n');
}

/** Trigger a browser download of the recovery .txt (no disk write by the app). */
export function downloadRecoveryBackupFile(
  sessionId: string,
  mnemonic: string,
  filename = 'ictus-recovery-key.txt',
): void {
  const body = formatRecoveryBackupFile(sessionId, mnemonic);
  const blob = new Blob([body], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.rel = 'noopener';
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 2_000);
}
