/**
 * Session ID and message-text validation / sanitization helpers.
 */

/** Session ID: `05` + 64 lowercase hex chars (Ed25519 pubkey). */
export const SESSION_ID_REGEX = /^05[0-9a-f]{64}$/;

const MAX_MESSAGE_CHARS = 8_000;

/**
 * Strip whitespace / non-printables, lowercase, and validate Session ID shape.
 * Returns the canonical 66-char id, or `null` when invalid.
 */
export function sanitizeSessionId(rawInput: string): string | null {
  const cleaned = rawInput
    .normalize('NFKC')
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, '')
    .replace(/\s+/g, '')
    .trim()
    .toLowerCase();

  if (!SESSION_ID_REGEX.test(cleaned)) {
    return null;
  }
  return cleaned;
}

/** Throw when the Session ID is not exactly the expected format. */
export function assertSessionId(rawInput: string): string {
  const id = sanitizeSessionId(rawInput);
  if (!id) {
    throw new Error('Session ID inválido (esperado 05 + 64 hex).');
  }
  return id;
}

export function isCanonicalSessionId(value: string): boolean {
  return SESSION_ID_REGEX.test(value);
}

/**
 * Bound message body length for vault / display paths (plain text only).
 */
export function clampMessageText(text: string, max = MAX_MESSAGE_CHARS): string {
  if (text.length <= max) {
    return text;
  }
  return text.slice(0, max);
}
