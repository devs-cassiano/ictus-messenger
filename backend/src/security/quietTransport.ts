/**
 * Classify expected upstream/transport noise (do not spam stderr).
 */

const NOISE_CODES = new Set([
  'ECONNREFUSED',
  'ETIMEDOUT',
  'ECONNRESET',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'ENOTFOUND',
  'EAI_AGAIN',
  'EPIPE',
  'ERR_CANCELED',
  'ERR_BAD_RESPONSE',
  'ECONNABORTED',
]);

const NOISE_MESSAGE_RE =
  /ECONNREFUSED|ETIMEDOUT|ECONNRESET|EHOSTUNREACH|ENETUNREACH|socket hang up|timeout|Network Error|Falha no transporte|Falha de conexão|Upstream node unreachable|connect ECONNREFUSED|getaddrinfo/i;

export function isExpectedUpstreamNoise(err: unknown): boolean {
  if (err && typeof err === 'object') {
    const record = err as {
      code?: unknown;
      cause?: unknown;
      message?: unknown;
    };
    if (typeof record.code === 'string' && NOISE_CODES.has(record.code)) {
      return true;
    }
    if (record.cause && isExpectedUpstreamNoise(record.cause)) {
      return true;
    }
  }
  const message = err instanceof Error ? err.message : String(err ?? '');
  return NOISE_MESSAGE_RE.test(message);
}

/** Log only unexpected failures — expected transport noise stays silent. */
export function logUnexpectedRelayError(tag: string, err: unknown): void {
  if (isExpectedUpstreamNoise(err)) {
    return;
  }
  const message = err instanceof Error ? err.message : String(err);
  // eslint-disable-next-line no-console
  console.error(tag, message);
}
