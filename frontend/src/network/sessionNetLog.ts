/**
 * Structured [SESSION-NET] console logger for decentralized Session traffic.
 * Never logs private keys, PINs, or plaintext message bodies — metadata only.
 * INFO / SUCCESS / verified are silent unless ENABLE_DEBUG_LOGS is flipped on.
 */

export type SessionNetLevel = 'INFO' | 'SUCCESS' | 'WARN' | 'ERROR';

/** Flip to true only when diagnosing Session network traffic locally. */
const ENABLE_DEBUG_LOGS = false;

const TAG = '[SESSION-NET]';

export const sessionNetLog = {
  info(message: string, detail?: unknown): void {
    if (!ENABLE_DEBUG_LOGS) {
      return;
    }
    if (detail !== undefined) {
      // eslint-disable-next-line no-console
      console.log(`${TAG} INFO`, message, detail);
    } else {
      // eslint-disable-next-line no-console
      console.log(`${TAG} INFO`, message);
    }
  },
  success(message: string, detail?: unknown): void {
    if (!ENABLE_DEBUG_LOGS) {
      return;
    }
    if (detail !== undefined) {
      // eslint-disable-next-line no-console
      console.log(`${TAG} SUCCESS`, message, detail);
    } else {
      // eslint-disable-next-line no-console
      console.log(`${TAG} SUCCESS`, message);
    }
  },
  warn(message: string, detail?: unknown): void {
    if (detail !== undefined) {
      // eslint-disable-next-line no-console
      console.warn(`${TAG} WARN`, message, detail);
    } else {
      // eslint-disable-next-line no-console
      console.warn(`${TAG} WARN`, message);
    }
  },
  error(message: string, detail?: unknown): void {
    if (detail !== undefined) {
      // eslint-disable-next-line no-console
      console.error(`${TAG} ERROR`, message, detail);
    } else {
      // eslint-disable-next-line no-console
      console.error(`${TAG} ERROR`, message);
    }
  },
  /** Hard proof that ciphertext was found on-node after store (debug only). */
  verified(message: string, detail?: unknown): void {
    if (!ENABLE_DEBUG_LOGS) {
      return;
    }
    // eslint-disable-next-line no-console
    console.log('[SESSION-NET-VERIFIED]', message, detail ?? '');
  },
  /** Store returned 200 but retrieve could not find the payload. */
  verifyError(message: string, detail?: unknown): void {
    // eslint-disable-next-line no-console
    console.error('[SESSION-NET-ERROR]', message, detail ?? '');
  },
};

/** Truncate Session ID / pubkey for safe console display. */
export function truncateId(id: string, head = 8, tail = 6): string {
  const value = id.trim();
  if (value.length <= head + tail + 1) {
    return value;
  }
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

export function truncateHash(hash: string, head = 10): string {
  if (!hash) {
    return '(empty)';
  }
  if (hash.length <= head) {
    return hash;
  }
  return `${hash.slice(0, head)}…`;
}

export interface SnodeLogView {
  ip: string;
  port: number;
  pubkey_ed25519: string;
}

/** Safe node summary: IP, port, truncated node pubkey only. */
export function summarizeSnode(node: {
  ip: string;
  port: number;
  pubkey_ed25519: string;
}): SnodeLogView {
  return {
    ip: node.ip,
    port: node.port,
    pubkey_ed25519: truncateId(node.pubkey_ed25519, 10, 6),
  };
}

export function summarizeSnodes(
  nodes: ReadonlyArray<{ ip: string; port: number; pubkey_ed25519: string }>,
): SnodeLogView[] {
  return nodes.map(summarizeSnode);
}

export function snodeEndpoint(node: { ip: string; port: number }): string {
  return `${node.ip}:${node.port}`;
}

/** Extract a safe RPC status label from a JSON-RPC / storage response body. */
export function describeRpcResult(payload: unknown): string {
  if (payload === null || payload === undefined) {
    return 'empty';
  }
  if (typeof payload === 'string') {
    return `string(${payload.length})`;
  }
  if (typeof payload !== 'object') {
    return typeof payload;
  }

  const record = payload as Record<string, unknown>;
  if (typeof record.error === 'string') {
    return `error: ${record.error}`;
  }
  if (record.error && typeof record.error === 'object') {
    const err = record.error as Record<string, unknown>;
    const code = err.code;
    const msg = typeof err.message === 'string' ? err.message : 'rpc-error';
    return `error(${String(code ?? '?')}): ${msg}`;
  }
  if (typeof record.status === 'string') {
    return `status: ${record.status}`;
  }
  if (record.result !== undefined) {
    return `result(${describeRpcResult(record.result)})`;
  }
  if (Array.isArray(record.messages)) {
    return `messages: ${record.messages.length}`;
  }
  if (Array.isArray(record.snodes)) {
    return `snodes: ${record.snodes.length}`;
  }
  return 'ok(object)';
}

export function httpStatusFromError(err: unknown): string {
  if (!(err instanceof Error)) {
    return 'unknown';
  }
  const match = err.message.match(/HTTP\s+(\d+)/i);
  if (match?.[1]) {
    return match[1];
  }
  if (err.name === 'AbortError' || /abort|timeout/i.test(err.message)) {
    return 'timeout';
  }
  return 'error';
}
