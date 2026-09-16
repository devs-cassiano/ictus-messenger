/**
 * Session storage_rpc client — store / retrieve against destination swarms.
 */

import { ensureSodium } from '../crypto/identity';
import type { HybridEnvelope } from '../crypto/envelope';
import {
  buildRetrieveParams,
  buildStoreParams,
  toSessionBase64,
} from './sessionAuth';
import {
  getSharedSnodePool,
  normalizeSessionPubkey,
  resetSharedSnodePool,
  type Snode,
  type SnodeTransportMode,
} from './snodePool';
import {
  sessionNetLog,
  snodeEndpoint,
  summarizeSnodes,
  truncateHash,
  truncateId,
} from './sessionNetLog';

export const DEFAULT_TTL_MS = 14 * 24 * 60 * 60 * 1000; // 14 days (legacy)
/** Storage servers expect TTL in seconds (14 days). */
export const DEFAULT_TTL_SECONDS = 14 * 24 * 60 * 60; // 1_209_600
export const EPHEMERAL_TTL_MS = 24 * 60 * 60 * 1000; // 1 day

type Sodium = Awaited<ReturnType<typeof ensureSodium>>;

export interface StoreMessageOptions {
  /** TTL in milliseconds; converted to seconds before store RPC. */
  ttlMs?: number;
  replicas?: number;
  signal?: AbortSignal;
  /**
   * Local user's Ed25519 secret key — required to authenticate the
   * post-store retrieve (RYOW). Must match `signerSessionId`.
   */
  signerSecretKey?: Uint8Array;
  /** Local user's Session ID (`05…`) corresponding to signerSecretKey. */
  signerSessionId?: string;
}

export interface RetrieveMessagesOptions {
  lastHash?: string;
  signal?: AbortSignal;
}

export interface RetrievedMessage {
  hash: string;
  timestamp: number;
  expiration?: number;
  data: string;
  envelope: HybridEnvelope | null;
}

/** Last sync hash per local Session ID (in-memory only). */
const lastHashByPubkey = new Map<string, string>();

let networkAbort: AbortController | null = null;

function getNetworkAbortSignal(): AbortSignal {
  if (!networkAbort || networkAbort.signal.aborted) {
    networkAbort = new AbortController();
  }
  return networkAbort.signal;
}

export function configureSnodeTransport(mode: SnodeTransportMode): void {
  getSharedSnodePool().setTransportMode(mode);
}

export function resetNetworkSession(): void {
  sessionNetLog.info('Reset da sessão de rede (abort + limpeza do pool)');
  networkAbort?.abort();
  networkAbort = null;
  lastHashByPubkey.clear();
  lastRefreshFailureAt = 0;
  resetSharedSnodePool();
}

export function getLastRetrieveHash(sessionId: string): string {
  return lastHashByPubkey.get(normalizeSessionPubkey(sessionId)) ?? '';
}

export function setLastRetrieveHash(sessionId: string, hash: string): void {
  lastHashByPubkey.set(normalizeSessionPubkey(sessionId), hash);
}

function isHybridEnvelope(value: unknown): value is HybridEnvelope {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate.wrappedKey === 'string' &&
    typeof candidate.bodyCiphertext === 'string' &&
    typeof candidate.nonce === 'string'
  );
}

/** Decode Base64 trying Session/storage variants (store uses ORIGINAL). */
function decodeBase64Variants(
  s: Sodium,
  raw: string,
): string | null {
  const variants = [
    s.base64_variants.ORIGINAL,
    s.base64_variants.ORIGINAL_NO_PADDING,
    s.base64_variants.URLSAFE,
    s.base64_variants.URLSAFE_NO_PADDING,
  ];
  for (const variant of variants) {
    try {
      return s.to_string(s.from_base64(raw, variant));
    } catch {
      // try next
    }
  }
  try {
    return new TextDecoder().decode(
      Uint8Array.from(atob(raw), (c) => c.charCodeAt(0)),
    );
  } catch {
    return null;
  }
}

/**
 * Peel Base64 → UTF-8 JSON wrappers until a HybridEnvelope is found.
 * Stored SNode `data` is typically ORIGINAL Base64 of
 * `{"wrappedKey","bodyCiphertext","nonce"}`.
 */
export function tryParseEnvelope(raw: unknown, s: Sodium): HybridEnvelope | null {
  if (isHybridEnvelope(raw)) {
    return raw;
  }

  if (typeof raw !== 'string' || raw.length === 0) {
    return null;
  }

  const queue: string[] = [raw];
  const seen = new Set<string>();

  while (queue.length > 0) {
    const current = queue.shift()!;
    if (seen.has(current)) {
      continue;
    }
    seen.add(current);

    // Direct JSON text
    if (current.trim().startsWith('{')) {
      try {
        const parsed: unknown = JSON.parse(current);
        if (isHybridEnvelope(parsed)) {
          return parsed;
        }
        if (isRecord(parsed)) {
          // Wrappers: { ciphertext }, { wrapped }, { data }, { envelope }, …
          for (const key of [
            'ciphertext',
            'wrapped',
            'data',
            'envelope',
            'body',
            'message',
            'payload',
          ] as const) {
            const nested = parsed[key];
            if (typeof nested === 'string' && nested.length > 0) {
              queue.push(nested);
            } else if (isHybridEnvelope(nested)) {
              return nested;
            }
          }
          // Alias field names some clients use
          if (
            typeof parsed.wrappedKey === 'string' ||
            typeof parsed.wrapped_key === 'string'
          ) {
            const normalized = {
              wrappedKey:
                (parsed.wrappedKey as string | undefined) ??
                (parsed.wrapped_key as string),
              bodyCiphertext:
                (parsed.bodyCiphertext as string | undefined) ??
                (parsed.body_ciphertext as string | undefined) ??
                (parsed.ciphertext as string | undefined),
              nonce: parsed.nonce as string | undefined,
            };
            if (
              typeof normalized.wrappedKey === 'string' &&
              typeof normalized.bodyCiphertext === 'string' &&
              typeof normalized.nonce === 'string'
            ) {
              return normalized as HybridEnvelope;
            }
          }
        }
      } catch {
        // not JSON
      }
    }

    // Base64 → UTF-8 (may yield JSON wrapper or nested Base64)
    const decoded = decodeBase64Variants(s, current);
    if (decoded && decoded !== current) {
      queue.push(decoded);
    }
  }

  return null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function asNumber(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function extractMessageRows(payload: unknown): Array<{
  hash: string;
  data: string;
  timestamp: number;
  expiration?: number;
}> {
  const rows: Array<{
    hash: string;
    data: string;
    timestamp: number;
    expiration?: number;
  }> = [];

  const push = (item: unknown): void => {
    if (!isRecord(item)) {
      return;
    }
    const data = asString(item.data);
    if (!data) {
      return;
    }
    const hash =
      asString(item.hash) ??
      asString(item.id) ??
      `${asNumber(item.timestamp) ?? Date.now()}-${data.slice(0, 16)}`;
    const timestamp = asNumber(item.timestamp) ?? Date.now();
    const row: {
      hash: string;
      data: string;
      timestamp: number;
      expiration?: number;
    } = { hash, data, timestamp };
    const expiration = asNumber(item.expiration) ?? asNumber(item.expiry);
    if (typeof expiration === 'number') {
      row.expiration = expiration;
    }
    rows.push(row);
  };

  const visit = (node: unknown): void => {
    if (node === null || node === undefined) {
      return;
    }
    if (Array.isArray(node)) {
      for (const item of node) {
        push(item);
      }
      return;
    }
    if (!isRecord(node)) {
      return;
    }
    if (asString(node.data)) {
      push(node);
      return;
    }
    for (const key of ['messages', 'result', 'body', 'data'] as const) {
      if (key in node) {
        visit(node[key]);
      }
    }
  };

  visit(payload);
  return rows;
}

/** Describe where message rows live in a retrieve body (for debug). */
function describeRetrieveShape(payload: unknown): string {
  if (!isRecord(payload)) {
    return `type:${typeof payload}`;
  }
  if (Array.isArray(payload.messages)) {
    return `messages[${payload.messages.length}]`;
  }
  if (isRecord(payload.result) && Array.isArray(payload.result.messages)) {
    return `result.messages[${payload.result.messages.length}]`;
  }
  if (Array.isArray(payload.data)) {
    return `data[${payload.data.length}]`;
  }
  if (typeof payload.data === 'string') {
    return 'data:string';
  }
  if (Array.isArray(payload.snodes)) {
    return `snodes[${payload.snodes.length}] (redirect?)`;
  }
  return `keys:${Object.keys(payload).join(',')}`;
}

/** Extract store receipt hash from a Session storage_rpc response body. */
export function extractStoreHash(payload: unknown): string | null {
  if (!isRecord(payload)) {
    return null;
  }
  if (typeof payload.hash === 'string' && payload.hash.length > 0) {
    return payload.hash;
  }
  if (isRecord(payload.result) && typeof payload.result.hash === 'string') {
    return payload.result.hash;
  }
  return null;
}

function retrieveContainsPayload(
  retrieveBody: unknown,
  storedData: string,
  expectedHash: string | null,
): boolean {
  const rows = extractMessageRows(retrieveBody);
  for (const row of rows) {
    if (row.data === storedData) {
      return true;
    }
    if (expectedHash && row.hash === expectedHash) {
      return true;
    }
  }
  return false;
}

export interface StoreReceipt {
  hash: string;
  nodeUrl: string;
  node: Snode;
  raw: unknown;
  verifiedOnNode: boolean;
}

export interface StoreResult {
  accepted: number;
  errors: unknown[];
  receipts: StoreReceipt[];
  /** Primary receipt hash required before UI can mark message as sent. */
  hash: string | null;
}

/**
 * Build the encrypted store envelope (Base64 of sealed HybridEnvelope JSON)
 * and fan-out to `replicas` healthy swarm nodes in parallel.
 * Only counts a replica when the SNode returns a receipt hash.
 */
export async function storeEncryptedMessage(
  destinationSessionId: string,
  envelope: HybridEnvelope,
  options: StoreMessageOptions = {},
): Promise<StoreResult> {
  const s = await ensureSodium();
  const pool = getSharedSnodePool();
  const parentSignal = options.signal ?? getNetworkAbortSignal();
  const ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
  const ttlSeconds =
    ttlMs > 10_000_000 ? Math.floor(ttlMs / 1000) : Math.floor(ttlMs);
  const ttl = ttlSeconds > 0 ? ttlSeconds : DEFAULT_TTL_SECONDS;
  const replicas = Math.max(1, options.replicas ?? 2);
  const timestamp = Date.now();
  const pubKeyFull = normalizeSessionPubkey(destinationSessionId);
  const data = await toSessionBase64(s.from_string(JSON.stringify(envelope)));

  sessionNetLog.info('Preparando store (ciphertext apenas — sem plaintext)', {
    destination: truncateId(pubKeyFull),
    storagePubKey: truncateId(pubKeyFull),
    ciphertextBase64Bytes: data.length,
    timestamp,
    ttlSeconds: ttl,
  });

  const swarm = await pool.getSwarmForPublicKey(pubKeyFull, parentSignal);
  if (swarm.length === 0) {
    sessionNetLog.error('Store abortado: swarm de destino vazia', {
      destination: truncateId(pubKeyFull),
    });
    throw new Error('Empty destination swarm');
  }

  sessionNetLog.info('Destino resolvido para a swarm:', summarizeSnodes(swarm));

  // Store ALWAYS targets the DESTINATION Session ID swarm (never the sender's).
  const params = await buildStoreParams({
    destinationSessionId: pubKeyFull,
    dataBase64: data,
    ttlSeconds: ttl,
    timestampMs: timestamp,
    namespace: 0,
    signerSessionId: options.signerSessionId,
    signerSecretKey: options.signerSecretKey,
  });

  const healthy = pool.healthyNodes(swarm);
  const targets = (healthy.length > 0 ? healthy : [...swarm]).slice(0, replicas);
  while (targets.length < replicas && targets.length < swarm.length) {
    const next = swarm.find(
      (n) => !targets.some((t) => t.ip === n.ip && t.port === n.port),
    );
    if (!next) {
      break;
    }
    targets.push(next);
  }

  sessionNetLog.info(
    `Disparando store paralelo para ${targets.length} nó(s) da swarm do destinatário`,
    summarizeSnodes(targets),
  );

  const errors: unknown[] = [];
  const receipts: StoreReceipt[] = [];

  async function acceptStoreOnNode(
    node: Snode,
    raw: unknown,
  ): Promise<StoreReceipt | null> {
    const nodeUrl = pool.storageUrl(node);
    const hash = extractStoreHash(raw);
    if (!hash) {
      sessionNetLog.error(
        `Store HTTP OK sem hash/recibo em ${nodeUrl} — ignorando`,
        { rawType: typeof raw },
      );
      return null;
    }

    sessionNetLog.success(`Recibo SNode hash=${truncateHash(hash, 16)}`, {
      nodeUrl,
    });

    // Every retrieve must be authenticated. Peer-inbox RYOW requires the
    // recipient's secret key (unavailable) — skip and trust the store hash.
    let verifiedOnNode = false;
    const signerId = options.signerSessionId
      ? normalizeSessionPubkey(options.signerSessionId)
      : null;
    const canAuthRyow =
      Boolean(options.signerSecretKey) &&
      signerId !== null &&
      signerId === pubKeyFull;

    if (!canAuthRyow) {
      sessionNetLog.info(
        `Retrieve pós-store autenticado omitido em ${nodeUrl} (inbox de terceiros ou sem signer) — recibo hash permanece válido`,
      );
    } else {
      try {
        const ryowAuth = await buildRetrieveParams({
          sessionId: pubKeyFull,
          ed25519SecretKey: options.signerSecretKey!,
          lastHash: '',
          timestampMs: Date.now(),
        });
        const retrieveRaw = await pool.storageRpc(
          node,
          'retrieve',
          ryowAuth.params as unknown as Record<string, unknown>,
          parentSignal,
          ryowAuth.headers,
        );
        verifiedOnNode = retrieveContainsPayload(retrieveRaw, data, hash);
        if (verifiedOnNode) {
          sessionNetLog.verified(
            `PROVA DE GRAVAÇÃO: A mensagem foi gravada e encontrada no nó ${nodeUrl} com o hash ${hash}`,
          );
        } else {
          sessionNetLog.verifyError(
            `O nó respondeu 200 no store, mas a mensagem NÃO consta no retrieve desse mesmo nó! (${nodeUrl})`,
          );
        }
      } catch (err) {
        sessionNetLog.verifyError(
          `Retrieve pós-store falhou em ${nodeUrl} (hash ${hash} ainda válido como recibo)`,
          { error: err instanceof Error ? err.message : 'retrieve-fail' },
        );
      }
    }

    return { hash, nodeUrl, node, raw, verifiedOnNode };
  }

  const results = await Promise.allSettled(
    targets.map((node: Snode) =>
      pool.storageRpc(node, 'store', params, parentSignal),
    ),
  );

  for (let i = 0; i < results.length; i += 1) {
    const result = results[i]!;
    const node = targets[i]!;
    if (result.status === 'fulfilled') {
      const receipt = await acceptStoreOnNode(node, result.value);
      if (receipt) {
        receipts.push(receipt);
      } else {
        errors.push(new Error(`Missing store hash from ${snodeEndpoint(node)}`));
      }
    } else {
      errors.push(result.reason);
    }
  }

  if (receipts.length === 0) {
    sessionNetLog.warn(
      'Réplicas paralelas sem recibo — failover sequencial na swarm completa',
    );
    try {
      const { result, node } = await pool.storageRpcWithFailover(
        swarm,
        'store',
        params,
        parentSignal,
      );
      const receipt = await acceptStoreOnNode(node, result);
      if (!receipt) {
        throw new Error('Store failover returned no receipt hash');
      }
      receipts.push(receipt);
    } catch (err) {
      sessionNetLog.error(
        'Falha na swarm: nenhum recibo hash obtido para method=store',
        {
          destination: truncateId(pubKeyFull),
          error: err instanceof Error ? err.message : 'store-fail',
        },
      );
      throw err;
    }
  } else {
    sessionNetLog.success(
      `Store concluído: ${receipts.length}/${targets.length} recibos com hash`,
      {
        destination: truncateId(pubKeyFull),
        hashes: receipts.map((r) => truncateHash(r.hash, 12)),
        verified: receipts.filter((r) => r.verifiedOnNode).length,
        errorCount: errors.length,
      },
    );
  }

  return {
    accepted: receipts.length,
    errors,
    receipts,
    hash: receipts[0]?.hash ?? null,
  };
}

/**
 * Poll the local user's swarm for new messages since `lastHash`.
 * Valid HybridEnvelopes are returned; caller persists to IndexedDB.
 */
export async function retrieveEncryptedMessages(
  mySessionId: string,
  myEd25519PrivateKey: Uint8Array,
  options: RetrieveMessagesOptions = {},
): Promise<RetrievedMessage[]> {
  const s = await ensureSodium();
  const pool = getSharedSnodePool();
  const parentSignal = options.signal ?? getNetworkAbortSignal();
  const pubKey = normalizeSessionPubkey(mySessionId);
  const timestamp = Date.now();
  const lastHash =
    options.lastHash ?? lastHashByPubkey.get(pubKey) ?? '';

  sessionNetLog.info('Ciclo retrieve/poll na swarm local', {
    localId: truncateId(pubKey),
    lastHash: truncateHash(lastHash),
    timestamp,
  });

  const auth = await buildRetrieveParams({
    sessionId: pubKey,
    ed25519SecretKey: myEd25519PrivateKey,
    lastHash,
    timestampMs: timestamp,
    namespace: 0,
  });
  const params = auth.params as unknown as Record<string, unknown>;

  sessionNetLog.info('Retrieve auth montado', {
    pubkey: truncateId(String(auth.params.pubkey)),
    timestamp: auth.params.timestamp,
    namespace: auth.params.namespace,
    signaturePrefix: String(auth.params.signature).slice(0, 16),
    last_hash: truncateHash(auth.params.last_hash),
  });

  const swarm = await pool.getSwarmForPublicKey(pubKey, parentSignal);
  if (swarm.length === 0) {
    sessionNetLog.error('Retrieve abortado: swarm local vazia', {
      localId: truncateId(pubKey),
    });
    throw new Error('Empty local swarm');
  }

  const { result, node } = await pool.storageRpcWithFailover(
    swarm,
    'retrieve',
    params,
    parentSignal,
    0,
    auth.headers,
  );

  const rows = extractMessageRows(result);
  sessionNetLog.info(
    `Nó ${snodeEndpoint(node)} devolveu ${rows.length} mensagem(ns)`,
    {
      localId: truncateId(pubKey),
      lastHash: truncateHash(lastHash),
      node: snodeEndpoint(node),
      nodeIp: node.ip,
      shape: describeRetrieveShape(result),
    },
  );

  const out: RetrievedMessage[] = [];
  let parsedOk = 0;
  let parsedFail = 0;

  for (const row of rows) {
    const envelope = tryParseEnvelope(row.data, s);
    if (envelope) {
      parsedOk += 1;
    } else {
      parsedFail += 1;
    }
    out.push({
      hash: row.hash,
      timestamp: row.timestamp,
      expiration: row.expiration,
      data: row.data,
      envelope,
    });
  }

  if (rows.length > 0) {
    const newest = rows[rows.length - 1]!;
    lastHashByPubkey.set(pubKey, newest.hash);
    sessionNetLog.success(
      `Retrieve: ${rows.length} raw, envelopes parseáveis=${parsedOk}, inválidos=${parsedFail}`,
      {
        nextLastHash: truncateHash(newest.hash),
        ciphertextSizes: rows.map((r) => r.data.length),
      },
    );
  } else {
    sessionNetLog.info('Retrieve: nenhuma mensagem nova neste ciclo');
  }

  return out;
}

/** Ensure the shared pool has been refreshed at least once. */
let lastRefreshFailureAt = 0;
const REFRESH_FAILURE_COOLDOWN_MS = 30_000;

export async function ensureSnodePoolReady(
  signal?: AbortSignal,
): Promise<number> {
  const pool = getSharedSnodePool();
  if (pool.getCachedNodes().length > 0) {
    return pool.getCachedNodes().length;
  }
  if (
    lastRefreshFailureAt > 0 &&
    Date.now() - lastRefreshFailureAt < REFRESH_FAILURE_COOLDOWN_MS
  ) {
    sessionNetLog.warn('Refresh do pool em cooldown — usando fallback local');
    throw new Error('SNode pool refresh in cooldown');
  }
  try {
    const nodes = await pool.refreshNodes(signal ?? getNetworkAbortSignal());
    lastRefreshFailureAt = 0;
    sessionNetLog.success(`SNode pool pronto (${nodes.length} nós)`);
    return nodes.length;
  } catch (err) {
    lastRefreshFailureAt = Date.now();
    sessionNetLog.error('Não foi possível preparar o SNode pool', {
      error: err instanceof Error ? err.message : 'refresh-fail',
    });
    throw err;
  }
}

/** Log Poly1305 open + IndexedDB persist outcomes (called from App sync). */
export function logEnvelopeDecryptResult(meta: {
  success: boolean;
  persisted: boolean;
  senderTruncated?: string;
}): void {
  if (meta.success) {
    sessionNetLog.success(
      `Decifragem Poly1305 OK` +
        (meta.persisted ? ' — gravado no IndexedDB' : ' — sem persistência'),
      meta.senderTruncated
        ? { sender: meta.senderTruncated }
        : undefined,
    );
  } else {
    sessionNetLog.warn(
      'Falha de autenticidade Poly1305 / envelope rejeitado (conteúdo não lido)',
    );
  }
}
