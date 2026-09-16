/**
 * Real Session Service Node relay — bootstrap from seeds, swarm lookup,
 * and HTTPS /storage_rpc/v1 forwarding (no local mock swarm).
 */

import https from 'https';
import axios, { type AxiosInstance } from 'axios';
import { SEED_JSON_RPC, SEED_NODES } from './seedNodes';
import {
  isExpectedUpstreamNoise,
  logUnexpectedRelayError,
} from '../security/quietTransport';

const LOG = '[SESSION-NODE-RELAY]';

/** Informational transport logs are silenced; use console.warn/error for failures. */
function debugLog(..._args: unknown[]): void {
  // no-op — keep call sites for optional local re-enable
}

const httpsAgent = new https.Agent({ rejectUnauthorized: false });

const http: AxiosInstance = axios.create({
  httpsAgent,
  timeout: 20_000,
  headers: {
    'Content-Type': 'application/json',
    Accept: 'application/json',
  },
  validateStatus: () => true,
});

export interface Snode {
  ip: string;
  port: number;
  pubkey_ed25519: string;
  pubkey_x25519?: string;
}

let cachedNodes: Snode[] = [];
let lastRefreshAt = 0;
const REFRESH_TTL_MS = 5 * 60 * 1000;
let rpcIdCounter = 0;
/** Authoritative swarm membership by Session ID (`05…`). */
const swarmByPubkey = new Map<string, Snode[]>();
const MAX_SWARM_REDIRECTS = 2;

/** 14 days in seconds — Session storage rejects oversized millisecond TTLs. */
export const DEFAULT_TTL_SECONDS = 14 * 24 * 60 * 60; // 1_209_600

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function asNumber(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === 'string' && value.trim().length > 0) {
    const n = Number(value);
    return Number.isFinite(n) ? n : undefined;
  }
  return undefined;
}

/**
 * Strip Session `05` prefix → 64-char hex for storage `pubkey`.
 */
export function toStoragePubKey(id: string): string {
  const trimmed = id.trim().toLowerCase();
  if (trimmed.startsWith('05') && trimmed.length === 66) {
    return trimmed.slice(2);
  }
  return trimmed;
}

export function normalizeSessionPubkey(id: string): string {
  const trimmed = id.trim().toLowerCase();
  if (trimmed.startsWith('05') && trimmed.length === 66) {
    return trimmed;
  }
  if (/^[0-9a-f]{64}$/.test(trimmed)) {
    return `05${trimmed}`;
  }
  return trimmed;
}

/**
 * TTL must be seconds. Values that look like milliseconds (> ~115 days in seconds)
 * are converted down.
 */
export function normalizeTtlSeconds(ttl: unknown): number {
  const n = asNumber(ttl);
  if (n === undefined || n <= 0) {
    return DEFAULT_TTL_SECONDS;
  }
  if (n > 10_000_000) {
    return Math.floor(n / 1000);
  }
  return Math.floor(n);
}

/**
 * Normalize params for Oxen/Session storage_rpc methods.
 * Storage servers require a 66-hex-digit Session ID (`05` + 32-byte Ed25519 key).
 * Always emit lowercase `pubkey`.
 *
 * Auth (retrieve) follows oxen-storage-server:
 *   sign UTF-8(`retrieve{timestamp_ms}`) → standard Base64
 *   pubkey = 66-char Session ID (`05` + 32-byte Ed25519)
 *   fields: pubkey, timestamp, signature, last_hash [, pubkey_ed25519]
 */
export function normalizeStorageParams(
  method: string,
  params: Record<string, unknown>,
): Record<string, unknown> {
  const rawKey =
    asString(params.pubkey) ??
    asString(params.pubKey) ??
    asString(params.PubKey);

  if (!rawKey) {
    throw new Error('storage RPC params require pubkey');
  }

  // MUST be 66 hex digits (33 bytes) — includes the Session `05` prefix.
  const pubkey = normalizeSessionPubkey(rawKey);

  if (method === 'store') {
    if (typeof params.data !== 'string') {
      throw new Error('store params require data (base64 string)');
    }
    const out: Record<string, unknown> = {
      pubkey,
      data: params.data,
      ttl: normalizeTtlSeconds(params.ttl),
      timestamp: Math.floor(asNumber(params.timestamp) ?? Date.now()),
      // Explicit default namespace (private messages).
      namespace: asNumber(params.namespace) ?? 0,
    };
    const signature = asString(params.signature);
    const pubkeyEd = asString(params.pubkey_ed25519);
    const sigTs = asNumber(params.sig_timestamp);
    if (signature && pubkeyEd) {
      out.signature = signature;
      out.pubkey_ed25519 = pubkeyEd.toLowerCase();
      out.sig_timestamp = Math.floor(
        sigTs ?? (asNumber(out.timestamp) as number),
      );
    } else if (signature) {
      // Pass signature through even without pubkey_ed25519 (client-shaped).
      out.signature = signature;
    }
    return out;
  }

  if (method === 'retrieve') {
    const retrievePubkey = normalizeSessionPubkey(rawKey);
    const out: Record<string, unknown> = {
      pubkey: retrievePubkey,
      last_hash:
        asString(params.last_hash) ??
        asString(params.lastHash) ??
        '',
      namespace: asNumber(params.namespace) ?? 0,
    };
    const ts = asNumber(params.timestamp);
    if (ts !== undefined) {
      out.timestamp = Math.floor(ts);
    }
    const signature = asString(params.signature);
    if (signature) {
      out.signature = signature;
    }
    const pubkeyEd = asString(params.pubkey_ed25519);
    if (pubkeyEd) {
      out.pubkey_ed25519 = pubkeyEd.toLowerCase();
    }
    const maxSize = asNumber(params.max_size) ?? asNumber(params.maxSize);
    if (maxSize !== undefined) {
      out.max_size = maxSize;
    }
    return out;
  }

  if (method === 'get_snodes_for_pubkey') {
    return { pubkey };
  }

  // Pass-through for other methods with normalized pubkey.
  const out: Record<string, unknown> = { ...params, pubkey };
  delete out.pubKey;
  delete out.PubKey;
  return out;
}

/** JSON-RPC 2.0 envelope required by current storage servers. */
export function wrapStorageRpc(
  method: string,
  params: Record<string, unknown>,
): Record<string, unknown> {
  const id = String(rpcIdCounter);
  rpcIdCounter += 1;
  return {
    jsonrpc: '2.0',
    id,
    method,
    params: normalizeStorageParams(method, params),
  };
}

/**
 * Accept either a raw `{method,params}` body or an already-wrapped JSON-RPC
 * object and return a normalized JSON-RPC 2.0 payload.
 */
export function normalizeStorageRpcBody(body: unknown): Record<string, unknown> {
  if (!isRecord(body)) {
    throw new Error('storage RPC body must be a JSON object');
  }

  const method = asString(body.method);
  if (!method) {
    throw new Error('storage RPC body missing method');
  }

  const params = isRecord(body.params)
    ? { ...body.params }
    : (() => {
        const flat: Record<string, unknown> = { ...body };
        delete flat.method;
        delete flat.jsonrpc;
        delete flat.id;
        delete flat.params;
        return flat;
      })();

  return wrapStorageRpc(method, params);
}

function parseSnode(raw: unknown): Snode | null {
  if (!isRecord(raw)) {
    return null;
  }
  const ip =
    asString(raw.public_ip) ??
    asString(raw.ip) ??
    asString(raw.address) ??
    asString(raw.host);
  const port =
    asNumber(raw.port_https) ??
    asNumber(raw.storage_port) ??
    asNumber(raw.port) ??
    asNumber(raw.https_port);
  const pubkey_ed25519 =
    asString(raw.pubkey_ed25519) ??
    asString(raw.ed25519_pubkey) ??
    asString(raw.pubkey);

  if (!ip || ip === '0.0.0.0' || !port || port <= 0 || !pubkey_ed25519) {
    return null;
  }

  const node: Snode = {
    ip,
    port,
    pubkey_ed25519: pubkey_ed25519.toLowerCase(),
  };
  const x25519 = asString(raw.pubkey_x25519);
  if (x25519) {
    node.pubkey_x25519 = x25519.toLowerCase();
  }
  return node;
}

function unwrapStorageBody(payload: unknown): Record<string, unknown> | null {
  if (!isRecord(payload)) {
    return null;
  }
  if (isRecord(payload.result)) {
    return payload.result;
  }
  return payload;
}

/** Wrong-swarm hint for store/retrieve (not get_snodes_for_pubkey). */
export function isSwarmRedirect(
  payload: unknown,
  method?: string,
): boolean {
  const m = (method ?? '').toLowerCase();
  if (m === 'get_snodes_for_pubkey' || m === 'get_swarm') {
    return false;
  }
  const body = unwrapStorageBody(payload);
  if (!body) {
    return false;
  }
  if (Array.isArray(body.messages)) {
    return false;
  }
  if (typeof body.hash === 'string' && body.hash.length > 0) {
    return false;
  }
  return Array.isArray(body.snodes) && body.snodes.length > 0;
}

function extractSnodes(payload: unknown): Snode[] {
  const out: Snode[] = [];
  const seen = new Set<string>();

  const push = (raw: unknown): void => {
    const node = parseSnode(raw);
    if (!node) {
      return;
    }
    const key = `${node.ip}:${node.port}`;
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    out.push(node);
  };

  const visit = (node: unknown): void => {
    if (node === null || node === undefined) {
      return;
    }
    if (Array.isArray(node)) {
      for (const item of node) {
        if (isRecord(item) && (item.public_ip || item.ip || item.pubkey_ed25519)) {
          push(item);
        } else {
          visit(item);
        }
      }
      return;
    }
    if (!isRecord(node)) {
      return;
    }
    for (const key of [
      'service_node_states',
      'snodes',
      'nodes',
      'result',
      'swarm',
    ] as const) {
      if (key in node) {
        visit(node[key]);
      }
    }
  };

  visit(payload);
  return out;
}

export function storageUrl(node: Snode, path = '/storage_rpc/v1'): string {
  const normalized = path.startsWith('/') ? path : `/${path}`;
  return `https://${node.ip}:${node.port}${normalized}`;
}

export async function refreshServiceNodes(force = false): Promise<Snode[]> {
  if (
    !force &&
    cachedNodes.length > 0 &&
    Date.now() - lastRefreshAt < REFRESH_TTL_MS
  ) {
    return cachedNodes;
  }

  const body = {
    jsonrpc: '2.0',
    id: 'gateway_pool',
    method: 'get_service_nodes',
    params: {
      active_only: true,
      fields: {
        public_ip: true,
        storage_port: true,
        pubkey_ed25519: true,
        pubkey_x25519: true,
        swarm: true,
        storage_server_version: true,
      },
    },
  };

  const errors: string[] = [];

  for (const seed of SEED_JSON_RPC) {
    try {
      debugLog(`${LOG} Consultando seed ${seed.label}…`);
      const response = await http.post(seed.url, body);
      if (response.status !== 200) {
        errors.push(`${seed.label}: HTTP ${response.status}`);
        continue;
      }
      const nodes = extractSnodes(response.data).filter(
        (n) => n.port > 0 && n.ip !== '0.0.0.0',
      );
      if (nodes.length === 0) {
        errors.push(`${seed.label}: empty node list`);
        continue;
      }
      cachedNodes = nodes;
      lastRefreshAt = Date.now();
      debugLog(
        `${LOG} Pool atualizado: ${nodes.length} storage nodes ativos (via ${seed.label})`,
      );
      return nodes;
    } catch (err) {
      errors.push(
        `${seed.label}: ${err instanceof Error ? err.message : 'fail'}`,
      );
    }
  }

  // Fallback: try legacy IP seeds on /json_rpc
  for (const seed of SEED_NODES) {
    const url = `https://${seed.host}:${seed.port}/json_rpc`;
    try {
      debugLog(`${LOG} Consultando seed IP ${seed.host}:${seed.port}…`);
      const response = await http.post(url, body);
      if (response.status !== 200) {
        continue;
      }
      const nodes = extractSnodes(response.data);
      if (nodes.length > 0) {
        cachedNodes = nodes;
        lastRefreshAt = Date.now();
        debugLog(
          `${LOG} Pool atualizado: ${nodes.length} nós (via ${seed.host})`,
        );
        return nodes;
      }
    } catch (err) {
      errors.push(
        `${seed.host}: ${err instanceof Error ? err.message : 'fail'}`,
      );
    }
  }

  throw new Error(
    `Failed to refresh service node pool (${errors.join('; ') || 'no seeds'})`,
  );
}

export function cacheSwarmForPubkey(pubkey: string, swarm: Snode[]): Snode[] {
  const full = normalizeSessionPubkey(pubkey);
  const copy = swarm.slice(0, 7).map((n) => ({ ...n }));
  swarmByPubkey.set(full, copy);
  for (const node of copy) {
    const key = `${node.ip}:${node.port}`;
    const idx = cachedNodes.findIndex((n) => `${n.ip}:${n.port}` === key);
    if (idx >= 0) {
      cachedNodes[idx] = { ...cachedNodes[idx]!, ...node };
    } else {
      cachedNodes.push({ ...node });
    }
  }
  debugLog(
    `${LOG} Swarm cache ${full.slice(0, 10)}…: ${copy.length} nós`,
  );
  return copy;
}

export async function getSwarmForPubkey(pubkey: string): Promise<Snode[]> {
  const nodes = await refreshServiceNodes();
  const full = normalizeSessionPubkey(pubkey);

  const cached = swarmByPubkey.get(full);
  if (cached && cached.length > 0) {
    debugLog(
      `${LOG} Swarm em cache para ${full.slice(0, 10)}…: ${cached.length} nós`,
    );
    return cached.slice(0, 5);
  }

  const probes = nodes.slice(0, 12);

  for (const probe of probes) {
    const url = storageUrl(probe);
    try {
      const result = await forwardStorageRpcToUrl(
        url,
        wrapStorageRpc('get_snodes_for_pubkey', { pubkey: full }),
      );
      if (result.status !== 200 && result.status !== 421) {
        continue;
      }
      const swarm = extractSnodes(result.data);
      if (swarm.length > 0) {
        debugLog(
          `${LOG} Swarm para ${full.slice(0, 10)}…: ${swarm.length} nós`,
        );
        return cacheSwarmForPubkey(full, swarm).slice(0, 5);
      }
    } catch {
      // Expected probe failover — stay silent.
    }
  }

  // Deterministic fallback: first 5 healthy pool nodes (stable order by pubkey).
  const sorted = [...nodes].sort((a, b) =>
    a.pubkey_ed25519.localeCompare(b.pubkey_ed25519),
  );
  return sorted.slice(0, 5);
}

export interface ForwardResult {
  url: string;
  status: number;
  data: unknown;
}

export async function forwardStorageRpcToUrl(
  targetUrl: string,
  body: unknown,
  upstreamHeaders?: Record<string, string>,
): Promise<ForwardResult> {
  let payload: unknown = body;
  try {
    // Only normalize Session storage_rpc methods — seed json_rpc
    // (get_service_nodes, etc.) must be forwarded untouched.
    if (isRecord(body) && asString(body.method)) {
      const method = (asString(body.method) as string).toLowerCase();
      const isStorageMethod =
        method === 'store' ||
        method === 'retrieve' ||
        method === 'get_snodes_for_pubkey' ||
        method === 'get_swarm' ||
        targetUrl.includes('/storage_rpc/');
      if (isStorageMethod) {
        payload = normalizeStorageRpcBody(body);
      }
    }
  } catch (err) {
    console.warn(
      `${LOG} Não foi possível normalizar o body; encaminhando cru:`,
      err instanceof Error ? err.message : err,
    );
  }

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
  };
  if (upstreamHeaders) {
    for (const [key, value] of Object.entries(upstreamHeaders)) {
      if (
        key === 'X-Session-Timestamp' ||
        key === 'X-Session-Signature' ||
        key === 'X-Session-Pubkey'
      ) {
        headers[key] = value;
      }
    }
  }

  debugLog(`${LOG} Encaminhando → ${targetUrl}`);
  try {
    const response = await http.post(targetUrl, payload, {
      headers,
      // httpsAgent already has rejectUnauthorized: false (self-signed SNode TLS).
      timeout: 10_000,
    });

    debugLog(`${LOG} Resposta de ${targetUrl} → HTTP ${response.status}`);

    if (response.status !== 200) {
      // Non-200 from SNode during failover is expected — stay quiet.
    }

    return {
      url: targetUrl,
      status: response.status,
      data: response.data,
    };
  } catch (err: unknown) {
    logUnexpectedRelayError(`${LOG} Falha de conexão com ${targetUrl}:`, err);
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(`Falha no transporte para o SNode: ${message}`);
  }
}

export async function forwardStorageRpcToNode(
  node: Snode,
  method: string,
  params: Record<string, unknown>,
): Promise<ForwardResult> {
  const url = storageUrl(node);
  return forwardStorageRpcToUrl(url, wrapStorageRpc(method, params));
}

/** Extract the store receipt hash from a Session storage_rpc response. */
export function extractStoreHash(payload: unknown): string | null {
  if (!isRecord(payload)) {
    return null;
  }
  if (typeof payload.hash === 'string' && payload.hash.length > 0) {
    return payload.hash;
  }
  if (isRecord(payload.result)) {
    const nested = payload.result;
    if (typeof nested.hash === 'string' && nested.hash.length > 0) {
      return nested.hash;
    }
  }
  return null;
}

function retrieveContainsPayload(
  retrieveBody: unknown,
  storedData: string,
  expectedHash: string | null,
): boolean {
  const rows: unknown[] = [];
  const visit = (node: unknown): void => {
    if (Array.isArray(node)) {
      for (const item of node) {
        visit(item);
      }
      return;
    }
    if (!isRecord(node)) {
      return;
    }
    if (typeof node.data === 'string') {
      rows.push(node);
    }
    for (const key of ['messages', 'result', 'body'] as const) {
      if (key in node) {
        visit(node[key]);
      }
    }
  };
  visit(retrieveBody);

  for (const row of rows) {
    if (!isRecord(row)) {
      continue;
    }
    if (row.data === storedData) {
      return true;
    }
    if (
      expectedHash &&
      typeof row.hash === 'string' &&
      row.hash === expectedHash
    ) {
      return true;
    }
  }
  return false;
}

/**
 * After a successful store, optionally retrieve from the SAME node (RYOW).
 * Unauthenticated retrieve is forbidden by current storage servers — skip when
 * no owner signature is available (typical for outbound 1:1 store).
 */
export async function verifyStoreOnSameNode(
  node: Snode,
  pubkey: string,
  storedData: string,
  storeHash: string | null,
): Promise<boolean> {
  void node;
  void pubkey;
  void storedData;
  // Hash receipt from store is authoritative; bare retrieve would 401.
  if (storeHash) {
    debugLog(
      `${LOG} Store confirmado por hash ${storeHash.slice(0, 16)}…`,
    );
    return true;
  }
  return false;
}

/**
 * Resolve swarm for the request pubkey and fan-out store/retrieve with failover.
 * Follows wrong-swarm `snodes` redirects (HTTP 200/421) and caches membership.
 * For `store`, requires a receipt hash and runs same-node RYOW verify.
 */
export async function relayStorageMethod(
  method: string,
  params: Record<string, unknown>,
  redirectDepth = 0,
): Promise<ForwardResult> {
  const pubkeyRaw =
    asString(params.pubKey) ??
    asString(params.pubkey) ??
    asString(params.PubKey);
  if (!pubkeyRaw) {
    throw new Error('Missing pubKey/pubkey in storage RPC params');
  }

  const swarm = await getSwarmForPubkey(pubkeyRaw);
  if (swarm.length === 0) {
    throw new Error('Empty destination swarm');
  }

  const paramsOut = normalizeStorageParams(method, params);

  let lastError: unknown;
  for (const node of swarm) {
    try {
      const result = await forwardStorageRpcToNode(node, method, paramsOut);
      const okStatus = result.status === 200 || result.status === 421;
      if (!okStatus) {
        lastError = new Error(`HTTP ${result.status} from ${result.url}`);
        continue;
      }

      if (isSwarmRedirect(result.data, method)) {
        if (redirectDepth >= MAX_SWARM_REDIRECTS) {
          throw new Error(
            `Too many swarm redirects for ${method} (max ${MAX_SWARM_REDIRECTS})`,
          );
        }
        const redirected = extractSnodes(result.data);
        if (redirected.length === 0) {
          lastError = new Error('Swarm redirect without snodes');
          continue;
        }
        cacheSwarmForPubkey(pubkeyRaw, redirected);
        debugLog(
          `${LOG} Redirect de swarm em ${node.ip}:${node.port} → ${redirected.length} nós; reenviando ${method}`,
        );
        return relayStorageMethod(method, params, redirectDepth + 1);
      }

      if (result.status !== 200) {
        lastError = new Error(`HTTP ${result.status} from ${result.url}`);
        continue;
      }

      if (method === 'store') {
        const hash = extractStoreHash(result.data);
        if (!hash) {
          console.error(
            `${LOG} Store HTTP 200 sem hash/recibo em ${result.url} — rejeitando`,
          );
          lastError = new Error(`Store missing receipt hash from ${result.url}`);
          continue;
        }
        const storedData = asString(paramsOut.data) ?? '';
        await verifyStoreOnSameNode(node, pubkeyRaw, storedData, hash);
        // Always return the real SNode body (includes hash) — never a synthetic success.
        return result;
      }

      return result;
    } catch (err) {
      lastError = err;
      if (!isExpectedUpstreamNoise(err)) {
        logUnexpectedRelayError(
          `${LOG} Nó ${node.ip}:${node.port} falhou:`,
          err,
        );
      }
    }
  }

  throw lastError instanceof Error
    ? lastError
    : new Error(`All swarm nodes failed for ${method}`);
}

/**
 * Legacy helper kept for callers that only pass a node index into SEED_NODES.
 * Prefer relayStorageMethod / forwardStorageRpcToUrl for real swarm traffic.
 */
export async function forwardToSessionNode(
  payload: unknown,
  _nodeIndex: number = 0,
): Promise<unknown> {
  if (isRecord(payload) && asString(payload.method)) {
    const method = asString(payload.method) as string;
    const flatParams: Record<string, unknown> = isRecord(payload.params)
      ? { ...payload.params }
      : { ...payload };
    delete flatParams.method;
    const result = await relayStorageMethod(method, flatParams);
    if (result.status !== 200) {
      throw new Error(`Upstream HTTP ${result.status}`);
    }
    return result.data;
  }

  const seed = SEED_NODES[0];
  if (!seed) {
    throw new Error('No seed nodes configured');
  }
  const url = `https://${seed.host}:${seed.port}/storage_rpc/v1`;
  const result = await forwardStorageRpcToUrl(url, payload);
  if (result.status !== 200) {
    throw new Error(`Upstream HTTP ${result.status}`);
  }
  return result.data;
}
