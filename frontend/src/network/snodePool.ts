/** Local Gateway Bridge — sole browser egress for Session network traffic. */
const RELAY_PATH = '/api/relay';

/**
 * Service Node pool — bootstrap from Oxen/Session seeds, swarm lookup,
 * and transparent failover for storage_rpc HTTPS targets.
 *
 * Browser NEVER opens TLS to SNode IPs. Every upstream HTTPS URL is sent
 * as `targetUrl` inside a same-origin POST to `/api/relay`.
 */

import {
  describeRpcResult,
  httpStatusFromError,
  sessionNetLog,
  snodeEndpoint,
  summarizeSnode,
  summarizeSnodes,
  truncateId,
} from './sessionNetLog';

export interface Snode {
  ip: string;
  port: number;
  pubkey_ed25519: string;
  pubkey_x25519?: string;
  swarm?: string;
}

/** How browser traffic reaches SNodes — always via local Gateway Bridge. */
export type SnodeTransportMode = 'relay';

export interface SnodePoolOptions {
  transportMode?: SnodeTransportMode;
  requestTimeoutMs?: number;
  penaltyMs?: number;
  swarmSize?: number;
}

const SEED_JSON_RPC: readonly string[] = [
  'https://seed3.getsession.org/json_rpc',
  'https://seed1.getsession.org/json_rpc',
  'https://seed2.getsession.org/json_rpc',
];

/** Known public HTTPS bootstrap hosts (reached only as targetUrl via /api/relay). */
const SEED_BOOTSTRAP_HTTPS: readonly string[] = [
  'https://seed3.getsession.org',
  'https://seed1.getsession.org',
  'https://seed2.getsession.org',
];

const DEFAULT_TIMEOUT_MS = 12_000;
const DEFAULT_PENALTY_MS = 60_000;
const DEFAULT_SWARM_SIZE = 5;
const MIN_SWARM_SIZE = 3;
const MAX_SWARM_REDIRECTS = 2;

function snodeKey(node: Pick<Snode, 'ip' | 'port'>): string {
  return `${node.ip}:${node.port}`;
}

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

async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', data);
  const bytes = new Uint8Array(digest);
  let hex = '';
  for (let i = 0; i < bytes.length; i += 1) {
    hex += bytes[i]!.toString(16).padStart(2, '0');
  }
  return hex;
}

function normalizeSessionPubkey(destinationSessionId: string): string {
  const cleaned = destinationSessionId
    .normalize('NFKC')
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, '')
    .replace(/\s+/g, '')
    .trim()
    .toLowerCase();
  if (cleaned.length === 66 && cleaned.startsWith('05')) {
    return cleaned;
  }
  if (cleaned.length === 64 && /^[0-9a-f]+$/.test(cleaned)) {
    return `05${cleaned}`;
  }
  if (/^[0-9a-f]{64}$/.test(cleaned)) {
    return `05${cleaned}`;
  }
  return cleaned;
}

/** @deprecated Prefer normalizeSessionPubkey / formatSessionPubkey (66 hex with 05). */
function sessionIdToStoragePubKey(destinationSessionId: string): string {
  const full = normalizeSessionPubkey(destinationSessionId);
  if (full.startsWith('05') && full.length === 66) {
    return full.slice(2);
  }
  return full;
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
  // Swarm redirects expose port_https; seed lists use storage_port.
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

  const swarm = asString(raw.swarm) ?? asString(raw.swarm_id);
  if (swarm) {
    node.swarm = swarm;
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

/**
 * Wrong-swarm hint: HTTP 200/421 body with `snodes` but no messages/hash.
 * Does NOT apply to `get_snodes_for_pubkey` (that response IS the swarm list).
 */
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

function pubkeyFromParams(params: Record<string, unknown>): string | undefined {
  const raw =
    asString(params.pubkey) ??
    asString(params.pubKey) ??
    asString(params.PubKey);
  return raw ? normalizeSessionPubkey(raw) : undefined;
}

/** Optional X-Session-* headers forwarded via /api/relay to the SNode. */
export type SessionAuthHeaders = {
  'X-Session-Timestamp': string;
  'X-Session-Signature': string;
  'X-Session-Pubkey': string;
};

function sessionAuthHeadersFromParams(
  params: Record<string, unknown>,
): SessionAuthHeaders | undefined {
  const ts = asNumber(params.timestamp);
  const signature = asString(params.signature);
  const rawPk = asString(params.pubkey);
  if (ts === undefined || !signature || !rawPk) {
    return undefined;
  }
  // Storage servers require 66-hex Session ID on X-Session-Pubkey as well.
  const pubkey = normalizeSessionPubkey(rawPk);
  return {
    'X-Session-Timestamp': String(Math.floor(ts)),
    'X-Session-Signature': signature,
    'X-Session-Pubkey': pubkey,
  };
}

function extractSnodeList(payload: unknown): Snode[] {
  const out: Snode[] = [];
  const seen = new Set<string>();

  const push = (raw: unknown): void => {
    const node = parseSnode(raw);
    if (!node) {
      return;
    }
    const key = snodeKey(node);
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

export class SnodePool {
  private nodes: Snode[] = [];
  /** Authoritative swarm membership keyed by Session ID (`05…`). */
  private readonly swarmByPubkey = new Map<string, Snode[]>();
  private readonly penalties = new Map<string, number>();
  private transportMode: SnodeTransportMode;
  private readonly requestTimeoutMs: number;
  private readonly penaltyMs: number;
  private readonly swarmSize: number;
  private refreshInFlight: Promise<Snode[]> | null = null;

  constructor(options: SnodePoolOptions = {}) {
    this.transportMode = options.transportMode ?? 'relay';
    this.requestTimeoutMs = options.requestTimeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.penaltyMs = options.penaltyMs ?? DEFAULT_PENALTY_MS;
    this.swarmSize = Math.max(
      MIN_SWARM_SIZE,
      options.swarmSize ?? DEFAULT_SWARM_SIZE,
    );
  }

  setTransportMode(_mode: SnodeTransportMode): void {
    // Only relay mode is supported — browser must never hit SNode IPs directly.
    this.transportMode = 'relay';
  }

  getTransportMode(): SnodeTransportMode {
    return this.transportMode;
  }

  getCachedNodes(): readonly Snode[] {
    return this.nodes;
  }

  /** Cached authoritative swarm for a Session ID, if previously discovered. */
  getCachedSwarm(sessionId: string): readonly Snode[] | undefined {
    return this.swarmByPubkey.get(normalizeSessionPubkey(sessionId));
  }

  /**
   * Persist swarm membership for a pubkey and merge nodes into the global pool.
   */
  cacheSwarm(sessionId: string, swarm: readonly Snode[]): Snode[] {
    const pubkey = normalizeSessionPubkey(sessionId);
    const selected = swarm.slice(0, Math.max(this.swarmSize, swarm.length));
    const copy = selected.map((n) => ({ ...n }));
    this.swarmByPubkey.set(pubkey, copy);

    for (const node of copy) {
      const key = snodeKey(node);
      const idx = this.nodes.findIndex((n) => snodeKey(n) === key);
      if (idx >= 0) {
        this.nodes[idx] = { ...this.nodes[idx]!, ...node };
      } else {
        this.nodes.push({ ...node });
      }
    }

    sessionNetLog.success(
      `Swarm cache atualizada para ${truncateId(pubkey)}: ${copy.length} nós`,
      summarizeSnodes(copy),
    );
    return copy;
  }

  clear(): void {
    sessionNetLog.info(
      'Limpando SnodePool (nós, swarms, penalizações e refresh em voo)',
    );
    this.nodes = [];
    this.swarmByPubkey.clear();
    this.penalties.clear();
    this.refreshInFlight = null;
  }

  markPenalized(node: Snode, reason?: string): void {
    void reason;
    this.penalties.set(snodeKey(node), Date.now() + this.penaltyMs);
  }

  isPenalized(node: Snode): boolean {
    const until = this.penalties.get(snodeKey(node));
    if (until === undefined) {
      return false;
    }
    if (until <= Date.now()) {
      this.penalties.delete(snodeKey(node));
      return false;
    }
    return true;
  }

  healthyNodes(list: readonly Snode[] = this.nodes): Snode[] {
    return list.filter((n) => !this.isPenalized(n));
  }

  /**
   * Absolute HTTPS URL of an upstream SNode/seed.
   * NEVER pass this to window.fetch — only as JSON `targetUrl` for /api/relay.
   */
  storageUrl(node: Snode, path = '/storage_rpc/v1'): string {
    const normalized = path.startsWith('/') ? path : `/${path}`;
    return `https://${node.ip}:${node.port}${normalized}`;
  }

  /**
   * Sole browser→network egress. Encapsulates upstream HTTPS inside /api/relay.
   * The Node gateway performs TLS (rejectUnauthorized: false) to the SNode.
   */
  private async relayFetch(
    targetUrl: string,
    payload: unknown,
    signal?: AbortSignal,
    upstreamHeaders?: SessionAuthHeaders,
  ): Promise<{ payload: unknown; httpStatus: number; rttMs: number }> {
    if (!/^https:\/\//i.test(targetUrl)) {
      throw new Error(`targetUrl must be https:// (got ${targetUrl})`);
    }
    if (
      /localhost|127\.0\.0\.1/i.test(targetUrl)
    ) {
      throw new Error('Refusing localhost as SNode targetUrl');
    }

    const controller = new AbortController();
    const timeout = window.setTimeout(
      () => controller.abort(),
      this.requestTimeoutMs,
    );
    const onAbort = (): void => controller.abort();
    signal?.addEventListener('abort', onAbort, { once: true });
    const started = performance.now();

    try {
      sessionNetLog.info(`POST ${RELAY_PATH} (relay → upstream)`, {
        targetUrl,
        method:
          typeof payload === 'object' &&
          payload !== null &&
          'method' in payload
            ? String((payload as { method?: unknown }).method)
            : undefined,
        hasSessionAuth: Boolean(upstreamHeaders),
      });

      const relayBody: Record<string, unknown> = {
        targetUrl,
        payload,
      };
      if (upstreamHeaders) {
        relayBody.headers = upstreamHeaders;
      }

      // CRITICAL: browser fetch URL is ALWAYS relative /api/relay — never targetUrl.
      const response = await fetch(RELAY_PATH, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(relayBody),
        signal: controller.signal,
      });

      const rttMs = Math.round(performance.now() - started);

      const contentType = response.headers.get('content-type') ?? '';
      let parsed: unknown;
      const readBody = async (): Promise<unknown> => {
        if (contentType.includes('application/json')) {
          return response.json();
        }
        const text = await response.text();
        try {
          return JSON.parse(text) as unknown;
        } catch {
          return text;
        }
      };

      // 421 Misdirected = wrong swarm; body usually carries authoritative `snodes`.
      if (response.status === 200 || response.status === 421) {
        parsed = await readBody();
        if (response.status === 421) {
          const body = unwrapStorageBody(parsed);
          const hasSnodes =
            !!body &&
            Array.isArray(body.snodes) &&
            body.snodes.length > 0;
          if (!hasSnodes) {
            sessionNetLog.error(
              `Relay ${RELAY_PATH} → HTTP 421 sem snodes (upstream ${targetUrl})`,
              typeof parsed === 'string' ? parsed.slice(0, 400) : parsed,
            );
            throw new Error(
              `Relay HTTP 421 for upstream ${targetUrl}`,
            );
          }
        }
        return { payload: parsed, httpStatus: response.status, rttMs };
      }

      let errorBody = '';
      try {
        errorBody = await response.text();
      } catch {
        errorBody = '(unreadable body)';
      }
      sessionNetLog.error(
        `Relay ${RELAY_PATH} → HTTP ${response.status} (upstream ${targetUrl})`,
        errorBody.slice(0, 400),
      );
      throw new Error(
        `Relay HTTP ${response.status} for upstream ${targetUrl}: ${errorBody.slice(0, 200)}`,
      );
    } finally {
      window.clearTimeout(timeout);
      signal?.removeEventListener('abort', onAbort);
    }
  }

  async postJson(
    absoluteHttpsUrl: string,
    body: unknown,
    signal?: AbortSignal,
  ): Promise<unknown> {
    const { payload } = await this.relayFetch(absoluteHttpsUrl, body, signal);
    return payload;
  }

  async postJsonDetailed(
    absoluteHttpsUrl: string,
    body: unknown,
    signal?: AbortSignal,
  ): Promise<{ payload: unknown; httpStatus: number; rttMs: number }> {
    return this.relayFetch(absoluteHttpsUrl, body, signal);
  }

  /**
   * Single-node storage_rpc (no redirect follow). Used internally by failover.
   */
  private async storageRpcOnce(
    node: Snode,
    method: string,
    params: Record<string, unknown>,
    signal?: AbortSignal,
    authHeaders?: SessionAuthHeaders,
  ): Promise<{ payload: unknown; httpStatus: number; rttMs: number }> {
    const targetUrl = this.storageUrl(node);
    const endpoint = snodeEndpoint(node);

    const rpcPayload = {
      jsonrpc: '2.0' as const,
      id: '0',
      method,
      params,
    };

    const headers =
      authHeaders ??
      (method === 'retrieve' ? sessionAuthHeadersFromParams(params) : undefined);

    sessionNetLog.info(
      `Enviando via ${RELAY_PATH} → SNode ${endpoint} method=${method}`,
      { targetUrl, transport: this.transportMode, hasSessionAuth: Boolean(headers) },
    );

    if (method === 'store') {
      sessionNetLog.info(
        `Disparando store via relay (targetUrl=${targetUrl})`,
      );
    }

    try {
      const result = await this.relayFetch(
        targetUrl,
        rpcPayload,
        signal,
        headers,
      );
      const rpcStatus = describeRpcResult(result.payload);

      if (isSwarmRedirect(result.payload, method)) {
        sessionNetLog.warn(
          `Nó ${endpoint} respondeu redirect de swarm (snodes) — HTTP ${result.httpStatus}`,
          { method, node: summarizeSnode(node), rpc: rpcStatus },
        );
        return result;
      }

      if (method === 'store') {
        sessionNetLog.success(
          `Resposta via relay: status ${result.httpStatus} OK (RTT: ${result.rttMs}ms)`,
          { rpc: rpcStatus, node: summarizeSnode(node) },
        );
      } else {
        sessionNetLog.success(
          `Resposta via relay de ${endpoint}: HTTP ${result.httpStatus}, RPC ${rpcStatus}, RTT ${result.rttMs}ms`,
          { method, node: summarizeSnode(node) },
        );
      }

      return result;
    } catch (err) {
      const status = httpStatusFromError(err);
      sessionNetLog.warn(
        `Nó ${endpoint} indisponível via relay (status ${status}). Penalizando e tentando próximo…`,
        {
          method,
          node: summarizeSnode(node),
          error: err instanceof Error ? err.message : 'rpc-fail',
        },
      );
      this.markPenalized(
        node,
        status === 'timeout' ? 'timeout' : `HTTP ${status}`,
      );
      throw err;
    }
  }

  /**
   * Apply an authoritative `snodes` redirect: cache swarm and retry on 1–2 nodes.
   */
  private async followSwarmRedirect(
    fromNode: Snode,
    method: string,
    params: Record<string, unknown>,
    redirectBody: unknown,
    signal: AbortSignal | undefined,
    redirectDepth: number,
    authHeaders?: SessionAuthHeaders,
  ): Promise<{ result: unknown; node: Snode }> {
    if (redirectDepth >= MAX_SWARM_REDIRECTS) {
      throw new Error(
        `Too many swarm redirects for ${method} (max ${MAX_SWARM_REDIRECTS})`,
      );
    }

    const pubkey = pubkeyFromParams(params);
    const newSwarm = extractSnodeList(redirectBody);
    if (newSwarm.length === 0) {
      throw new Error('Swarm redirect without parseable snodes');
    }

    if (pubkey) {
      this.cacheSwarm(pubkey, newSwarm);
    } else {
      sessionNetLog.warn(
        'Swarm redirect sem pubkey nos params — seguindo sem cache persistente',
        summarizeSnodes(newSwarm),
      );
    }

    this.markPenalized(fromNode, 'wrong-swarm');

    const healthy = this.healthyNodes(newSwarm);
    const preferred = (healthy.length > 0 ? healthy : newSwarm).filter(
      (n) => snodeKey(n) !== snodeKey(fromNode),
    );
    const primary = preferred.slice(0, 2);
    const rest = newSwarm.filter(
      (n) => !primary.some((p) => snodeKey(p) === snodeKey(n)),
    );
    const ordered = primary.length > 0 ? [...primary, ...rest] : newSwarm;

    sessionNetLog.info(
      `Seguindo redirect de swarm → reenviando ${method} (prioridade ${Math.min(2, ordered.length)} nó(s))`,
      summarizeSnodes(ordered.slice(0, 2)),
    );

    return this.storageRpcWithFailover(
      ordered,
      method,
      params,
      signal,
      redirectDepth + 1,
      authHeaders,
    );
  }

  async storageRpc(
    node: Snode,
    method: string,
    params: Record<string, unknown>,
    signal?: AbortSignal,
    authHeaders?: SessionAuthHeaders,
  ): Promise<unknown> {
    const { payload } = await this.storageRpcOnce(
      node,
      method,
      params,
      signal,
      authHeaders,
    );
    if (isSwarmRedirect(payload, method)) {
      const followed = await this.followSwarmRedirect(
        node,
        method,
        params,
        payload,
        signal,
        0,
        authHeaders,
      );
      return followed.result;
    }
    return payload;
  }

  /**
   * Try swarm nodes in order until one returns a real store/retrieve body.
   * Wrong-swarm `snodes` responses update the cache and restart on the new set.
   */
  async storageRpcWithFailover(
    swarm: readonly Snode[],
    method: string,
    params: Record<string, unknown>,
    signal?: AbortSignal,
    redirectDepth = 0,
    authHeaders?: SessionAuthHeaders,
  ): Promise<{ result: unknown; node: Snode }> {
    const candidates = this.healthyNodes(swarm);
    const queue = candidates.length > 0 ? candidates : [...swarm];
    let lastError: unknown;

    sessionNetLog.info(
      `Failover ${method}: tentando ${queue.length} nó(s) da swarm`,
      summarizeSnodes(queue),
    );

    for (const node of queue) {
      if (signal?.aborted) {
        throw new DOMException('Aborted', 'AbortError');
      }
      try {
        const { payload } = await this.storageRpcOnce(
          node,
          method,
          params,
          signal,
          authHeaders,
        );
        if (isSwarmRedirect(payload, method)) {
          return this.followSwarmRedirect(
            node,
            method,
            params,
            payload,
            signal,
            redirectDepth,
            authHeaders,
          );
        }
        return { result: payload, node };
      } catch (err) {
        lastError = err;
      }
    }

    sessionNetLog.error(
      `Falha na swarm: todos os nós falharam para method=${method}`,
      { attempted: queue.length },
    );

    throw lastError instanceof Error
      ? lastError
      : new Error(`All swarm nodes failed for ${method}`);
  }

  async refreshNodes(signal?: AbortSignal): Promise<Snode[]> {
    if (this.refreshInFlight) {
      return this.refreshInFlight;
    }

    this.refreshInFlight = this.doRefreshNodes(signal).finally(() => {
      this.refreshInFlight = null;
    });
    return this.refreshInFlight;
  }

  private async doRefreshNodes(signal?: AbortSignal): Promise<Snode[]> {
    const params = {
      active_only: true,
      fields: {
        public_ip: true,
        storage_port: true,
        pubkey_ed25519: true,
        pubkey_x25519: true,
        swarm: true,
        storage_server_version: true,
        storage_lmq_port: true,
      },
    };

    const body = {
      jsonrpc: '2.0',
      id: 'snode_pool',
      method: 'get_service_nodes',
      params,
    };

    sessionNetLog.info('Consultando seed nodes (get_service_nodes)...', {
      seeds: [...SEED_JSON_RPC],
      transport: this.transportMode,
    });

    try {
      const payload = await Promise.any(
        SEED_JSON_RPC.map((seedUrl) => this.postJson(seedUrl, body, signal)),
      );
      const nodes = extractSnodeList(payload).filter(
        (n) => n.port > 0 && n.ip !== '0.0.0.0',
      );
      if (nodes.length > 0) {
        this.nodes = nodes;
        sessionNetLog.success(
          `Pool atualizado: ${nodes.length} storage nodes ativos`,
          {
            sample: summarizeSnodes(nodes.slice(0, 8)),
            total: nodes.length,
          },
        );
        return nodes;
      }
      sessionNetLog.warn('Seed respondeu sem nós de storage válidos');
    } catch (err) {
      sessionNetLog.warn('get_service_nodes falhou em todos os seeds', {
        error: err instanceof Error ? err.message : 'seed-fail',
      });
    }

    // Secondary attempt: oxend-style get_n_service_nodes against bootstrap hosts.
    sessionNetLog.info('Tentando fallback get_n_service_nodes nos seeds...');
    try {
      const payload = await Promise.any(
        SEED_BOOTSTRAP_HTTPS.map((base) =>
          this.postJson(
            `${base}/json_rpc`,
            {
              jsonrpc: '2.0',
              id: 'snode_pool_n',
              method: 'get_n_service_nodes',
              params: {
                active_only: true,
                fields: [
                  'public_ip',
                  'storage_port',
                  'pubkey_x25519',
                  'pubkey_ed25519',
                  'swarm_id',
                ],
              },
            },
            signal,
          ),
        ),
      );
      const nodes = extractSnodeList(payload).filter(
        (n) => n.port > 0 && n.ip !== '0.0.0.0',
      );
      if (nodes.length > 0) {
        this.nodes = nodes;
        sessionNetLog.success(
          `Pool atualizado via get_n_service_nodes: ${nodes.length} nós`,
          {
            sample: summarizeSnodes(nodes.slice(0, 8)),
            total: nodes.length,
          },
        );
        return nodes;
      }
    } catch (err) {
      sessionNetLog.error('Falha ao refrescar pool a partir dos seeds', {
        error: err instanceof Error ? err.message : 'seed-fail',
      });
    }

    throw new Error('Failed to refresh service node pool from seeds');
  }

  /**
   * Locate the 3–5 storage nodes responsible for a Session ID.
   * Prefers cached authoritative swarm, then live `get_snodes_for_pubkey`,
   * then consistent hashing.
   */
  async getSwarmForPublicKey(
    destinationSessionId: string,
    signal?: AbortSignal,
  ): Promise<Snode[]> {
    if (this.nodes.length === 0) {
      await this.refreshNodes(signal);
    }

    const pubkey = normalizeSessionPubkey(destinationSessionId);

    const cached = this.swarmByPubkey.get(pubkey);
    if (cached && cached.length > 0) {
      const healthy = this.healthyNodes(cached);
      const use = healthy.length > 0 ? healthy : cached;
      sessionNetLog.info(
        `Swarm em cache para ${truncateId(pubkey)}: ${use.length} nós`,
        summarizeSnodes(use),
      );
      return use.slice(0, this.swarmSize);
    }

    sessionNetLog.info(
      `Calculando swarm para destino ${truncateId(pubkey)}`,
    );

    const probes = this.healthyNodes().slice(0, 8);
    const probeList = probes.length > 0 ? probes : this.nodes.slice(0, 8);

    for (const probe of probeList) {
      try {
        const result = await this.storageRpcOnce(
          probe,
          'get_snodes_for_pubkey',
          { pubkey },
          signal,
        );
        const swarm = extractSnodeList(result.payload);
        if (swarm.length >= MIN_SWARM_SIZE) {
          const selected = this.cacheSwarm(pubkey, swarm.slice(0, this.swarmSize));
          sessionNetLog.success(
            `Swarm RPC para ${truncateId(pubkey)}: ${selected.length} nós`,
            summarizeSnodes(selected),
          );
          return selected;
        }
        if (swarm.length > 0) {
          const selected = this.cacheSwarm(pubkey, swarm);
          sessionNetLog.success(
            `Swarm RPC (parcial) para ${truncateId(pubkey)}: ${selected.length} nós`,
            summarizeSnodes(selected),
          );
          return selected;
        }
      } catch {
        // try next probe
      }
    }

    const hashed = await this.consistentHashSwarm(pubkey);
    sessionNetLog.warn(
      `Swarm por hash consistente para ${truncateId(pubkey)}: ${hashed.length} nós`,
      summarizeSnodes(hashed),
    );
    return hashed;
  }

  /** Deterministic swarm selection when RPC lookup is unavailable. */
  async consistentHashSwarm(destinationSessionId: string): Promise<Snode[]> {
    const pubkey = normalizeSessionPubkey(destinationSessionId);
    const pool = this.healthyNodes();
    const source = pool.length >= MIN_SWARM_SIZE ? pool : this.nodes;
    if (source.length === 0) {
      return [];
    }

    const scored = await Promise.all(
      source.map(async (node) => {
        const score = await sha256Hex(`${pubkey}|${node.pubkey_ed25519}|${snodeKey(node)}`);
        return { node, score };
      }),
    );

    scored.sort((a, b) => {
      if (a.score < b.score) {
        return -1;
      }
      if (a.score > b.score) {
        return 1;
      }
      return a.node.pubkey_ed25519.localeCompare(b.node.pubkey_ed25519);
    });

    return scored.slice(0, this.swarmSize).map((entry) => entry.node);
  }
}

let sharedPool: SnodePool | null = null;

export function getSharedSnodePool(options?: SnodePoolOptions): SnodePool {
  if (!sharedPool) {
    sharedPool = new SnodePool(options);
  } else if (options?.transportMode) {
    sharedPool.setTransportMode(options.transportMode);
  }
  return sharedPool;
}

export function resetSharedSnodePool(): void {
  sharedPool?.clear();
  sharedPool = null;
}

export { normalizeSessionPubkey, sessionIdToStoragePubKey, SEED_JSON_RPC, SEED_BOOTSTRAP_HTTPS };
