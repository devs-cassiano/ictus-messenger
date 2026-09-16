/**
 * POST /api/relay handler helpers — explicit targetUrl forwarding.
 * Kept in server.ts for the request path; TLS agent lives in session/client.
 *
 * Production also serves the Vite SPA from ../../frontend/dist (monorepo-safe via
 * path.resolve(__dirname, ...)), so `node backend/dist/server.js` works from repo root.
 */

import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs';
import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import {
  forwardStorageRpcToUrl,
  refreshServiceNodes,
  relayStorageMethod,
  forwardToSessionNode,
} from './session/client';
import {
  SSRF_BLOCKED_MESSAGE,
  validateTargetUrl,
} from './security/validateTargetUrl';
import { logUnexpectedRelayError } from './security/quietTransport';

/** Always load backend/.env regardless of process.cwd() (root vs backend/). */
dotenv.config({ path: path.resolve(__dirname, '../.env') });

const PORT = Number(process.env.PORT) || 3001;

/**
 * Absolute path to the Vite production build.
 * __dirname = <repo>/backend/dist → ../../frontend/dist
 *
 * Resolves the same way on:
 *   - host (`npm start` / PM2 from monorepo root or cwd=backend)
 *   - Docker (`WORKDIR /app`, CMD node backend/dist/server.js)
 */
const FRONTEND_DIST = path.resolve(__dirname, '../../frontend/dist');
const FRONTEND_INDEX = path.join(FRONTEND_DIST, 'index.html');


/**
 * External Session nodes are ON by default.
 * Set USE_EXTERNAL_NODES=false only for emergency local debugging (not recommended).
 */
const USE_EXTERNAL_NODES = process.env.USE_EXTERNAL_NODES !== 'false';

const LOG = '[SESSION-NODE-RELAY]';
const RELAY_LOG = '[SESSION-RELAY]';
const isDev = process.env.NODE_ENV !== 'production';

/** Informational transport logs are silenced; use console.warn/error for failures. */
function debugLog(..._args: unknown[]): void {
  // no-op — keep call sites for optional local re-enable
}

/**
 * Production CORS: comma-separated origins via CORS_ORIGINS.
 * Development defaults to local Vite origins.
 */
function resolveCorsOrigins(): boolean | string | string[] {
  const fromEnv = process.env.CORS_ORIGINS?.trim();
  if (fromEnv) {
    const list = fromEnv
      .split(',')
      .map((o) => o.trim())
      .filter((o) => o.length > 0);
    if (list.length === 1) {
      return list[0]!;
    }
    if (list.length > 1) {
      return list;
    }
  }
  if (isDev) {
    return [
      'http://localhost:5173',
      'http://127.0.0.1:5173',
      'http://localhost:5174',
      'http://127.0.0.1:5174',
    ];
  }
  // Same-origin reverse proxy / missing config — deny cross-origin browser calls.
  return false;
}

const app = express();

/** CORS must be first — Vite proxies same-origin, but direct :3001 calls still need it. */
app.use(
  cors({
    origin: resolveCorsOrigins(),
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'Accept',
      'X-Requested-With',
      'X-Session-Timestamp',
      'X-Session-Signature',
      'X-Session-Pubkey',
    ],
  }),
);
app.options('/{*splat}', cors({ origin: resolveCorsOrigins(), credentials: true }));

/** Forensic / browser hardening headers on every response. */
app.use((_req: Request, res: Response, next: NextFunction): void => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Embedder-Policy', 'credentialless');
  res.setHeader(
    'Cache-Control',
    'no-store, no-cache, must-revalidate, private',
  );
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

/** Strict CSP only for API JSON responses — SPA relies on index.html meta CSP. */
app.use((req: Request, res: Response, next: NextFunction): void => {
  if (
    req.path.startsWith('/api') ||
    req.path.startsWith('/storage_rpc') ||
    req.path === '/health'
  ) {
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'none'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'",
    );
  }
  next();
});

app.use(express.json({ limit: '2mb', strict: false }));

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

/**
 * Normalize /api/relay JSON body from the browser.
 * Accepts canonical `{ targetUrl, payload, headers? }` and tolerates mild shape drift.
 */
function normalizeRelayBody(raw: unknown): {
  targetUrl?: string;
  payload?: unknown;
  headers?: Record<string, unknown>;
  onionPacket?: unknown;
  targetNodeIndex?: number;
} {
  let body: unknown = raw;
  if (typeof body === 'string') {
    try {
      body = JSON.parse(body) as unknown;
    } catch {
      return {};
    }
  }
  if (!isRecord(body)) {
    return {};
  }

  const targetUrl =
    asString(body.targetUrl)?.trim() ??
    asString(body.target)?.trim() ??
    asString(body.url)?.trim();

  let payload: unknown =
    body.payload !== undefined
      ? body.payload
      : body.body !== undefined
        ? body.body
        : body.jsonrpc !== undefined
          ? body
          : undefined;

  if (typeof payload === 'string') {
    try {
      payload = JSON.parse(payload) as unknown;
    } catch {
      // keep string — upstream may reject
    }
  }

  const headers = isRecord(body.headers) ? body.headers : undefined;
  const onionPacket = body.onionPacket;
  const targetNodeIndex =
    typeof body.targetNodeIndex === 'number' &&
    Number.isFinite(body.targetNodeIndex)
      ? body.targetNodeIndex
      : undefined;

  return { targetUrl, payload, headers, onionPacket, targetNodeIndex };
}

function extractMethodAndParams(body: unknown): {
  method: string;
  params: Record<string, unknown>;
} | null {
  if (!isRecord(body)) {
    return null;
  }

  const root = isRecord(body.onionPacket) ? body.onionPacket : body;
  const method = asString(root.method)?.toLowerCase();
  if (!method) {
    return null;
  }

  if (isRecord(root.params)) {
    return { method, params: { ...root.params } };
  }

  const params: Record<string, unknown> = { ...root };
  delete params.method;
  return { method, params };
}

/**
 * Decode authority segments such as `seed2.getsession.org%3A443`.
 */
function decodeAuthority(raw: string): string {
  let decoded = raw;
  try {
    decoded = decodeURIComponent(raw);
  } catch {
    decoded = raw;
  }
  if (decoded.includes('%')) {
    try {
      decoded = decodeURIComponent(decoded);
    } catch {
      // keep first decode
    }
  }
  return decoded;
}

function buildSnodeTarget(authorityRaw: string, pathSuffix: string): string {
  const authority = decodeAuthority(authorityRaw);
  let host = authority;
  let port: string | undefined;

  if (authority.startsWith('[')) {
    const m = authority.match(/^\[([^\]]+)\](?::(\d+))?$/);
    if (m) {
      host = m[1]!;
      port = m[2];
    }
  } else {
    const idx = authority.lastIndexOf(':');
    if (idx > 0 && /^\d+$/.test(authority.slice(idx + 1))) {
      host = authority.slice(0, idx);
      port = authority.slice(idx + 1);
    }
  }

  const rest =
    pathSuffix && pathSuffix.length > 0
      ? pathSuffix.startsWith('/')
        ? pathSuffix
        : `/${pathSuffix}`
      : '/storage_rpc/v1';

  if (!port || port === '443') {
    return `https://${host}${rest}`;
  }
  return `https://${host}:${port}${rest}`;
}

/**
 * POST /storage_rpc/v1 — swarm-aware store/retrieve (server picks nodes).
 */
app.post(
  '/storage_rpc/v1',
  async (req: Request, res: Response): Promise<void> => {
    try {
      if (!USE_EXTERNAL_NODES) {
        res.status(503).json({
          error:
            'External Session nodes disabled. Set USE_EXTERNAL_NODES=true.',
        });
        return;
      }

      const parsed = extractMethodAndParams(req.body);
      if (!parsed) {
        res.status(400).json({
          error: 'Expected JSON body with method (store|retrieve|…) and params',
        });
        return;
      }

      debugLog(`${LOG} /storage_rpc/v1 method=${parsed.method}`);
      const result = await relayStorageMethod(parsed.method, parsed.params);
      res.status(result.status).json(result.data);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      logUnexpectedRelayError(`${LOG} Erro em /storage_rpc/v1:`, error);
      res.status(502).json({
        error: 'Upstream node unreachable',
        details: message,
      });
    }
  },
);

/**
 * POST /api/relay
 *
 * Primary browser transport:
 *   { targetUrl: "https://ip:port/storage_rpc/v1", payload: { jsonrpc, method, params } }
 *
 * Legacy (still supported):
 *   { onionPacket: { method, pubkey, data, ... } }
 */
app.post('/api/relay', async (req: Request, res: Response): Promise<void> => {
  try {
    if (!USE_EXTERNAL_NODES) {
      res.status(503).json({
        error:
          'External Session nodes disabled. Set USE_EXTERNAL_NODES=true.',
      });
      return;
    }

    const body = normalizeRelayBody(req.body);

    // --- Preferred: explicit targetUrl + payload (frontend SnodePool) ---
    const targetUrl = body.targetUrl;
    if (targetUrl) {
      if (body.payload === undefined || body.payload === null) {
        res.status(400).json({ error: 'targetUrl e payload são obrigatórios' });
        return;
      }
      if (!validateTargetUrl(targetUrl)) {
        res.status(400).json({
          error: SSRF_BLOCKED_MESSAGE,
          targetUrl,
        });
        return;
      }

      const methodHint = isRecord(body.payload)
        ? asString(body.payload.method)
        : undefined;
      debugLog(
        `${RELAY_LOG} Encaminhando chamada para ${targetUrl}` +
          (methodHint ? ` (method: ${methodHint})` : ''),
      );

      const upstreamHeaders: Record<string, string> = {};
      if (body.headers) {
        for (const key of [
          'X-Session-Timestamp',
          'X-Session-Signature',
          'X-Session-Pubkey',
        ] as const) {
          const value =
            asString(body.headers[key]) ??
            asString(body.headers[key.toLowerCase()]);
          if (value) {
            upstreamHeaders[key] = value;
          }
        }
      }

      const result = await forwardStorageRpcToUrl(
        targetUrl,
        body.payload,
        Object.keys(upstreamHeaders).length > 0 ? upstreamHeaders : undefined,
      );
      debugLog(
        `${RELAY_LOG} Resposta do nó ${targetUrl}: HTTP ${result.status}`,
      );
      res.status(result.status).json(result.data);
      return;
    }

    // --- Legacy onionPacket swarm-aware path ---
    const { onionPacket, targetNodeIndex } = body;
    if (onionPacket === undefined || onionPacket === null) {
      res.status(400).json({
        error: 'Informe targetUrl+payload ou onionPacket',
      });
      return;
    }

    const parsed = extractMethodAndParams({ onionPacket });
    if (parsed) {
      debugLog(`${LOG} /api/relay onionPacket method=${parsed.method}`);
      const result = await relayStorageMethod(parsed.method, parsed.params);
      res.status(result.status).json(result.data);
      return;
    }

    const upstream = await forwardToSessionNode(
      onionPacket,
      targetNodeIndex ?? 0,
    );
    res.json(upstream);
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    logUnexpectedRelayError(`${RELAY_LOG} Falha de conexão:`, error);
    res.status(502).json({
      error: 'Upstream node unreachable',
      details: message,
    });
  }
});

/** Explicit method discovery for misconfigured clients / probes. */
app.all('/api/relay', (req: Request, res: Response): void => {
  if (req.method === 'OPTIONS') {
    res.sendStatus(204);
    return;
  }
  res.setHeader('Allow', 'POST, OPTIONS');
  res.status(405).json({ error: 'POST required on /api/relay' });
});

/**
 * Explicit JSON relay: POST /api/snode/rpc  { target, body }
 * (kept for compatibility; prefer /api/relay { targetUrl, payload })
 */
app.all('/api/snode/rpc', async (req: Request, res: Response): Promise<void> => {
  try {
    if (req.method === 'OPTIONS') {
      res.sendStatus(204);
      return;
    }
    if (req.method !== 'POST') {
      res.status(405).json({ error: 'POST required' });
      return;
    }
    if (!USE_EXTERNAL_NODES) {
      res.status(503).json({ error: 'External nodes disabled' });
      return;
    }
    const target = asString((req.body as { target?: unknown }).target);
    const body = (req.body as { body?: unknown }).body ?? {};
    if (!target) {
      res.status(400).json({ error: 'Missing target URL' });
      return;
    }
    if (!validateTargetUrl(target)) {
      res.status(400).json({ error: SSRF_BLOCKED_MESSAGE });
      return;
    }
    const result = await forwardStorageRpcToUrl(target, body);
    res.status(result.status).json(result.data);
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    logUnexpectedRelayError(`${LOG} Erro no repasse /api/snode/rpc:`, error);
    res.status(502).json({
      error: 'Upstream node unreachable',
      details: message,
    });
  }
});

/**
 * Dynamic seed/snode path proxy (legacy):
 *   /api/snode/<host>/json_rpc|storage_rpc/v1
 */
app.all(
  '/api/snode/{*splat}',
  async (req: Request, res: Response): Promise<void> => {
    try {
      if (req.method === 'OPTIONS') {
        res.sendStatus(204);
        return;
      }
      if (req.method !== 'POST' && req.method !== 'GET') {
        res.status(405).json({ error: 'POST or GET required' });
        return;
      }
      if (!USE_EXTERNAL_NODES) {
        res.status(503).json({ error: 'External nodes disabled' });
        return;
      }

      const splatParam = req.params.splat as string | string[] | undefined;
      const splat = Array.isArray(splatParam)
        ? splatParam.join('/')
        : String(splatParam ?? '');
      if (!splat || splat === 'rpc' || splat.startsWith('rpc/')) {
        if (!res.headersSent) {
          res
            .status(404)
            .json({ error: 'Use /api/relay or /api/snode/<host>/…' });
        }
        return;
      }

      const slash = splat.indexOf('/');
      const authorityRaw = slash === -1 ? splat : splat.slice(0, slash);
      const pathSuffix = slash === -1 ? '' : splat.slice(slash);
      if (!authorityRaw) {
        res.status(400).json({ error: 'Malformed /api/snode path' });
        return;
      }

      const targetUrl = buildSnodeTarget(authorityRaw, pathSuffix);
      if (!validateTargetUrl(targetUrl)) {
        res.status(400).json({ error: SSRF_BLOCKED_MESSAGE });
        return;
      }
      debugLog(`${LOG} Proxy ${req.method} → ${targetUrl}`);

      const result = await forwardStorageRpcToUrl(
        targetUrl,
        req.method === 'GET' ? {} : req.body,
      );
      res.status(result.status).json(result.data);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      logUnexpectedRelayError(`${LOG} Erro no repasse para seed/snode:`, error);
      res.status(502).json({
        error: 'Upstream node unreachable',
        details: message,
      });
    }
  },
);

app.get('/health', (_req: Request, res: Response): void => {
  res.json({
    ok: true,
    mode: USE_EXTERNAL_NODES ? 'external' : 'disabled',
    frontendDist: FRONTEND_DIST,
    frontendReady: fs.existsSync(FRONTEND_INDEX),
  });
});

/**
 * Serve the Vite SPA from the monorepo frontend build.
 * Works when started from repo root (`npm start`) or with cwd=backend (PM2).
 */
if (fs.existsSync(FRONTEND_DIST)) {
  app.use(
    express.static(FRONTEND_DIST, {
      index: false,
      fallthrough: true,
      // Hashed assets can be cached; HTML stays no-store via global header.
      setHeaders(res, filePath) {
        if (filePath.endsWith('.html')) {
          res.setHeader(
            'Cache-Control',
            'no-store, no-cache, must-revalidate, private',
          );
        } else if (/\.(?:js|css|woff2?|svg|png|jpg|webp)$/i.test(filePath)) {
          res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
        }
      },
    }),
  );

  app.get('/{*splat}', (req: Request, res: Response, next: NextFunction): void => {
    if (
      req.path.startsWith('/api') ||
      req.path.startsWith('/storage_rpc') ||
      req.path === '/health'
    ) {
      next();
      return;
    }
    if (!fs.existsSync(FRONTEND_INDEX)) {
      res.status(503).json({
        error: 'Frontend build missing',
        hint: 'Run npm run build from the monorepo root',
        expected: FRONTEND_INDEX,
      });
      return;
    }
    res.sendFile(FRONTEND_INDEX);
  });
} else {
  console.warn(
    `${LOG} Frontend dist não encontrado em ${FRONTEND_DIST} — apenas API ativa`,
  );
}

app.use(
  (
    err: unknown,
    _req: Request,
    res: Response,
    _next: NextFunction,
  ): void => {
    const message = err instanceof Error ? err.message : 'Internal relay error';
    logUnexpectedRelayError(`${LOG}`, err);
    if (!res.headersSent) {
      res.status(502).json({ error: message });
    }
  },
);

app.listen(PORT, () => {
  console.warn(
    `${LOG} Listening on :${PORT} (frontend: ${FRONTEND_DIST})`,
  );
  if (USE_EXTERNAL_NODES) {
    void refreshServiceNodes().catch((err: unknown) => {
      console.warn(
        `${LOG} Bootstrap inicial falhou (será retentado na 1ª request):`,
        err instanceof Error ? err.message : err,
      );
    });
  } else {
    console.warn(
      `${LOG} Modo externo DESATIVADO (USE_EXTERNAL_NODES=false) — relay recusará tráfego`,
    );
  }
});
