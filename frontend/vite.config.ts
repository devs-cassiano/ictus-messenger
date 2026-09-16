import react from '@vitejs/plugin-react'
import { defineConfig, type Plugin } from 'vite'

/**
 * CSP for <meta> and HTTP headers.
 * - No `frame-ancestors` in meta (invalid there); clickjacking via X-Frame-Options.
 * - Libsodium WASM needs `wasm-unsafe-eval` (+ `unsafe-eval` for some builds).
 * - `connect-src` allows same-origin relay and http(s) for tooling; browser still
 *   sends Session upstream only as JSON `targetUrl` inside POST /api/relay.
 */
const ICTUS_CSP =
  "default-src 'self'; " +
  "script-src 'self' 'unsafe-inline' 'unsafe-eval' 'wasm-unsafe-eval'; " +
  "style-src 'self' 'unsafe-inline'; " +
  "font-src 'self' data:; " +
  "img-src 'self' data: blob:; " +
  "media-src 'self' blob: mediastream:; " +
  "connect-src 'self' http: https: data: ws: wss:; " +
  "worker-src 'self' blob:; " +
  "object-src 'none'; " +
  "base-uri 'self'; " +
  "form-action 'self'"

const sharedHeaders = {
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'credentialless',
  'Cache-Control': 'no-store, no-cache, must-revalidate, private',
  Pragma: 'no-cache',
  'Referrer-Policy': 'no-referrer',
}

function htmlCspPlugin(csp: string): Plugin {
  return {
    name: 'ictus-html-csp',
    transformIndexHtml(html) {
      return html.replace(
        /(<meta\s+http-equiv="Content-Security-Policy"\s+content=")([^"]*)(")/i,
        `$1${csp}$3`,
      )
    },
  }
}

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const isProd = mode === 'production'

  return {
    plugins: [react(), htmlCspPlugin(ICTUS_CSP)],
    build: isProd
      ? {
          rolldownOptions: {
            output: {
              minify: {
                compress: {
                  dropConsole: true,
                  dropDebugger: true,
                },
              },
            },
          },
        }
      : undefined,
    server: {
      port: 5173,
      headers: {
        ...sharedHeaders,
        'Content-Security-Policy': ICTUS_CSP,
      },
      // Dev-only reverse proxy → Gateway Bridge.
      proxy: {
        '/api': {
          target: 'http://127.0.0.1:3001',
          changeOrigin: true,
          secure: false,
        },
        '/storage_rpc': {
          target: 'http://127.0.0.1:3001',
          changeOrigin: true,
          secure: false,
        },
      },
    },
    preview: {
      headers: {
        ...sharedHeaders,
        'Content-Security-Policy': ICTUS_CSP,
      },
    },
  }
})
