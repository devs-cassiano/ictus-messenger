import react from '@vitejs/plugin-react'
import { defineConfig, type Plugin } from 'vite'

/**
 * Production CSP stays strict (no unsafe-inline).
 * Dev must allow Vite's React Refresh preamble (inline <script>).
 * connect-src is same-origin only — blocks accidental browser→SNode HTTPS fetches.
 * Upstream HTTPS lives only as JSON `targetUrl` inside POST /api/relay.
 */
const cspProd =
  "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' blob: data:; media-src 'self' blob: mediastream:; connect-src 'self'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'; object-src 'none'"

const cspDev =
  "default-src 'none'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' blob: data:; media-src 'self' blob: mediastream:; connect-src 'self' ws://localhost:5173 wss://localhost:5173 ws://localhost:5174 wss://localhost:5174; worker-src 'self' blob:; frame-ancestors 'none'; form-action 'none'; base-uri 'none'; object-src 'none'"

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
        /content="__ICTUS_CSP__"/,
        `content="${csp}"`,
      )
    },
  }
}

// https://vite.dev/config/
export default defineConfig(({ command, mode }) => {
  const isServe = command === 'serve'
  const isProd = mode === 'production'
  const csp = isServe ? cspDev : cspProd

  return {
    plugins: [react(), htmlCspPlugin(csp)],
    // Vite 8 uses Oxc (via Rolldown) instead of esbuild.drop for stripping
    // console/debugger — equivalent to the former `esbuild: { drop: [...] }`.
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
        'Content-Security-Policy': csp,
      },
      // Dev-only reverse proxy → Gateway Bridge. Production static builds are
      // served behind the app gateway / reverse proxy (this block is ignored
      // for `vite build` output).
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
        'Content-Security-Policy': cspProd,
      },
    },
  }
})
