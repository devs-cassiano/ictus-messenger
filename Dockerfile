# =============================================================================
# Ictus Messenger — multi-stage Docker image (optional; PM2/NPM host flow unchanged)
# Runtime layout mirrors the monorepo so path.resolve(__dirname, '../../frontend/dist')
# resolves identically on the host and inside the container.
# =============================================================================

# ----- Stage 1: build frontend + backend -----
FROM node:20-alpine AS builder

WORKDIR /app

# Dependency manifests first (better layer cache)
COPY package.json package-lock.json ./
COPY frontend/package.json ./frontend/
COPY backend/package.json ./backend/

RUN npm install

# Source + compile both workspaces
COPY . .
RUN npm run build

# ----- Stage 2: production runner -----
FROM node:20-alpine AS runner

WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3001

# Workspace manifests (frontend package.json required for workspace map; no FE runtime deps)
COPY package.json package-lock.json ./
COPY frontend/package.json ./frontend/
COPY backend/package.json ./backend/

RUN npm install --omit=dev --workspace=backend \
  && npm cache clean --force

# Compiled artifacts only
COPY --from=builder /app/backend/dist ./backend/dist
COPY --from=builder /app/frontend/dist ./frontend/dist

EXPOSE 3001

# Same entry as `npm start` on the host — __dirname = /app/backend/dist
CMD ["node", "backend/dist/server.js"]
