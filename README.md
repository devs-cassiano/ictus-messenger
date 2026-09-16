# Ictus Messenger — Monorepo & Execução

Monorepo TypeScript com **NPM Workspaces**: frontend React/Vite e backend Express (relay Session), orquestrados a partir da raiz.

**Requisito:** Node.js ≥ 20.

---

## 1. Arquitetura Monorepo

O projeto usa **NPM Workspaces** nativo (sem Lerna/Nx). A raiz declara os workspaces e concentra scripts globais, dependências de orquestração e o Dockerfile.

```text
session-messenger/
├── package.json          # workspaces, scripts unificados, concurrently, pm2
├── package-lock.json     # lockfile único
├── Dockerfile            # build multi-stage (opcional)
├── .dockerignore
├── frontend/             # React + TypeScript + Vite
│   └── package.json
└── backend/              # Express + TypeScript (relay + SPA estática)
    └── package.json
```

| Pacote | Papel |
|--------|--------|
| **Raiz** | Orquestração: instalação única, scripts globais (`dev`, `build`, `start`, PM2, Docker) e Dockerfile |
| **`/frontend`** | App React/TypeScript/Vite (UI, criptografia no cliente, IndexedDB) |
| **`/backend`** | Servidor Express/TypeScript: relay JSON-RPC para Service Nodes e, em produção, serve `frontend/dist` |

### Vantagens da raiz unificada

- **Instalação única** — `npm install` na raiz resolve dependências de todos os workspaces (`node_modules` hoisting + lockfile compartilhado).
- **Builds encadeados** — `npm run build` compila frontend e depois backend, gerando `frontend/dist` e `backend/dist`.
- **Execução paralela** — `npm run dev` sobe backend e frontend em watch via `concurrently`.

---

## 2. Guia de Comandos Unificados

Todos os comandos abaixo são executados na **raiz** do repositório.

### Setup

```bash
npm install
```

### Scripts (`package.json` da raiz)

| Script | Descrição |
|--------|-----------|
| `npm run dev` | Backend e frontend em paralelo (modo watch) via `concurrently` |
| `npm run build` | Compila sequencialmente os dois workspaces → pastas `dist` |
| `npm start` | Inicia o servidor já compilado com Node (`backend/dist/server.js`) |
| `npm run start:prod` | Sobe a aplicação em segundo plano com **PM2** (`ictus-messenger`) |
| `npm run restart:prod` | Reinicia o processo no PM2 |
| `npm run stop:prod` | Interrompe o processo no PM2 |

### Fluxos típicos

**Desenvolvimento**

```bash
npm install
npm run dev
```

- Backend: `http://localhost:3001`
- Frontend (Vite): `http://localhost:5173` (proxy `/api` → backend)

**Produção no host (build + Node)**

```bash
npm run build
npm start
```

**Produção no host (PM2)**

```bash
npm run build
npm run start:prod      # sobe
npm run restart:prod    # reinicia
npm run stop:prod       # para
```

> Em produção o Express serve o SPA estático de `frontend/dist` e a API em `/api/*` na mesma origem (porta `3001` por padrão).

---

## 3. Execução Conteinerizada (Docker)

Opcional: a mesma árvore monorepo roda em container. O fluxo host (NPM / PM2) permanece inalterado.

### Build multi-stage

O `Dockerfile` usa dois estágios:

1. **`builder` (`node:20-alpine`)** — `npm install` + `npm run build` nos workspaces; gera `frontend/dist` e `backend/dist`.
2. **`runner` (`node:20-alpine`)** — imagem final enxuta: apenas manifests, `node_modules` de produção do backend e os artefatos `dist`. Entrypoint: `node backend/dist/server.js` na porta `3001`.

A layout no container espelha o monorepo para que o caminho resolvido pelo backend (`…/frontend/dist`) seja idêntico ao do host.

### Comandos

| Ação | Docker | Atalho NPM |
|------|--------|------------|
| Build da imagem | `docker build -t ictus-messenger .` | `npm run docker:build` |
| Execução | `docker run -d --name ictus-messenger -p 3001:3001 --restart unless-stopped ictus-messenger` | `npm run docker:run` |
| Logs | `docker logs -f ictus-messenger` | `npm run docker:logs` |
| Parada / remoção | `docker stop ictus-messenger && docker rm ictus-messenger` | `npm run docker:stop` |

Exemplos:

```bash
# Build
docker build -t ictus-messenger .
# ou
npm run docker:build

# Run (detach, porta 3001, restart policy)
docker run -d --name ictus-messenger -p 3001:3001 --restart unless-stopped ictus-messenger
# ou
npm run docker:run

# Logs
docker logs -f ictus-messenger
# ou
npm run docker:logs

# Stop + remove
docker stop ictus-messenger && docker rm ictus-messenger
# ou
npm run docker:stop
```

> O script `npm run docker:run` publica a porta em `127.0.0.1:3001` (bind local). Para expor em todas as interfaces, use o `docker run … -p 3001:3001` acima.

---

## Mapa rápido

| Objetivo | Comando |
|----------|---------|
| Dev (watch) | `npm run dev` |
| Build | `npm run build` |
| Start (Node) | `npm start` |
| Start (PM2) | `npm run start:prod` |
| Docker build/run | `npm run docker:build` → `npm run docker:run` |
