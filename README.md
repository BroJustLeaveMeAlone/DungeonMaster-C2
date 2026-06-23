# DungeonMaster (DM)

A modular, operator-first command-and-control framework built for authorized red team operations. DungeonMaster gives a full team real-time visibility into every session, task, and evasion event — with an AI co-pilot that suggests the next TTP based on live target context.

---

## Architecture

```
┌─────────────┐     HTTPS (TLS 1.3)     ┌──────────────────────────────────────┐
│   DM Agent  │ ──────────────────────► │           DM Server (Go)             │
│   (Rust)    │ ◄────────────────────── │  ┌─────────┐  ┌────────┐  ┌──────┐  │
└─────────────┘    poll / task output   │  │  C2 API │  │ REST   │  │ gRPC │  │
                                        │  └────┬────┘  └───┬────┘  └──┬───┘  │
┌─────────────┐     SSE / REST          │       └───────────┴──────────┘      │
│  Operator   │ ──────────────────────► │       session mgr · collab bus       │
│  UI (React) │ ◄────────────────────── │  PostgreSQL  ·  Redis  ·  MinIO     │
└─────────────┘    live event stream    └──────────────────┬───────────────────┘
                                                           │ gRPC
┌─────────────┐                                  ┌────────▼────────┐
│  Redirector │ ── filters + forwards ──►         │   AI Engine     │
│  (nginx)    │                                   │   (FastAPI)     │
└─────────────┘                                   │  TTP ranker     │
                                                  │  Claude API     │
                                                  └─────────────────┘
```

---

## Components

| Component | Stack | What it does |
|-----------|-------|-------------|
| `server/` | Go 1.22 | REST + gRPC operator API, C2 listener, session lifecycle, collab bus |
| `agent/` | Rust (no_std-friendly) | Implant: ECDH key exchange, AES-GCM task encryption, HTTPS/DNS/SMB channels |
| `ai/` | Python / FastAPI | TTP suggestion engine, evasion advisor, report generator (Claude API) |
| `ui/` | React + TypeScript | Operator console: session list, xterm.js shell, live event feed, MITRE heatmap |
| `redirector/` | nginx | Traffic filtering, domain-fronting support, agent callback forwarding |

---

## Prerequisites

```
winget install GoLang.Go           # Go 1.22+
winget install Rustlang.Rustup     # then: rustup target add x86_64-pc-windows-gnu
winget install Docker.DockerDesktop
winget install Google.Protobuf     # for Phase 2 gRPC codegen
```

---

## Quick Start

**1. Start the full stack**
```bash
cd DungeonMaster-C2
docker-compose up
```

This starts PostgreSQL (TimescaleDB), Redis, MinIO, the DM server, AI engine, and UI.

**2. Verify the server**
```
GET http://localhost:8080/api/v1/campaigns   # requires JWT
```

**3. Build the UI (dev mode)**
```bash
cd ui
npm install
npm run dev     # → http://localhost:5173
```

**4. Build the agent**
```bash
cd agent
cargo build --release --target x86_64-pc-windows-gnu
```

---

## Configuration

All runtime config is environment-variable driven. The key ones:

| Variable | Default | Description |
|----------|---------|-------------|
| `DM_DB_DSN` | `postgres://dm:dm@localhost:5432/dm` | PostgreSQL connection string |
| `DM_REDIS_ADDR` | `localhost:6379` | Redis address |
| `DM_JWT_SECRET` | *(hardcoded fallback)* | **Override this in production** |
| `DM_HTTP_ADDR` | `:8080` | Operator REST API + UI |
| `DM_GRPC_ADDR` | `:50051` | gRPC service port |
| `DM_C2_ADDR` | `:4443` | C2 listener (agent callbacks, TLS) |
| `DM_TLS_CERT` / `DM_TLS_KEY` | `tls/server.crt/.key` | TLS cert for C2 listener |
| `ANTHROPIC_API_KEY` | — | Required for AI report generation |

---

## API Overview

```
POST   /api/v1/auth/login             # bcrypt + TOTP → JWT pair
POST   /api/v1/auth/refresh           # refresh token → new access token

GET    /api/v1/sessions               # list sessions (?campaign_id= &alive_only=)
GET    /api/v1/sessions/{id}
POST   /api/v1/sessions/{id}/revoke
PATCH  /api/v1/sessions/{id}/sleep    # update sleep/jitter
GET    /api/v1/sessions/{id}/tasks    # (?pending_only=)

POST   /api/v1/tasks                  # queue a task
GET    /api/v1/tasks/{id}
DELETE /api/v1/tasks/{id}             # cancel (queued only)

GET    /api/v1/campaigns              # (?active_only=)
POST   /api/v1/campaigns
GET    /api/v1/campaigns/{id}
PUT    /api/v1/campaigns/{id}

GET    /api/v1/events                 # SSE stream (?campaign_id= required)
```

---

## Operator Channels (agent → server)

```
POST /r   — agent registration (first contact, ECDH key exchange)
GET  /c   — task poll (encrypted session ID in X-Request-ID header)
POST /c   — task output submission
```

---

## Security Notes

- All agent↔server traffic: TLS 1.3 minimum
- Session keys derived via ECDH P-256 + HKDF
- Task payloads encrypted with AES-256-GCM
- Operator tokens: HS256 JWT, 8h access / 7d refresh
- Operator login requires bcrypt password + TOTP (RFC 6238)
- **For authorized use only.** Ensure written authorization from the target organization is in place before deployment.

---

## License

MIT
