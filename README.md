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
| `server/` | Go 1.22 | REST + gRPC operator API, C2 listener (HTTPS + TCP), session lifecycle, collab bus |
| `agent/` | Rust (no_std-friendly) | Implant: ECDH key exchange, AES-GCM task encryption, multi-transport channels (HTTPS/TCP/SMB), sleep encryption, Linux musl target |
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
| `DM_JWT_SECRET` | *(required)* | Generate: `openssl rand -hex 32` |
| `DM_HTTP_ADDR` | `:8080` | Operator REST API |
| `DM_GRPC_ADDR` | `:50051` | gRPC service port |
| `DM_C2_ADDR` | `:4443` | HTTPS C2 listener (agent callbacks, TLS 1.3) |
| `DM_TCP_C2_ADDR` | *(unset = disabled)* | Raw TCP C2 listener — e.g. `:4444` |
| `DM_TLS_CERT` / `DM_TLS_KEY` | `tls/server.crt/.key` | TLS cert for HTTPS C2 |
| `DM_TOTP_DISABLED` | `false` | Set `true` to bypass TOTP enforcement (dev only) |
| `DM_C2_PATH_REG` | `/r` | Override agent registration path (malleable profiles) |
| `DM_C2_PATH_POLL` | `/c` | Override agent poll/callback path (malleable profiles) |
| `DM_ALLOWED_ORIGINS` | `localhost:3000,localhost:5173` | CORS allowlist for operator UI |
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

GET    /api/v1/listeners
POST   /api/v1/listeners

GET    /api/v1/builds                 # (?campaign_id=)
POST   /api/v1/builds                 # trigger Docker agent build
GET    /api/v1/builds/{id}

GET    /api/v1/profiles               # malleable C2 profiles
POST   /api/v1/profiles
GET    /api/v1/profiles/{name}
DELETE /api/v1/profiles/{name}
```

---

## Operator Channels (agent → server)

Paths are configurable via `DM_C2_PATH_REG` / `DM_C2_PATH_POLL` on the server and the malleable profile system — defaults shown below.

```
POST /r   — agent registration (first contact, ECDH key exchange)
GET  /c   — task poll (session ID in X-Request-ID header)
POST /c   — task output submission
```

A raw TCP C2 listener is also available when `DM_TCP_C2_ADDR` is set. Same length-prefixed JSON protocol, no TLS requirement (use behind a stunnel/redirector).

---

## Security Notes

- All agent↔server traffic: TLS 1.3 minimum
- Session keys derived via ECDH P-256 + HKDF
- Task payloads encrypted with AES-256-GCM
- Operator tokens: HS256 JWT, 8h access / 7d refresh
- Operator login: bcrypt password + TOTP (RFC 6238) enforced by default; rate-limited to 5 attempts/min per source IP
- **For authorized use only.** Ensure written authorization from the target organization is in place before deployment.

---

## Roadmap

DungeonMaster is developed in five phases. **Phase 1 (foundation) is complete.** See [ROADMAP.md](ROADMAP.md) for the full checklist — every planned module, evasion primitive, and capability is listed with its target phase.

| Phase | Name | Status |
|-------|------|--------|
| 1 | Foundation — server, agent, UI, Docker build system | ✅ Complete |
| 2 | Operational Core — file ops, SMB/TCP channels, malleable C2, TOTP enforcement | ✅ Complete |
| 3 | Evasion & Injection — process injection, indirect syscalls, unhooking, UDRL | 🔲 Planned |
| 4 | Post-Exploitation Module Library — creds, AD/Kerberos, lateral movement, cloud, Linux/macOS | 🔲 Planned |
| 5 | Beyond Cobalt Strike — AI co-pilot, BOF loader, kill chain templates, MITRE heatmap, collaboration | 🔲 Planned |

---

## License

GPL-3.0 — see [LICENSE](LICENSE). Free to use, modify, and distribute; derivative works must remain open-source under the same terms.
