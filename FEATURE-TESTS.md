# DungeonMaster C2 — Feature Test Results

## Test Environment

- **Target:** DM-TARGET01, Windows 10 Enterprise Eval build 26200 (domain-joined AMITLAB.local)
- **EDR:** Windows Defender active (real-time, no exclusions)
- **Agent:** dm-noev2-session15.exe (944640 bytes) — DM_NO_EVASION=true build, no obfuscation
- **Sessions tested:** labadmin (medium integrity via PS Direct) + SYSTEM (via schtasks trick)
- **C2:** local Docker stack, `10.10.10.1:4443` TLS listener
- **Sessions 14–16 (Oct 2026)**

## Legend

```
[P] PASS        — executed cleanly, correct output
[E] ENV FAIL    — blocked by environment (Defender, missing component, no creds, etc.) — not a code bug
[B] BUG         — code defect identified
[ ] UNTESTED    — not yet tested in this environment
```

> **Note on task ordering:** Tasks submitted simultaneously with equal `created_at` timestamps execute in non-deterministic order. Sequential operations (e.g., file/write then file/read) must each be queued and waited on before queuing the next.

---

## Core

| Status | Feature | Notes |
|--------|---------|-------|
| [P] | `shell` | Works; cmd runs via cmd /c |
| [P] | `sleep` | Args: seconds (string), jitter_pct (string) |
| [P] | `kill` | Sends kill-acknowledge, agent exits cleanly |
| [P] | `upload` | Reads local file, sends to C2 as base64 |
| [P] | `download` | Pushes file to agent; requires both `path` AND `data` (b64) fields |
| [P] | `relay_start` | Named-pipe SMB relay; args: pipe, c2_host, c2_port |
| [P] | `relay_stop` | Clears RELAY_RUNNING flag |

---

## File Manager

| Status | Feature | Notes |
|--------|---------|-------|
| [P] | `file/mkdir` | |
| [P] | `file/write` | `data` field is base64-encoded content |
| [P] | `file/info` | Returns path, type, size, readonly |
| [P] | `file/ls` | Returns filename + size per entry |
| [P] | `file/read` | Returns base64-encoded file content |
| [P] | `file/cp` | `src` + `dst` fields |
| [P] | `file/mv` | `src` + `dst` fields |
| [P] | `file/rm` | Works for both files and directories |

---

## Enumeration

### Local

| Status | Feature | Notes |
|--------|---------|-------|
| [P] | `enum/computer` | Full system fingerprint |
| [P] | `enum/processes` | |
| [P] | `enum/services` | |
| [P] | `enum/tasks` | |
| [P] | `enum/sessions` | |
| [P] | `enum/shares` | |
| [P] | `enum/users` | |
| [P] | `enum/groups` | |
| [P] | `enum/localadmins` | |
| [P] | `enum/netdiscovery` | /24 scan ~11 min with timeout_ms=300; args: target (CIDR or host), ports, timeout_ms |
| [P] | `enum/routes` | |
| [P] | `enum/domain` | |

### Active Directory *(requires domain context)*

| Status | Feature | Notes |
|--------|---------|-------|
| [ ] | `enum/bloodhound` | |
| [ ] | `enum/acl` | |
| [ ] | `enum/unconstrained-deleg` | |

---

## Privilege Escalation

### UAC Bypass *(standard user → high integrity)*

| Status | Feature | Notes |
|--------|---------|-------|
| [E] | `priv/uac-fodhelper` | Defender blocks RegCreateKeyExA to ms-settings hijack path with ERROR_KEY_DELETED (1018); shell reg.exe to same path works fine |
| [E] | `priv/uac-eventvwr` | Same Defender registry interception |

### Local Privilege Escalation

| Status | Feature | Notes |
|--------|---------|-------|
| [ ] | `priv/potato` | |
| [P] | `priv/sam-dump` | Requires SYSTEM + no pre-existing `~s1/s2/s3.tmp` in `%TEMP%`; returns SAM/SYSTEM/SECURITY hives as base64 JSON |
| [P] | `priv/token-steal` | Requires elevated/SYSTEM session; impersonates SYSTEM |
| [P] | `priv/token-make` | Args: `user`/`pass`/`domain` (NOT `username`/`password`) |
| [E] | `priv/pipe-impersonate` | Creates mojo.PID.chrome.XXXX named pipe, waits 60s for privileged client; timeout expected with no client (hardcoded 60s, `timeout_secs` arg not actually used) |
| [P] | `priv/dll-hijack` | Enumerates writable directories in PATH |
| [P] | `priv/unquoted-paths` | Enumerates services with unquoted path vulnerabilities |
| [P] | `priv/always-install-elevated` | Checks HKLM/HKCU AlwaysInstallElevated policy |

### Active Directory *(requires domain context)*

| Status | Feature | Notes |
|--------|---------|-------|
| [ ] | `priv/shadow-creds` | |
| [ ] | `priv/adcs` | |
| [ ] | `priv/rbcd` | |
| [ ] | `priv/acl-abuse` | |
| [ ] | `priv/s4u` | |

---

## Credential Access

### LSASS *(requires admin)*

| Status | Feature | Notes |
|--------|---------|-------|
| [E] | `cred/lsass-pss` | NtOpenProcess 0xc0000022 (STATUS_ACCESS_DENIED) — lsass PPL (Protected Process Light) on Win10 build 26200 |
| [E] | `cred/lsass-syscall` | Same PPL protection |
| [E] | `cred/lsass` | Same PPL; note: correct method name is `lsass`, not `lsass-dump` |

### Active Directory Attacks *(requires domain context)*

| Status | Feature | Notes |
|--------|---------|-------|
| [ ] | `cred/kerberoast` | |
| [ ] | `cred/asrep-roast` | |
| [ ] | `cred/pth` | |
| [ ] | `cred/ptt` | |
| [ ] | `cred/opth` | |
| [ ] | `cred/dcsync` | |
| [ ] | `cred/golden-ticket` | |
| [ ] | `cred/silver-ticket` | |

---

## Collection

| Status | Feature | Notes |
|--------|---------|-------|
| [P] | `collect/clipboard` | Returns empty if clipboard is non-text or empty |
| [E] | `collect/vault` | CredEnumerateW — no creds in Credential Manager |
| [E] | `collect/browser-creds` | No browser installed |
| [E] | `collect/browser-history` | No browser installed |
| [ ] | `collect/dpapi` | |
| [E] | `collect/screen-record` | Returns empty base64 frames in headless/non-interactive session (no display context) |
| [P] | `collect/file-search` | Args: glob (pattern), path (search root) |
| [P] | `collect/ssh-keys` | Returns empty object if no keys present |
| [E] | `collect/wifi` | WlanOpenHandle failed — no WiFi adapter on VM |
| [P] | `collect/certs` | Returns JSON with cert stores; empty if no user certs |
| [P] | `collect/keylog-start` | |
| [P] | `collect/keylog-dump` | Returns empty buffer if no keys captured |
| [P] | `collect/keylog-stop` | |
| [P] | `collect/email` | Returns empty if no MAPI/Outlook profile |

---

## Lateral Movement

| Status | Feature | Notes |
|--------|---------|-------|
| [P] | `lateral/smb-psexec` | Returns cmd output (e.g., `nt authority\system` on localhost) |
| [P] | `lateral/wmi` | Fire-and-forget; output is WMI invocation result, not spawned command output; uses wmic.exe or PowerShell fallback |
| [E] | `lateral/winrm` | WinRS error: cannot connect — WinRM not configured for loopback connections on test VM |
| [ ] | `lateral/rdp-pth` | |

---

## Persistence

| Status | Feature | Notes |
|--------|---------|-------|
| [E] | `persist/reg` | Defender intercepts RegCreateKeyExA to Run key, returns ERROR_KEY_DELETED (1018); child-process reg.exe writes to same key successfully — behavior-based API interception |
| [E] | `persist/reg-rm` | Same interception as persist/reg |
| [P] | `persist/task` | Warning "No mapping between account names and security IDs" is cosmetic (schtasks warning, task still created) |
| [P] | `persist/startup` | Copies to %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup |
| [P] | `persist/com` | Writes InprocServer32 under HKCU\Software\Classes\CLSID |
| [P] | `persist/wmi` | Creates WMI event subscription via mofcomp.exe |
| [P] | `persist/svc` | Creates and registers service; requires elevation |
| [P] | `persist/svc-rm` | Removes service by name; requires elevation |

---

## Anti-Forensics

| Status | Feature | Notes |
|--------|---------|-------|
| [P] | `antifor/timestomp` | Sets mtime; args: path, mtime (ISO 8601) |
| [P] | `antifor/indicator-rm` | Secure-deletes file; ENV FAIL if file not present |
| [P] | `antifor/eventlog-clear` | Clears entire channel; requires elevation |
| [P] | `antifor/eventlog-del` | Clears channel containing `record_id`; **record_id must be integer, not string**; requires elevation |
| [P] | `antifor/shadow-delete` | Runs vssadmin; reports benign if no shadows exist |

---

## Injection

| Status | Feature | Notes |
|--------|---------|-------|
| [P] | `inject/classic` | VirtualAllocEx + WPM + CRT into existing PID; args: pid (integer), shellcode (b64) |
| [E] | `inject/apc` | CreateProcessA(CREATE_SUSPENDED) blocked by Defender; no-evasion build is detected |
| [E] | `inject/classic-spawn` | Same Defender blocking of CREATE_SUSPENDED process creation |
| [E] | `inject/hollow` | Same |
| [P] | `inject/hijack` | Thread-context hijack into existing PID; args: pid (integer), shellcode (b64) |
| [ ] | `inject/stomp` | Not compiled — requires `inject-stomp` feature flag at build time |

---

## Known Bugs

1. **`cred/lsass` — method name mismatch** — correct API method name is `lsass`, not `lsass-dump` (returns "unknown method: lsass-dump").

2. **`priv/token-make` — arg name mismatch** — code uses `user`/`pass`, not `username`/`password`.

3. ~~**Task ordering non-determinism**~~ — **FIXED**: `seq BIGSERIAL` column added to `tasks` table; ORDER BY `created_at ASC, seq ASC` in `manager.go`. New tasks get deterministic insertion order.

4. ~~**`priv/sam-dump` — RegSaveKeyExA error silently ignored**~~ — **FIXED**: `privesc.rs:182` now checks `save_err != 0`, cleans temp file, records error, and continues.

5. **TCP/SMB channels skip `encrypt_reg_payload()`** — agent registration sent in plaintext on non-HTTPS channels (`agent_loop.rs:38`).

6. **Session key dead code** — ECDH P-256 key exchange never used for task encryption.

7. **`inject/stomp` comment says `module` arg but code uses `pid`** (`inject/mod.rs`).

8. **`lateral/winrm` — unquoted args** (security issue, not functional).

9. **`lateral/dcom` — delegates to wmi** — DCOM label is cosmetic.

10. **gRPC Phase 2** — `dm.proto` defines 9 services, none implemented.

11. **`collect/screen-record` — returns empty array** in headless/service session context (no display).

---

## AD-Dependent Features (Tested in Phase B)

| Feature | Status |
|---------|--------|
| `enum/bloodhound` | [ ] |
| `enum/acl` | [ ] |
| `enum/unconstrained-deleg` | [ ] |
| `priv/shadow-creds` | [ ] |
| `priv/adcs` | [ ] |
| `priv/rbcd` | [ ] |
| `priv/acl-abuse` | [ ] |
| `priv/s4u` | [ ] |
| `cred/kerberoast` | [ ] |
| `cred/asrep-roast` | [ ] |
| `cred/pth` | [ ] |
| `cred/ptt` | [ ] |
| `cred/opth` | [ ] |
| `cred/dcsync` | [ ] |
| `cred/golden-ticket` | [ ] |
| `cred/silver-ticket` | [ ] |
| `lateral/rdp-pth` | [ ] |
| `priv/potato` | [ ] |
