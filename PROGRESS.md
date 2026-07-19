# DungeonMaster C2 — Progress Tracker

Last updated: 2026-07-19

---

## Current Status

**Active phase:** B3 — Per-feature WD evasion testing

**Active work order (sequential):**

### Stage 1 — Batch-7 ✅ COMPLETE (2026-07-19)
lsass-pss, lsass-syscall, potato all fixed and verified on dm-batch7-final.exe.

### Stage 2 — Make the 13 graceful-fail features fully functional
These are code-correct and WD-clean but need proper test conditions (elevation, live target, test data). See §Graceful-Fail Backlog below.

### Stage 3 — ~13 remaining AD-only features
Need domain admin + full AD lab. See §AD-Only Backlog below.

---

## Immediate Blockers & Next Actions

### Blocker: DC01 domain admin password unknown
- **Known:** PS Direct to DC01 fails for all tried credentials. Domain admin password ends in `@DC2023` (exact prefix unknown).
- **Attempted:** Offline VHD SYSTEM hive SetupType=2 CmdLine approach — resetpw.bat ran on DC01 (unconfirmed), but domain auth still fails.
- **Next action:** Try WinRE keyboard navigation on DC01 (same approach that worked for TARGET01 password fix). Or try common prefix + @DC2023.
- **Blocks:** All AD-only features (Stage 3) and Stage 2 features that need domain admin.

### Stage 2 next action:
Start with features that work under local admin on TARGET01 (no domain needed): `sam-dump`, `pipe-impersonate`, `token-steal`, `token-make` (use local admin creds), `lsass`, `browser-creds`, `browser-history`, `ssh-keys`. Deploy test data (browser creds, SSH key) on TARGET01 first.

---

## Batch-7 Final Results (2026-07-19)

Session: `ebbb8816` on TARGET01\Administrator (dm-batch7-final.exe, 908288 bytes)

| Feature | Result | Notes |
|---------|--------|-------|
| `cred/lsass-pss` | ✅ complete | 83.9MB MDMP, XOR-encoded, MDMP sig verified |
| `cred/lsass-syscall` | ✅ complete | 88.2MB MDMP, XOR-encoded, MDMP sig verified |
| `priv/potato` | ✅ complete | `potato: impersonating SYSTEM (schtasks trigger)` |

**Root causes fixed this session:**
- `lsass-pss` hang: C2 server `handleOutput` had 32MB body limit; LSASS dump is ~105MB base64. Fixed to 256MB in `server/internal/api/c2.go:175`.
- `potato` ImpersonateNamedPipeClient failure: trigger command `cmd /c type` opened the pipe for reading, but impersonation requires the client to WRITE data. Fixed to `cmd /c echo x>` (client writes). Added ReadFile drain on server side before impersonation. Also fixed schtasks invocation to call `schtasks.exe` directly (not via `cmd /C "..."` which caused quoting bugs with inner `/c`).

---

## Batch-7 Results (2026-07-18, run 2 — earlier session)

Session: `0d87d53b` (TARGET01\Administrator — local admin, not domain admin)

| Feature | Result | Reason |
|---------|--------|--------|
| `enum/bloodhound` | ❌ failed | `USERDNSDOMAIN not set` — local admin context |
| `cred/kerberoast` | ❌ failed | `ldap_bind_s: 0x31` — invalid LDAP creds (local admin) |
| `cred/asrep-roast` | ❌ failed | `ldap_bind_s: 0x31` |
| `cred/dcsync` | ❌ failed | `ldap_bind_s: 0x31` |
| `priv/shadow-creds` | ❌ failed | `USERDNSDOMAIN not set` |
| `priv/rbcd` | ❌ failed | `USERDNSDOMAIN not set` |

**All 6 AD failures** → retest once agent runs as domain admin (AMITLAB\Administrator). Blocked on DC01 password.

---

## Confirmed ✅ — 44 features fully working + zero WD alerts

**File Manager (8):** `ls` `read` `write` `rm` `mkdir` `mv` `cp` `info`

**Enumeration non-AD (12):** `processes` `services` `tasks` `sessions` `shares` `users` `groups` `localadmins` `computer` `domain` `netdiscovery` `routes`

**Privilege Escalation (6):** `uac-fodhelper` `uac-eventvwr` `uac-sdclt` `unquoted-paths` `dll-hijack` `always-install-elevated`

**Collection (10):** `clipboard` `dpapi` `vault` `file-search` `screen-record` `certs` `email` `keylog-start` `keylog-dump` `keylog-stop`

**Persistence (5):** `reg` `reg-rm` `task` `startup` `com`

**Anti-Forensics (2):** `timestomp` `indicator-rm`

**Credential Dump (2):** `lsass-pss` `lsass-syscall`

**Privilege Escalation (1):** `potato`

---

## Graceful-Fail Backlog — 13 features (Stage 2)

Code-correct, WD-clean, but need test conditions. Work through these after batch-7 is done.

| Feature | What's needed to get a real result |
|---------|-----------------------------------|
| `priv/sam-dump` | Elevated domain admin session |
| `priv/token-steal` | SYSTEM-level process on machine (escalate via potato first) |
| `priv/token-make` | Pass valid domain creds as args (use AMITLAB\Administrator once known) |
| `priv/pipe-impersonate` | Trigger a privileged process to connect to the pipe (use potato/UAC bypass) |
| `cred/lsass` | Elevated session (domain admin should have SeDebugPrivilege) |
| `collect/wifi` | No WiFi adapter on VM — hardware limitation, graceful-fail is correct behavior, skip |
| `collect/browser-creds` | Save test creds in Chrome/Edge on TARGET01 first |
| `collect/browser-history` | Visit some URLs in Chrome/Edge on TARGET01 first |
| `collect/ssh-keys` | Create a test `~/.ssh/id_rsa` on TARGET01 first |
| `lateral/smb-psexec` | Reachable admin target (DC01 once domain admin works) |
| `lateral/wmi` | Reachable admin target (DC01) |
| `lateral/winrm` | Reachable target with WinRM enabled |
| `lateral/dcom` | Reachable admin target (DC01) |

---

## AD-Only Backlog — ~13 features (Stage 3)

Requires domain admin session + DC01 running.

`enum/bloodhound` `enum/acl` `enum/unconstrained-deleg`
`cred/kerberoast` `cred/asrep-roast` `cred/dcsync`
`cred/pth` `cred/ptt` `cred/opth`
`cred/golden-ticket` `cred/silver-ticket` `cred/diamond-ticket`
`priv/shadow-creds` `priv/rbcd` `priv/adcs` `priv/s4u` `priv/acl-abuse`
`lateral/rdp-pth` `lateral/adidns`
`persist/svc` `persist/svc-rm`

---

## Key Technical Notes

- **AV on test VMs:** Windows Defender (`msmpeng.exe`) — To-Do-list calls it "BD" but testing is against WD.
- **wl! macro fix:** All 6 LDAP resolutions use GetProcAddress (not get_export_by_name). In current binary.
- **lsass-syscall OOM fix:** 600MB cap + try_reserve_exact. In current binary.
- **lsass-pss:** Fixed — no OOM crash. PSS_FLAGS = 0x00000001 only. Dump completes in < 1 second (818 regions, ~80MB).
- **C2 server body limit:** Increased to 256MB in `server/internal/api/c2.go:175` — required for LSASS dumps (~105MB base64).
- **potato trigger:** Use `echo x>{pipe}` (writes to pipe), not `type {pipe}` (reads from pipe). Server must ReadFile before ImpersonateNamedPipeClient.
- **schtasks invocation:** Call `schtasks.exe` directly, NOT via `cmd /C "schtasks ..."`. Nested cmd quoting breaks `/TR` parsing.
- **Agent binary:** `C:\dev\DM-clean\Testing-builds\dm-batch7-final.exe` (908288 bytes, built 2026-07-19). Active session: `ebbb8816` on TARGET01.
- **PS Direct:** Use `.\Administrator` or `MACHINENAME\Administrator` — bare `Administrator` on domain-joined VM resolves to domain account and fails.
- **Docker context:** Must be `default`. Run `docker context use default` if builds fail.
