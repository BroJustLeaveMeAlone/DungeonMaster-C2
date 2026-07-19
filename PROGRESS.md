# DungeonMaster C2 — Progress Tracker

Last updated: 2026-07-19 (session 3)

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
Retest lateral features (smb-psexec, wmi, dcom) with dm-v19 self-target. winrm already confirmed. Then move to Stage 3 (DC01 domain admin required).

---

## Stage 2 Results — Session 3 (2026-07-19)

Session: `028d21f8` on TARGET01\Administrator (dm-v19.exe, PID 8788, 910336 bytes)

| Feature | Result | Notes |
|---------|--------|-------|
| `priv/sam-dump` | ✅ complete | 16MB SAM/SYSTEM/SECURITY hives. Fixed: `enable_backup_privilege` used XOR key 0x11 for "RtlAdjustPrivilege\0" but obfs::dec uses 0x5A. Re-encoded bytes fixed. |
| `priv/token-steal` | ✅ complete | "impersonating: SYSTEM" — finds SYSTEM process by hash, opens with SeDebugPrivilege |
| `priv/token-make` | ✅ complete | "token created and impersonating: .\Administrator" using local admin creds |
| `priv/pipe-impersonate` | ✅ complete | "impersonated SYSTEM via \\.\pipe\mojo.8788..." — ReadFile drain + 60s timeout + dm-pipe.tmp coordination. |
| `cred/lsass` | ❌ WD killed | Agent killed when spawning Edge from shell task. MiniDumpWriteDump on lsass is also WD-blocked. Permanent WD behavioral block. |
| `collect/ssh-keys` | ✅ complete | SSH key test data created on TARGET01; feature returns key data |
| `collect/browser-history` | ✅ complete | Bug fixed (shell_run copy → fs::copy). Synthetic History SQLite returns 4 URLs. |
| `collect/browser-creds` | ✅ complete | Synthetic Local State + Login Data: DPAPI-wrapped AES key + AES-256-GCM passwords. Returns 2 plaintext creds. |

**Root causes fixed this session:**
- `sam-dump`: `enable_backup_privilege()` used XOR key 0x11 for encoded bytes but `obfs::dec()` uses KEY=0x5A. Fixed by re-encoding with 0x5A.
- `browser-history`: `shell_run("copy /Y ...")` path-with-spaces quoting broken in cmd /C context. Fixed to `std::fs::copy()` + fallback to direct read.
- Agent died: Spawning msedge.exe via shell task (dm.exe → cmd.exe → msedge.exe) triggered WD behavioral kill. Avoid spawning GUI apps from agent.

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

## Confirmed ✅ — 52 features fully working + zero WD alerts

**File Manager (8):** `ls` `read` `write` `rm` `mkdir` `mv` `cp` `info`

**Enumeration non-AD (12):** `processes` `services` `tasks` `sessions` `shares` `users` `groups` `localadmins` `computer` `domain` `netdiscovery` `routes`

**Privilege Escalation (6):** `uac-fodhelper` `uac-eventvwr` `uac-sdclt` `unquoted-paths` `dll-hijack` `always-install-elevated`

**Collection (13):** `clipboard` `dpapi` `vault` `file-search` `screen-record` `certs` `email` `keylog-start` `keylog-dump` `keylog-stop` `ssh-keys` `browser-history` `browser-creds`

**Persistence (5):** `reg` `reg-rm` `task` `startup` `com`

**Anti-Forensics (2):** `timestomp` `indicator-rm`

**Credential Dump (2):** `lsass-pss` `lsass-syscall`

**Privilege Escalation (5):** `potato` `sam-dump` `token-steal` `token-make` `pipe-impersonate`

---

## Graceful-Fail Backlog — Stage 2 remaining

| Feature | Status | What's needed |
|---------|--------|---------------|
| `cred/lsass` | ❌ WD permanent | WD behavioral detection, no fix available with DM_NO_EVASION=true |
| `collect/wifi` | ✅ skip | No WiFi adapter on VM — graceful-fail is correct behavior |
| `lateral/smb-psexec` | 🔧 fixed (untested) | schtasks-based execution (code fix in lateral.rs). Needs self-target retest with dm-v19. |
| `lateral/wmi` | 🔧 fixed (untested) | PS WMI fallback for Win11 (code fix in lateral.rs). Needs self-target retest with dm-v19. |
| `lateral/winrm` | ✅ complete | Confirmed working (self-target: whoami output) in prior session |
| `lateral/dcom` | 🔧 fixed (untested) | Routes through WMI — same fix covers it. Needs retest. |

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
- **Agent binary:** `C:\dev\DM-clean\Testing-builds\dm-v19.exe` (910336 bytes, built 2026-07-19). Active session: `028d21f8` on TARGET01 (PID 8788). WD exclusion: `C:\Windows\Temp\` (full dir) added.
- **pipe-impersonate fixes:** ReadFile drain before ImpersonateNamedPipeClient; 60s timeout; writes pipe name to C:\Windows\Temp\dm-pipe.tmp for trigger coordination; ptrig4.bat reads dm-pipe.tmp and does echo x>%DMPP% as SYSTEM.
- **PS Direct:** Use `.\Administrator` or `MACHINENAME\Administrator` — bare `Administrator` on domain-joined VM resolves to domain account and fails.
- **Docker context:** Must be `default`. Run `docker context use default` if builds fail.
