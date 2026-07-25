# DungeonMaster C2 — Progress Tracker

Last updated: 2026-07-26 (session 10)

---

## Current Status

**Active phase:** B3 — Per-feature WD evasion testing

**Session 10 complete:** USER-MANUAL.md fully rewritten — all 75+ task methods documented with args tables, output formats, and attack chain examples. Committed and pushed (6b769ea).

**Next:** Continue B3 per-feature WD evasion testing.

---

## Session 9 Results (2026-07-25) — cred/opth end-to-end domain access confirmed

Agent: `dm-batch33.exe` (942592 bytes). Session `2322c04a` on TARGET01\Administrator.

| Feature | Result | Notes |
|---------|--------|-------|
| `cred/opth` + cmd | ✅ complete | `dir \\DC01.AMITLAB.LOCAL\C$` returns full DC directory listing. Domain access confirmed end-to-end. |

**Root cause of prior cmd failure:** `spawn_opth_cmd` created a child process via `CreateProcessWithLogonW(LOGON_NETCREDENTIALS_ONLY)` and tried to inject the TGT into the child's LUID via `lsa_privileged_inject_ticket`. The injection result was silently discarded (`let _ = ...`). The child ran with fake password "x" and fell back to NTLM → "The user name or password is incorrect."

**Fix (batch33):** `cred_ptt` already injects the TGT into the agent's current logon session. Replaced `spawn_opth_cmd` with `std::process::Command::new("cmd").args(["/C", cmd])`. Child inherits the parent's logon session, which now has the TGT. Kerberos gets a TGS for `cifs/DC01.AMITLAB.LOCAL` and access succeeds.

---

## Session 7–8 Results (2026-07-21) — cred/ptt + cred/opth fixed

Agent: `dm-batch28.exe` (944640 bytes). Session on TARGET01\Administrator.

| Feature | Result | Notes |
|---------|--------|-------|
| `cred/ptt` | ✅ complete | Switched from AP-REQ to KRB-CRED format (APPLICATION 22 / KerbSubmitTicketMessage type 21). klist confirms 1 cached ticket after injection. |
| `cred/opth` | ✅ complete | RC4-HMAC AS-REQ/AS-REP exchange with DC. Session key extracted from enc-part (RC4 decrypt, key usage 3/8). EncKrbCredPart (APPLICATION 29) built correctly with session key in KrbCredInfo[0]. TGT injected via cred_ptt. klist confirms `Administrator @ AMITLAB.LOCAL`. UI has all fields including optional `cmd`. |

**Fixes applied (sessions 7–8):**
- `cred/ptt`: Was generating AP-REQ; Windows `KerbSubmitTicketMessage` expects KRB-CRED (.kirbi format). Rewrote `build_kerb_cred` to produce APPLICATION 22 with APPLICATION 29 EncKrbCredPart.
- `cred/opth`: Added `rc4_hmac_decrypt` to extract session key from AS-REP enc-part. Added `extract_session_key_from_as_rep`. Rewrote `build_kerb_cred_from_as_rep` to include session key in KrbCredInfo[0] (required for Windows to accept the injected ticket).
- UI: `cmd` field added to TaskBuilder.tsx opth schema.

---

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

### Stage 2 — COMPLETE ✅
All lateral + persistence features confirmed. Only `cred/lsass` permanently WD-blocked. Move to Stage 3 (DC01 domain admin required).

---

## Stage 2 Results — Session 5 (2026-07-19)

Session: `466e71b5` on TARGET01\Administrator (dm-v20.exe, PID 3248, 912384 bytes — svc-rm API fix)

| Feature | Result | Notes |
|---------|--------|-------|
| `persist/svc` | ✅ complete | `created service 'WinTelemetry'` — CreateServiceA via advapi32 direct load |
| `persist/svc-rm` | ✅ complete | `deleted service 'WinTelemetry'` — fixed: replaced `sc delete` shell_run (quoting bug) with OpenService+DeleteService via API |

**Root causes fixed this session:**
- `persist/svc-rm`: `sc delete "{name}"` via `shell_run` → `cmd /C` returned error 1060 (service not found) despite service existing. Bug: cmd passes quoted argument with literal quotes to sc.exe. Fix: use `OpenServiceA` + `DeleteService` directly via advapi32 dynamic load.

---

## Stage 2 Results — Session 4 (2026-07-19)

Session: `07cd1b3e` on TARGET01\Administrator (dm-v19.exe, PID 4476, 911360 bytes — bat-wrapper smb-psexec fix)

| Feature | Result | Notes |
|---------|--------|-------|
| `lateral/smb-psexec` | ✅ complete | `nt authority\system` — bat-wrapper fix: writes `@echo off\r\n{cmd} > "{output}" 2>&1` to `~dmlat{id}.bat`, schtasks runs the bat. Output captured correctly. |
| `lateral/wmi` | ✅ complete | `status=complete` — PS Win32_Process.Create fallback for Win11 (no wmic.exe). Fire-and-forget as expected. |
| `lateral/dcom` | ✅ complete | `status=complete` — routes through WMI path. Fire-and-forget as expected. |

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

## Confirmed ✅ — 79 features fully working + zero WD alerts

**File Manager (8):** `ls` `read` `write` `rm` `mkdir` `mv` `cp` `info`

**Enumeration non-AD (12):** `processes` `services` `tasks` `sessions` `shares` `users` `groups` `localadmins` `computer` `domain` `netdiscovery` `routes`

**Privilege Escalation (6):** `uac-fodhelper` `uac-eventvwr` `uac-sdclt` `unquoted-paths` `dll-hijack` `always-install-elevated`

**Collection (13):** `clipboard` `dpapi` `vault` `file-search` `screen-record` `certs` `email` `keylog-start` `keylog-dump` `keylog-stop` `ssh-keys` `browser-history` `browser-creds`

**Persistence (5):** `reg` `reg-rm` `task` `startup` `com`

**Anti-Forensics (2):** `timestomp` `indicator-rm`

**Credential Dump (2):** `lsass-pss` `lsass-syscall`

**Privilege Escalation (5):** `potato` `sam-dump` `token-steal` `token-make` `pipe-impersonate`

**Lateral Movement (4):** `smb-psexec` `wmi` `dcom` `winrm`

**Persistence (2 additional):** `svc` `svc-rm`

**AD — Credential (8):** `kerberoast` `asrep-roast` `dcsync` `pth` `ptt` ✅ `opth` ✅ `golden-ticket` `silver-ticket` `diamond-ticket`

**AD — Enumeration (3):** `bloodhound` `acl` `unconstrained-deleg`

**AD — Privilege Escalation (4):** `shadow-creds` `rbcd` `adcs` (enum) `acl-abuse`

**AD — Misc (2):** `s4u` (enum) `adidns`

---

## Graceful-Fail Backlog — Stage 2 COMPLETE

| Feature | Status | Notes |
|---------|--------|-------|
| `cred/lsass` | ❌ WD permanent | WD behavioral detection, no fix available with DM_NO_EVASION=true |
| `collect/wifi` | ✅ skip | No WiFi adapter on VM — graceful-fail is correct behavior |
| `lateral/smb-psexec` | ✅ complete | bat-wrapper fix confirmed |
| `lateral/wmi` | ✅ complete | PS WMI fallback confirmed |
| `lateral/winrm` | ✅ complete | Self-target confirmed |
| `lateral/dcom` | ✅ complete | Routes through WMI, confirmed |

---

## AD-Only Backlog — Session 6 COMPLETE ✅ (2026-07-20)

All AD-only features tested with dm-batch19/20.exe on session `bd762505`/`8a87db1c`.

### Still needs work:
| Feature | Issue |
|---------|-------|
| `cred/ptt` | ✅ FIXED (sessions 7–8) — KRB-CRED format, klist confirmed |
| `cred/opth` | ✅ FIXED (sessions 7–8) — TGT obtained + injected, klist confirmed |
| `priv/s4u` attack | Enum works ✅; actual S4U2Self attack needs TGT in memory — separate issue |

### All remaining AD features confirmed functional:
`enum/bloodhound` ✅ `enum/acl` ✅ `enum/unconstrained-deleg` ✅
`cred/kerberoast` ✅ `cred/asrep-roast` ✅ `cred/dcsync` ✅
`cred/pth` ✅ `cred/golden-ticket` ✅ `cred/silver-ticket` ✅ `cred/diamond-ticket` ✅
`priv/shadow-creds` ✅ `priv/rbcd` ✅ `priv/adcs` ✅ `priv/acl-abuse` ✅ `priv/s4u` (enum) ✅
`lateral/rdp-pth` ✅ `lateral/adidns` ✅

---

## Key Technical Notes

- **AV on test VMs:** Windows Defender (`msmpeng.exe`) — To-Do-list calls it "BD" but testing is against WD.
- **wl! macro fix:** All 6 LDAP resolutions use GetProcAddress (not get_export_by_name). In current binary.
- **lsass-syscall OOM fix:** 600MB cap + try_reserve_exact. In current binary.
- **lsass-pss:** Fixed — no OOM crash. PSS_FLAGS = 0x00000001 only. Dump completes in < 1 second (818 regions, ~80MB).
- **C2 server body limit:** Increased to 256MB in `server/internal/api/c2.go:175` — required for LSASS dumps (~105MB base64).
- **potato trigger:** Use `echo x>{pipe}` (writes to pipe), not `type {pipe}` (reads from pipe). Server must ReadFile before ImpersonateNamedPipeClient.
- **schtasks invocation:** Call `schtasks.exe` directly, NOT via `cmd /C "schtasks ..."`. Nested cmd quoting breaks `/TR` parsing.
- **Agent binary (latest):** `C:\dev\DM-clean\lab-builds\dm-batch33.exe` (942592 bytes, 2026-07-25 — opth cmd runs directly in current session after TGT injection). Active session: `2322c04a` on TARGET01.

**Previous agent binaries:** dm-batch19.exe (acl-abuse ext_s fix), dm-batch18.exe (SD_FLAGS per-connection attempt), dm-batch17.exe (shadow-creds + rbcd fix), dm-batch16.exe (LDAP_MOD_BVALUES 0x80 fix).

**acl-abuse fix:** Per-connection `ldap_set_option(LDAP_OPT_SERVER_CONTROLS)` does NOT propagate to `ldap_modify_s`. Must use `ldap_search_ext_s` + `ldap_modify_ext_s` with EXPLICIT SD_FLAGS control on both operations.

**LDAP_MOD_BVALUES = 0x80** (not 0x8000). Critical for all binary LDAP attribute writes.

**msDS-KeyCredentialLink:** DN-Binary string format: `B:{hex_len}:{hex}:{dn}` — NOT raw binary.

**rbcd SD:** Must include Owner+Group SIDs (Domain Admins, RID 512 derived from attacker SID prefix) or AD rejects with CONSTRAINT_VIOLATION.

**WD exclusion:** `C:\Windows\Temp\` (full dir) added.
- **smb-psexec bat-wrapper:** `>` redirect inside schtasks /TR "cmd /c {cmd} > {out}" gets consumed by outer cmd /C in shell_run. Fix: write a .bat file containing the redirect, schtasks runs the .bat. Output captured as SYSTEM.
- **lateral API format:** task type=`lateral`, args JSON must contain `method` field (e.g. `{"method":"smb-psexec","host":"127.0.0.1","cmd":"whoami"}`). Not `lateral/smb-psexec`.
- **pipe-impersonate fixes:** ReadFile drain before ImpersonateNamedPipeClient; 60s timeout; writes pipe name to C:\Windows\Temp\dm-pipe.tmp for trigger coordination; ptrig4.bat reads dm-pipe.tmp and does echo x>%DMPP% as SYSTEM.
- **PS Direct:** Use `.\Administrator` or `MACHINENAME\Administrator` — bare `Administrator` on domain-joined VM resolves to domain account and fails.
- **Docker context:** Must be `default`. Run `docker context use default` if builds fail.
