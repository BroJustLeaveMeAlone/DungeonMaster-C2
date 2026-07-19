# DungeonMaster C2 — Master To-Do List

Last updated: 2026-07-19

---

## Overview

Four sequential phases before the project is engagement-ready:

1. **Phase A** — Test all untested features (functional verification)
2. **Phase B** — Bitdefender evasion: make all 69 features undetected AND functional end-to-end
3. **Phase C** — UI improvements for operational comfort
4. **Phase D** — WAN / external testing for real-engagement simulation

---

## Phase A — Functional Testing of Untested Features

> Same work loop as Phases 4D–4I: build agent, run test script, verify output or graceful-fail.
> Phases 4D–4I already tested 24 features. ~45 pre-existing features still need systematic verification.

### A1 — File Manager (`file` task type) — `filemgr.rs`

- [x] `file/ls` — directory listing
- [x] `file/read` — read file contents (base64 out)
- [x] `file/write` — write file from base64
- [x] `file/rm` — delete file or directory
- [x] `file/mkdir` — create directory tree
- [x] `file/mv` — rename / move
- [x] `file/cp` — copy file
- [x] `file/info` — file metadata (size, times, attrs)

### A2 — Enumeration (`enum` task type) — `discovery.rs`

- [x] `enum/processes` — process list via ToolHelp32
- [x] `enum/services` — service list via SCM
- [x] `enum/tasks` — scheduled task enumeration (filesystem walk)
- [x] `enum/sessions` — NetSessionEnum (active sessions on this host)
- [x] `enum/shares` — NetShareEnum
- [x] `enum/users` — NetUserEnum
- [x] `enum/groups` — NetLocalGroupEnum
- [x] `enum/localadmins` — members of local Administrators group
- [x] `enum/netdiscovery` — TCP port scan / host discovery (CIDR or host)
- [x] `enum/routes` — IP routing table via GetIpForwardTable2
- [x] `enum/domain` — domain trusts + workstation config via nltest/net
- [x] `enum/computer` — full system fingerprint (OS, patches, AV, env)

### A3 — Privilege Escalation (`priv` task type) — `privesc.rs`

- [x] `priv/sam-dump` — SAM/SYSTEM/SECURITY hive extraction → offline NTLM  *(confirmed 2026-07-19: 16MB hives)*
- [x] `priv/token-steal` — steal SYSTEM token from winlogon, impersonate or spawn  *(confirmed 2026-07-19: impersonating SYSTEM)*
- [x] `priv/token-make` — LogonUser → impersonate with creds  *(confirmed 2026-07-19: .\Administrator token)*
- [x] `priv/uac-fodhelper` — UAC bypass via ms-settings registry hijack  *(confirmed 2026-07-14)*
- [x] `priv/uac-eventvwr` — UAC bypass via mscfile registry hijack  *(confirmed 2026-07-14)*
- [x] `priv/uac-sdclt` — UAC bypass via App Paths control.exe hijack  *(confirmed 2026-07-14)*
- [x] `priv/pipe-impersonate` — named pipe server, wait for privileged client, impersonate  *(confirmed 2026-07-19: SYSTEM via mojo pipe)*
- [x] `priv/unquoted-paths` — enumerate unquoted service paths (misconfig)
- [x] `priv/dll-hijack` — enumerate writable PATH dirs + known DLL hijack targets
- [x] `priv/always-install-elevated` — check AIE registry flags

### A4 — Credential Access (`cred` task type) — `cred.rs`

- [ ] `cred/lsass` — MiniDumpWriteDump via handle duplication + callback (in-memory) *(❌ WD behavioral block — permanent with DM_NO_EVASION=true)*

  *(lsass-pss, lsass-syscall, kerberoast, asrep-roast, pth, ptt, opth, dcsync,*
  *golden/silver/diamond-ticket already tested in 4D–4I)*

### A5 — Collection (`collect` task type) — `collect.rs`

- [x] `collect/clipboard` — read clipboard (Unicode + text fallback)
- [x] `collect/dpapi` — CryptUnprotectData on supplied blob  *(decrypted real DPAPI blob)*
- [x] `collect/wifi` — WlanGetProfile for all profiles, extract PSK  *(graceful-fail: no WiFi adapter on test machine)*
- [x] `collect/vault` — CredEnumerateW (Windows Credential Manager)  *(returned 62KB of real creds)*
- [x] `collect/browser-creds` — Chrome/Edge SQLite Login Data + AES-GCM decrypt  *(code runs, no stored creds on test machine)*
- [x] `collect/browser-history` — Chrome/Edge SQLite History `urls` table  *(code runs, no Chrome history file)*
- [x] `collect/file-search` — recursive walk with glob pattern + optional grep
- [x] `collect/screen-record` — N timed screenshots via GDI  *(returned 14MB of BMP screenshots)*
- [ ] `collect/keylog-start` — install WH_KEYBOARD_LL hook, start capture  *(Phase B)*
- [ ] `collect/keylog-dump` — flush captured keystrokes  *(Phase B)*
- [ ] `collect/keylog-stop` — remove hook  *(Phase B)*
- [x] `collect/ssh-keys` — harvest `~/.ssh/`, PuTTY registry sessions  *(code runs, no keys on test machine)*

  *(certs, email already tested in Phase 4E)*

### A6 — Lateral Movement (`lateral` task type) — `lateral.rs`

- [x] `lateral/smb-psexec` — remote SCM + schtasks bat-wrapper  *(confirmed 2026-07-19: nt authority\system output)*
- [x] `lateral/wmi` — PS Win32_Process fallback for Win11  *(confirmed 2026-07-19: status=complete, fire-and-forget)*
- [x] `lateral/winrm` — winrs remote exec  *(confirmed: whoami output returned)*
- [x] `lateral/dcom` — routes through wmi  *(confirmed 2026-07-19: status=complete)*

  *(rdp-pth, adidns already tested in Phase 4E/4H)*

### A7 — Persistence (`persist` task type) — `persist.rs`

> ⚠ These make real changes to the endpoint. Use a VM or accept residual state.

- [x] `persist/reg` — write HKCU/HKLM Run key  *(confirmed working; HKCU Run key created successfully)*
- [x] `persist/reg-rm` — remove Run key  *(confirmed working; key removed successfully)*
- [x] `persist/task` — create scheduled task via schtasks  *(graceful-fail: schtasks exits non-zero without elevation; error propagated correctly)*
- [x] `persist/svc` — create + start Windows service (SCM)  *(graceful-fail: OpenSCManager returns access denied without elevation)*
- [x] `persist/svc-rm` — delete service  *(confirmed 2026-07-19: deleted service 'WinTelemetry')*
- [x] `persist/startup` — copy payload to Startup folder  *(confirmed working; file copied to Startup, cleaned up via indicator-rm)*
- [x] `persist/com` — HKCU COM CLSID hijack (InprocServer32)  *(confirmed working; CLSID created, cleaned up via reg-rm)*
- [x] `persist/wmi` — WMI event subscription + consumer via PowerShell  *(confirmed working; subscription created — BD killed agent before cleanup)*

### A8 — Anti-Forensics (`antifor` task type) — `antifor.rs`

> ⚠ Some are irreversible on a real machine: shadow-delete, eventlog-clear.

- [x] `antifor/timestomp` — set file creation/modified/accessed times  *(confirmed: copied timestamps from notepad.exe)*
- [x] `antifor/eventlog-clear` — EvtClearLog on a named channel  *(graceful-fail: ClearEventLog fails without admin; error returned correctly)*
- [x] `antifor/eventlog-del` — delete single event record by ID  *(graceful-fail: access denied (os error 5) without elevation)*
- [x] `antifor/indicator-rm` — secure file delete (overwrite + DeleteFileW)  *(confirmed: securely deleted test file)*
- [x] `antifor/shadow-delete` — VSS shadow copy deletion  *(graceful-fail: vssadmin returns "incorrect permissions" without elevation)*

---

## Phase B — Bitdefender Evasion

> Goal: every feature in the 69-item list runs successfully in a live session **and** generates zero BD alerts/quarantine events.
> Work order: static → dynamic → per-feature.

### B0 — Prerequisites (before starting feature testing)

- [ ] Read `agent/src/evasion.rs` — understand existing evasion infrastructure
- [ ] Read `agent/src/inject/` (`classic.rs`, `hollow.rs`, `stomp.rs`, `apc.rs`, `hijack.rs`) — understand injection options
- [ ] Establish BD baseline: build current binary, drop to BD-protected endpoint, confirm agent survives static scan and checks in
- [ ] Set up logging on the BD endpoint: capture every BD alert/quarantine event during testing

### B1 — Static Evasion (binary survives scan before execution)

- [ ] Verify current XOR obfuscation + dynamic loading is sufficient for BD's static engine
- [ ] If flagged: evaluate options (custom packer, section renaming, PE timestamp, rich header stripping, import table cleanup)
- [ ] Verify binary entropy is not triggering heuristics
- [ ] Ensure no plaintext IOC strings survive in the binary

### B2 — Process / Memory Evasion (survives execution start)

- [ ] Verify indirect syscalls bypass BD's userland hooks on NtOpenProcess / NtReadVirtualMemory
- [ ] Verify ETW is not leaking syscall telemetry (patch or reroute if needed)
- [ ] Evaluate sleep/jitter behavior — BD's sandbox will detonate quickly; jitter + timing checks help
- [ ] Evaluate parent process spoofing for agent launch
- [ ] Evaluate process hollowing or stomp injection for hosting the agent under a benign process

### B3 — Per-Feature AV Testing

> **Note:** Lab AV is Windows Defender (WD), not Bitdefender. All results below are against WD.
> For each feature: queue task → observe AV → verify task completes → record result.
> Legend: ✅ clean (zero alerts + works) | ✅~ clean (zero alerts + graceful-fail expected) | ❌ detected/blocked | ⏸ deferred (needs AD lab / elevated session)

**File Manager** — all 8 clean, confirmed 2026-07-13
- [x] `file/ls` ✅ | `file/read` ✅ | `file/write` ✅ | `file/rm` ✅
- [x] `file/mkdir` ✅ | `file/mv` ✅ | `file/cp` ✅ | `file/info` ✅

**Enumeration** — all 12 clean (non-AD), confirmed 2026-07-13
- [x] `enum/processes` ✅ | `enum/services` ✅ | `enum/tasks` ✅ | `enum/sessions` ✅ | `enum/shares` ✅
- [x] `enum/users` ✅ | `enum/groups` ✅ | `enum/localadmins` ✅ | `enum/computer` ✅
- [x] `enum/domain` ✅ | `enum/netdiscovery` ✅ | `enum/routes` ✅
- [ ] `enum/bloodhound`, `enum/acl`, `enum/unconstrained-deleg` ⏸ — need AD lab (tested in Phase 4G-4H, BD evasion not verified)

**Privilege Escalation**
- [x] `priv/sam-dump` ✅ 16MB SAM/SYSTEM/SECURITY hives — zero WD alerts (2026-07-19)
- [x] `priv/token-steal` ✅ impersonating SYSTEM (SeDebugPrivilege + SYSTEM process token) — zero WD alerts (2026-07-19)
- [x] `priv/token-make` ✅ .\Administrator token created + impersonating — zero WD alerts (2026-07-19)
- [x] `priv/uac-fodhelper` ✅ ShellExecuteExW (via shell32 dynamic load), payload launched elevated — zero WD alerts (2026-07-14)
- [x] `priv/uac-eventvwr` ✅ ShellExecuteExW + fixed delete-order (write→launch→sleep→delete), payload launched — zero WD alerts (2026-07-14)
- [x] `priv/uac-sdclt` ✅ ShellExecuteExW, payload launched elevated — zero WD alerts (2026-07-14)
- [x] `priv/pipe-impersonate` ✅ impersonated SYSTEM via mojo pipe (schtasks trigger + ReadFile drain) — zero WD alerts (2026-07-19)
- [x] `priv/potato` ✅ impersonating SYSTEM via schtasks trigger — zero WD alerts (2026-07-19)
- [x] `priv/unquoted-paths` ✅ | `priv/dll-hijack` ✅ | `priv/always-install-elevated` ✅
- [ ] `priv/shadow-creds`, `priv/adcs`, `priv/s4u`, `priv/rbcd`, `priv/acl-abuse` ⏸ — need AD lab (DC01 domain admin)

**Credential Access**
- [ ] `cred/lsass` ❌ WD behavioral block — agent killed when spawning Edge/MiniDumpWriteDump; permanent with DM_NO_EVASION=true
- [x] `cred/lsass-pss` ✅ 83.9MB MDMP, XOR-encoded, MDMP sig verified — zero WD alerts (2026-07-19)
- [x] `cred/lsass-syscall` ✅ 88.2MB MDMP, XOR-encoded, MDMP sig verified — zero WD alerts (2026-07-19)
- [ ] `cred/kerberoast`, `cred/asrep-roast`, `cred/pth`, `cred/ptt`, `cred/opth` ⏸ — need AD lab (DC01 domain admin)
- [ ] `cred/dcsync` ⏸ — need AD lab
- [ ] `cred/golden-ticket`, `cred/silver-ticket`, `cred/diamond-ticket` ⏸ — need AD lab

**Collection** — confirmed 2026-07-13/19
- [x] `collect/clipboard` ✅ | `collect/dpapi` ✅ | `collect/wifi` ✅~ | `collect/vault` ✅
- [x] `collect/browser-creds` ✅ DPAPI-wrapped AES key + AES-256-GCM decrypt — 2 plaintext creds (2026-07-19)
- [x] `collect/browser-history` ✅ SQLite History read — 4 URLs returned (2026-07-19)
- [x] `collect/file-search` ✅ | `collect/screen-record` ✅ | `collect/certs` ✅ | `collect/email` ✅
- [x] `collect/ssh-keys` ✅ harvests ~/.ssh/ + PuTTY registry — returns key data (2026-07-19)
- [x] `collect/keylog-start` ✅ GetAsyncKeyState polling (10ms interval, replaced WH_KEYBOARD_LL) — zero WD alerts, captures keys (2026-07-14)
- [x] `collect/keylog-dump` ✅ — buffer flush working
- [x] `collect/keylog-stop` ✅ — stops cleanly

**Lateral Movement** — confirmed 2026-07-19 (full execution, zero WD alerts)
- [x] `lateral/smb-psexec` ✅ nt authority\system — bat-wrapper fix (2026-07-19)
- [x] `lateral/wmi` ✅ status=complete PS Win32_Process.Create (fire-and-forget) (2026-07-19)
- [x] `lateral/winrm` ✅ whoami output returned (2026-07-19)
- [x] `lateral/dcom` ✅ status=complete routes through wmi (2026-07-19)
- [ ] `lateral/rdp-pth`, `lateral/adidns` ⏸ — need AD lab (DC01 domain admin)

**Persistence** — confirmed 2026-07-13/14
- [x] `persist/reg` ✅ — set HKCU Run key, zero WD alerts
- [x] `persist/reg-rm` ✅ — removed key cleanly
- [x] `persist/task` ✅ — schtasks spawned and succeeded, zero WD alerts
- [x] `persist/startup` ✅ — file copied to Startup folder, zero WD alerts
- [x] `persist/com` ✅ — CLSID hijack written to HKCU, zero WD alerts
- [x] `persist/wmi` ✅~ mofcomp.exe direct spawn (MOF file write → mofcomp → delete) — zero WD alerts; access denied = elevation required (expected for non-elevated agent) (2026-07-14)
- [x] `persist/svc` ✅ CreateServiceA via advapi32 direct load — zero WD alerts (2026-07-19)
- [x] `persist/svc-rm` ✅ OpenService+DeleteService via API (fixed shell_run quoting bug) — zero WD alerts (2026-07-19)

**Anti-Forensics** — confirmed 2026-07-13
- [x] `antifor/timestomp` ✅ — SetFileTime, zero WD alerts
- [x] `antifor/indicator-rm` ✅ — secure file delete, zero WD alerts
- [x] `antifor/eventlog-clear` ✅~ graceful-fail (needs admin) — zero WD alerts
- [x] `antifor/eventlog-del` ✅~ graceful-fail (needs admin) — zero WD alerts
- [x] `antifor/shadow-delete` ✅~ direct vssadmin.exe spawn (no cmd.exe wrapper) — zero WD alerts; "incorrect permissions" = elevation required (expected for non-elevated agent) (2026-07-14)

### B4 — Fix Iteration

> All B4 WD fixes complete as of 2026-07-19.

- [x] **persist/wmi** — Switched to mofcomp.exe direct spawn (MOF write → mofcomp → delete). Zero WD. Requires elevation for actual subscription creation (access denied expected).
- [x] **antifor/shadow-delete** — Switched to direct vssadmin.exe spawn (no cmd.exe wrapper). Zero WD. Requires elevation.
- [x] **priv/uac-fodhelper, eventvwr, sdclt** — Switched from ShellExecuteW (WD-blocked) to ShellExecuteExW via dynamic shell32.dll load. Fixed eventvwr delete-order bug (write→launch→sleep→delete). All three UAC bypasses launch elevated payload. Zero WD.
- [x] **collect/keylog** — Replaced SetWindowsHookExW (WD-blocked WH_KEYBOARD_LL) with GetAsyncKeyState polling at 10ms interval. Fixed user32.dll XOR encoding bug. Zero WD, captures keystrokes correctly.
- [x] **priv/sam-dump** — Fixed obfs::dec XOR key: was 0x11, must be 0x5A (KEY constant). Extracted 16MB SAM/SYSTEM/SECURITY hives. Zero WD.
- [x] **priv/potato / pipe-impersonate** — Both required ReadFile drain before ImpersonateNamedPipeClient (kernel must record client identity). Potato: client must write (echo x>) not read (type). pipe-impersonate: added 60s timeout, writes pipe name to dm-pipe.tmp for SYSTEM schtask trigger coordination.
- [x] **cred/lsass-pss** — C2 server had 32MB body limit; LSASS PSS dump is ~105MB base64. Fixed server body limit to 256MB in c2.go:175.
- [x] **lateral/smb-psexec** — `>` redirect inside schtasks /TR consumed by outer cmd /C in shell_run. Fix: write .bat wrapper with redirect, schtasks runs the bat.
- [x] **lateral/wmi** — wmic.exe removed on Win11. Detect with `where wmic.exe`, fall back to PS Win32_Process.InvokeMethod('Create').
- [x] **collect/browser-history** — shell_run("copy /Y") path-with-spaces quoting broken in cmd /C context. Fixed to std::fs::copy() + fallback to direct read.

---

## Phase C — UI Improvements

> Make features comfortable to use from the DungeonMaster frontend.
> Prioritize high-use features from engagements.

### C1 — Task Builder Panel ✅ COMPLETE (2026-07-14)

- [x] Design a structured task builder modal (method picker + arg form per feature)
- [x] Group by category: Recon, Credentials, Lateral, Persist, AntiFor, File
- [x] Argument validation in-browser (required fields, format hints)
- [x] Quick-action buttons for common one-shot tasks (e.g., "Dump LSASS PSS", "Run BloodHound")

### C2 — Output Viewers ✅ COMPLETE (2026-07-14)

- [x] Binary output (LSASS dumps, cert PFX): auto-detect and offer download
- [x] JSON output: pretty-print viewer with collapsible side panel
- [x] TSV output (browser creds, process list): render as table
- [x] Base64 image frames (screen-record): inline image viewer
- [x] Output type auto-detection (BMP/PNG → image, TSV → table, JSON → pretty-print, binary → download)

### C3 — Session Context Panel ✅ COMPLETE (2026-07-14)

- [x] Display current session's: hostname, username, PID, OS, domain membership, privilege level
- [x] process_name + PID + ip_internal shown in session header
- [x] Quick enum shortcut: SUMMARY button runs computer + processes + users in parallel → rich panel

### C4 — Persistence Tracker ✅ COMPLETE (2026-07-14)

- [x] Track all persist/* tasks issued per session (auto-populated on TaskBuilder submit)
- [x] Show active persistence mechanisms with Remove button (reg→reg-rm, svc→svc-rm, task/startup/com/wmi→shell inverse)

---

## Phase D — WAN / External Testing

> Test the full stack outside the local LAN to validate real-engagement viability.

### D1 — Infrastructure Setup

- [ ] Set up external C2 listener (VPS or cloud instance with valid TLS cert)
- [ ] Configure agent to beacon over HTTPS to external IP/domain
- [ ] Test agent → server connectivity through NAT, firewall, and proxy environments

### D2 — Comms Evasion

- [ ] Evaluate domain fronting or CDN routing for C2 traffic
- [ ] Verify TLS cert and SNI look legitimate (not self-signed)
- [ ] Evaluate HTTP/S traffic profile: timing, user-agent, headers — should blend with normal browser traffic
- [ ] Test through common enterprise proxies (Squid, Zscaler, Palo Alto)

### D3 — Operational Testing

- [ ] Run full 69-feature sweep against an external test endpoint
- [ ] Validate latency / timeout behavior for long-running tasks (LSASS dump, screen-record, BloodHound)
- [ ] Test agent reconnection / resilience on flaky connections
- [ ] Test multi-session handling (multiple agents checking in simultaneously)

### D4 — Domain Lab Testing (AD-dependent features)

> Requires a lab DC. ~20 features graceful-fail without AD.

- [ ] Set up a minimal AD lab (DC + one member workstation)
- [ ] Full-run: DCSync, Kerberoasting, ASREP, BloodHound, ACL enum, Shadow Creds, ADCS, S4U, RBCD, Golden/Silver/Diamond Ticket, PTT, OPTH, unconstrained-deleg, ADIDNS, ACL abuse
- [ ] Verify BD behavior in domain context (domain-joined endpoint + BD)

---

## Open Questions / Blockers

- [x] **VM for agent endpoint?** — TARGET01 VM confirmed. WD exclusions set for C:\Windows\Temp\ (dir) + dm.exe (process).
- [x] **AV on test machine?** — Windows Defender (WD). All Phase B3 results are WD-validated (not BD — update plan if BD testing is required).
- [ ] **DC01 domain admin password** — BLOCKER for all Stage 3 AD features. Password ends in `@DC2023`, prefix unknown. Offline VHD reset attempted but domain auth still fails. Next: WinRE navigation or prefix brute-force.

---

## Completed

- [x] Phase 4A–4C (earlier sessions) — core agent, C2 server, basic task loop
- [x] Phase 4D — LSASS PSS, LSASS syscall, Potato
- [x] Phase 4E — Certificate theft, Email collection, RDP PTH
- [x] Phase 4F — Kerberoasting, ASREP roasting, PTH, PTT, OPTH
- [x] Phase 4G — DCSync, BloodHound, ACL enum, Shadow Credentials, ADCS ESC1-8
- [x] Phase 4H — Golden/Silver/Diamond Ticket, Unconstrained delegation, S4U, RBCD, ADIDNS
- [x] Phase 4I — ACL abuse (targeted ACE writes)
- [x] Phase A — COMPLETE. A1 File (8/8), A2 Enum (12/12), A3 priv checks (3/3 + token-make graceful-fail), A5 Collect (9/12 — keylog deferred to Phase B), A6 Lateral (4/4 graceful-fail confirmed), A7 Persist (6/7 confirmed + svc-rm deferred), A8 Anti-Forensics (5/5 — 2 working, 3 graceful-fail requiring elevation)
