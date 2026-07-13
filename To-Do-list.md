# DungeonMaster C2 — Master To-Do List

Last updated: 2026-07-13

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

- [ ] `priv/sam-dump` — SAM/SYSTEM/SECURITY hive extraction → offline NTLM  *(Phase B)*
- [ ] `priv/token-steal` — steal SYSTEM token from winlogon, impersonate or spawn  *(Phase B)*
- [x] `priv/token-make` — LogonUser → impersonate with creds  *(graceful-fail: bad creds → LogonUserW failed, correct)*
- [ ] `priv/uac-fodhelper` — UAC bypass via ms-settings registry hijack  *(Phase B)*
- [ ] `priv/uac-eventvwr` — UAC bypass via mscfile registry hijack  *(Phase B)*
- [ ] `priv/uac-sdclt` — UAC bypass via App Paths control.exe hijack  *(Phase B)*
- [ ] `priv/pipe-impersonate` — named pipe server, wait for privileged client, impersonate  *(Phase B)*
- [x] `priv/unquoted-paths` — enumerate unquoted service paths (misconfig)
- [x] `priv/dll-hijack` — enumerate writable PATH dirs + known DLL hijack targets
- [x] `priv/always-install-elevated` — check AIE registry flags

### A4 — Credential Access (`cred` task type) — `cred.rs`

- [ ] `cred/lsass` — MiniDumpWriteDump via handle duplication + callback (in-memory)

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

- [x] `lateral/smb-psexec` — remote SCM service create + start, poll UNC output  *(graceful-fail: OpenSCManagerA failed on unreachable host)*
- [x] `lateral/wmi` — wmic remote process create (shell-based)  *(graceful-fail: no output → now returns proper error)*
- [x] `lateral/winrm` — winrs remote exec (shell-based)  *(graceful-fail: WinRM TrustedHosts error)*
- [x] `lateral/dcom` — DCOM exec (routes through wmi internally)  *(graceful-fail: same as wmi)*

  *(rdp-pth, adidns already tested in Phase 4E/4H)*

### A7 — Persistence (`persist` task type) — `persist.rs`

> ⚠ These make real changes to the endpoint. Use a VM or accept residual state.

- [x] `persist/reg` — write HKCU/HKLM Run key  *(confirmed working; HKCU Run key created successfully)*
- [x] `persist/reg-rm` — remove Run key  *(confirmed working; key removed successfully)*
- [x] `persist/task` — create scheduled task via schtasks  *(graceful-fail: schtasks exits non-zero without elevation; error propagated correctly)*
- [x] `persist/svc` — create + start Windows service (SCM)  *(graceful-fail: OpenSCManager returns access denied without elevation)*
- [ ] `persist/svc-rm` — delete service  *(untested — depends on svc; defer to Phase B elevated session)*
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

### B3 — Per-Feature BD Testing

> For each feature: queue task → observe BD → verify task completes → record result.
> Status: ✅ Clean | ⚠ Partial (BD alert but task completes) | ❌ Blocked (BD kills task or quarantines)

**File Manager**
- [ ] `file/ls`, `file/read`, `file/write`, `file/rm`, `file/mkdir`, `file/mv`, `file/cp`, `file/info`

**Enumeration**
- [ ] `enum/processes`, `enum/services`, `enum/tasks`, `enum/sessions`, `enum/shares`
- [ ] `enum/users`, `enum/groups`, `enum/localadmins`, `enum/computer`
- [ ] `enum/domain`, `enum/netdiscovery`, `enum/routes`
- [ ] `enum/bloodhound`, `enum/acl`, `enum/unconstrained-deleg`

**Privilege Escalation**
- [ ] `priv/sam-dump` — LSASS and hive access; likely highest-risk for BD kernel driver
- [ ] `priv/token-steal` — OpenProcessToken on winlogon; monitored
- [ ] `priv/token-make` — LogonUser; lower signal
- [ ] `priv/uac-fodhelper`, `priv/uac-eventvwr`, `priv/uac-sdclt`
- [ ] `priv/pipe-impersonate`
- [ ] `priv/potato` — schtasks + named pipe; schtasks is a known BD behavioral rule
- [ ] `priv/unquoted-paths`, `priv/dll-hijack`, `priv/always-install-elevated`
- [ ] `priv/shadow-creds`, `priv/adcs`, `priv/s4u`, `priv/rbcd`, `priv/acl-abuse`

**Credential Access**
- [ ] `cred/lsass` — MiniDumpWriteDump; highest-risk feature
- [ ] `cred/lsass-pss` — PSS approach; quieter
- [ ] `cred/lsass-syscall` — direct syscall; stealthiest of the three
- [ ] `cred/kerberoast`, `cred/asrep-roast`
- [ ] `cred/pth`, `cred/ptt`, `cred/opth`
- [ ] `cred/dcsync`
- [ ] `cred/golden-ticket`, `cred/silver-ticket`, `cred/diamond-ticket`

**Collection**
- [ ] `collect/clipboard`, `collect/dpapi`, `collect/wifi`, `collect/vault`
- [ ] `collect/browser-creds` — DPAPI + SQLite read; BD monitors Chrome DB access
- [ ] `collect/browser-history`, `collect/file-search`
- [ ] `collect/screen-record`, `collect/keylog-start/dump/stop`
- [ ] `collect/ssh-keys`, `collect/certs`, `collect/email`

**Lateral Movement**
- [ ] `lateral/smb-psexec` — SCM remote service creation; high BD signal
- [ ] `lateral/wmi` — wmic child process; monitored
- [ ] `lateral/winrm` — winrs child process
- [ ] `lateral/dcom`
- [ ] `lateral/rdp-pth`
- [ ] `lateral/adidns`

**Persistence**
- [ ] `persist/reg` — Run key; BD monitors this heavily
- [ ] `persist/task` — schtasks; very high BD signal
- [ ] `persist/svc` — service creation; high BD signal
- [ ] `persist/startup` — startup folder copy; moderate signal
- [ ] `persist/com` — HKCU COM hijack; moderate signal
- [ ] `persist/wmi` — WMI subscription; high BD signal

**Anti-Forensics**
- [ ] `antifor/timestomp` — SetFileTime; low signal
- [ ] `antifor/eventlog-clear` — EvtClearLog; BD alerts on this
- [ ] `antifor/eventlog-del`
- [ ] `antifor/indicator-rm`
- [ ] `antifor/shadow-delete` — VSS deletion; BD will almost certainly alert

### B4 — Fix Iteration

> For each ❌ or ⚠ item in B3: implement evasion fix, rebuild, retest until ✅.

- [ ] Persistence: replace schtasks/sc.exe shell calls with direct API calls (WMI COM, SCM direct, etc.)
- [ ] LSASS: evaluate kernel-handle duplication or driver-assisted dump if BD blocks all three variants
- [ ] Token stealing: evaluate direct SYSTEM token path vs. named object enumeration approach
- [ ] Eventlog: evaluate direct binary manipulation of .evtx files vs. EvtClearLog API
- [ ] Browser creds: evaluate VSS snapshot copy approach to bypass locked-file detection
- [ ] All `cmd.exe`-spawning methods: replace with direct API equivalents

---

## Phase C — UI Improvements

> Make features comfortable to use from the DungeonMaster frontend.
> Prioritize high-use features from engagements.

### C1 — Task Builder Panel

- [ ] Design a structured task builder modal (method picker + arg form per feature)
- [ ] Group by category: Recon, Credentials, Lateral, Persist, AntiFor, File
- [ ] Argument validation in-browser (required fields, format hints)
- [ ] Quick-action buttons for common one-shot tasks (e.g., "Dump LSASS PSS", "Run BloodHound")

### C2 — Output Viewers

- [ ] Binary output (LSASS dumps, cert PFX): auto-detect and offer download
- [ ] JSON output: collapsible tree viewer
- [ ] TSV output (browser creds, process list): render as table
- [ ] Base64 image frames (screen-record): inline gallery viewer
- [ ] Keylog dump: plain text viewer with timestamp

### C3 — Session Context Panel

- [ ] Display current session's: hostname, username, PID, OS, domain membership, privilege level
- [ ] Live "priv check" indicator (admin / SYSTEM / standard)
- [ ] Quick enum shortcut: one click to run computer + processes + users for session summary

### C4 — Persistence Tracker

- [ ] Track all persist/* tasks issued per session
- [ ] Show active persistence mechanisms with a "remove" button (calls persist/reg-rm, persist/svc-rm, etc.)

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

- [ ] **VM for agent endpoint?** — Recommended before running Phase A7 (persist) and A8 (antifor). Destructive tests (shadow-delete, eventlog-clear) should not run on host machine.
- [ ] **Is Bitdefender currently active on the test machine?** — Needed before Phase B0 baseline.
- [ ] **Lab DC available?** — Determines whether AD-dependent features can be fully tested in Phase B3 or deferred to Phase D4.

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
