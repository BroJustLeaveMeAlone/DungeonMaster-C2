# DungeonMaster C2 — Roadmap

> Checkbox list — checked items are shipped. Phases are sequential; a phase begins when the previous one is feature-complete.

---

## Phase 1 — Foundation ✅ (complete)

- [x] Go REST + gRPC server with JWT auth, bcrypt, TOTP scaffolding
- [x] Campaign, session, task, listener, build data model (PostgreSQL)
- [x] SSE event bus (Redis pub/sub) for real-time operator feed
- [x] Rust Windows agent — ECDH key exchange, AES-256-GCM task encryption
- [x] HTTPS C2 channel with configurable sleep/jitter
- [x] Agent sandbox detection (process count, analysis tool enumeration)
- [x] WinAPI fingerprinting (OpenProcessToken, RtlGetVersion, CreateToolhelp32Snapshot)
- [x] Docker-in-Docker build system — per-engagement agent compilation (~80s)
- [x] MinIO artifact + evidence store with presigned download URLs
- [x] React operator UI — dashboard, session list, xterm.js shell, campaign event feed
- [x] Build page with live history, status polling, download links
- [x] Campaign creation modal
- [x] Python FastAPI AI engine scaffolding (Claude API, TTP ranker stub)
- [x] Nginx redirector config

---

## Phase 2 — Operational Core

*First version you'd actually take on a real engagement.*

### Infrastructure
- [ ] **TOTP enforcement** — enabled by default; opt-out via `DM_TOTP_DISABLED=true`
- [ ] **Rate limiting** — brute-force protection on `/auth/login` (5 req/min per IP, 429 + lockout)
- [ ] **CORS allowlist** — `DM_ALLOWED_ORIGINS` env var; dev default `localhost:3000/5173` only
- [ ] **LICENSE + SECURITY.md** — GPL-3.0 license, responsible disclosure policy

### Task types
- [ ] **File upload** — operator → agent; chunked transfer, progress in UI
- [ ] **File download** — agent → MinIO; auto-stored as evidence
- [ ] **Screenshot** — GDI capture, stored in evidence bucket
- [ ] **Kill** — clean agent shutdown with cleanup
- [ ] **Sleep update** — change beacon interval on a live session without rebuild

### C2 channels
- [ ] **SMB named-pipe channel** — P2P beacon for internal hosts; chains through one internet-facing agent
- [ ] **TCP bind/reverse channel** — raw TCP for air-gapped environments
- [ ] **Malleable C2 profiles** — YAML config: custom HTTP headers, paths, user-agents, response bodies, URI rotation, jitter profiles

### Agent
- [ ] **Sleep encryption** — AES encrypt agent heap region during sleep; invisible to memory scanners at rest
- [ ] **Linux agent** — same Rust codebase cross-compiled for Linux x64; opens server/cloud pivots

---

## Phase 3 — Evasion & Injection

*Survive on EDR-protected, hardened endpoints.*

### Process injection
- [ ] **Classic injection** — `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`
- [ ] **Early-bird APC injection** — inject via APC queue at process creation before EDR hooks load
- [ ] **Process hollowing** — real implementation of existing `process_hollow` flag
- [ ] **Thread hijacking** — suspend thread, overwrite RIP/EIP, resume
- [ ] **Module stomping** — overwrite a legitimate module's .text section with shellcode

### Evasion primitives
- [ ] **Indirect syscalls** — call NT functions via syscall stubs without touching `ntdll` exports; bypasses userland hooks
- [ ] **ETW patching** — real implementation of `etw_patch` flag; blind ETW-based detections
- [ ] **AMSI bypass** — real implementation of `amsi_patch` flag; neuter AMSI in .NET/PowerShell hosts
- [ ] **Parent PID spoofing** — real implementation of existing `parent_spoof` flag
- [ ] **Heap sleep masking** — ChaCha20 encrypt the full agent heap while sleeping; zero readable strings at rest
- [ ] **Unhooking** — restore `ntdll` from a clean on-disk copy at startup; remove all userland EDR hooks
- [ ] **Stack spoofing** — forge a clean call stack during syscalls to defeat call-stack-based detections
- [ ] **Stomped module loader** — load agent into memory disguised as a legitimate signed DLL

### Loader
- [ ] **UDRL (user-defined reflective loader)** — custom PE loader; replaces default loader to bypass static and behavioral loader detections
- [ ] **Staged payload** — small stager (~8KB) pulls full agent over C2; minimal initial AV surface

---

## Phase 4 — Post-Exploitation Module Library

*Deeper than Cobalt Strike. Every category built out.*

### Credential Access
- [ ] LSASS dump — `MiniDumpWriteDump` via handle duplication
- [ ] LSASS dump — direct syscall variant (no `MiniDump` API; bypasses API-level hooks)
- [ ] LSASS dump — `PssCaptureSnapshot` variant (process snapshot, less noisy)
- [ ] SAM/SYSTEM/SECURITY hive extraction (offline NTLM hash recovery)
- [ ] DPAPI secret decryption — browser master keys, WiFi passwords, certificate private keys
- [ ] Windows Credential Manager enumeration (`CredEnumerate`)
- [ ] Browser credential extraction — Chrome, Edge, Firefox (cookies, saved passwords, sessions)
- [ ] Certificate theft — export user and machine certificates from the cert store
- [ ] SSH key theft — enumerate and exfiltrate `~/.ssh/` keys
- [ ] WiFi password extraction — `WlanGetProfileCustomUserData`
- [ ] Clipboard capture — snapshot current clipboard contents
- [ ] Keylogger — per-window keystroke capture via `SetWindowsHookEx`

### Discovery & Enumeration
- [ ] Domain enumeration — domain info, forest trusts, DCs via LDAP
- [ ] User and group enumeration — AD users, group memberships, nested groups
- [ ] Computer enumeration — domain computers, OS versions, last logon
- [ ] Session enumeration — who is logged on to which machine (`NetSessionEnum`)
- [ ] Share enumeration — SMB shares across the domain
- [ ] ACL enumeration — interesting permissions on AD objects (for BloodHound-style analysis)
- [ ] BloodHound data collection — full SharpHound-equivalent data collection built in
- [ ] Network discovery — ARP scan, ping sweep, port scan
- [ ] Subnet and route enumeration
- [ ] Local admin enumeration — which domain users/groups have local admin where
- [ ] Process list — remote process enumeration via `EnumProcesses`
- [ ] Service enumeration — local and remote services
- [ ] Scheduled task enumeration

### Lateral Movement
- [ ] SMB lateral movement — PsExec-style service execution
- [ ] WMI lateral movement — `Win32_Process.Create` remote execution
- [ ] DCOM lateral movement — `MMC20.Application` and `ShellBrowserWindow`
- [ ] WinRM lateral movement — PowerShell remoting via WS-Man
- [ ] RDP pass-the-hash — restricted admin mode RDP with NTLM hash
- [ ] SSH lateral movement — execute commands using stolen keys
- [ ] Kubernetes lateral movement — enumerate and exec into pods via stolen service account tokens

### Kerberos & Active Directory
- [ ] AS-REP roasting — harvest crackable TGTs for accounts without pre-auth
- [ ] Kerberoasting — request service tickets for offline cracking
- [ ] DCSync — DRSUAPI replication; pull any NTLM hash directly from a DC
- [ ] Pass-the-Hash — authenticate with NTLM hash, no plaintext
- [ ] Pass-the-Ticket — inject Kerberos ticket into current session
- [ ] Overpass-the-Hash — exchange NTLM hash for a fully usable Kerberos TGT
- [ ] Golden Ticket — forge TGTs with KRBTGT hash (full domain persistence)
- [ ] Silver Ticket — forge service tickets for specific service access
- [ ] Diamond Ticket — forge a TGT derived from a real ticket (less detectable than golden)
- [ ] ADCS ESC1 — enroll a certificate on behalf of any user via misconfigured template
- [ ] ADCS ESC2–ESC8 — full coverage of known ADCS privilege escalation paths
- [ ] Shadow Credentials — add `msDS-KeyCredentialLink` to a target for certificate-based auth
- [ ] Unconstrained delegation abuse — capture TGTs from machines with unconstrained delegation
- [ ] Constrained delegation abuse (S4U2Self / S4U2Proxy)
- [ ] Resource-based constrained delegation (RBCD) — write `msDS-AllowedToActOnBehalfOfOtherIdentity`
- [ ] ADIDNS abuse — add/modify DNS records for relay/spoofing attacks
- [ ] ACL abuse — targeted write of dangerous ACEs (GenericAll, WriteDACL, etc.)

### Privilege Escalation
- [ ] Token impersonation — `ImpersonateLoggedOnUser`, `make_token`, `steal_token`
- [ ] Named pipe impersonation — create a pipe, wait for SYSTEM connection, impersonate
- [ ] PrintSpoofer / EfsPotato — potato-family SYSTEM escalation on modern Windows
- [ ] Service misconfiguration — unquoted service paths, writable service binaries
- [ ] DLL hijacking escalation — detect and exploit missing DLL load order entries
- [ ] UAC bypass — auto-elevation via `fodhelper`, `eventvwr`, `sdclt` and others
- [ ] AlwaysInstallElevated — exploit misconfigured MSI policy for SYSTEM

### Persistence
- [ ] Registry run keys — `HKCU`/`HKLM` run key entries
- [ ] Scheduled tasks — register a task via Task Scheduler API
- [ ] Service installation — register a new Windows service
- [ ] COM object hijacking — redirect per-user COM class to attacker-controlled DLL
- [ ] WMI event subscription — `__EventFilter` + `CommandLineEventConsumer` persistence
- [ ] DLL side-loading — drop a DLL alongside a legitimate signed binary
- [ ] Startup folder — drop a file into the user or all-users startup folder
- [ ] Boot/pre-OS persistence — MBR/UEFI module (advanced, Phase 4 end-state)

### Collection & Exfiltration
- [ ] File browser — directory listing, file read/write, recursive search
- [ ] File content search — grep across the filesystem for patterns (credentials, config files)
- [ ] Screen recording — continuous video capture of the desktop
- [ ] Email collection — harvest emails from Outlook/Exchange via MAPI
- [ ] Browser history and bookmarks — Chrome, Edge, Firefox
- [ ] Clipboard monitoring — continuous clipboard capture loop
- [ ] Exfiltration over C2 — chunked, encrypted file exfil through the existing C2 channel
- [ ] Exfiltration over DNS — encode data in DNS queries as alternate exfil channel

### Defense Evasion & Anti-Forensics
- [ ] Timestomping — modify MACE timestamps (`NtSetInformationFile`)
- [ ] Windows Event Log clearing — clear Security, System, Application logs
- [ ] Windows Event Log tampering — delete individual event records without clearing log
- [ ] VSS shadow copy deletion — `IVssBackupComponents` delete all shadow copies
- [ ] Prefetch disabling and tampering
- [ ] MFT entry manipulation — hide files from NTFS MFT enumeration
- [ ] Indicator removal — clean up dropped files, registry keys, scheduled tasks from current op

### Linux Modules
- [ ] sudo enumeration — `sudo -l`, sudoers file parsing
- [ ] SUID/SGID binary discovery — find and exploit setuid binaries
- [ ] Cron job enumeration and poisoning
- [ ] /etc/passwd and /etc/shadow manipulation
- [ ] LD_PRELOAD hijacking — shared library injection
- [ ] SSH authorized_keys persistence
- [ ] D-Bus service enumeration
- [ ] Linux capability abuse — enumerate processes with dangerous capabilities
- [ ] Docker socket abuse — escape container via mounted Docker socket
- [ ] Namespace escape — user namespace, mount namespace escapes
- [ ] Kernel exploit launcher — load and execute compiled kernel exploits in memory

### macOS Modules
- [ ] Keychain extraction — dump keychain items (passwords, certificates, keys)
- [ ] TCC bypass — circumvent Transparency, Consent and Control restrictions
- [ ] LaunchAgent/LaunchDaemon persistence
- [ ] Login item persistence
- [ ] `AuthorizationExecuteWithPrivileges` abuse — escalate privileges via deprecated API
- [ ] macOS credential extraction — `security` command wrapper, `securityd` memory access
- [ ] Gatekeeper bypass — unsigned code execution bypasses
- [ ] macOS sudo timestamp abuse — extend sudo session without re-authenticating

### Cloud & Container Modules
- [ ] AWS IMDSv1/v2 — metadata service credential extraction
- [ ] AWS IAM enumeration — roles, policies, effective permissions
- [ ] AWS role assumption — assume IAM roles via stolen credentials
- [ ] AWS S3 enumeration — bucket listing, object access
- [ ] AWS Lambda abuse — invoke and enumerate Lambda functions
- [ ] Azure IMDS — managed identity token extraction
- [ ] Azure AAD enumeration — tenant users, service principals, app registrations
- [ ] Azure Storage account abuse
- [ ] GCP metadata service credential extraction
- [ ] GCP service account key theft
- [ ] Kubernetes API server enumeration — namespaces, pods, secrets
- [ ] Kubernetes secret extraction — `kubectl`-equivalent secret dump
- [ ] Container escape — `cgroup`, `overlay` filesystem escapes

---

## Phase 5 — Beyond Cobalt Strike

*Capabilities CS fundamentally cannot offer.*

### AI Engine (functional)
- [ ] **Real-time TTP auto-tagging** — AI reads task output and maps to MITRE ATT&CK techniques automatically; no manual tagging
- [ ] **Evasion advisor** — AI reads current session (EDR list, OS version, process tree, elevation) and recommends next TTPs with estimated detection risk
- [ ] **Post-engagement report generation** — AI synthesizes the full campaign into a professional operator report (Markdown + PDF): timeline, TTP heatmap, findings, recommendations
- [ ] **Anomaly detection** — AI flags unusual session behaviour that may indicate the operator is being tracked or redirected

### Plugin & Module System
- [ ] **Native module API** — drop-in server-side and agent-side extensions; new task types appear in UI automatically
- [ ] **BOF (Beacon Object File) loader** — run community-written Cobalt Strike BOFs in-memory, natively, without modification
- [ ] **Aggressor Script equivalent** — operator-side automation scripting (event hooks, macros, automated response chains)

### Automation & Orchestration
- [ ] **Kill chain templates** — pre-built attack sequences (initial access → persistence → cred dump → lateral move → exfil); operator approves each step
- [ ] **Automated enumeration pipeline** — trigger a chain of discovery tasks on new session check-in; results fed to AI for prioritised next steps
- [ ] **Multi-operator real-time collaboration** — shared cursors, session locking, operator chat, conflict resolution (Figma-like, but for red team ops)

### Reporting & Intelligence
- [ ] **MITRE ATT&CK heatmap UI** — live heatmap of techniques used across the campaign; updates as tasks complete
- [ ] **Blue team export** — share campaign TTPs in STIX 2.1 format for direct import into the client's SIEM/SOAR
- [ ] **Engagement comparison** — diff two campaigns; track technique drift and detection improvement over repeated assessments
- [ ] **IOC timeline** — auto-generated timeline of all indicators created during the engagement for the deconfliction report

### Ecosystem
- [ ] **Community module registry** — searchable index of community-contributed modules; install with one click from the UI
- [ ] **Operator profiles + teams** — role-based access control per campaign; lead operator, analyst, read-only observer roles
- [ ] **Mobile agent** — Android red team agent for mobile device assessment scenarios
- [ ] **Hardware implant support** — C2 over LoRa / LTE for physical red team scenarios
