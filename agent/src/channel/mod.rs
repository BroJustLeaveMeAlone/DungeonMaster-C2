pub mod https;
#[cfg(feature = "channel-tcp")]
pub mod tcp;
#[cfg(all(feature = "channel-smb", target_os = "windows"))]
pub mod smb;

use crate::task::{PollResponse, RegisterRequest, RegisterResponse};

/// Channel is the trait that all C2 transport implementations must satisfy.
/// The main loop only talks to a Channel — it never touches HTTP/DNS/SMB directly.
pub trait Channel: Send {
    fn register(&mut self, req: &RegisterRequest, path: &str) -> Result<RegisterResponse, ChannelError>;

    fn poll(&mut self, session: &crate::Session, path: &str) -> Result<PollResponse, ChannelError>;

    fn submit_output(
        &mut self,
        session:             &crate::Session,
        path:                &str,
        task_id:             &str,
        output:              Vec<u8>,
        success:             bool,
        evasion_event:       bool,
        evasion_description: String,
    ) -> Result<(), ChannelError>;
}

#[derive(Debug)]
pub enum ChannelError {
    Network(String),
    Auth,
    Timeout,
    Parse(String),
}

impl std::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network(s) => write!(f, "network: {s}"),
            Self::Auth        => write!(f, "auth failure"),
            Self::Timeout     => write!(f, "timeout"),
            Self::Parse(s)    => write!(f, "parse: {s}"),
        }
    }
}
