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
        // Re-run the build script if any of these change
        println!("cargo:rerun-if-env-changed={key}");
        // Emit as a string constant available via env!("DM_*")
        println!("cargo:rustc-env={key}={val}");
    }
}
