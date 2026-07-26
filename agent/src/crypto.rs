//! Cryptographic primitives for the agent.
//!
//! Key exchange: ECDH P-256 (agent generates ephemeral key pair at startup)
//! Session encryption: AES-256-GCM
//! Key derivation: HKDF-SHA256 over the ECDH shared secret

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use p256::{
    ecdh::EphemeralSecret,
    EncodedPoint, PublicKey,
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

// The agent's ephemeral key pair is generated once at startup.
// Using lazy initialization with a static OnceLock.
use std::sync::OnceLock;

static AGENT_KEY: OnceLock<EphemeralSecret> = OnceLock::new();

fn agent_key() -> &'static EphemeralSecret {
    AGENT_KEY.get_or_init(|| EphemeralSecret::random(&mut OsRng))
}

/// Returns the agent's ECDH public key bytes (uncompressed point).
pub fn agent_pubkey_bytes() -> Vec<u8> {
    EncodedPoint::from(agent_key().public_key()).as_bytes().to_vec()
}

/// Derives the AES-256 session key from the server's ECDH public key.
/// Must be called once after registration, with the server's public key bytes.
pub fn derive_session_key(server_pubkey_bytes: &[u8]) -> Result<[u8; 32], CryptoError> {
    let server_pub = PublicKey::from_sec1_bytes(server_pubkey_bytes)
        .map_err(|_| CryptoError::InvalidKey)?;

    let shared_secret = agent_key().diffie_hellman(&server_pub);

    // Derive AES key via HKDF-SHA256 over the shared secret
    let hk = Hkdf::<Sha256>::new(None, shared_secret.raw_secret_bytes().as_slice());
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(b"dm-session-key-v1", key.as_mut())
        .map_err(|_| CryptoError::Derive)?;

    Ok(*key)
}

/// Encrypts data with AES-256-GCM using the session key.
/// Returns nonce (12 bytes) prepended to ciphertext.
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::Cipher)?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::Encrypt)?;

    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypts data produced by `encrypt`.
/// Expects nonce (12 bytes) prepended to ciphertext.
pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.len() < 12 {
        return Err(CryptoError::InvalidKey);
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::Cipher)?;
    cipher.decrypt(nonce, ciphertext).map_err(|_| CryptoError::Decrypt)
}

const REG_KEY_HEX: &str = env!("DM_REG_KEY");

const fn all_zero_hex(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 64 { return true; }
    let mut i = 0;
    while i < 64 {
        if b[i] != b'0' { return false; }
        i += 1;
    }
    true
}

const fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

const fn decode_key_hex(s: &str) -> [u8; 32] {
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (hex_nibble(bytes[i * 2]) << 4) | hex_nibble(bytes[i * 2 + 1]);
        i += 1;
    }
    out
}

const REG_KEY_ACTIVE: bool = !all_zero_hex(REG_KEY_HEX);
const REG_KEY: [u8; 32] = decode_key_hex(REG_KEY_HEX);

/// Encrypts the registration payload with the compiled-in AES-256-GCM key.
/// Returns plaintext unchanged when the key is all zeros (dev/lab mode).
pub fn encrypt_reg_payload(plaintext: &[u8]) -> Vec<u8> {
    if !REG_KEY_ACTIVE {
        return plaintext.to_vec();
    }
    encrypt(&REG_KEY, plaintext).unwrap_or_else(|_| plaintext.to_vec())
}

#[derive(Debug)]
pub enum CryptoError {
    InvalidKey,
    Derive,
    Cipher,
    Encrypt,
    Decrypt,
}
