//! E2E crypto primitives for the Chutes TEE protocol.
//!
//! The protocol uses ML-KEM-768 (FIPS 203) — despite some docs calling it
//! "ML-KEM-1024", the actual key/ciphertext sizes (1184-byte EK, 2400-byte SK,
//! 1088-byte CT) match ML-KEM-768. We use the `ml-kem` crate's `MlKem768`.

use ml_kem::{EncapsulationKey, KeyExport, MlKem768};
use rand::RngCore;

pub const MLKEM_EK_SIZE: usize = 1184;
pub const MLKEM_SK_SIZE: usize = 2400;
pub const MLKEM_CT_SIZE: usize = 1088;
pub const MLKEM_SHARED_SECRET_SIZE: usize = 32;
/// Error type for crypto operations.
#[derive(Debug)]
pub enum CryptoError {
    Keygen,
    Encapsulate,
    Decapsulate,
    InvalidKey(usize),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::Keygen => write!(f, "ML-KEM keygen failed"),
            CryptoError::Encapsulate => write!(f, "ML-KEM encapsulate failed"),
            CryptoError::Decapsulate => write!(f, "ML-KEM decapsulate failed"),
            CryptoError::InvalidKey(n) => write!(f, "invalid key length: {n}"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// An ephemeral ML-KEM-768 keypair for one E2E request/response cycle.
pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

/// Generate an ephemeral ML-KEM-768 keypair.
///
/// The expanded decapsulation key (2400 bytes) is stored so that it can be
/// reconstructed later for decapsulation. The `ml-kem` crate's `to_bytes()`
/// returns a 64-byte seed; we use the expanded form via `from_seed` round-trip
/// to keep the 2400-byte representation the protocol expects.
pub fn generate_response_keypair() -> Result<KeyPair, CryptoError> {
    use ml_kem::Kem;
    let (dk, ek) = MlKem768::generate_keypair();
    let public_key = ek.to_bytes().to_vec();
    // Store the 64-byte seed; we reconstruct the DK from the seed for decapsulation.
    let secret_key = dk.to_bytes().to_vec();
    Ok(KeyPair {
        public_key,
        secret_key,
    })
}

/// Encapsulate against the server's raw 1184-byte public key.
///
/// Returns the 1088-byte ciphertext and 32-byte shared secret.
pub fn encapsulate_against_server_pubkey(
    server_pubkey: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    use ml_kem::kem::Encapsulate;
    if server_pubkey.len() != MLKEM_EK_SIZE {
        return Err(CryptoError::InvalidKey(server_pubkey.len()));
    }
    let arr: ml_kem::Key<EncapsulationKey<MlKem768>> = server_pubkey
        .try_into()
        .map_err(|_| CryptoError::InvalidKey(server_pubkey.len()))?;
    let ek = EncapsulationKey::<MlKem768>::new(&arr).map_err(|_| CryptoError::Encapsulate)?;
    let (ct, ss) = ek.encapsulate();
    Ok((ct.to_vec(), ss.to_vec()))
}

/// Decapsulate a 1088-byte ciphertext using the 2400-byte (seed-based) secret key.
///
/// `secret_key` here is the 64-byte seed produced by `generate_response_keypair`.
/// We reconstruct the DK from the seed for decapsulation.
pub fn decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    use ml_kem::kem::Decapsulate;
    if ciphertext.len() != MLKEM_CT_SIZE {
        return Err(CryptoError::InvalidKey(ciphertext.len()));
    }
    if secret_key.len() != 64 {
        return Err(CryptoError::InvalidKey(secret_key.len()));
    }
    let seed_arr: [u8; 64] = secret_key
        .try_into()
        .map_err(|_| CryptoError::InvalidKey(secret_key.len()))?;
    let dk = ml_kem::DecapsulationKey::<MlKem768>::from_seed(seed_arr.into());
    let ct: ml_kem::Ciphertext<MlKem768> = ciphertext
        .try_into()
        .map_err(|_| CryptoError::InvalidKey(ciphertext.len()))?;
    let ss = dk.decapsulate(&ct);
    Ok(ss.to_vec())
}

/// Generate random bytes using the system CSPRNG.
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand::rng().fill_bytes(&mut buf);
    buf
}

/// HKDF-SHA256 key derivation.
///
/// Derives a 32-byte key from a shared secret, salt, and info string.
pub fn hkdf_sha256(secret: &[u8], salt: &[u8], info: &[u8]) -> Result<Vec<u8>, CryptoError> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(Some(salt), secret);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).map_err(|_| CryptoError::Keygen)?;
    Ok(okm.to_vec())
}

/// ChaCha20-Poly1305 AEAD encrypt.
///
/// Returns ciphertext with the 16-byte Poly1305 tag appended.
pub fn chacha20poly1305_seal(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
    if key.len() != 32 {
        return Err(CryptoError::InvalidKey(key.len()));
    }
    if nonce.len() != 12 {
        return Err(CryptoError::InvalidKey(nonce.len()));
    }
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::Keygen)?;
    let nonce = Nonce::from_slice(nonce);
    cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::Encapsulate)
}

/// ChaCha20-Poly1305 AEAD decrypt.
///
/// Expects ciphertext with the 16-byte tag appended. Returns plaintext.
pub fn chacha20poly1305_open(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
    if key.len() != 32 {
        return Err(CryptoError::InvalidKey(key.len()));
    }
    if nonce.len() != 12 {
        return Err(CryptoError::InvalidKey(nonce.len()));
    }
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::Keygen)?;
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|_| CryptoError::Decapsulate)
}

/// Gzip compress data.
pub fn gzip_compress(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).map_err(|_| CryptoError::Keygen)?;
    encoder.finish().map_err(|_| CryptoError::Keygen)
}

/// Gzip decompress data.
pub fn gzip_decompress(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    use flate2::read::GzDecoder;
    use std::io::Read;
    let mut decoder = GzDecoder::new(data);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|_| CryptoError::Decapsulate)?;
    Ok(out)
}

/// Minimum blob size: mlkem_ct(1088) + nonce(12) + tag(16), with zero-length ciphertext.
pub const MIN_BLOB_SIZE: usize = MLKEM_CT_SIZE + 12 + 16;

/// Build a request blob: `mlkem_ct(1088) || nonce(12) || ciphertext || tag(16)`.
///
/// `ciphertext_with_tag` is the ChaCha20-Poly1305 output (ct+tag concatenated).
/// For compatibility with the protocol, you can also pass separate ct and tag;
/// here we accept them pre-concatenated since that's what the AEAD produces.
pub fn build_request_blob(mlkem_ct: &[u8], nonce: &[u8], ciphertext: &[u8], tag: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(mlkem_ct.len() + nonce.len() + ciphertext.len() + tag.len());
    blob.extend_from_slice(mlkem_ct);
    blob.extend_from_slice(nonce);
    blob.extend_from_slice(ciphertext);
    blob.extend_from_slice(tag);
    blob
}

/// Parse a request/response blob into (mlkem_ct, nonce, ciphertext_with_tag).
///
/// The ciphertext_with_tag is the AEAD ciphertext with the 16-byte tag appended.
pub fn parse_request_blob(blob: &[u8]) -> Result<(&[u8], &[u8], &[u8]), CryptoError> {
    if blob.len() < MIN_BLOB_SIZE {
        return Err(CryptoError::InvalidKey(blob.len()));
    }
    let mlkem_ct = &blob[..MLKEM_CT_SIZE];
    let nonce = &blob[MLKEM_CT_SIZE..MLKEM_CT_SIZE + 12];
    let ciphertext_with_tag = &blob[MLKEM_CT_SIZE + 12..];
    Ok((mlkem_ct, nonce, ciphertext_with_tag))
}

/// HKDF info strings matching the Lua e2ee-proxy protocol.
pub const HKDF_INFO_REQUEST: &[u8] = b"e2e-req-v1";
pub const HKDF_INFO_RESPONSE: &[u8] = b"e2e-resp-v1";
pub const HKDF_INFO_STREAM: &[u8] = b"e2e-stream-v1";

/// Encrypt a request payload (the full E2E request pipeline).
///
/// 1. Generate ephemeral ML-KEM-768 response keypair.
/// 2. ML-KEM encapsulate against server pubkey → 1088-byte ct + 32-byte shared secret.
/// 3. HKDF-SHA256: salt = mlkem_ct[0:16], info = "e2e-req-v1" → request key.
/// 4. gzip the payload, random 12-byte nonce, ChaCha20-Poly1305 encrypt.
/// 5. Blob: mlkem_ct(1088) || nonce(12) || ciphertext || tag(16).
///
/// Returns (blob, response_secret_key) where response_secret_key is the 64-byte
/// ML-KEM seed used to derive the decapsulation key for the response.
pub fn encrypt_request(
    server_pubkey: &[u8],
    payload: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    // 1. Ephemeral response keypair
    let response_kp = generate_response_keypair()?;
    // 2. ML-KEM encapsulate
    let (mlkem_ct, shared_secret) = encapsulate_against_server_pubkey(server_pubkey)?;
    // 3. HKDF: salt = mlkem_ct[0:16], info = "e2e-req-v1"
    let salt = &mlkem_ct[..16];
    let request_key = hkdf_sha256(&shared_secret, salt, HKDF_INFO_REQUEST)?;
    // 4. gzip + ChaCha20-Poly1305
    let compressed = gzip_compress(payload)?;
    let nonce = random_bytes(12);
    let ciphertext = chacha20poly1305_seal(&request_key, &nonce, &compressed, b"")?;
    // 5. Blob layout: ct(1088) || nonce(12) || ciphertext || tag(16)
    // chacha20poly1305_seal returns ciphertext+tag concatenated, so split for build.
    let (ct_part, tag_part) = ciphertext.split_at(ciphertext.len() - 16);
    let blob = build_request_blob(&mlkem_ct, &nonce, ct_part, tag_part);
    Ok((blob, response_kp.secret_key))
}

/// Decrypt a request blob (server-side inverse, used for testing).
///
/// Parses the blob, decapsulates the ML-KEM ciphertext, derives the request key,
/// and opens the ChaCha20-Poly1305 ciphertext, then gunzips.
pub fn decrypt_request_blob(
    server_secret_key: &[u8],
    blob: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let (mlkem_ct, nonce, ciphertext_with_tag) = parse_request_blob(blob)?;
    let shared_secret = decapsulate(server_secret_key, mlkem_ct)?;
    let salt = &mlkem_ct[..16];
    let request_key = hkdf_sha256(&shared_secret, salt, HKDF_INFO_REQUEST)?;
    let compressed = chacha20poly1305_open(&request_key, nonce, ciphertext_with_tag, b"")?;
    let plaintext = gzip_decompress(&compressed)?;
    Ok(plaintext)
}

/// Decrypt a non-streaming response blob.
///
/// The response blob has the same layout as the request blob. The client uses
/// its ephemeral response secret key to decapsulate, then HKDF info="e2e-resp-v1".
pub fn decrypt_response(
    response_secret_key: &[u8],
    blob: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let (mlkem_ct, nonce, ciphertext_with_tag) = parse_request_blob(blob)?;
    let shared_secret = decapsulate(response_secret_key, mlkem_ct)?;
    let salt = &mlkem_ct[..16];
    let response_key = hkdf_sha256(&shared_secret, salt, HKDF_INFO_RESPONSE)?;
    let compressed = chacha20poly1305_open(&response_key, nonce, ciphertext_with_tag, b"")?;
    let plaintext = gzip_decompress(&compressed)?;
    Ok(plaintext)
}

/// Decrypt the stream init line (`{"e2e_init": <base64 1088-byte ct>}`).
///
/// Returns the stream key for decrypting subsequent `{"e2e": <base64 chunk>}` lines.
pub fn decrypt_stream_init(
    response_secret_key: &[u8],
    e2e_init_ct: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let shared_secret = decapsulate(response_secret_key, e2e_init_ct)?;
    let salt = &e2e_init_ct[..16];
    let stream_key = hkdf_sha256(&shared_secret, salt, HKDF_INFO_STREAM)?;
    Ok(stream_key)
}

/// Decrypt a single stream chunk: `nonce(12) + ciphertext + tag(16)`.
pub fn decrypt_stream_chunk(stream_key: &[u8], chunk: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if chunk.len() < 12 + 16 {
        return Err(CryptoError::InvalidKey(chunk.len()));
    }
    let nonce = &chunk[..12];
    let ciphertext_with_tag = &chunk[12..];
    let plaintext = chacha20poly1305_open(stream_key, nonce, ciphertext_with_tag, b"")?;
    Ok(plaintext)
}
