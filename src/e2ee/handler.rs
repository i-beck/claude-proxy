//! E2E invoke handler — ties discovery + crypto together.
//!
//! Encrypts a request, POSTs to api.chutes.ai/e2e/invoke with the required
//! X-E2E-* headers, and decrypts the response (streaming or non-streaming).

use crate::e2ee::attestation::{
    self, AttestationError, AttestationMode, MeasurementOverride, VerifyParams,
};
use crate::e2ee::crypto::{self, CryptoError, HKDF_INFO_RESPONSE, HKDF_INFO_STREAM};
use crate::e2ee::discovery::{self, Discovery, DiscoveryError};
use base64::Engine;

/// Error type for the E2E handler.
#[derive(Debug)]
pub enum E2EError {
    Discovery(DiscoveryError),
    Crypto(CryptoError),
    Http(reqwest::Error),
    Status(u16, String),
    Parse(String),
    NoNonce,
    Attestation(AttestationError),
}

impl std::fmt::Display for E2EError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            E2EError::Discovery(e) => write!(f, "discovery: {e}"),
            E2EError::Crypto(e) => write!(f, "crypto: {e}"),
            E2EError::Http(e) => write!(f, "http: {e}"),
            E2EError::Status(c, b) => write!(f, "status {c}: {b}"),
            E2EError::Parse(m) => write!(f, "parse: {m}"),
            E2EError::NoNonce => write!(f, "no nonce available"),
            E2EError::Attestation(e) => write!(f, "attestation: {e}"),
        }
    }
}

impl std::error::Error for E2EError {}

/// FIX 3: human-readable message for end users.
///
/// The original error is preserved as the debug source — this is a *method on
/// the error*, so callers can still use `{:?}` / `to_string()` (the `Display`
/// impl above) for logging while surfacing `user_message()` to the user. Each
/// variant maps to a plain-language message; the `Crypto` / `Attestation` /
/// `Discovery` variants delegate to their inner error's `user_message()`.
impl E2EError {
    pub fn user_message(&self) -> String {
        match self {
            E2EError::Discovery(e) => e.user_message(),
            E2EError::Crypto(e) => e.user_message(),
            E2EError::Http(e) => {
                format!("Network error talking to the TEE: {e}. Please try again in a moment.")
            }
            E2EError::Status(code, _body) => match code {
                403 => "The TEE rejected the request (nonce expired or invalid). Retry in 2s.".to_string(),
                404 => "The TEE instance could not be found. It may have gone offline.".to_string(),
                500..=599 => "The TEE service is temporarily unavailable. Please try again in a moment.".to_string(),
                other => format!("The TEE service returned an unexpected error ({other}). Please try again."),
            },
            E2EError::Parse(msg) => {
                format!("Malformed response from the TEE: {msg}. Please try again.")
            }
            E2EError::NoNonce => {
                "No encryption nonce available from the TEE. Check instance is live and E2E is offered."
                    .to_string()
            }
            E2EError::Attestation(e) => e.user_message(),
        }
    }
}

impl From<DiscoveryError> for E2EError {
    fn from(e: DiscoveryError) -> Self {
        E2EError::Discovery(e)
    }
}
impl From<CryptoError> for E2EError {
    fn from(e: CryptoError) -> Self {
        E2EError::Crypto(e)
    }
}

impl From<AttestationError> for E2EError {
    fn from(e: AttestationError) -> Self {
        E2EError::Attestation(e)
    }
}

/// The result of encrypting a request: the blob to POST, the response secret
/// key (for decrypting the response), and the headers to send.
pub struct EncryptedRequest {
    pub blob: Vec<u8>,
    pub response_secret_key: Vec<u8>,
    pub instance_id: String,
    pub nonce: String,
}

/// Encrypt a request for the E2E invoke endpoint.
///
/// `server_pubkey` is the raw 1184-byte ML-KEM-768 public key from the instance.
/// `payload` is the already-translated OpenAI-format JSON body (with
/// `e2e_response_pk` injected).
pub fn prepare_encrypted_request(
    server_pubkey: &[u8],
    payload: &[u8],
    instance_id: String,
    nonce: String,
) -> Result<EncryptedRequest, E2EError> {
    let (blob, response_sk) = crypto::encrypt_request(server_pubkey, payload)?;
    Ok(EncryptedRequest {
        blob,
        response_secret_key: response_sk,
        instance_id,
        nonce,
    })
}

/// Inject the `e2e_response_pk` field into a JSON payload.
///
/// The response public key is base64-encoded and added to the top-level JSON.
pub fn inject_response_pk(payload: &str, response_pk: &[u8]) -> Result<String, E2EError> {
    let mut value: serde_json::Value =
        serde_json::from_str(payload).map_err(|e| E2EError::Parse(e.to_string()))?;
    if let Some(obj) = value.as_object_mut() {
        let encoded = base64::engine::general_purpose::STANDARD.encode(response_pk);
        obj.insert("e2e_response_pk".into(), serde_json::Value::String(encoded));
    }
    serde_json::to_string(&value).map_err(|e| E2EError::Parse(e.to_string()))
}

/// POST the encrypted blob to the E2E invoke endpoint.
///
/// Returns the raw response body (for non-streaming) or the response stream
/// (for streaming). The caller is responsible for decryption.
pub async fn post_e2e_invoke(
    client: &reqwest::Client,
    api_base: &str,
    api_key: &str,
    chute_id: &str,
    encrypted: &EncryptedRequest,
    stream: bool,
    original_path: &str,
) -> Result<reqwest::Response, E2EError> {
    let url = format!("{}/e2e/invoke", api_base.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", api_key))
        .header("X-Chute-Id", chute_id)
        .header("X-Instance-Id", &encrypted.instance_id)
        .header("X-E2E-Nonce", &encrypted.nonce)
        .header("X-E2E-Stream", if stream { "true" } else { "false" })
        .header("X-E2E-Path", original_path)
        .header("Content-Type", "application/octet-stream")
        .body(encrypted.blob.clone())
        .send()
        .await
        .map_err(E2EError::Http)?;
    Ok(resp)
}

/// Decrypt a non-streaming E2E response body.
pub fn decrypt_non_streaming_response(
    response_secret_key: &[u8],
    body: &[u8],
) -> Result<Vec<u8>, E2EError> {
    let plaintext = crypto::decrypt_response(response_secret_key, body)?;
    Ok(plaintext)
}

/// Check if a 403 response body indicates a nonce issue (triggering retry).
pub fn is_nonce_403(status: u16, body: &str) -> bool {
    status == 403 && body.to_lowercase().contains("nonce")
}

/// The full E2E request flow: acquire nonce, encrypt, POST, decrypt.
///
/// Handles nonce retry on 403: invalidates cache, re-fetches, retries once.
pub async fn e2e_request(
    discovery: &Discovery,
    client: &reqwest::Client,
    api_base: &str,
    api_key: &str,
    chute_id: &str,
    payload: &[u8],
    stream: bool,
    original_path: &str,
) -> Result<E2EResponse, E2EError> {
    // First attempt.
    match e2e_request_once(
        discovery,
        client,
        api_base,
        api_key,
        chute_id,
        payload,
        stream,
        original_path,
    )
    .await
    {
        Ok(resp) => Ok(resp),
        Err(E2EError::Status(403, ref body)) if is_nonce_403(403, body) => {
            // Nonce issue: invalidate cache, re-fetch, retry once.
            log::warn!("E2E 403 nonce error, refreshing and retrying");
            discovery.invalidate().await;
            e2e_request_once(
                discovery,
                client,
                api_base,
                api_key,
                chute_id,
                payload,
                stream,
                original_path,
            )
            .await
        }
        Err(e) => Err(e),
    }
}

/// Single attempt of the E2E request flow (no retry).
async fn e2e_request_once(
    discovery: &Discovery,
    client: &reqwest::Client,
    api_base: &str,
    api_key: &str,
    chute_id: &str,
    payload: &[u8],
    stream: bool,
    original_path: &str,
) -> Result<E2EResponse, E2EError> {
    let (instance_id, server_pubkey, nonce, _quote) = discovery
        .acquire(chute_id, api_key)
        .await
        .map_err(E2EError::from)?;
    // Generate ephemeral response keypair and inject e2e_response_pk into the payload.
    let response_kp = crypto::generate_response_keypair()?;
    let injected_payload = inject_response_pk(
        std::str::from_utf8(payload).map_err(|e| E2EError::Parse(e.to_string()))?,
        &response_kp.public_key,
    )?;
    let (blob, _response_sk) =
        crypto::encrypt_request(&server_pubkey, injected_payload.as_bytes())?;
    let encrypted = EncryptedRequest {
        blob,
        response_secret_key: response_kp.secret_key,
        instance_id,
        nonce,
    };
    let resp = post_e2e_invoke(
        client,
        api_base,
        api_key,
        chute_id,
        &encrypted,
        stream,
        original_path,
    )
    .await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(E2EError::Status(status.as_u16(), body));
    }
    Ok(E2EResponse {
        response: resp,
        response_secret_key: encrypted.response_secret_key,
    })
}

/// The response from an E2E invoke: the raw reqwest response (for streaming
/// or reading the body) and the secret key to decrypt it.
#[derive(Debug)]
pub struct E2EResponse {
    pub response: reqwest::Response,
    pub response_secret_key: Vec<u8>,
}

/// Configuration for attestation-gated E2E requests.
#[derive(Clone, Debug)]
pub struct AttestationConfig<'a> {
    /// The guest image version to verify against (e.g. "1.5.0").
    pub expected_version: &'a str,
    /// Strict or permissive mode.
    pub mode: AttestationMode,
    /// Optional measurement override (env-var/config-file path).
    pub override_measurements: Option<&'a MeasurementOverride>,
    /// Optional: public IP of the miner's TEE worker node. When set, the client
    /// fetches a fresh TDX quote from the miner's public attestation service
    /// (`https://{node_ip}:30443/server/attest`) with a client-generated nonce,
    /// and verifies it instead of relying on a quote embedded in
    /// `/e2e/instances`. When `None` (the default), this path is disabled and
    /// attestation falls back to the quote from `/e2e/instances` if any.
    ///
    /// NOTE: the public NodePort 30443 bridges to the proxy's external port,
    /// whose `/server/attest` route requires validator auth — so a bare user
    /// API key can only reach it if the operator exposes the quote or the user
    /// obtains validator credentials. This field exists for deployments that
    /// have arranged such access; most users leave it `None`.
    pub node_ip: Option<&'a str>,
    /// Optional: Intel PCS / PCCS base URL for fetching DCAP collateral.
    /// When set, after a quote is obtained, the client fetches collateral
    /// (PCK CRL, TCB info, QE identity, root CA CRL) and runs the full
    /// cryptographic signature verification (`verify_dcap`) in addition to the
    /// measurement + key-binding checks. When `None` (the default), collateral
    /// is not fetched and `signature_verified` stays `false` (the
    /// measurement-only fallback).
    pub collateral_url: Option<&'a str>,
    /// When `true` and no quote is available from `/e2e/instances`, fall back
    /// to the best-effort control-plane attestation-status check
    /// (`check_attestation_status`, i.e. `GET /chutes/{chute_id}` →
    /// `instances[].verified`). In strict mode a non-`Verified` status (or a
    /// failed check) refuses the request; in permissive mode it logs and
    /// proceeds. When `false` (the default), the no-quote path keeps its
    /// original behavior (strict refuses, permissive proceeds) and no
    /// `/chutes/` call is made.
    pub check_status: bool,
    /// When `true`, fetch a live quote + TEE certificate from the Chutes API
    /// evidence endpoint (`GET /instances/{id}/evidence?nonce={e2e_nonce}`).
    /// This is the user-reachable path (no validator token, no node IP). The
    /// quote's REPORTDATA binds the E2E pool nonce (verbatim, confirmed against
    /// the live API); the cert-hash half is verified as
    /// `SHA-256(SPKI-der(evid_cert)) == report_data[32..]`, proving the quote
    /// is bound to the TEE's own attestation-service key. When `check_status`
    /// is also enabled, this takes precedence (it is cryptographic, not just
    /// control-plane). When `collateral_url` is set, the fetched quote is also
    /// DCAP-verified.
    pub use_evidence: bool,
}

impl<'a> Default for AttestationConfig<'a> {
    fn default() -> Self {
        Self {
            expected_version: "",
            mode: AttestationMode::default(),
            override_measurements: None,
            node_ip: None,
            collateral_url: None,
            check_status: false,
            use_evidence: false,
        }
    }
}

/// E2E request with attestation verification.
///
/// After acquiring an instance, if the instance carries a TDX quote, the quote
/// is parsed and verified against the pinned measurements and key binding
/// before encryption proceeds. If no quote is present, behavior depends on the
/// mode: strict refuses, permissive logs and proceeds.
///
/// The nonce used for key binding is the E2E nonce from the instance pool.
pub async fn e2e_request_attested(
    discovery: &Discovery,
    client: &reqwest::Client,
    api_base: &str,
    api_key: &str,
    chute_id: &str,
    payload: &[u8],
    stream: bool,
    original_path: &str,
    attest: &AttestationConfig<'_>,
) -> Result<E2EResponse, E2EError> {
    // Acquire instance + nonce + optional quote.
    let (instance_id, server_pubkey, nonce, quote) = discovery
        .acquire(chute_id, api_key)
        .await
        .map_err(E2EError::from)?;

    // ── Attestation quote source ─────────────────────────────────────────
    // Priority: (1) a live quote fetched from the miner's attestation service
    // when `attest.node_ip` is set; (2) a quote carried on `/e2e/instances`
    // (none today); (3) none. The live-fetch path binds the quote to the
    // client-generated nonce that also goes to the E2E channel, so it replaces
    // the instance nonce for key-binding checks on that path.
    let mut live_quote: Option<(Vec<u8>, String)> = None;
    if let Some(node_ip) = attest.node_ip {
        let att_nonce = attestation::new_attestation_nonce();
        match attestation::fetch_quote_from_miner(client, node_ip, &att_nonce).await {
            Ok(q) => {
                log::info!(
                    "attestation: fetched live quote from miner ({} bytes)",
                    q.len()
                );
                live_quote = Some((q, att_nonce));
            }
            Err(e) => {
                log::warn!("attestation: live quote fetch failed: {e}");
                match attest.mode {
                    AttestationMode::Strict => {
                        return Err(E2EError::Attestation(AttestationError::UnknownVersion {
                            version: format!("live quote fetch failed: {e}"),
                        }));
                    }
                    AttestationMode::Permissive => {}
                }
            }
        }
    }

    // ── Evidence fetch (user-reachable live quote) ────────────────────────
    // When `use_evidence` is set and no live miner quote was fetched, fetch a
    // quote + TEE certificate from the Chutes API evidence endpoint using the
    // E2E pool nonce as the binding nonce. The quote's REPORTDATA binds the
    // E2E nonce verbatim (confirmed live); the cert-hash half is verified as
    // `SHA-256(SPKI-der(cert)) == report_data[32..]` via `expected_pubkey`.
    let mut evidence_spki: Option<Vec<u8>> = None;
    if attest.use_evidence && live_quote.is_none() {
        match attestation::fetch_quote_with_cert(client, api_base, api_key, &instance_id, &nonce)
            .await
        {
            Ok(ev) => {
                log::info!(
                    "attestation: fetched evidence quote from Chutes API ({} bytes)",
                    ev.quote.len()
                );
                live_quote = Some((ev.quote, ev.nonce_b64));
                if !ev.certificate_b64.is_empty() {
                    match attestation::extract_spki_der(&ev.certificate_b64) {
                        Ok(spki) => evidence_spki = Some(spki),
                        Err(e) => log::warn!("attestation: SPKI extract failed: {e}"),
                    }
                }
            }
            Err(e) => {
                log::warn!("attestation: evidence fetch failed: {e}");
                if attest.mode == AttestationMode::Strict {
                    return Err(E2EError::Attestation(AttestationError::UnknownVersion {
                        version: format!("evidence fetch failed: {e}"),
                    }));
                }
            }
        }
    }

    // Effective (quote_bytes, binding_nonce): live quote wins when present.
    let (effective_quote, binding_nonce): (Option<Vec<u8>>, String) = match &live_quote {
        Some((q, n)) => (Some(q.clone()), n.clone()),
        None => (quote.clone(), nonce.clone()),
    };

    // Determine key-binding target: if the quote came from the evidence path
    // (`live_quote` was just set by `use_evidence`), we verify the cert-hash
    // half against the TEE attestation-service cert SPKI (extracted above).
    // Otherwise, the quote binds the E2E ML-KEM public key (`server_pubkey`).
    let evidence_proof_of_key: Option<&[u8]> = evidence_spki.as_deref();
    let (expected_pubkey, skip_nonce_binding) = match evidence_proof_of_key {
        Some(spki) => (spki, true),
        None => (&server_pubkey[..], false),
    };

    // Attestation verification if a quote is available.
    if let Some(quote_bytes) = &effective_quote {
        let parsed = attestation::parse_quote(quote_bytes)?;

        // Optional DCAP collateral for full cryptographic verification.
        let mut collateral: Option<attestation::DcapCollateral> = None;
        if let Some(url) = attest.collateral_url {
            let base = if url.is_empty() { None } else { Some(url) };
            match attestation::fetch_intel_pcs_collateral(client, quote_bytes, base).await {
                Ok(c) => {
                    log::info!("attestation: fetched Intel PCS collateral");
                    collateral = Some(c);
                }
                Err(e) => {
                    log::warn!("attestation: collateral fetch failed: {e}");
                    if attest.mode == AttestationMode::Strict {
                        return Err(E2EError::Attestation(AttestationError::UnknownVersion {
                            version: format!("collateral fetch failed: {e}"),
                        }));
                    }
                }
            }
        }
        let now_secs = if collateral.is_some() {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        } else {
            0
        };

        let params = VerifyParams {
            expected_version: attest.expected_version,
            expected_nonce: &binding_nonce,
            expected_pubkey,
            override_measurements: attest.override_measurements,
            mode: attest.mode,
            collateral: collateral.as_ref(),
            now_secs,
            skip_nonce_binding,
        };
        let result = attestation::verify(&parsed, &params);
        attestation::should_proceed(&result, attest.mode)?;
    } else {
        // No quote: in strict mode, refuse. In permissive, log and proceed.
        // When `check_status` is enabled, fall back to the best-effort
        // control-plane attestation-status check before deciding.
        if attest.check_status {
            match check_attestation_status(client, api_base, api_key, chute_id, &instance_id).await
            {
                Ok(AttestationStatus::Verified) => {
                    log::info!("attestation: no quote, control-plane status = Verified");
                    // Treated as permissive-proceed regardless of mode: the
                    // control plane vouches for the instance.
                }
                Ok(AttestationStatus::Unverified) => {
                    log::warn!("attestation: no quote, control-plane status = Unverified");
                    match attest.mode {
                        AttestationMode::Strict => {
                            return Err(E2EError::Attestation(AttestationError::UnknownVersion {
                                version: "control-plane attestation status: Unverified".into(),
                            }));
                        }
                        AttestationMode::Permissive => {}
                    }
                }
                Ok(AttestationStatus::NotFound) => {
                    log::warn!("attestation: no quote, control-plane status = NotFound");
                    match attest.mode {
                        AttestationMode::Strict => {
                            return Err(E2EError::Attestation(AttestationError::UnknownVersion {
                                version: "control-plane attestation status: instance not found"
                                    .into(),
                            }));
                        }
                        AttestationMode::Permissive => {}
                    }
                }
                Err(e) => {
                    log::warn!("attestation: no quote, status check failed: {e}");
                    match attest.mode {
                        AttestationMode::Strict => {
                            return Err(E2EError::Attestation(AttestationError::UnknownVersion {
                                version: format!("attestation status check failed: {e}"),
                            }));
                        }
                        AttestationMode::Permissive => {}
                    }
                }
            }
        } else {
            match attest.mode {
                AttestationMode::Strict => {
                    log::warn!("attestation: no quote from instance, strict mode refuses");
                    return Err(E2EError::Attestation(AttestationError::UnknownVersion {
                        version: "no quote in instance response".into(),
                    }));
                }
                AttestationMode::Permissive => {
                    log::info!("attestation: no quote from instance, permissive mode proceeds");
                }
            }
        }
    }

    // Generate ephemeral response keypair and inject e2e_response_pk.
    let response_kp = crypto::generate_response_keypair()?;
    let injected_payload = inject_response_pk(
        std::str::from_utf8(payload).map_err(|e| E2EError::Parse(e.to_string()))?,
        &response_kp.public_key,
    )?;
    let (blob, _response_sk) =
        crypto::encrypt_request(&server_pubkey, injected_payload.as_bytes())?;
    let encrypted = EncryptedRequest {
        blob,
        response_secret_key: response_kp.secret_key,
        instance_id,
        nonce,
    };
    let resp = post_e2e_invoke(
        client,
        api_base,
        api_key,
        chute_id,
        &encrypted,
        stream,
        original_path,
    )
    .await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(E2EError::Status(status.as_u16(), body));
    }
    Ok(E2EResponse {
        response: resp,
        response_secret_key: encrypted.response_secret_key,
    })
}

// ── Best-effort attestation status from the user API ──────────────────────────
//
// The Chutes user API does not expose a per-instance TDX quote or server IP —
// the real quote lives behind validator-auth'd miner endpoints the client
// cannot reach. The only operator-visible attestation signal available to a
// bare API key is the `instances[i].verified` flag on `/chutes/{chute_id}`,
// which the Chutes control plane maintains. This is a *control-plane* signal,
// not a cryptographic one — use the live-quote fetch path
// (`AttestationConfig::node_ip`) when it is available.

/// Attestation status signal derived from the public API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttestationStatus {
    /// The instance is reported `verified` by the control plane.
    Verified,
    /// The instance is present but `verified` is false.
    Unverified,
    /// The instance_id was not found in the chute's instance list.
    NotFound,
}

/// Best-effort check of an instance's attestation/verification status via the
/// user-facing Chutes API.
///
/// `GET {api_base}/chutes/{chute_id}` → `instances[]`. Looks up `instance_id`
/// and returns whether `verified` is true. Note: this is NOT cryptographic
/// attestation — it is the control plane's view of the instance. In
/// permissive mode callers may log and proceed; in strict mode call sites
/// should refuse on anything other than `Verified`.
pub async fn check_attestation_status(
    client: &reqwest::Client,
    api_base: &str,
    api_key: &str,
    chute_id: &str,
    instance_id: &str,
) -> Result<AttestationStatus, E2EError> {
    let url = format!("{}/chutes/{}", api_base.trim_end_matches('/'), chute_id);
    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await
        .map_err(E2EError::Http)?;
    let status = resp.status().as_u16();
    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(E2EError::Status(status, body));
    }
    let body: serde_json::Value = resp.json().await.map_err(E2EError::Http)?;
    let instances = body
        .get("instances")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    for inst in instances {
        if inst.get("instance_id").and_then(|v| v.as_str()) == Some(instance_id) {
            let verified = inst
                .get("verified")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            return Ok(if verified {
                AttestationStatus::Verified
            } else {
                AttestationStatus::Unverified
            });
        }
    }
    Ok(AttestationStatus::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inject_response_pk_adds_field() {
        let payload = r#"{"model":"test","messages":[]}"#;
        let pk = vec![1u8; 1184];
        let result = inject_response_pk(payload, &pk).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(parsed.get("e2e_response_pk").is_some());
        let encoded = parsed["e2e_response_pk"].as_str().unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        assert_eq!(decoded, pk);
    }

    #[test]
    fn test_inject_response_pk_preserves_existing_fields() {
        let payload = r#"{"model":"test","messages":[{"role":"user","content":"hi"}]}"#;
        let pk = vec![2u8; 1184];
        let result = inject_response_pk(payload, &pk).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["model"], "test");
        assert!(parsed.get("e2e_response_pk").is_some());
    }

    #[test]
    fn test_inject_response_pk_invalid_json_returns_error() {
        let payload = "not json";
        let pk = vec![1u8; 1184];
        assert!(inject_response_pk(payload, &pk).is_err());
    }

    #[test]
    fn test_is_nonce_403_detects_nonce_error() {
        assert!(is_nonce_403(403, r#"{"detail":"nonce expired"}"#));
        assert!(is_nonce_403(403, r#"{"detail":"Invalid nonce"}"#));
        assert!(!is_nonce_403(403, r#"{"detail":"forbidden"}"#));
        assert!(!is_nonce_403(401, r#"{"detail":"nonce expired"}"#));
    }

    // ── FIX 3: human-readable error messages ──────────────────────────────

    #[test]
    fn test_crypto_error_user_message_decapsulate() {
        // Exact string from the task spec.
        assert_eq!(
            CryptoError::Decapsulate.user_message(),
            "Failed to establish encrypted session with TEE. Attestation key mismatch or stale session. Retry in 2s."
        );
    }

    #[test]
    fn test_crypto_error_user_message_invalid_key() {
        // Exact string from the task spec, with the byte count interpolated.
        assert_eq!(
            CryptoError::InvalidKey(7).user_message(),
            "Invalid key format (got 7 bytes, expected 1184) from TEE evidence. Attestation may have failed."
        );
        assert_eq!(
            CryptoError::InvalidKey(1184).user_message(),
            "Invalid key format (got 1184 bytes, expected 1184) from TEE evidence. Attestation may have failed."
        );
    }

    #[test]
    fn test_e2e_error_user_message_no_nonce() {
        // Exact string from the task spec.
        assert_eq!(
            E2EError::NoNonce.user_message(),
            "No encryption nonce available from the TEE. Check instance is live and E2E is offered."
        );
    }

    #[test]
    fn test_e2e_error_user_message_delegates_to_inner_errors() {
        // E2EError::Crypto delegates to CryptoError::user_message().
        let e = E2EError::Crypto(CryptoError::Decapsulate);
        assert_eq!(
            e.user_message(),
            "Failed to establish encrypted session with TEE. Attestation key mismatch or stale session. Retry in 2s."
        );
        // E2EError::Discovery delegates to DiscoveryError::user_message()
        // (NoNonces → same string as E2EError::NoNonce).
        let d = E2EError::Discovery(DiscoveryError::NoNonces);
        assert_eq!(
            d.user_message(),
            "No encryption nonce available from the TEE. Check instance is live and E2E is offered."
        );
        // E2EError::Attestation delegates to AttestationError::user_message().
        let a = E2EError::Attestation(AttestationError::NonceMismatch {
            expected: "a".into(),
            got: "b".into(),
        });
        assert_eq!(
            a.user_message(),
            "The TEE attestation nonce did not match. The session may be stale. Retry in 2s."
        );
    }

    #[test]
    fn test_e2e_error_user_message_status_variants() {
        // 403 → nonce/expired message.
        assert_eq!(
            E2EError::Status(403, "nonce expired".into()).user_message(),
            "The TEE rejected the request (nonce expired or invalid). Retry in 2s."
        );
        // 5xx → temporary-unavailable message.
        assert_eq!(
            E2EError::Status(503, "boom".into()).user_message(),
            "The TEE service is temporarily unavailable. Please try again in a moment."
        );
    }

    #[test]
    fn test_user_message_keeps_original_error_as_debug_source() {
        // The original error is preserved as the debug source: `{:?}` /
        // `to_string()` still yield the machine-readable form, independent of
        // `user_message()`.
        let e = CryptoError::Decapsulate;
        assert_eq!(format!("{e:?}"), "Decapsulate");
        assert_eq!(e.to_string(), "ML-KEM decapsulate failed");
        assert_ne!(
            e.user_message(),
            e.to_string(),
            "user_message must differ from the debug Display form"
        );
    }

    #[test]
    fn test_prepare_encrypted_request_produces_valid_blob() {
        let server = crypto::generate_response_keypair().unwrap();
        let payload = br#"{"model":"test"}"#;
        let enc = prepare_encrypted_request(
            &server.public_key,
            payload,
            "inst-1".into(),
            "nonce-1".into(),
        )
        .unwrap();
        assert!(enc.blob.len() > 1088 + 12 + 16);
        assert_eq!(enc.instance_id, "inst-1");
        assert_eq!(enc.nonce, "nonce-1");
        assert_eq!(enc.response_secret_key.len(), 64);
    }

    #[tokio::test]
    async fn test_full_e2e_request_cycle_with_mock_backend() {
        // Mock backend that simulates the full E2E flow:
        // 1. /e2e/instances/:chute_id returns instances+nonces
        // 2. /e2e/invoke receives the encrypted blob, decrypts it, re-encrypts
        //    a response, and returns it.
        use axum::{
            body::Bytes,
            extract::Path,
            http::HeaderMap,
            routing::{get, post},
            Json, Router,
        };
        use std::sync::Arc;
        use tokio::sync::Mutex;

        // Server keypair (the TEE instance's key).
        let server_kp = crypto::generate_response_keypair().unwrap();
        let server_pk_b64 = discovery::base64_encode(&server_kp.public_key);
        let server_sk = Arc::new(Mutex::new(server_kp.secret_key.clone()));

        let resp_plaintext = br#"{"id":"msg_1","type":"message","content":[{"type":"text","text":"Hello from TEE"}]}"#;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_sk_clone = server_sk.clone();
        let resp_body = serde_json::json!({
            "instances": [{
                "instance_id": "inst-test-1",
                "e2e_pubkey": server_pk_b64,
                "nonces": ["nonce-1", "nonce-2"]
            }],
            "nonce_expires_in": 60
        });

        let app = Router::new()
            .route(
                "/e2e/instances/:chute_id",
                get(move || {
                    let body = resp_body.clone();
                    async move { Json(body) }
                }),
            )
            .route(
                "/e2e/invoke",
                post(move |_headers: HeaderMap, body: Bytes| {
                    let server_sk = server_sk_clone.clone();
                    async move {
                        use axum::response::IntoResponse;
                        // Decrypt the request blob.
                        let sk = server_sk.lock().await;
                        let req_plaintext = crypto::decrypt_request_blob(&sk, &body).unwrap();
                        let req_json: serde_json::Value =
                            serde_json::from_slice(&req_plaintext).unwrap();
                        assert!(req_json.get("e2e_response_pk").is_some());
                        assert_eq!(req_json["model"], "test-model");
                        // Encrypt a response using the client's response_pk.
                        let resp_pk_b64 = req_json["e2e_response_pk"].as_str().unwrap();
                        let resp_pk = discovery::base64_decode(resp_pk_b64).unwrap();
                        let (mlkem_ct, shared_secret) =
                            crypto::encapsulate_against_server_pubkey(&resp_pk).unwrap();
                        let salt = &mlkem_ct[..16];
                        let resp_key =
                            crypto::hkdf_sha256(&shared_secret, salt, crypto::HKDF_INFO_RESPONSE)
                                .unwrap();
                        let compressed = crypto::gzip_compress(resp_plaintext).unwrap();
                        let nonce = crypto::random_bytes(12);
                        let ciphertext =
                            crypto::chacha20poly1305_seal(&resp_key, &nonce, &compressed, b"")
                                .unwrap();
                        let (ct_part, tag_part) = ciphertext.split_at(ciphertext.len() - 16);
                        let resp_blob =
                            crypto::build_request_blob(&mlkem_ct, &nonce, ct_part, tag_part);
                        (
                            axum::http::StatusCode::OK,
                            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                            resp_blob,
                        )
                            .into_response()
                    }
                }),
            );
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        // Client side: discovery + e2e_request.
        let client = reqwest::Client::new();
        let api_base = format!("http://{}", addr);
        let discovery = Discovery::new(client.clone(), api_base.clone());

        let payload = br#"{"model":"test-model","messages":[{"role":"user","content":"hi"}]}"#;
        let result = e2e_request(
            &discovery,
            &client,
            &api_base,
            "test-key",
            "test-chute",
            payload,
            false,
            "/v1/chat/completions",
        )
        .await
        .unwrap();

        let body = result.response.bytes().await.unwrap();
        let decrypted = decrypt_non_streaming_response(&result.response_secret_key, &body).unwrap();
        assert_eq!(decrypted, resp_plaintext);
    }

    #[tokio::test]
    async fn test_e2e_request_retries_on_nonce_403() {
        // Mock backend that returns 403 nonce error on first invoke, then succeeds.
        use axum::{
            body::Bytes,
            extract::State as AxumState,
            http::HeaderMap,
            routing::{get, post},
            Json, Router,
        };
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;

        let server_kp = crypto::generate_response_keypair().unwrap();
        let server_pk_b64 = discovery::base64_encode(&server_kp.public_key);
        let attempt = Arc::new(AtomicU32::new(0));

        let resp_body = serde_json::json!({
            "instances": [{
                "instance_id": "inst-1",
                "e2e_pubkey": server_pk_b64,
                "nonces": ["n1", "n2", "n3", "n4"]
            }],
            "nonce_expires_in": 60
        });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let attempt_clone = attempt.clone();
        let server_sk = server_kp.secret_key.clone();
        let app = Router::new()
            .route(
                "/e2e/instances/:chute_id",
                get(move || {
                    let body = resp_body.clone();
                    async move { Json(body) }
                }),
            )
            .route(
                "/e2e/invoke",
                post(move |headers: HeaderMap, body: Bytes| {
                    let attempt = attempt_clone.clone();
                    let sk = server_sk.clone();
                    async move {
                        use axum::response::IntoResponse;
                        let n = attempt.fetch_add(1, Ordering::SeqCst);
                        if n == 0 {
                            // First attempt: return 403 nonce error.
                            return (
                                axum::http::StatusCode::FORBIDDEN,
                                [(axum::http::header::CONTENT_TYPE, "application/json")],
                                serde_json::to_vec(
                                    &serde_json::json!({"detail": "nonce expired or invalid"}),
                                )
                                .unwrap(),
                            )
                                .into_response();
                        }
                        // Second attempt: succeed.
                        let req_plaintext = crypto::decrypt_request_blob(&sk, &body).unwrap();
                        let req_json: serde_json::Value =
                            serde_json::from_slice(&req_plaintext).unwrap();
                        let resp_pk_b64 = req_json["e2e_response_pk"].as_str().unwrap();
                        let resp_pk = discovery::base64_decode(resp_pk_b64).unwrap();
                        let (mlkem_ct, shared_secret) =
                            crypto::encapsulate_against_server_pubkey(&resp_pk).unwrap();
                        let salt = &mlkem_ct[..16];
                        let resp_key =
                            crypto::hkdf_sha256(&shared_secret, salt, crypto::HKDF_INFO_RESPONSE)
                                .unwrap();
                        let resp_text = br#"{"ok":true}"#;
                        let compressed = crypto::gzip_compress(resp_text).unwrap();
                        let nonce = crypto::random_bytes(12);
                        let ct = crypto::chacha20poly1305_seal(&resp_key, &nonce, &compressed, b"")
                            .unwrap();
                        let (ct_part, tag_part) = ct.split_at(ct.len() - 16);
                        let blob = crypto::build_request_blob(&mlkem_ct, &nonce, ct_part, tag_part);
                        (
                            axum::http::StatusCode::OK,
                            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                            blob,
                        )
                            .into_response()
                    }
                }),
            );
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let client = reqwest::Client::new();
        let api_base = format!("http://{}", addr);
        let discovery = Discovery::new(client.clone(), api_base.clone());

        let payload = br#"{"model":"test","messages":[]}"#;
        let result = e2e_request(
            &discovery,
            &client,
            &api_base,
            "key",
            "chute",
            payload,
            false,
            "/v1/chat/completions",
        )
        .await
        .unwrap();

        let body = result.response.bytes().await.unwrap();
        let decrypted = decrypt_non_streaming_response(&result.response_secret_key, &body).unwrap();
        assert_eq!(decrypted, br#"{"ok":true}"#);
        // Verify we retried.
        assert_eq!(attempt.load(Ordering::SeqCst), 2);
    }

    // ── Attestation integration tests ─────────────────────────────────────

    /// Integration test: mock API returns a valid TDX quote, handler accepts it
    /// and proceeds with encryption.
    #[tokio::test]
    async fn test_attested_request_valid_quote_proceeds() {
        use axum::{
            body::Bytes,
            http::HeaderMap,
            routing::{get, post},
            Json, Router,
        };

        // Server keypair (the TEE instance's key).
        let server_kp = crypto::generate_response_keypair().unwrap();
        let server_pk_b64 = discovery::base64_encode(&server_kp.public_key);
        let server_sk = std::sync::Arc::new(tokio::sync::Mutex::new(server_kp.secret_key.clone()));

        // Build a valid TDX quote with pinned measurements + key binding.
        let pinned = attestation::pinned_measurement_for_version("1.5.0").unwrap();
        let mrtd = attestation::hex_to_reg(pinned.mrtd).unwrap();
        let rtmr1 = attestation::hex_to_reg(pinned.rtmr1).unwrap();
        let rtmr2 = attestation::hex_to_reg(pinned.rtmr2).unwrap();
        let rtmr3 = attestation::hex_to_reg(pinned.rtmr3).unwrap();
        // Use a 64-hex-char nonce so the E2E nonce matches the REPORTDATA nonce.
        let nonce_str = "a1b2c3d4".repeat(8); // 64 hex chars = 32 bytes
        let report_data = attestation::build_report_data(&nonce_str, &server_kp.public_key);
        let quote_bytes = attestation::build_mock_quote(
            &mrtd,
            &[0; attestation::REGISTER_SIZE],
            &rtmr1,
            &rtmr2,
            &rtmr3,
            &report_data,
        );
        let quote_b64 = discovery::base64_encode(&quote_bytes);

        let resp_body = serde_json::json!({
            "instances": [{
                "instance_id": "inst-attest-1",
                "e2e_pubkey": server_pk_b64,
                "nonces": [nonce_str.clone()],
                "quote": quote_b64,
            }],
            "nonce_expires_in": 60
        });

        let resp_plaintext =
            br#"{"id":"msg_1","type":"message","content":[{"type":"text","text":"Hello"}]}"#;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_sk_clone = server_sk.clone();
        let app = Router::new()
            .route(
                "/e2e/instances/:chute_id",
                get(move || {
                    let body = resp_body.clone();
                    async move { Json(body) }
                }),
            )
            .route(
                "/e2e/invoke",
                post(move |_headers: HeaderMap, body: Bytes| {
                    let server_sk = server_sk_clone.clone();
                    async move {
                        use axum::response::IntoResponse;
                        let sk = server_sk.lock().await;
                        let req_plaintext = crypto::decrypt_request_blob(&sk, &body).unwrap();
                        let req_json: serde_json::Value =
                            serde_json::from_slice(&req_plaintext).unwrap();
                        let resp_pk_b64 = req_json["e2e_response_pk"].as_str().unwrap();
                        let resp_pk = discovery::base64_decode(resp_pk_b64).unwrap();
                        let (mlkem_ct, shared_secret) =
                            crypto::encapsulate_against_server_pubkey(&resp_pk).unwrap();
                        let salt = &mlkem_ct[..16];
                        let resp_key =
                            crypto::hkdf_sha256(&shared_secret, salt, crypto::HKDF_INFO_RESPONSE)
                                .unwrap();
                        let compressed = crypto::gzip_compress(resp_plaintext).unwrap();
                        let nonce = crypto::random_bytes(12);
                        let ciphertext =
                            crypto::chacha20poly1305_seal(&resp_key, &nonce, &compressed, b"")
                                .unwrap();
                        let (ct_part, tag_part) = ciphertext.split_at(ciphertext.len() - 16);
                        let resp_blob =
                            crypto::build_request_blob(&mlkem_ct, &nonce, ct_part, tag_part);
                        (
                            axum::http::StatusCode::OK,
                            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                            resp_blob,
                        )
                            .into_response()
                    }
                }),
            );
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let client = reqwest::Client::new();
        let api_base = format!("http://{}", addr);
        let discovery = Discovery::new(client.clone(), api_base.clone());

        let payload = br#"{"model":"test-model","messages":[]}"#;
        let attest_cfg = AttestationConfig {
            expected_version: "1.5.0",
            mode: AttestationMode::Strict,
            override_measurements: None,
            ..Default::default()
        };
        let result = e2e_request_attested(
            &discovery,
            &client,
            &api_base,
            "test-key",
            "test-chute",
            payload,
            false,
            "/v1/chat/completions",
            &attest_cfg,
        )
        .await;

        assert!(
            result.is_ok(),
            "valid quote should allow encryption: {:?}",
            result.err()
        );
        let result = result.unwrap();
        let body = result.response.bytes().await.unwrap();
        let decrypted = decrypt_non_streaming_response(&result.response_secret_key, &body).unwrap();
        assert_eq!(decrypted, resp_plaintext);
    }

    /// Integration test: mock API returns an INVALID TDX quote (wrong MRTD),
    /// handler REFUSES to encrypt in strict mode.
    #[tokio::test]
    async fn test_attested_request_invalid_quote_refused() {
        use axum::{
            routing::{get, post},
            Json, Router,
        };

        let server_kp = crypto::generate_response_keypair().unwrap();
        let server_pk_b64 = discovery::base64_encode(&server_kp.public_key);

        // Build a quote with WRONG MRTD (all 0xFF).
        let wrong_mrtd = [0xFF; attestation::REGISTER_SIZE];
        let nonce_hex = "a1b2c3d4".repeat(8);
        let report_data = attestation::build_report_data(&nonce_hex, &server_kp.public_key);
        let quote_bytes = attestation::build_mock_quote(
            &wrong_mrtd,
            &[0; attestation::REGISTER_SIZE],
            &[0; attestation::REGISTER_SIZE],
            &[0; attestation::REGISTER_SIZE],
            &[0; attestation::REGISTER_SIZE],
            &report_data,
        );
        let quote_b64 = discovery::base64_encode(&quote_bytes);

        let resp_body = serde_json::json!({
            "instances": [{
                "instance_id": "inst-bad-1",
                "e2e_pubkey": server_pk_b64,
                "nonces": [nonce_hex.clone()],
                "quote": quote_b64,
            }],
            "nonce_expires_in": 60
        });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // The invoke endpoint should never be reached in strict mode.
        let invoke_reached = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let invoke_reached_clone = invoke_reached.clone();
        let app = Router::new()
            .route(
                "/e2e/instances/:chute_id",
                get(move || {
                    let body = resp_body.clone();
                    async move { Json(body) }
                }),
            )
            .route(
                "/e2e/invoke",
                post(move || {
                    let reached = invoke_reached_clone.clone();
                    async move {
                        reached.store(true, std::sync::atomic::Ordering::SeqCst);
                        "should not reach here"
                    }
                }),
            );
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let client = reqwest::Client::new();
        let api_base = format!("http://{}", addr);
        let discovery = Discovery::new(client.clone(), api_base.clone());

        let payload = br#"{"model":"test","messages":[]}"#;
        let attest_cfg = AttestationConfig {
            expected_version: "1.5.0",
            mode: AttestationMode::Strict,
            override_measurements: None,
            ..Default::default()
        };
        let result = e2e_request_attested(
            &discovery,
            &client,
            &api_base,
            "test-key",
            "test-chute",
            payload,
            false,
            "/v1/chat/completions",
            &attest_cfg,
        )
        .await;

        assert!(result.is_err(), "invalid quote should be refused");
        assert!(
            !invoke_reached.load(std::sync::atomic::Ordering::SeqCst),
            "invoke endpoint should NOT have been reached"
        );
        // Verify the error is an attestation error.
        match result.unwrap_err() {
            E2EError::Attestation(_) => {} // expected
            other => panic!("expected Attestation error, got {other:?}"),
        }
    }

    /// Integration test: no quote in instance response — strict mode refuses,
    /// permissive mode proceeds.
    #[tokio::test]
    async fn test_attested_request_no_quote_strict_refuses_permissive_proceeds() {
        use axum::{
            body::Bytes,
            http::HeaderMap,
            routing::{get, post},
            Json, Router,
        };

        let server_kp = crypto::generate_response_keypair().unwrap();
        let server_pk_b64 = discovery::base64_encode(&server_kp.public_key);
        let server_sk = std::sync::Arc::new(tokio::sync::Mutex::new(server_kp.secret_key.clone()));

        // No "quote" field in the instance response.
        let resp_body = serde_json::json!({
            "instances": [{
                "instance_id": "inst-noquote-1",
                "e2e_pubkey": server_pk_b64,
                "nonces": ["nonce-a"],
            }],
            "nonce_expires_in": 60
        });

        let resp_plaintext = br#"{"ok":true}"#;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_sk_clone = server_sk.clone();
        let app = Router::new()
            .route(
                "/e2e/instances/:chute_id",
                get(move || {
                    let body = resp_body.clone();
                    async move { Json(body) }
                }),
            )
            .route(
                "/e2e/invoke",
                post(move |_headers: HeaderMap, body: Bytes| {
                    let server_sk = server_sk_clone.clone();
                    async move {
                        use axum::response::IntoResponse;
                        let sk = server_sk.lock().await;
                        let req_plaintext = crypto::decrypt_request_blob(&sk, &body).unwrap();
                        let req_json: serde_json::Value =
                            serde_json::from_slice(&req_plaintext).unwrap();
                        let resp_pk_b64 = req_json["e2e_response_pk"].as_str().unwrap();
                        let resp_pk = discovery::base64_decode(resp_pk_b64).unwrap();
                        let (mlkem_ct, shared_secret) =
                            crypto::encapsulate_against_server_pubkey(&resp_pk).unwrap();
                        let salt = &mlkem_ct[..16];
                        let resp_key =
                            crypto::hkdf_sha256(&shared_secret, salt, crypto::HKDF_INFO_RESPONSE)
                                .unwrap();
                        let compressed = crypto::gzip_compress(resp_plaintext).unwrap();
                        let nonce = crypto::random_bytes(12);
                        let ciphertext =
                            crypto::chacha20poly1305_seal(&resp_key, &nonce, &compressed, b"")
                                .unwrap();
                        let (ct_part, tag_part) = ciphertext.split_at(ciphertext.len() - 16);
                        let resp_blob =
                            crypto::build_request_blob(&mlkem_ct, &nonce, ct_part, tag_part);
                        (
                            axum::http::StatusCode::OK,
                            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                            resp_blob,
                        )
                            .into_response()
                    }
                }),
            );
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let client = reqwest::Client::new();
        let api_base = format!("http://{}", addr);

        // Strict mode: should refuse.
        let discovery_strict = Discovery::new(client.clone(), api_base.clone());
        let attest_strict = AttestationConfig {
            expected_version: "1.5.0",
            mode: AttestationMode::Strict,
            override_measurements: None,
            ..Default::default()
        };
        let result = e2e_request_attested(
            &discovery_strict,
            &client,
            &api_base,
            "test-key",
            "test-chute",
            br#"{"model":"test"}"#,
            false,
            "/v1/chat/completions",
            &attest_strict,
        )
        .await;
        assert!(result.is_err(), "strict mode should refuse without quote");

        // Permissive mode: should proceed.
        let discovery_perm = Discovery::new(client.clone(), api_base.clone());
        let attest_perm = AttestationConfig {
            expected_version: "1.5.0",
            mode: AttestationMode::Permissive,
            override_measurements: None,
            ..Default::default()
        };
        let result = e2e_request_attested(
            &discovery_perm,
            &client,
            &api_base,
            "test-key",
            "test-chute",
            br#"{"model":"test"}"#,
            false,
            "/v1/chat/completions",
            &attest_perm,
        )
        .await;
        assert!(
            result.is_ok(),
            "permissive mode should proceed without quote"
        );
    }

    // ── check_attestation_status tests ────────────────────────────────────

    /// Start a mock `/chutes/{id}` server returning a JSON body.
    async fn start_chutes_mock(
        body: serde_json::Value,
        status: u16,
    ) -> (String, tokio::task::JoinHandle<()>) {
        use axum::{routing::get, Router};
        let app = Router::new().route(
            "/chutes/:chute_id",
            get(move || async move {
                use axum::http::StatusCode;
                use axum::response::IntoResponse;
                let code = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
                (code, body.to_string()).into_response()
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        (format!("http://{addr}"), handle)
    }

    #[tokio::test]
    async fn test_check_attestation_status_verified() {
        let body = serde_json::json!({
            "instances": [
                {"instance_id": "inst-1", "verified": true},
                {"instance_id": "inst-2", "verified": false},
            ]
        });
        let (base, handle) = start_chutes_mock(body, 200).await;
        let client = reqwest::Client::new();
        let status = check_attestation_status(&client, &base, "key", "chute", "inst-1")
            .await
            .unwrap();
        assert_eq!(status, AttestationStatus::Verified);
        handle.abort();
    }

    #[tokio::test]
    async fn test_check_attestation_status_unverified() {
        let body = serde_json::json!({
            "instances": [
                {"instance_id": "inst-1", "verified": true},
                {"instance_id": "inst-2", "verified": false},
            ]
        });
        let (base, handle) = start_chutes_mock(body, 200).await;
        let client = reqwest::Client::new();
        let status = check_attestation_status(&client, &base, "key", "chute", "inst-2")
            .await
            .unwrap();
        assert_eq!(status, AttestationStatus::Unverified);
        handle.abort();
    }

    #[tokio::test]
    async fn test_check_attestation_status_not_found() {
        let body = serde_json::json!({
            "instances": [
                {"instance_id": "inst-1", "verified": true},
            ]
        });
        let (base, handle) = start_chutes_mock(body, 200).await;
        let client = reqwest::Client::new();
        let status = check_attestation_status(&client, &base, "key", "chute", "nonexistent")
            .await
            .unwrap();
        assert_eq!(status, AttestationStatus::NotFound);
        handle.abort();
    }

    #[tokio::test]
    async fn test_check_attestation_status_empty_instances() {
        let body = serde_json::json!({"instances": []});
        let (base, handle) = start_chutes_mock(body, 200).await;
        let client = reqwest::Client::new();
        let status = check_attestation_status(&client, &base, "key", "chute", "inst-1")
            .await
            .unwrap();
        assert_eq!(status, AttestationStatus::NotFound);
        handle.abort();
    }

    #[tokio::test]
    async fn test_check_attestation_status_missing_instances_key() {
        let body = serde_json::json!({"version": "1.5.0"});
        let (base, handle) = start_chutes_mock(body, 200).await;
        let client = reqwest::Client::new();
        let status = check_attestation_status(&client, &base, "key", "chute", "inst-1")
            .await
            .unwrap();
        assert_eq!(status, AttestationStatus::NotFound);
        handle.abort();
    }

    #[tokio::test]
    async fn test_check_attestation_status_error_status() {
        let body = serde_json::json!({"detail": "not found"});
        let (base, handle) = start_chutes_mock(body, 404).await;
        let client = reqwest::Client::new();
        let result = check_attestation_status(&client, &base, "key", "chute", "inst-1").await;
        assert!(result.is_err());
        handle.abort();
    }

    // ── Integration: check_status wired into e2e_request_attested ──────────

    /// Helper: start a mock server with /e2e/instances (no quote), /chutes/:id,
    /// and /e2e/invoke (returns a minimal encrypted response).
    async fn start_no_quote_with_chutes_mock(
        chutes_body: serde_json::Value,
        chutes_status: u16,
    ) -> (String, tokio::task::JoinHandle<()>) {
        use axum::{
            body::Bytes,
            http::HeaderMap,
            routing::{get, post},
            Json, Router,
        };

        let server_kp = crypto::generate_response_keypair().unwrap();
        let server_pk_b64 = discovery::base64_encode(&server_kp.public_key);
        let server_sk = std::sync::Arc::new(tokio::sync::Mutex::new(server_kp.secret_key.clone()));

        let instances_body = serde_json::json!({
            "instances": [{
                "instance_id": "inst-noquote-1",
                "e2e_pubkey": server_pk_b64,
                "nonces": ["nonce-a"],
            }],
            "nonce_expires_in": 60
        });
        let resp_plaintext = br#"{"ok":true}"#.to_vec();

        let server_sk_clone = server_sk.clone();
        let chutes_body_clone = chutes_body.clone();
        let app = Router::new()
            .route(
                "/e2e/instances/:chute_id",
                get(move || {
                    let body = instances_body.clone();
                    async move { Json(body) }
                }),
            )
            .route(
                "/chutes/:chute_id",
                get(move || async move {
                    use axum::http::StatusCode;
                    use axum::response::IntoResponse;
                    let code = StatusCode::from_u16(chutes_status).unwrap_or(StatusCode::OK);
                    (code, chutes_body_clone.to_string()).into_response()
                }),
            )
            .route(
                "/e2e/invoke",
                post(move |_headers: HeaderMap, body: Bytes| {
                    let server_sk = server_sk_clone.clone();
                    async move {
                        use axum::response::IntoResponse;
                        let sk = server_sk.lock().await;
                        let req_plaintext = crypto::decrypt_request_blob(&sk, &body).unwrap();
                        let req_json: serde_json::Value =
                            serde_json::from_slice(&req_plaintext).unwrap();
                        let resp_pk_b64 = req_json["e2e_response_pk"].as_str().unwrap();
                        let resp_pk = discovery::base64_decode(resp_pk_b64).unwrap();
                        let (mlkem_ct, shared_secret) =
                            crypto::encapsulate_against_server_pubkey(&resp_pk).unwrap();
                        let salt = &mlkem_ct[..16];
                        let resp_key =
                            crypto::hkdf_sha256(&shared_secret, salt, crypto::HKDF_INFO_RESPONSE)
                                .unwrap();
                        let compressed = crypto::gzip_compress(&resp_plaintext).unwrap();
                        let nonce = crypto::random_bytes(12);
                        let ciphertext =
                            crypto::chacha20poly1305_seal(&resp_key, &nonce, &compressed, b"")
                                .unwrap();
                        let (ct_part, tag_part) = ciphertext.split_at(ciphertext.len() - 16);
                        let resp_blob =
                            crypto::build_request_blob(&mlkem_ct, &nonce, ct_part, tag_part);
                        (
                            axum::http::StatusCode::OK,
                            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                            resp_blob,
                        )
                            .into_response()
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        (format!("http://{addr}"), handle)
    }

    #[tokio::test]
    async fn test_check_status_verified_proceeds_in_strict_mode() {
        let chutes_body = serde_json::json!({
            "instances": [{"instance_id": "inst-noquote-1", "verified": true}]
        });
        let (api_base, handle) = start_no_quote_with_chutes_mock(chutes_body, 200).await;
        let client = reqwest::Client::new();
        let discovery = Discovery::new(client.clone(), api_base.clone());
        let attest = AttestationConfig {
            expected_version: "1.5.0",
            mode: AttestationMode::Strict,
            check_status: true,
            ..Default::default()
        };
        let result = e2e_request_attested(
            &discovery,
            &client,
            &api_base,
            "test-key",
            "test-chute",
            br#"{"model":"test"}"#,
            false,
            "/v1/chat/completions",
            &attest,
        )
        .await;
        assert!(
            result.is_ok(),
            "Verified status should allow strict mode to proceed"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn test_check_status_unverified_refuses_in_strict_mode() {
        let chutes_body = serde_json::json!({
            "instances": [{"instance_id": "inst-noquote-1", "verified": false}]
        });
        let (api_base, handle) = start_no_quote_with_chutes_mock(chutes_body, 200).await;
        let client = reqwest::Client::new();
        let discovery = Discovery::new(client.clone(), api_base.clone());
        let attest = AttestationConfig {
            expected_version: "1.5.0",
            mode: AttestationMode::Strict,
            check_status: true,
            ..Default::default()
        };
        let result = e2e_request_attested(
            &discovery,
            &client,
            &api_base,
            "test-key",
            "test-chute",
            br#"{"model":"test"}"#,
            false,
            "/v1/chat/completions",
            &attest,
        )
        .await;
        assert!(
            result.is_err(),
            "Unverified status should refuse in strict mode"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn test_check_status_unverified_proceeds_in_permissive_mode() {
        let chutes_body = serde_json::json!({
            "instances": [{"instance_id": "inst-noquote-1", "verified": false}]
        });
        let (api_base, handle) = start_no_quote_with_chutes_mock(chutes_body, 200).await;
        let client = reqwest::Client::new();
        let discovery = Discovery::new(client.clone(), api_base.clone());
        let attest = AttestationConfig {
            expected_version: "1.5.0",
            mode: AttestationMode::Permissive,
            check_status: true,
            ..Default::default()
        };
        let result = e2e_request_attested(
            &discovery,
            &client,
            &api_base,
            "test-key",
            "test-chute",
            br#"{"model":"test"}"#,
            false,
            "/v1/chat/completions",
            &attest,
        )
        .await;
        assert!(
            result.is_ok(),
            "Unverified in permissive mode should proceed"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn test_check_status_not_found_refuses_in_strict_mode() {
        let chutes_body = serde_json::json!({
            "instances": [{"instance_id": "other-instance", "verified": true}]
        });
        let (api_base, handle) = start_no_quote_with_chutes_mock(chutes_body, 200).await;
        let client = reqwest::Client::new();
        let discovery = Discovery::new(client.clone(), api_base.clone());
        let attest = AttestationConfig {
            expected_version: "1.5.0",
            mode: AttestationMode::Strict,
            check_status: true,
            ..Default::default()
        };
        let result = e2e_request_attested(
            &discovery,
            &client,
            &api_base,
            "test-key",
            "test-chute",
            br#"{"model":"test"}"#,
            false,
            "/v1/chat/completions",
            &attest,
        )
        .await;
        assert!(result.is_err(), "NotFound should refuse in strict mode");
        handle.abort();
    }

    #[tokio::test]
    async fn test_check_status_error_refuses_in_strict_mode() {
        let chutes_body = serde_json::json!({"detail": "internal error"});
        let (api_base, handle) = start_no_quote_with_chutes_mock(chutes_body, 500).await;
        let client = reqwest::Client::new();
        let discovery = Discovery::new(client.clone(), api_base.clone());
        let attest = AttestationConfig {
            expected_version: "1.5.0",
            mode: AttestationMode::Strict,
            check_status: true,
            ..Default::default()
        };
        let result = e2e_request_attested(
            &discovery,
            &client,
            &api_base,
            "test-key",
            "test-chute",
            br#"{"model":"test"}"#,
            false,
            "/v1/chat/completions",
            &attest,
        )
        .await;
        assert!(
            result.is_err(),
            "status check error should refuse in strict mode"
        );
        handle.abort();
    }

    /// `check_status` + NotFound + permissive mode → PROCEEDS (logs the warning,
    /// falls through to the no-quote permissive path). Covers the
    /// `Ok(AttestationStatus::NotFound) => Permissive` arm (handler.rs:498-500).
    #[tokio::test]
    async fn test_check_status_not_found_proceeds_in_permissive_mode() {
        let chutes_body = serde_json::json!({
            "instances": [{"instance_id": "other-instance", "verified": true}]
        });
        let (api_base, handle) = start_no_quote_with_chutes_mock(chutes_body, 200).await;
        let client = reqwest::Client::new();
        let discovery = Discovery::new(client.clone(), api_base.clone());
        let attest = AttestationConfig {
            expected_version: "1.5.0",
            mode: AttestationMode::Permissive,
            check_status: true,
            ..Default::default()
        };
        let result = e2e_request_attested(
            &discovery,
            &client,
            &api_base,
            "test-key",
            "test-chute",
            br#"{"model":"test"}"#,
            false,
            "/v1/chat/completions",
            &attest,
        )
        .await;
        assert!(
            result.is_ok(),
            "NotFound status should proceed in permissive mode: {:?}",
            result.err()
        );
        handle.abort();
    }

    /// `check_status` + status-check error + permissive mode → PROCEEDS (logs
    /// the warning, falls through). Covers the `Err(e) => Permissive` arm
    /// (handler.rs:509-510).
    #[tokio::test]
    async fn test_check_status_error_proceeds_in_permissive_mode() {
        let chutes_body = serde_json::json!({"detail": "internal error"});
        let (api_base, handle) = start_no_quote_with_chutes_mock(chutes_body, 500).await;
        let client = reqwest::Client::new();
        let discovery = Discovery::new(client.clone(), api_base.clone());
        let attest = AttestationConfig {
            expected_version: "1.5.0",
            mode: AttestationMode::Permissive,
            check_status: true,
            ..Default::default()
        };
        let result = e2e_request_attested(
            &discovery,
            &client,
            &api_base,
            "test-key",
            "test-chute",
            br#"{"model":"test"}"#,
            false,
            "/v1/chat/completions",
            &attest,
        )
        .await;
        assert!(
            result.is_ok(),
            "status check error should proceed in permissive mode: {:?}",
            result.err()
        );
        handle.abort();
    }

    // ── Integration: node_ip wiring through e2e_request_attested ───────────

    #[tokio::test]
    async fn test_node_ip_unreachable_strict_refuses() {
        // Point node_ip at a port that's definitely not listening.
        // The /e2e/instances response has no quote, and the live fetch
        // from the miner will fail → strict mode should refuse.
        let server_kp = crypto::generate_response_keypair().unwrap();
        let server_pk_b64 = discovery::base64_encode(&server_kp.public_key);
        let server_sk = std::sync::Arc::new(tokio::sync::Mutex::new(server_kp.secret_key.clone()));
        let resp_plaintext = br#"{"ok":true}"#;

        let instances_body = serde_json::json!({
            "instances": [{
                "instance_id": "inst-1",
                "e2e_pubkey": server_pk_b64,
                "nonces": ["nonce-a"],
            }],
            "nonce_expires_in": 60
        });

        let server_sk_clone = server_sk.clone();
        let app = axum::Router::new()
            .route(
                "/e2e/instances/:chute_id",
                axum::routing::get(move || {
                    let body = instances_body.clone();
                    async move { axum::Json(body) }
                }),
            )
            .route(
                "/e2e/invoke",
                axum::routing::post(move |_h: axum::http::HeaderMap, body: axum::body::Bytes| {
                    let server_sk = server_sk_clone.clone();
                    async move {
                        use axum::response::IntoResponse;
                        let sk = server_sk.lock().await;
                        let req_plaintext = crypto::decrypt_request_blob(&sk, &body).unwrap();
                        let req_json: serde_json::Value =
                            serde_json::from_slice(&req_plaintext).unwrap();
                        let resp_pk_b64 = req_json["e2e_response_pk"].as_str().unwrap();
                        let resp_pk = discovery::base64_decode(resp_pk_b64).unwrap();
                        let (mlkem_ct, shared_secret) =
                            crypto::encapsulate_against_server_pubkey(&resp_pk).unwrap();
                        let salt = &mlkem_ct[..16];
                        let resp_key =
                            crypto::hkdf_sha256(&shared_secret, salt, crypto::HKDF_INFO_RESPONSE)
                                .unwrap();
                        let compressed = crypto::gzip_compress(resp_plaintext).unwrap();
                        let nonce = crypto::random_bytes(12);
                        let ciphertext =
                            crypto::chacha20poly1305_seal(&resp_key, &nonce, &compressed, b"")
                                .unwrap();
                        let (ct_part, tag_part) = ciphertext.split_at(ciphertext.len() - 16);
                        let resp_blob =
                            crypto::build_request_blob(&mlkem_ct, &nonce, ct_part, tag_part);
                        (
                            axum::http::StatusCode::OK,
                            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                            resp_blob,
                        )
                            .into_response()
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client = reqwest::Client::new();
        let api_base = format!("http://{addr}");

        // node_ip points to 127.0.0.1:30443 which is not listening → fetch fails.
        // Strict mode should refuse because the live quote fetch failed.
        let discovery = Discovery::new(client.clone(), api_base.clone());
        let attest = AttestationConfig {
            expected_version: "1.5.0",
            mode: AttestationMode::Strict,
            node_ip: Some("127.0.0.1"),
            ..Default::default()
        };
        let result = e2e_request_attested(
            &discovery,
            &client,
            &api_base,
            "test-key",
            "test-chute",
            br#"{"model":"test"}"#,
            false,
            "/v1/chat/completions",
            &attest,
        )
        .await;
        assert!(
            result.is_err(),
            "unreachable node_ip should refuse in strict mode"
        );
        // The error should be an Attestation error (not a discovery error).
        match result.unwrap_err() {
            E2EError::Attestation(_) => {} // expected
            other => panic!("expected Attestation error for unreachable node_ip, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_node_ip_unreachable_permissive_proceeds() {
        // Same setup but permissive mode → the failed live fetch should be
        // logged and the request should proceed (no quote → permissive).
        let server_kp = crypto::generate_response_keypair().unwrap();
        let server_pk_b64 = discovery::base64_encode(&server_kp.public_key);
        let server_sk = std::sync::Arc::new(tokio::sync::Mutex::new(server_kp.secret_key.clone()));
        let resp_plaintext = br#"{"ok":true}"#;

        let instances_body = serde_json::json!({
            "instances": [{
                "instance_id": "inst-1",
                "e2e_pubkey": server_pk_b64,
                "nonces": ["nonce-a"],
            }],
            "nonce_expires_in": 60
        });

        let server_sk_clone = server_sk.clone();
        let app = axum::Router::new()
            .route(
                "/e2e/instances/:chute_id",
                axum::routing::get(move || {
                    let body = instances_body.clone();
                    async move { axum::Json(body) }
                }),
            )
            .route(
                "/e2e/invoke",
                axum::routing::post(move |_h: axum::http::HeaderMap, body: axum::body::Bytes| {
                    let server_sk = server_sk_clone.clone();
                    async move {
                        use axum::response::IntoResponse;
                        let sk = server_sk.lock().await;
                        let req_plaintext = crypto::decrypt_request_blob(&sk, &body).unwrap();
                        let req_json: serde_json::Value =
                            serde_json::from_slice(&req_plaintext).unwrap();
                        let resp_pk_b64 = req_json["e2e_response_pk"].as_str().unwrap();
                        let resp_pk = discovery::base64_decode(resp_pk_b64).unwrap();
                        let (mlkem_ct, shared_secret) =
                            crypto::encapsulate_against_server_pubkey(&resp_pk).unwrap();
                        let salt = &mlkem_ct[..16];
                        let resp_key =
                            crypto::hkdf_sha256(&shared_secret, salt, crypto::HKDF_INFO_RESPONSE)
                                .unwrap();
                        let compressed = crypto::gzip_compress(resp_plaintext).unwrap();
                        let nonce = crypto::random_bytes(12);
                        let ciphertext =
                            crypto::chacha20poly1305_seal(&resp_key, &nonce, &compressed, b"")
                                .unwrap();
                        let (ct_part, tag_part) = ciphertext.split_at(ciphertext.len() - 16);
                        let resp_blob =
                            crypto::build_request_blob(&mlkem_ct, &nonce, ct_part, tag_part);
                        (
                            axum::http::StatusCode::OK,
                            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                            resp_blob,
                        )
                            .into_response()
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client = reqwest::Client::new();
        let api_base = format!("http://{addr}");

        let discovery = Discovery::new(client.clone(), api_base.clone());
        let attest = AttestationConfig {
            expected_version: "1.5.0",
            mode: AttestationMode::Permissive,
            node_ip: Some("127.0.0.1"),
            ..Default::default()
        };
        let result = e2e_request_attested(
            &discovery,
            &client,
            &api_base,
            "test-key",
            "test-chute",
            br#"{"model":"test"}"#,
            false,
            "/v1/chat/completions",
            &attest,
        )
        .await;
        assert!(
            result.is_ok(),
            "unreachable node_ip in permissive mode should proceed"
        );
    }

    // ── Integration: use_evidence wiring through e2e_request_attested ──────
    //
    // The flagship v3 path: a user API client with no node IP fetches a live
    // TDX quote + TEE cert from the user-reachable evidence endpoint
    // (`GET /instances/{id}/evidence`), and the handler verifies the quote's
    // cert-hash half against `SHA-256(SPKI-der(cert))` (skip_nonce_binding),
    // then proceeds to encrypt. These tests use the REAL captured quote+cert
    // fixtures so the cert-binding invariant is exercised end-to-end offline.

    /// Helper: start a mock server that serves /e2e/instances (NO quote), the
    /// evidence endpoint `/instances/:id/evidence`, and /e2e/invoke (which
    /// decrypts the request and re-encrypts a response). Returns the base URL.
    async fn start_evidence_mock(
        evidence_body: serde_json::Value,
        evidence_status: u16,
    ) -> (String, tokio::task::JoinHandle<()>) {
        use axum::{
            body::Bytes,
            http::HeaderMap,
            routing::{get, post},
            Json, Router,
        };

        let server_kp = crypto::generate_response_keypair().unwrap();
        let server_pk_b64 = discovery::base64_encode(&server_kp.public_key);
        let server_sk = std::sync::Arc::new(tokio::sync::Mutex::new(server_kp.secret_key.clone()));
        let resp_plaintext = br#"{"ok":true}"#.to_vec();

        // /e2e/instances returns an instance with NO quote (the evidence path
        // is the only quote source here).
        let instances_body = serde_json::json!({
            "instances": [{
                "instance_id": "inst-evidence-1",
                "e2e_pubkey": server_pk_b64,
                "nonces": ["nonce-a"],
            }],
            "nonce_expires_in": 60
        });

        let server_sk_clone = server_sk.clone();
        let evidence_body_clone = evidence_body.clone();
        let app = Router::new()
            .route(
                "/e2e/instances/:chute_id",
                get(move || {
                    let body = instances_body.clone();
                    async move { Json(body) }
                }),
            )
            .route(
                "/instances/:instance_id/evidence",
                get(move || async move {
                    use axum::http::StatusCode;
                    use axum::response::IntoResponse;
                    let code =
                        StatusCode::from_u16(evidence_status).unwrap_or(StatusCode::OK);
                    (code, evidence_body_clone.to_string()).into_response()
                }),
            )
            .route(
                "/e2e/invoke",
                post(move |_headers: HeaderMap, body: Bytes| {
                    let server_sk = server_sk_clone.clone();
                    async move {
                        use axum::response::IntoResponse;
                        let sk = server_sk.lock().await;
                        let req_plaintext = crypto::decrypt_request_blob(&sk, &body).unwrap();
                        let req_json: serde_json::Value =
                            serde_json::from_slice(&req_plaintext).unwrap();
                        let resp_pk_b64 = req_json["e2e_response_pk"].as_str().unwrap();
                        let resp_pk = discovery::base64_decode(resp_pk_b64).unwrap();
                        let (mlkem_ct, shared_secret) =
                            crypto::encapsulate_against_server_pubkey(&resp_pk).unwrap();
                        let salt = &mlkem_ct[..16];
                        let resp_key =
                            crypto::hkdf_sha256(&shared_secret, salt, crypto::HKDF_INFO_RESPONSE)
                                .unwrap();
                        let compressed = crypto::gzip_compress(&resp_plaintext).unwrap();
                        let nonce = crypto::random_bytes(12);
                        let ciphertext =
                            crypto::chacha20poly1305_seal(&resp_key, &nonce, &compressed, b"")
                                .unwrap();
                        let (ct_part, tag_part) = ciphertext.split_at(ciphertext.len() - 16);
                        let resp_blob =
                            crypto::build_request_blob(&mlkem_ct, &nonce, ct_part, tag_part);
                        (
                            axum::http::StatusCode::OK,
                            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                            resp_blob,
                        )
                            .into_response()
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        (format!("http://{addr}"), handle)
    }

    /// The real captured evidence response (quote + cert) from a GLM-5.1-TEE
    /// miner. The quote's REPORTDATA cert-hash half equals
    /// `SHA-256(SPKI-der(cert))`, so the evidence key-binding invariant holds.
    const EVIDENCE_RESPONSE: &str =
        include_str!("../../tests/fixtures/evidence_response.json");

    /// `use_evidence` + valid real quote/cert → strict mode PROCEEDS (the
    /// evidence path is cryptographic: cert-hash binding passes). This is the
    /// end-to-end proof that the user-reachable evidence path works offline.
    #[tokio::test]
    async fn test_use_evidence_valid_quote_proceeds_in_strict_mode() {
        let evidence_body: serde_json::Value = serde_json::from_str(EVIDENCE_RESPONSE).unwrap();
        let (api_base, handle) = start_evidence_mock(evidence_body, 200).await;
        let client = reqwest::Client::new();
        let discovery = Discovery::new(client.clone(), api_base.clone());

        // The real quote is a 1.4.1 image; pin to that version. The cert-hash
        // binding is checked via the evidence cert SPKI (skip_nonce_binding is
        // set automatically when the cert is extracted).
        let attest = AttestationConfig {
            expected_version: "1.4.1",
            mode: AttestationMode::Strict,
            use_evidence: true,
            ..Default::default()
        };
        let result = e2e_request_attested(
            &discovery,
            &client,
            &api_base,
            "test-key",
            "test-chute",
            br#"{"model":"test"}"#,
            false,
            "/v1/chat/completions",
            &attest,
        )
        .await;
        assert!(
            result.is_ok(),
            "use_evidence with a valid real quote+cert should proceed in strict mode: {:?}",
            result.err()
        );
        handle.abort();
    }

    /// `use_evidence` + evidence endpoint error (404) → strict mode REFUSES.
    /// Confirms the error path of the evidence fetch is wired into the gate.
    #[tokio::test]
    async fn test_use_evidence_fetch_error_refuses_in_strict_mode() {
        let evidence_body = serde_json::json!({"detail": "evidence not found"});
        let (api_base, handle) = start_evidence_mock(evidence_body, 404).await;
        let client = reqwest::Client::new();
        let discovery = Discovery::new(client.clone(), api_base.clone());
        let attest = AttestationConfig {
            expected_version: "1.4.1",
            mode: AttestationMode::Strict,
            use_evidence: true,
            ..Default::default()
        };
        let result = e2e_request_attested(
            &discovery,
            &client,
            &api_base,
            "test-key",
            "test-chute",
            br#"{"model":"test"}"#,
            false,
            "/v1/chat/completions",
            &attest,
        )
        .await;
        assert!(
            result.is_err(),
            "use_evidence with a failed evidence fetch should refuse in strict mode"
        );
        match result.unwrap_err() {
            E2EError::Attestation(_) => {} // expected
            other => panic!("expected Attestation error for failed evidence fetch, got {other:?}"),
        }
        handle.abort();
    }

    /// `use_evidence` + evidence endpoint error → permissive mode PROCEEDS
    /// (logs the failed fetch and falls through to the no-quote permissive path).
    #[tokio::test]
    async fn test_use_evidence_fetch_error_proceeds_in_permissive_mode() {
        let evidence_body = serde_json::json!({"detail": "evidence not found"});
        let (api_base, handle) = start_evidence_mock(evidence_body, 404).await;
        let client = reqwest::Client::new();
        let discovery = Discovery::new(client.clone(), api_base.clone());
        let attest = AttestationConfig {
            expected_version: "1.4.1",
            mode: AttestationMode::Permissive,
            use_evidence: true,
            ..Default::default()
        };
        let result = e2e_request_attested(
            &discovery,
            &client,
            &api_base,
            "test-key",
            "test-chute",
            br#"{"model":"test"}"#,
            false,
            "/v1/chat/completions",
            &attest,
        )
        .await;
        assert!(
            result.is_ok(),
            "use_evidence with a failed evidence fetch should proceed in permissive mode"
        );
        handle.abort();
    }

    /// `use_evidence` + valid quote but EMPTY certificate → the handler skips
    /// SPKI extraction and falls back to E2E-pubkey key binding. In strict mode
    /// this MUST fail: the quote's REPORTDATA cert-hash half was bound to the
    /// TEE attestation-service cert, not the E2E ML-KEM key, so `key_ok` is
    /// false and `should_proceed` refuses. Covers the empty-cert branch
    /// (handler.rs `if !ev.certificate_b64.is_empty()`) and the fallback to
    /// `(&server_pubkey[..], false)` — the non-evidence key-binding path.
    #[tokio::test]
    async fn test_use_evidence_empty_cert_refuses_in_strict_mode() {
        // Same real quote as the valid-cert test, but with the `certificate`
        // field stripped out so the handler can't extract the SPKI.
        let mut evidence_body: serde_json::Value =
            serde_json::from_str(EVIDENCE_RESPONSE).unwrap();
        evidence_body["certificate"] = serde_json::Value::String(String::new());
        let (api_base, handle) = start_evidence_mock(evidence_body, 200).await;
        let client = reqwest::Client::new();
        let discovery = Discovery::new(client.clone(), api_base.clone());

        let attest = AttestationConfig {
            expected_version: "1.4.1",
            mode: AttestationMode::Strict,
            use_evidence: true,
            ..Default::default()
        };
        let result = e2e_request_attested(
            &discovery,
            &client,
            &api_base,
            "test-key",
            "test-chute",
            br#"{"model":"test"}"#,
            false,
            "/v1/chat/completions",
            &attest,
        )
        .await;
        assert!(
            result.is_err(),
            "use_evidence with an empty cert should fail key binding in strict mode \
             (quote binds TEE cert, not E2E key): {:?}",
            result.err()
        );
        match result.unwrap_err() {
            E2EError::Attestation(_) => {} // expected — key binding failed
            other => panic!(
                "expected Attestation error for empty-cert key-binding failure, got {other:?}"
            ),
        }
        handle.abort();
    }

    /// `use_evidence` + valid quote but MALFORMED certificate (non-empty, not
    /// valid base64 DER) → `extract_spki_der` returns `Err`, the handler logs a
    /// warning and falls back to E2E-pubkey key binding. In strict mode this
    /// MUST fail for the same reason as the empty-cert case: the quote's
    /// REPORTDATA cert-hash half was bound to the TEE cert, not the E2E key.
    /// Covers the `Err(e) => log::warn!(...)` branch (handler.rs:391) — the
    /// malformed-cert fallback path.
    #[tokio::test]
    async fn test_use_evidence_malformed_cert_refuses_in_strict_mode() {
        // Same real quote, but the certificate is non-empty garbage that
        // fails base64 decoding inside extract_spki_der.
        let mut evidence_body: serde_json::Value =
            serde_json::from_str(EVIDENCE_RESPONSE).unwrap();
        evidence_body["certificate"] =
            serde_json::Value::String("not-a-valid-base64-cert!!!".to_string());
        let (api_base, handle) = start_evidence_mock(evidence_body, 200).await;
        let client = reqwest::Client::new();
        let discovery = Discovery::new(client.clone(), api_base.clone());

        let attest = AttestationConfig {
            expected_version: "1.4.1",
            mode: AttestationMode::Strict,
            use_evidence: true,
            ..Default::default()
        };
        let result = e2e_request_attested(
            &discovery,
            &client,
            &api_base,
            "test-key",
            "test-chute",
            br#"{"model":"test"}"#,
            false,
            "/v1/chat/completions",
            &attest,
        )
        .await;
        assert!(
            result.is_err(),
            "use_evidence with a malformed cert should fail key binding in strict mode \
             (SPKI extract fails → fallback to E2E key, quote binds TEE cert): {:?}",
            result.err()
        );
        match result.unwrap_err() {
            E2EError::Attestation(_) => {} // expected — key binding failed
            other => panic!(
                "expected Attestation error for malformed-cert key-binding failure, got {other:?}"
            ),
        }
        handle.abort();
    }

    /// `use_evidence` + valid quote+cert + `collateral_url` pointing at a dead
    /// port → PCS fetch fails → strict mode REFUSES. Covers the error arm of
    /// the collateral fetch (handler.rs:436-441): the `Err(e) => log::warn` +
    /// `if attest.mode == Strict { return Err(...) }` branch.
    #[tokio::test]
    async fn test_use_evidence_collateral_error_refuses_in_strict_mode() {
        let evidence_body: serde_json::Value =
            serde_json::from_str(EVIDENCE_RESPONSE).unwrap();
        let (api_base, handle) = start_evidence_mock(evidence_body, 200).await;
        let client = reqwest::Client::new();
        let discovery = Discovery::new(client.clone(), api_base.clone());
        let attest = AttestationConfig {
            expected_version: "1.4.1",
            mode: AttestationMode::Strict,
            use_evidence: true,
            collateral_url: Some("http://127.0.0.1:1"),
            ..Default::default()
        };
        let result = e2e_request_attested(
            &discovery,
            &client,
            &api_base,
            "test-key",
            "test-chute",
            br#"{"model":"test"}"#,
            false,
            "/v1/chat/completions",
            &attest,
        )
        .await;
        assert!(
            result.is_err(),
            "collateral fetch failure should refuse in strict mode: {:?}",
            result.err()
        );
        match result.unwrap_err() {
            E2EError::Attestation(_) => {} // expected — collateral fetch failed
            other => panic!("expected Attestation error, got {other:?}"),
        }
        handle.abort();
    }

    /// `use_evidence` + valid quote+cert + `collateral_url` pointing at a mock
    /// PCS that serves the captured `live_tdx_collateral.json` → the PCS fetch
    /// SUCCEEDS and the request proceeds. Covers the collateral-fetch *success*
    /// arm (handler.rs:432-433: `Ok(c) => { log::info!(...); collateral = Some(c) }`)
    /// and the `now_secs` branch (handler.rs:446-449: `if collateral.is_some()`
    /// → `SystemTime::now()`). Permissive mode so a DCAP signature mismatch on
    /// the mock collateral doesn't refuse the request — the goal is exercising
    /// the success path, not the DCAP verdict.
    #[tokio::test]
    async fn test_use_evidence_collateral_success_proceeds_in_permissive_mode() {
        let evidence_body: serde_json::Value =
            serde_json::from_str(EVIDENCE_RESPONSE).unwrap();
        let (api_base, handle) = start_evidence_mock(evidence_body, 200).await;
        let (pcs_port, pcs_handle) = crate::e2ee::attestation::start_mock_pcs_server().await;
        // Bind the URL to a local so the `&str` outlives the `attest` struct
        // (a bare `&format!(...)` temporary would be dropped at the end of the
        // `let` statement, leaving `collateral_url` dangling).
        let pcs_url = format!("http://127.0.0.1:{pcs_port}");
        let client = reqwest::Client::new();
        let discovery = Discovery::new(client.clone(), api_base.clone());
        let attest = AttestationConfig {
            expected_version: "1.4.1",
            mode: AttestationMode::Permissive,
            use_evidence: true,
            collateral_url: Some(&pcs_url),
            ..Default::default()
        };
        let result = e2e_request_attested(
            &discovery,
            &client,
            &api_base,
            "test-key",
            "test-chute",
            br#"{"model":"test"}"#,
            false,
            "/v1/chat/completions",
            &attest,
        )
        .await;
        assert!(
            result.is_ok(),
            "collateral fetch success should proceed in permissive mode: {:?}",
            result.err()
        );
        handle.abort();
        pcs_handle.abort();
    }

    /// Same as above but permissive mode → PROCEEDS (logs the collateral fetch
    /// warning, falls through). Covers the permissive branch of the collateral
    /// fetch error path (handler.rs:436-441 → fall-through).
    #[tokio::test]
    async fn test_use_evidence_collateral_error_proceeds_in_permissive_mode() {
        let evidence_body: serde_json::Value =
            serde_json::from_str(EVIDENCE_RESPONSE).unwrap();
        let (api_base, handle) = start_evidence_mock(evidence_body, 200).await;
        let client = reqwest::Client::new();
        let discovery = Discovery::new(client.clone(), api_base.clone());
        let attest = AttestationConfig {
            expected_version: "1.4.1",
            mode: AttestationMode::Permissive,
            use_evidence: true,
            collateral_url: Some("http://127.0.0.1:1"),
            ..Default::default()
        };
        let result = e2e_request_attested(
            &discovery,
            &client,
            &api_base,
            "test-key",
            "test-chute",
            br#"{"model":"test"}"#,
            false,
            "/v1/chat/completions",
            &attest,
        )
        .await;
        assert!(
            result.is_ok(),
            "collateral fetch failure should proceed in permissive mode: {:?}",
            result.err()
        );
        handle.abort();
    }

    // ── Error-shape / passthrough coverage ────────────────────────────────
    //
    // These close the remaining reachable production lines: the `Display`
    // arms, the `From` conversions, and the non-403 / non-success passthrough
    // branches in `e2e_request` / `e2e_request_attested`.

    /// Covers every arm of `impl Display for E2EError` (handler.rs:28-34).
    #[tokio::test]
    async fn test_e2eerror_display_all_variants() {
        let discovery_err = E2EError::Discovery(DiscoveryError::NoNonces);
        assert!(format!("{discovery_err}").starts_with("discovery:"));
        let crypto_err = E2EError::Crypto(CryptoError::Keygen);
        assert!(format!("{crypto_err}").starts_with("crypto:"));
        // A real reqwest::Error from a connection failure.
        let client = reqwest::Client::new();
        let http_err = client.get("http://127.0.0.1:1").send().await.unwrap_err();
        let http_e2e = E2EError::Http(http_err);
        assert!(format!("{http_e2e}").starts_with("http:"));
        let status_err = E2EError::Status(403, "nope".into());
        assert!(format!("{status_err}").starts_with("status 403:"));
        let parse_err = E2EError::Parse("bad".into());
        assert!(format!("{parse_err}").starts_with("parse:"));
        let no_nonce = E2EError::NoNonce;
        assert_eq!(format!("{no_nonce}"), "no nonce available");
        let attest_err = E2EError::Attestation(AttestationError::QuoteTooShort { len: 0 });
        assert!(format!("{attest_err}").starts_with("attestation:"));
    }

    /// Covers `From<DiscoveryError>` (handler.rs:42-44) and
    /// `From<CryptoError>` (handler.rs:47-49).
    #[test]
    fn test_e2eerror_from_conversions() {
        let d: E2EError = DiscoveryError::NoNonces.into();
        match d {
            E2EError::Discovery(_) => {}
            other => panic!("expected Discovery, got {other:?}"),
        }
        let c: E2EError = CryptoError::Keygen.into();
        match c {
            E2EError::Crypto(_) => {}
            other => panic!("expected Crypto, got {other:?}"),
        }
    }

    /// A non-JSON payload makes `inject_response_pk` fail with `Parse`, which
    /// `e2e_request_once` returns and `e2e_request` passes through via the
    /// `Err(e) => Err(e)` arm (handler.rs:187). Covers L187 + L211.
    #[tokio::test]
    async fn test_e2e_request_bad_payload_passthrough() {
        use axum::{routing::get, Json, Router};
        let server_kp = crypto::generate_response_keypair().unwrap();
        let server_pk_b64 = discovery::base64_encode(&server_kp.public_key);
        let resp_body = serde_json::json!({
            "instances": [{
                "instance_id": "inst-1",
                "e2e_pubkey": server_pk_b64,
                "nonces": ["nonce-a"],
            }],
            "nonce_expires_in": 60
        });
        let app = Router::new().route(
            "/e2e/instances/:chute_id",
            get(move || {
                let body = resp_body.clone();
                async move { Json(body) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client = reqwest::Client::new();
        let api_base = format!("http://{addr}");
        let discovery = Discovery::new(client.clone(), api_base.clone());
        // Valid UTF-8 but not JSON → inject_response_pk Parse error.
        let payload = b"not valid json at all";
        let result = e2e_request(
            &discovery,
            &client,
            &api_base,
            "key",
            "chute",
            payload,
            false,
            "/v1/chat/completions",
        )
        .await;
        match result {
            Err(E2EError::Parse(_)) => {} // expected
            other => panic!("expected Parse error, got {other:?}"),
        }
    }

    /// Same as above but through `e2e_request_attested`: permissive mode with
    /// no quote proceeds to the inject step, where a bad payload yields a
    /// `Parse` error (handler.rs:533).
    #[tokio::test]
    async fn test_attested_request_bad_payload_parse_error() {
        use axum::{routing::get, Json, Router};
        let server_kp = crypto::generate_response_keypair().unwrap();
        let server_pk_b64 = discovery::base64_encode(&server_kp.public_key);
        let resp_body = serde_json::json!({
            "instances": [{
                "instance_id": "inst-1",
                "e2e_pubkey": server_pk_b64,
                "nonces": ["nonce-a"],
            }],
            "nonce_expires_in": 60
        });
        let app = Router::new().route(
            "/e2e/instances/:chute_id",
            get(move || {
                let body = resp_body.clone();
                async move { Json(body) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client = reqwest::Client::new();
        let api_base = format!("http://{addr}");
        let discovery = Discovery::new(client.clone(), api_base.clone());
        let attest = AttestationConfig {
            expected_version: "1.5.0",
            mode: AttestationMode::Permissive,
            ..Default::default()
        };
        let payload = b"not valid json at all";
        let result = e2e_request_attested(
            &discovery,
            &client,
            &api_base,
            "key",
            "chute",
            payload,
            false,
            "/v1/chat/completions",
            &attest,
        )
        .await;
        match result {
            Err(E2EError::Parse(_)) => {} // expected
            other => panic!("expected Parse error, got {other:?}"),
        }
    }

    /// Attestation passes (permissive, no quote) but the invoke endpoint
    /// returns a non-2xx status → `e2e_request_attested` surfaces it as
    /// `Status` (handler.rs:554-555).
    #[tokio::test]
    async fn test_attested_request_invoke_non_success_status() {
        use axum::{
            body::Bytes,
            http::HeaderMap,
            routing::{get, post},
            Json, Router,
        };
        let server_kp = crypto::generate_response_keypair().unwrap();
        let server_pk_b64 = discovery::base64_encode(&server_kp.public_key);
        let resp_body = serde_json::json!({
            "instances": [{
                "instance_id": "inst-1",
                "e2e_pubkey": server_pk_b64,
                "nonces": ["nonce-a"],
            }],
            "nonce_expires_in": 60
        });
        let app = Router::new()
            .route(
                "/e2e/instances/:chute_id",
                get(move || {
                    let body = resp_body.clone();
                    async move { Json(body) }
                }),
            )
            .route(
                "/e2e/invoke",
                post(move |_h: HeaderMap, _body: Bytes| async move {
                    use axum::response::IntoResponse;
                    (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response()
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client = reqwest::Client::new();
        let api_base = format!("http://{addr}");
        let discovery = Discovery::new(client.clone(), api_base.clone());
        let attest = AttestationConfig {
            expected_version: "1.5.0",
            mode: AttestationMode::Permissive,
            ..Default::default()
        };
        let payload = br#"{"model":"test"}"#;
        let result = e2e_request_attested(
            &discovery,
            &client,
            &api_base,
            "key",
            "chute",
            payload,
            false,
            "/v1/chat/completions",
            &attest,
        )
        .await;
        match result {
            Err(E2EError::Status(500, _)) => {} // expected
            other => panic!("expected Status(500) error, got {other:?}"),
        }
    }
}
