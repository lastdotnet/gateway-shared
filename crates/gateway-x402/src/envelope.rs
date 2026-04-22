//! R-5 — signed envelope for x402 gateway responses.
//!
//! Without this layer, the BE trusts the gateway's HTTP status alone
//! (`Ok(resp.status().is_success())`) — a compromised gateway or MITM on
//! the compose bridge can return `200 OK` with any body and the BE treats
//! the payment as settled / the API key as valid.
//!
//! The envelope is an HMAC-SHA256 MAC over the canonical JSON
//! serialisation of every field except `sig`, using a shared secret
//! (`X402_GATEWAY_VERIFY_SECRET`). Verification is constant-time
//! (`Mac::verify_slice`) and rejects expired envelopes.

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Signed gateway response envelope. The gateway populates the fields
/// and produces `sig`; the BE re-computes the MAC over the canonical
/// serialisation (all fields except `sig`) and compares constant-time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayEnvelope {
    /// Did the gateway validate the request (key valid / payment settled)?
    pub ok: bool,
    /// Anti-replay nonce — 16+ random bytes hex-encoded. The BE may
    /// de-dupe nonces in a short sliding window to harden against replay
    /// within the `expires_at` window.
    pub nonce: String,
    /// Pay-to address the gateway asserts the payment went to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pay_to: Option<String>,
    /// Payment amount (atomic units, stringified to preserve precision).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    /// Scheme (`permit2`, `exact`, `eip3009`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    /// Payer address (populated on settle).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    /// Network identifier (e.g. `eip155:999`, `hyperliquid:mainnet`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// Envelope expiry — UNIX seconds. Reject if `now > expires_at`.
    pub expires_at: u64,
    /// Hex-encoded HMAC-SHA256 of the canonical serialisation of all
    /// above fields.
    pub sig: String,
}

fn canonical(env: &GatewayEnvelope) -> Vec<u8> {
    // Build a stable sorted-key JSON blob of all fields EXCEPT `sig`.
    // `serde_json::Map` preserves insertion order — we insert in a fixed
    // order matching the struct declaration so producer and verifier
    // agree byte-for-byte.
    let mut map = serde_json::Map::new();
    map.insert("ok".into(), serde_json::Value::Bool(env.ok));
    map.insert("nonce".into(), serde_json::Value::String(env.nonce.clone()));
    if let Some(v) = &env.pay_to {
        map.insert("pay_to".into(), serde_json::Value::String(v.clone()));
    }
    if let Some(v) = &env.amount {
        map.insert("amount".into(), serde_json::Value::String(v.clone()));
    }
    if let Some(v) = &env.scheme {
        map.insert("scheme".into(), serde_json::Value::String(v.clone()));
    }
    if let Some(v) = &env.payer {
        map.insert("payer".into(), serde_json::Value::String(v.clone()));
    }
    if let Some(v) = &env.network {
        map.insert("network".into(), serde_json::Value::String(v.clone()));
    }
    map.insert(
        "expires_at".into(),
        serde_json::Value::Number(env.expires_at.into()),
    );
    serde_json::to_vec(&map).expect("serialise canonical envelope")
}

#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    #[error("gateway envelope malformed")]
    Malformed,
    #[error("gateway envelope signature invalid")]
    InvalidSignature,
    #[error("gateway envelope expired")]
    Expired,
}

/// Sign an envelope in place. Producer side.
pub fn sign_gateway_envelope(envelope: &mut GatewayEnvelope, secret: &[u8]) {
    let bytes = canonical(envelope);
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac key length");
    mac.update(&bytes);
    let tag = mac.finalize().into_bytes();
    envelope.sig = hex::encode(tag);
}

/// Verify an envelope's HMAC and expiry. Constant-time compare via
/// `Mac::verify_slice`.
pub fn verify_gateway_hmac(
    envelope: &GatewayEnvelope,
    secret: &[u8],
) -> Result<(), EnvelopeError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if envelope.expires_at < now {
        return Err(EnvelopeError::Expired);
    }
    let tag = hex::decode(&envelope.sig).map_err(|_| EnvelopeError::InvalidSignature)?;
    let bytes = canonical(envelope);
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac key length");
    mac.update(&bytes);
    mac.verify_slice(&tag)
        .map_err(|_| EnvelopeError::InvalidSignature)
}

/// Parse a gateway response body and verify its HMAC in one step.
pub fn parse_and_verify(body: &[u8], secret: &[u8]) -> Result<GatewayEnvelope, EnvelopeError> {
    let envelope: GatewayEnvelope =
        serde_json::from_slice(body).map_err(|_| EnvelopeError::Malformed)?;
    verify_gateway_hmac(&envelope, secret)?;
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_envelope() -> GatewayEnvelope {
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60;
        GatewayEnvelope {
            ok: true,
            nonce: "0102030405060708".into(),
            pay_to: Some("0xpay".into()),
            amount: Some("1000".into()),
            scheme: Some("permit2".into()),
            payer: Some("0xabc".into()),
            network: Some("eip155:999".into()),
            expires_at,
            sig: String::new(),
        }
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let mut env = fresh_envelope();
        sign_gateway_envelope(&mut env, b"shared-secret");
        verify_gateway_hmac(&env, b"shared-secret").expect("valid hmac");
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let mut env = fresh_envelope();
        sign_gateway_envelope(&mut env, b"right-secret");
        let err = verify_gateway_hmac(&env, b"wrong-secret").unwrap_err();
        matches!(err, EnvelopeError::InvalidSignature);
    }

    #[test]
    fn verify_rejects_tampered_field() {
        let mut env = fresh_envelope();
        sign_gateway_envelope(&mut env, b"secret");
        env.payer = Some("0xattacker".into());
        let err = verify_gateway_hmac(&env, b"secret").unwrap_err();
        matches!(err, EnvelopeError::InvalidSignature);
    }

    #[test]
    fn verify_rejects_expired() {
        let mut env = fresh_envelope();
        env.expires_at = 1; // very old
        sign_gateway_envelope(&mut env, b"secret");
        let err = verify_gateway_hmac(&env, b"secret").unwrap_err();
        matches!(err, EnvelopeError::Expired);
    }

    #[test]
    fn parse_and_verify_rejects_malformed_body() {
        let err = parse_and_verify(b"not-json", b"secret").unwrap_err();
        matches!(err, EnvelopeError::Malformed);
    }
}
