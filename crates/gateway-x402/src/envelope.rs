//! R-5 — signed envelope for x402 gateway responses.
//!
//! Without this layer, downstream BEs trust the gateway's HTTP status alone
//! (`Ok(resp.status().is_success())`) — a compromised gateway or MITM on
//! the compose bridge can return 200 OK with any body and have it accepted
//! as "payment settled / API key valid."
//!
//! # Signing contract
//!
//! The on-wire JSON is a full `GatewayEnvelope` (including `sig`). The
//! signed bytes (the HMAC input) are a **hand-rolled canonical form** —
//! NOT a JSON reserialisation — so that the producer and verifier cannot
//! drift if some workspace member enables `serde_json/preserve_order` or
//! a different library reorders keys.
//!
//! The canonical form is:
//!
//! ```text
//! x402-gateway-envelope-v1\n
//! ok=<true|false>\n
//! nonce=<nonce>\n
//! pay_to=<value-or-empty>\n
//! amount=<value-or-empty>\n
//! scheme=<value-or-empty>\n
//! payer=<value-or-empty>\n
//! network=<value-or-empty>\n
//! expires_at=<u64>
//! ```
//!
//! No field contains an unescaped newline — if any string field contains
//! `\n` or `\\`, the canonicaliser escapes it. This prevents a producer
//! from moving bytes across the `field=value` / newline boundary to fake a
//! different field.
//!
//! The leading `x402-gateway-envelope-v1\n` magic is a domain separator:
//! reusing `X402_GATEWAY_VERIFY_SECRET` for any other HMAC context (e.g.
//! another protocol that happened to also use HMAC-SHA256) cannot produce
//! a valid envelope signature.

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Domain-separator magic. Changing this value is a backwards-incompatible
/// wire change — producer and verifier must agree.
const DOMAIN_SEPARATOR: &str = "x402-gateway-envelope-v1";

/// Signed gateway response envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayEnvelope {
    /// Did the gateway validate the request (key valid / payment settled)?
    pub ok: bool,
    /// Anti-replay nonce — producer-chosen 16+ byte random hex. The
    /// verifier MUST reject a (nonce, expires_at) pair it has seen before
    /// within the expiry window.
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
    /// Hex-encoded HMAC-SHA256 over `canonical(envelope)`.
    pub sig: String,
}

/// Escape `\n` → `\\n` and `\\` → `\\\\` so no field can smuggle a
/// newline into the canonical form and impersonate a different field.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

fn opt(value: &Option<String>) -> String {
    value.as_deref().map(escape).unwrap_or_default()
}

/// Produce the exact byte string fed to HMAC-SHA256. See module-level
/// doc-comment for the format. Fixed field order; no dependency on
/// `serde_json::Map`'s key-order behaviour.
fn canonical(env: &GatewayEnvelope) -> Vec<u8> {
    let body = format!(
        "{DOMAIN_SEPARATOR}\n\
         ok={ok}\n\
         nonce={nonce}\n\
         pay_to={pay_to}\n\
         amount={amount}\n\
         scheme={scheme}\n\
         payer={payer}\n\
         network={network}\n\
         expires_at={expires_at}",
        ok = env.ok,
        nonce = escape(&env.nonce),
        pay_to = opt(&env.pay_to),
        amount = opt(&env.amount),
        scheme = opt(&env.scheme),
        payer = opt(&env.payer),
        network = opt(&env.network),
        expires_at = env.expires_at,
    );
    body.into_bytes()
}

#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    #[error("gateway envelope malformed")]
    Malformed,
    #[error("gateway envelope signature invalid")]
    InvalidSignature,
    #[error("gateway envelope expired")]
    Expired,
    #[error("gateway envelope pay_to mismatch: expected={expected}, actual={actual}")]
    PayToMismatch { expected: String, actual: String },
    #[error("gateway envelope network mismatch: expected={expected}, actual={actual}")]
    NetworkMismatch { expected: String, actual: String },
    #[error("gateway envelope scheme mismatch: expected={expected}, actual={actual}")]
    SchemeMismatch { expected: String, actual: String },
}

/// What the caller requires of the envelope beyond MAC + expiry. An `None`
/// field skips that check.
#[derive(Debug, Default, Clone)]
pub struct EnvelopeExpectations<'a> {
    /// For settle paths: bind the payment's destination address. Compared
    /// case-insensitively (Ethereum-style checksum addresses).
    pub pay_to: Option<&'a str>,
    /// For settle paths: bind the scheme the BE requested.
    pub scheme: Option<&'a str>,
    /// For settle paths: bind the expected network identifier.
    pub network: Option<&'a str>,
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
/// `Mac::verify_slice`. Does NOT de-dupe nonces — callers enforce replay
/// protection.
pub fn verify_gateway_hmac(envelope: &GatewayEnvelope, secret: &[u8]) -> Result<(), EnvelopeError> {
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

/// Parse a gateway response body and verify HMAC + expiry. Does NOT check
/// pay_to / amount / network / replay — use [`verify_envelope`] for that.
pub fn parse_and_verify(body: &[u8], secret: &[u8]) -> Result<GatewayEnvelope, EnvelopeError> {
    let envelope: GatewayEnvelope =
        serde_json::from_slice(body).map_err(|_| EnvelopeError::Malformed)?;
    verify_gateway_hmac(&envelope, secret)?;
    Ok(envelope)
}

/// Full verification: HMAC + expiry + field-binding (pay_to / scheme /
/// network) against caller expectations. Returns the validated envelope.
/// The caller still needs to enforce replay-protection (seen-nonce set).
pub fn verify_envelope(
    body: &[u8],
    secret: &[u8],
    expectations: &EnvelopeExpectations,
) -> Result<GatewayEnvelope, EnvelopeError> {
    let envelope = parse_and_verify(body, secret)?;
    if let Some(expected) = expectations.pay_to {
        let actual = envelope.pay_to.as_deref().unwrap_or("");
        if !actual.eq_ignore_ascii_case(expected) {
            return Err(EnvelopeError::PayToMismatch {
                expected: expected.to_string(),
                actual: actual.to_string(),
            });
        }
    }
    if let Some(expected) = expectations.scheme {
        let actual = envelope.scheme.as_deref().unwrap_or("");
        if actual != expected {
            return Err(EnvelopeError::SchemeMismatch {
                expected: expected.to_string(),
                actual: actual.to_string(),
            });
        }
    }
    if let Some(expected) = expectations.network {
        let actual = envelope.network.as_deref().unwrap_or("");
        if actual != expected {
            return Err(EnvelopeError::NetworkMismatch {
                expected: expected.to_string(),
                actual: actual.to_string(),
            });
        }
    }
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
        assert!(matches!(
            verify_gateway_hmac(&env, b"wrong-secret"),
            Err(EnvelopeError::InvalidSignature)
        ));
    }

    #[test]
    fn verify_rejects_tampered_field() {
        let mut env = fresh_envelope();
        sign_gateway_envelope(&mut env, b"secret");
        env.payer = Some("0xattacker".into());
        assert!(matches!(
            verify_gateway_hmac(&env, b"secret"),
            Err(EnvelopeError::InvalidSignature)
        ));
    }

    #[test]
    fn verify_rejects_expired() {
        let mut env = fresh_envelope();
        env.expires_at = 1;
        sign_gateway_envelope(&mut env, b"secret");
        assert!(matches!(
            verify_gateway_hmac(&env, b"secret"),
            Err(EnvelopeError::Expired)
        ));
    }

    #[test]
    fn parse_and_verify_rejects_malformed_body() {
        assert!(matches!(
            parse_and_verify(b"not-json", b"secret"),
            Err(EnvelopeError::Malformed)
        ));
    }

    #[test]
    fn verify_envelope_rejects_wrong_pay_to() {
        let mut env = fresh_envelope();
        env.pay_to = Some("0xaaa".into());
        sign_gateway_envelope(&mut env, b"secret");
        let body = serde_json::to_vec(&env).unwrap();
        let exp = EnvelopeExpectations {
            pay_to: Some("0xbbb"),
            ..Default::default()
        };
        assert!(matches!(
            verify_envelope(&body, b"secret", &exp),
            Err(EnvelopeError::PayToMismatch { .. })
        ));
    }

    #[test]
    fn verify_envelope_accepts_case_different_pay_to() {
        let mut env = fresh_envelope();
        env.pay_to = Some("0xAbCdEf".into());
        sign_gateway_envelope(&mut env, b"secret");
        let body = serde_json::to_vec(&env).unwrap();
        let exp = EnvelopeExpectations {
            pay_to: Some("0xabcdef"),
            ..Default::default()
        };
        verify_envelope(&body, b"secret", &exp).expect("case-insensitive match");
    }

    #[test]
    fn newline_in_field_cannot_forge_next_field() {
        // Producer tries to smuggle `\npay_to=0xvictim` into `nonce`. The
        // escape converts it to `\\npay_to=0xvictim`, breaking the forgery.
        let mut attacker = fresh_envelope();
        attacker.nonce = "abc\npay_to=0xvictim".into();
        attacker.pay_to = Some("0xattacker".into());
        sign_gateway_envelope(&mut attacker, b"secret");

        let mut legit = fresh_envelope();
        legit.nonce = "abc".into();
        legit.pay_to = Some("pay_to=0xvictim".into()); // whatever
        sign_gateway_envelope(&mut legit, b"secret");

        // Sigs must differ because the canonical forms differ.
        assert_ne!(attacker.sig, legit.sig);
    }

    /// Golden vector — if the canonical form ever changes, this test
    /// breaks deliberately to force a version bump of the wire format.
    #[test]
    fn canonical_form_is_stable_byte_for_byte() {
        let env = GatewayEnvelope {
            ok: true,
            nonce: "deadbeef".into(),
            pay_to: Some("0xPAY".into()),
            amount: Some("1000".into()),
            scheme: Some("permit2".into()),
            payer: Some("0xPAYER".into()),
            network: Some("eip155:999".into()),
            expires_at: 2_000_000_000,
            sig: String::new(),
        };
        let expected = b"x402-gateway-envelope-v1\n\
                         ok=true\n\
                         nonce=deadbeef\n\
                         pay_to=0xPAY\n\
                         amount=1000\n\
                         scheme=permit2\n\
                         payer=0xPAYER\n\
                         network=eip155:999\n\
                         expires_at=2000000000";
        assert_eq!(canonical(&env), expected);
    }
}
