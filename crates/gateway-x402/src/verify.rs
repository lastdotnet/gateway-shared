use crate::types::{EIP3009Authorization, PaymentSignatureHeader};
use alloy::{
    dyn_abi::Eip712Domain,
    primitives::{Address, Signature as PrimitiveSignature, U256, keccak256},
    sol_types::SolValue,
};
use gateway_common::{GatewayError, GatewayResult, TOKEN_REGISTRY, token_amount_to_usd};
use rust_decimal::Decimal;
use std::borrow::Cow;
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub valid: bool,
    pub payer: Address,
    pub token_address: Address,
    pub amount: U256,
    pub amount_usd: Decimal,
    pub invalidation_reason: Option<String>,
}

/// Stateful verifier for x402 payments.
///
/// The `used_nonces` store is an `Arc<Mutex<HashSet>>` so that `Clone` gives a
/// new handle pointing at the *same* set — callers that clone this verifier
/// (e.g. Axum `State`) share nonce state across requests within one process.
/// For multi-process deployments, replace the in-memory set with a Redis store.
#[derive(Clone)]
pub struct PaymentVerifier {
    gateway_address: Address,
    accepted_tokens: Vec<Address>,
    used_nonces: Arc<Mutex<HashSet<String>>>,
}

impl PaymentVerifier {
    pub fn new(gateway_address: Address, accepted_tokens: Vec<Address>) -> Self {
        Self {
            gateway_address,
            accepted_tokens,
            used_nonces: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub fn verify_payment(
        &self,
        payment: &PaymentSignatureHeader,
        required_amount_usd: Decimal,
    ) -> GatewayResult<VerificationResult> {
        if payment.x402_version != 2 {
            return Ok(invalid_result(
                Address::ZERO,
                Address::ZERO,
                U256::ZERO,
                Decimal::ZERO,
                format!(
                    "Invalid x402 version: expected 2, got {}",
                    payment.x402_version
                ),
            ));
        }

        if payment.accepted.network != "eip155:999" {
            return Ok(invalid_result(
                Address::ZERO,
                Address::ZERO,
                U256::ZERO,
                Decimal::ZERO,
                format!(
                    "Invalid network: expected eip155:999, got {}",
                    payment.accepted.network
                ),
            ));
        }

        let token_address = parse_address(&payment.accepted.asset, "Invalid token address format")?;

        if !self.accepted_tokens.contains(&token_address) {
            return Ok(invalid_result(
                Address::ZERO,
                token_address,
                U256::ZERO,
                Decimal::ZERO,
                "Token not accepted".to_string(),
            ));
        }

        match payment.accepted.scheme.as_str() {
            "permit2" => self.verify_permit2(payment, required_amount_usd),
            "eip3009" => {
                let Some(auth) = &payment.payload.authorization else {
                    return Ok(invalid_result(
                        Address::ZERO,
                        token_address,
                        U256::ZERO,
                        Decimal::ZERO,
                        "Missing authorization".to_string(),
                    ));
                };
                self.verify_eip3009(
                    auth,
                    &payment.payload.signature,
                    token_address,
                    required_amount_usd,
                )
            }
            "exact" => Ok(invalid_result(
                Address::ZERO,
                token_address,
                U256::ZERO,
                Decimal::ZERO,
                "HyperCore exact payments must be verified with HyperCoreInlineVerifier"
                    .to_string(),
            )),
            other => Ok(invalid_result(
                Address::ZERO,
                token_address,
                U256::ZERO,
                Decimal::ZERO,
                format!("Unsupported payment scheme: {other}"),
            )),
        }
    }

    pub fn verify_permit2(
        &self,
        payment: &PaymentSignatureHeader,
        required_amount_usd: Decimal,
    ) -> GatewayResult<VerificationResult> {
        if payment.accepted.scheme != "permit2" {
            return Ok(invalid_result(
                Address::ZERO,
                Address::ZERO,
                U256::ZERO,
                Decimal::ZERO,
                format!(
                    "Invalid payment scheme for Permit2: expected permit2, got {}",
                    payment.accepted.scheme
                ),
            ));
        }

        let Some(auth) = &payment.payload.permit2_authorization else {
            return Ok(invalid_result(
                Address::ZERO,
                Address::ZERO,
                U256::ZERO,
                Decimal::ZERO,
                "Missing permit2 authorization".to_string(),
            ));
        };

        let token_address = parse_address(&payment.accepted.asset, "Invalid token address format")?;
        let owner = parse_address(&auth.owner, "Invalid permit2 owner address")?;
        let auth_token = parse_address(&auth.token, "Invalid permit2 token address")?;

        if auth_token != token_address {
            return Ok(invalid_result(
                owner,
                token_address,
                U256::ZERO,
                Decimal::ZERO,
                format!(
                    "Permit2 token mismatch: accepted {}, authorization {}",
                    token_address, auth_token
                ),
            ));
        }

        if !self.accepted_tokens.contains(&auth_token) {
            return Ok(invalid_result(
                owner,
                token_address,
                U256::ZERO,
                Decimal::ZERO,
                "Token not accepted".to_string(),
            ));
        }

        let spender = parse_address(&payment.accepted.pay_to, "Invalid spender address")?;
        if spender != self.gateway_address {
            return Ok(invalid_result(
                owner,
                token_address,
                U256::ZERO,
                Decimal::ZERO,
                format!(
                    "Permit2 spender mismatch: expected {}, got {}",
                    self.gateway_address, spender
                ),
            ));
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| GatewayError::Internal("Failed to get current time".to_string()))?
            .as_secs();

        if auth.deadline <= now {
            return Ok(invalid_result(
                owner,
                token_address,
                U256::ZERO,
                Decimal::ZERO,
                format!(
                    "Permit2 authorization expired: current {}, deadline {}",
                    now, auth.deadline
                ),
            ));
        }

        let amount = U256::from_str(&auth.amount)
            .map_err(|_| GatewayError::Payment("Invalid permit2 amount format".to_string()))?;

        let decimals = token_decimals(token_address).ok_or_else(|| {
            GatewayError::Payment(format!("Token metadata not found for {token_address}"))
        })?;
        let amount_usd = token_amount_to_usd(amount, decimals);

        if amount_usd < required_amount_usd {
            return Ok(invalid_result(
                owner,
                token_address,
                amount,
                amount_usd,
                format!(
                    "Insufficient amount: required {}, provided {}",
                    required_amount_usd, amount_usd
                ),
            ));
        }

        Ok(VerificationResult {
            valid: true,
            payer: owner,
            token_address,
            amount,
            amount_usd,
            invalidation_reason: None,
        })
    }

    pub fn verify_eip3009(
        &self,
        auth: &EIP3009Authorization,
        signature: &str,
        token_address: Address,
        required_amount_usd: Decimal,
    ) -> GatewayResult<VerificationResult> {
        let from = parse_address(&auth.from, "Invalid from address")?;
        let to = parse_address(&auth.to, "Invalid to address")?;

        if to != self.gateway_address {
            return Ok(invalid_result(
                from,
                token_address,
                U256::ZERO,
                Decimal::ZERO,
                format!(
                    "Payment not to gateway: expected {}, got {}",
                    self.gateway_address, to
                ),
            ));
        }

        let amount = U256::from_str(&auth.value)
            .map_err(|_| GatewayError::Payment("Invalid amount format".to_string()))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| GatewayError::Internal("Failed to get current time".to_string()))?
            .as_secs();

        if now < auth.valid_after {
            return Ok(invalid_result(
                from,
                token_address,
                amount,
                Decimal::ZERO,
                format!(
                    "Authorization not yet valid: current {}, valid_after {}",
                    now, auth.valid_after
                ),
            ));
        }

        if now >= auth.valid_before {
            return Ok(invalid_result(
                from,
                token_address,
                amount,
                Decimal::ZERO,
                format!(
                    "Authorization expired: current {}, valid_before {}",
                    now, auth.valid_before
                ),
            ));
        }

        let decimals = token_decimals(token_address).ok_or_else(|| {
            GatewayError::Payment(format!("Token metadata not found for {token_address}"))
        })?;
        let amount_usd = token_amount_to_usd(amount, decimals);

        if amount_usd < required_amount_usd {
            return Ok(invalid_result(
                from,
                token_address,
                amount,
                amount_usd,
                format!(
                    "Insufficient amount: required {}, provided {}",
                    required_amount_usd, amount_usd
                ),
            ));
        }

        // ── Cryptographic signature verification (EIP-712 / EIP-3009) ─────────
        // EIP-3009 signatures are standard secp256k1 compact: r (32) || s (32) || v (1)
        let sig_hex = signature.strip_prefix("0x").unwrap_or(signature);
        let sig_bytes = match hex::decode(sig_hex) {
            Ok(b) if b.len() == 65 => b,
            Ok(b) => {
                return Ok(invalid_result(
                    from,
                    token_address,
                    amount,
                    amount_usd,
                    format!(
                        "Invalid signature length: expected 65 bytes, got {}",
                        b.len()
                    ),
                ));
            }
            Err(_) => {
                return Ok(invalid_result(
                    from,
                    token_address,
                    amount,
                    amount_usd,
                    "Invalid signature: not valid hex".to_string(),
                ));
            }
        };
        let mut raw = [0u8; 65];
        raw.copy_from_slice(&sig_bytes);
        let prim_sig = match PrimitiveSignature::from_raw_array(&raw) {
            Ok(s) => s,
            Err(_) => {
                return Ok(invalid_result(
                    from,
                    token_address,
                    amount,
                    amount_usd,
                    "Invalid signature encoding".to_string(),
                ));
            }
        };

        // Parse EIP-3009 nonce as bytes32 (left-padded)
        let nonce_hex = auth.nonce.strip_prefix("0x").unwrap_or(&auth.nonce);
        let nonce_bytes = hex::decode(nonce_hex)
            .map_err(|_| GatewayError::Payment("Invalid nonce hex".to_string()))?;
        if nonce_bytes.len() > 32 {
            return Ok(invalid_result(
                from,
                token_address,
                amount,
                amount_usd,
                "Nonce exceeds 32 bytes".to_string(),
            ));
        }
        let mut nonce_b32 = [0u8; 32];
        nonce_b32[32 - nonce_bytes.len()..].copy_from_slice(&nonce_bytes);
        let nonce_fixed: alloy::primitives::FixedBytes<32> = nonce_b32.into();

        // Look up the EIP-712 domain for this token (name + version from contract)
        let (domain_name, domain_version) = match token_eip712_domain(token_address) {
            Some(p) => p,
            None => {
                return Err(GatewayError::Payment(format!(
                    "EIP-712 domain not configured for token {token_address}"
                )));
            }
        };

        // TransferWithAuthorization struct hash (EIP-3009 §5)
        const TYPEHASH_INPUT: &[u8] = b"TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)";
        let type_hash = keccak256(TYPEHASH_INPUT);
        let struct_hash = keccak256(
            (
                type_hash,
                from,
                to,
                amount,
                U256::from(auth.valid_after),
                U256::from(auth.valid_before),
                nonce_fixed,
            )
                .abi_encode(),
        );

        // EIP-712 domain separator for this token on HyperEVM (chain 999)
        let domain = Eip712Domain {
            name: Some(Cow::Borrowed(domain_name)),
            version: Some(Cow::Borrowed(domain_version)),
            chain_id: Some(U256::from(999u64)),
            verifying_contract: Some(token_address),
            salt: None,
        };
        let mut digest_bytes = [0u8; 66];
        digest_bytes[0] = 0x19;
        digest_bytes[1] = 0x01;
        digest_bytes[2..34].copy_from_slice(domain.separator().as_slice());
        digest_bytes[34..66].copy_from_slice(struct_hash.as_slice());
        let digest = keccak256(digest_bytes);

        // Recover the signer and assert it matches auth.from
        let recovered = match prim_sig.recover_address_from_prehash(&digest) {
            Ok(addr) => addr,
            Err(_) => {
                return Ok(invalid_result(
                    from,
                    token_address,
                    amount,
                    amount_usd,
                    "EIP-3009 signature recovery failed".to_string(),
                ));
            }
        };

        if recovered != from {
            return Ok(invalid_result(
                from,
                token_address,
                amount,
                amount_usd,
                format!(
                    "EIP-3009 signer mismatch: authorization from {from:#x}, signature by {recovered:#x}"
                ),
            ));
        }

        // ── Nonce deduplication (CRITICAL-2) ──────────────────────────────────
        // EIP-3009 nonces must be unique per token contract. Record the nonce on
        // first acceptance and reject any replay within this verifier's lifetime.
        // Production deployments with multiple gateway processes should replace
        // this in-memory set with a Redis store keyed on {token}:{nonce}.
        let nonce_key = format!("{token_address:#x}:{}", hex::encode(nonce_b32));
        {
            let mut nonces = self
                .used_nonces
                .lock()
                .map_err(|_| GatewayError::Internal("nonce store lock poisoned".to_string()))?;
            if nonces.contains(&nonce_key) {
                return Ok(invalid_result(
                    from,
                    token_address,
                    amount,
                    amount_usd,
                    "EIP-3009 nonce already used".to_string(),
                ));
            }
            nonces.insert(nonce_key);
        }

        Ok(VerificationResult {
            valid: true,
            payer: from,
            token_address,
            amount,
            amount_usd,
            invalidation_reason: None,
        })
    }
}

fn token_decimals(token_address: Address) -> Option<u8> {
    TOKEN_REGISTRY
        .values()
        .find(|token| token.address == token_address)
        .map(|token| token.decimals)
}

/// Returns the EIP-712 domain (name, version) for known EIP-3009 tokens on HyperEVM.
/// These values must match the token contract's `DOMAIN_SEPARATOR` exactly.
fn token_eip712_domain(token: Address) -> Option<(&'static str, &'static str)> {
    use alloy::primitives::address;
    match token {
        // Circle CCTP USDC deployed on HyperEVM
        t if t == address!("b88339cb7199b77e23db6e890353e22632ba630f") => Some(("USD Coin", "2")),
        _ => None,
    }
}

fn parse_address(value: &str, error: &str) -> GatewayResult<Address> {
    value
        .parse::<Address>()
        .map_err(|_| GatewayError::Payment(error.to_string()))
}

fn invalid_result(
    payer: Address,
    token_address: Address,
    amount: U256,
    amount_usd: Decimal,
    reason: String,
) -> VerificationResult {
    VerificationResult {
        valid: false,
        payer,
        token_address,
        amount,
        amount_usd,
        invalidation_reason: Some(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{PaymentPayload, PaymentRequirement, Permit2Authorization, ResourceInfo};

    const GATEWAY_ADDRESS: &str = "0x1234567890123456789012345678901234567890";
    const USDC_ADDRESS: &str = "0xb88339cb7199b77e23db6e890353e22632ba630f";

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("current time should be after unix epoch")
            .as_secs()
    }

    fn gateway_address() -> Address {
        Address::from_str(GATEWAY_ADDRESS).expect("gateway address should parse")
    }

    fn usdc_address() -> Address {
        Address::from_str(USDC_ADDRESS).expect("USDC address should parse")
    }

    fn payer_address() -> String {
        "0x1111111111111111111111111111111111111111".to_string()
    }

    fn valid_authorization(value: &str) -> EIP3009Authorization {
        let now = now_secs();
        EIP3009Authorization {
            from: payer_address(),
            to: GATEWAY_ADDRESS.to_string(),
            value: value.to_string(),
            valid_after: now.saturating_sub(60),
            valid_before: now + 3600,
            nonce: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        }
    }

    fn valid_permit2_authorization(amount: &str) -> Permit2Authorization {
        Permit2Authorization {
            owner: payer_address(),
            token: USDC_ADDRESS.to_string(),
            amount: amount.to_string(),
            nonce: "42".to_string(),
            deadline: now_secs() + 3600,
        }
    }

    fn payment_header(
        scheme: &str,
        x402_version: u8,
        network: &str,
        asset: &str,
        authorization: Option<EIP3009Authorization>,
        permit2_authorization: Option<Permit2Authorization>,
    ) -> PaymentSignatureHeader {
        PaymentSignatureHeader {
            x402_version,
            resource: ResourceInfo {
                url: "https://api.example.com/premium".to_string(),
                description: "Premium endpoint".to_string(),
                mime_type: Some("application/json".to_string()),
            },
            accepted: PaymentRequirement {
                scheme: scheme.to_string(),
                network: network.to_string(),
                amount: "1000000".to_string(),
                asset: asset.to_string(),
                pay_to: GATEWAY_ADDRESS.to_string(),
                max_timeout_seconds: 3600,
                extra: None,
            },
            payload: PaymentPayload {
                authorization,
                signature: format!("0x{}", "11".repeat(65)),
                permit2_authorization,
            },
        }
    }

    #[test]
    fn payment_verifier_new_sets_expected_state() {
        let gateway = gateway_address();
        let token = usdc_address();
        let verifier = PaymentVerifier::new(gateway, vec![token]);

        assert_eq!(verifier.gateway_address, gateway);
        assert_eq!(verifier.accepted_tokens, vec![token]);
    }

    #[test]
    fn verify_payment_rejects_wrong_x402_version() {
        let verifier = PaymentVerifier::new(gateway_address(), vec![usdc_address()]);
        let header = payment_header(
            "permit2",
            1,
            "eip155:999",
            USDC_ADDRESS,
            None,
            Some(valid_permit2_authorization("1000000")),
        );

        let result = verifier
            .verify_payment(
                &header,
                Decimal::from_str("0.1").expect("decimal should parse"),
            )
            .expect("verification should return result");

        assert!(!result.valid);
        assert!(
            result
                .invalidation_reason
                .expect("reason should be present")
                .contains("Invalid x402 version")
        );
    }

    #[test]
    fn verify_payment_rejects_wrong_network() {
        let verifier = PaymentVerifier::new(gateway_address(), vec![usdc_address()]);
        let header = payment_header(
            "permit2",
            2,
            "eip155:1",
            USDC_ADDRESS,
            None,
            Some(valid_permit2_authorization("1000000")),
        );

        let result = verifier
            .verify_payment(
                &header,
                Decimal::from_str("0.1").expect("decimal should parse"),
            )
            .expect("verification should return result");

        assert!(!result.valid);
        assert!(
            result
                .invalidation_reason
                .expect("reason should be present")
                .contains("Invalid network")
        );
    }

    #[test]
    fn verify_payment_rejects_unaccepted_token() {
        let verifier = PaymentVerifier::new(gateway_address(), vec![usdc_address()]);
        let header = payment_header(
            "permit2",
            2,
            "eip155:999",
            "0xca79db4b49f608ef54a5cb813fbed3a6387bc645",
            None,
            Some(valid_permit2_authorization("1000000")),
        );

        let result = verifier
            .verify_payment(
                &header,
                Decimal::from_str("0.1").expect("decimal should parse"),
            )
            .expect("verification should return result");

        assert!(!result.valid);
        assert_eq!(
            result.token_address,
            Address::from_str("0xca79db4b49f608ef54a5cb813fbed3a6387bc645")
                .expect("USDXL address should parse")
        );
        assert_eq!(
            result
                .invalidation_reason
                .expect("reason should be present"),
            "Token not accepted"
        );
    }

    #[test]
    fn verify_payment_dispatches_eip3009_and_rejects_invalid_signature() {
        // payment_header uses a garbage 65-byte signature (0x11 * 65).
        // After the C-1 fix, verify_eip3009 recovers a signer from that signature
        // (or fails parsing) — either way the recovered address ≠ auth.from → rejected.
        let verifier = PaymentVerifier::new(gateway_address(), vec![usdc_address()]);
        let header = payment_header(
            "eip3009",
            2,
            "eip155:999",
            USDC_ADDRESS,
            Some(valid_authorization("1000000")),
            None,
        );

        let result = verifier
            .verify_payment(
                &header,
                Decimal::from_str("0.5").expect("decimal should parse"),
            )
            .expect("verification should return result");

        assert!(
            !result.valid,
            "garbage signature must be rejected after C-1 fix"
        );
        assert!(result.invalidation_reason.is_some());
    }

    #[test]
    fn verify_payment_rejects_missing_permit2_authorization() {
        let verifier = PaymentVerifier::new(gateway_address(), vec![usdc_address()]);
        let header = payment_header("permit2", 2, "eip155:999", USDC_ADDRESS, None, None);

        let result = verifier
            .verify_payment(
                &header,
                Decimal::from_str("0.1").expect("decimal should parse"),
            )
            .expect("verification should return result");

        assert!(!result.valid);
        assert_eq!(
            result
                .invalidation_reason
                .expect("reason should be present"),
            "Missing permit2 authorization"
        );
    }

    #[test]
    fn verify_permit2_rejects_expired_deadline() {
        let verifier = PaymentVerifier::new(gateway_address(), vec![usdc_address()]);
        let mut auth = valid_permit2_authorization("1000000");
        auth.deadline = now_secs().saturating_sub(1);

        let header = payment_header("permit2", 2, "eip155:999", USDC_ADDRESS, None, Some(auth));

        let result = verifier
            .verify_payment(
                &header,
                Decimal::from_str("0.1").expect("decimal should parse"),
            )
            .expect("verification should return result");

        assert!(!result.valid);
        assert!(
            result
                .invalidation_reason
                .expect("reason should be present")
                .contains("Permit2 authorization expired")
        );
    }

    #[test]
    fn verify_permit2_rejects_spender_mismatch() {
        let verifier = PaymentVerifier::new(gateway_address(), vec![usdc_address()]);
        let mut header = payment_header(
            "permit2",
            2,
            "eip155:999",
            USDC_ADDRESS,
            None,
            Some(valid_permit2_authorization("1000000")),
        );
        header.accepted.pay_to = "0x2222222222222222222222222222222222222222".to_string();

        let result = verifier
            .verify_payment(
                &header,
                Decimal::from_str("0.1").expect("decimal should parse"),
            )
            .expect("verification should return result");

        assert!(!result.valid);
        assert!(
            result
                .invalidation_reason
                .expect("reason should be present")
                .contains("Permit2 spender mismatch")
        );
    }

    #[test]
    fn verify_permit2_rejects_token_mismatch_between_accepted_and_authorization() {
        let verifier = PaymentVerifier::new(gateway_address(), vec![usdc_address()]);
        let mut auth = valid_permit2_authorization("1000000");
        auth.token = "0xca79db4b49f608ef54a5cb813fbed3a6387bc645".to_string();

        let header = payment_header("permit2", 2, "eip155:999", USDC_ADDRESS, None, Some(auth));

        let result = verifier
            .verify_payment(
                &header,
                Decimal::from_str("0.1").expect("decimal should parse"),
            )
            .expect("verification should return result");

        assert!(!result.valid);
        assert!(
            result
                .invalidation_reason
                .expect("reason should be present")
                .contains("Permit2 token mismatch")
        );
    }

    #[test]
    fn verify_permit2_accepts_valid_authorization_with_sufficient_amount() {
        let verifier = PaymentVerifier::new(gateway_address(), vec![usdc_address()]);
        let header = payment_header(
            "permit2",
            2,
            "eip155:999",
            USDC_ADDRESS,
            None,
            Some(valid_permit2_authorization("1000000")),
        );

        let result = verifier
            .verify_payment(
                &header,
                Decimal::from_str("0.5").expect("decimal should parse"),
            )
            .expect("verification should return result");

        assert!(result.valid);
        assert_eq!(result.token_address, usdc_address());
        assert_eq!(result.amount, U256::from(1_000_000_u64));
        assert_eq!(result.amount_usd, Decimal::ONE);
        assert!(result.invalidation_reason.is_none());
    }

    // ── CRITICAL-1 regression guard ──────────────────────────────────────────
    // Proves that verify_eip3009 rejects a forged authorization whose signature
    // is the 1-byte garbage value "0x00". Before the C-1 fix the _signature
    // parameter was unused and this test passed with result.valid == true.
    // After the fix the signature-length check fires and returns valid == false.
    //
    // This test FAILS when the bug is re-introduced and PASSES when it is fixed.
    #[test]
    fn critical1_forged_eip3009_rejected_with_garbage_signature() {
        use crate::types::EIP3009Authorization;
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let verifier = PaymentVerifier::new(gateway_address(), vec![usdc_address()]);

        let forged_auth = EIP3009Authorization {
            from: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
            to: GATEWAY_ADDRESS.to_string(),
            value: "5000000".to_string(),
            valid_after: now - 60,
            valid_before: now + 3600,
            nonce: "0x0000000000000000000000000000000000000000000000000000000000000001".to_string(),
        };

        let result = verifier
            .verify_eip3009(
                &forged_auth,
                "0x00", // 1-byte garbage — must be rejected at length check
                usdc_address(),
                Decimal::from_str("1.0").unwrap(),
            )
            .expect("verify_eip3009 should not return Err");

        assert!(
            !result.valid,
            "C-1 regression: garbage signature must be rejected"
        );
        assert!(
            result
                .invalidation_reason
                .as_deref()
                .unwrap_or("")
                .contains("signature"),
            "rejection reason must mention the signature problem; got: {:?}",
            result.invalidation_reason
        );
    }

    // Regression guard through the public verify_payment dispatch path —
    // confirms the scheme routing in verify_payment reaches the fixed verify_eip3009.
    #[test]
    fn critical1_forged_eip3009_rejected_via_verify_payment_dispatch() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let verifier = PaymentVerifier::new(gateway_address(), vec![usdc_address()]);

        let header = payment_header(
            "eip3009",
            2,
            "eip155:999",
            USDC_ADDRESS,
            Some(EIP3009Authorization {
                from: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
                to: GATEWAY_ADDRESS.to_string(),
                value: "5000000".to_string(),
                valid_after: now - 60,
                valid_before: now + 3600,
                nonce: "0xdead".to_string(),
            }),
            None,
        );

        // payment_header uses signature "0x11" * 65; after C-1 fix the recovered
        // signer won't match `from` so the result is invalid.
        let result = verifier
            .verify_payment(&header, Decimal::from_str("1.0").unwrap())
            .expect("verify_payment should not error");

        assert!(
            !result.valid,
            "C-1 regression: forged eip3009 via dispatch must be rejected"
        );
        assert!(result.invalidation_reason.is_some());
    }

    // ── CRITICAL-2 regression guard ───────────────────────────────────────────
    // Proves that verify_eip3009 rejects the second use of any nonce within the
    // same PaymentVerifier instance. The nonce is recorded on the first valid
    // call and the identical authorization is refused on the second call.
    //
    // This test FAILS when C-2 is re-introduced and PASSES when it is fixed.
    #[test]
    fn critical2_eip3009_same_nonce_rejected_on_replay() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let verifier = PaymentVerifier::new(gateway_address(), vec![usdc_address()]);

        // Hardhat dev account #1: address derived from this key is auth.from.
        const KEY_C2: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

        // Fixed nonce — "c2" bytes are a mnemonic for CRITICAL-2.
        let auth = EIP3009Authorization {
            from: "0x70997970c51812dc3a010c7d01b50e0d17dc79c8".to_string(),
            to: GATEWAY_ADDRESS.to_string(),
            value: "5000000".to_string(), // 5 USDC raw (6 decimals) = $5
            valid_after: now - 60,
            valid_before: now + 3600,
            nonce: "0xc2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2".to_string(),
        };
        let required_usd = Decimal::from_str("1.0").unwrap();

        // Generate a real EIP-712 signature (C-1 is fixed so "0x00" no longer works).
        let signature = sign_eip3009_for_test(&auth, usdc_address(), KEY_C2);

        // First call — expected to succeed.
        let first = verifier
            .verify_eip3009(&auth, &signature, usdc_address(), required_usd)
            .expect("first verify_eip3009 should not error");

        assert!(
            first.valid,
            "first call should be accepted with a valid signature"
        );

        // Second call — same nonce, same authorization, same verifier instance.
        // C-2 FIXED: the nonce was recorded on the first call; the second call
        // must be rejected with an "already used" invalidation reason.
        let second = verifier
            .verify_eip3009(&auth, &signature, usdc_address(), required_usd)
            .expect("second verify_eip3009 should not error");

        assert!(
            !second.valid,
            "C-2 regression: second use of the same nonce must be rejected"
        );
        assert!(
            second
                .invalidation_reason
                .as_deref()
                .unwrap_or("")
                .contains("nonce"),
            "rejection reason must mention the nonce; got: {:?}",
            second.invalidation_reason
        );
    }

    /// Compute and sign an EIP-3009 TransferWithAuthorization digest for testing.
    /// Uses the same domain + struct-hash logic as verify_eip3009 so the
    /// resulting signature will pass the C-1 check.
    fn sign_eip3009_for_test(
        auth: &EIP3009Authorization,
        token_address: Address,
        private_key: &str,
    ) -> String {
        use alloy::dyn_abi::Eip712Domain;
        use alloy::primitives::{U256, keccak256};
        use alloy::signers::SignerSync;
        use alloy::signers::local::PrivateKeySigner;
        use alloy::sol_types::SolValue;
        use std::borrow::Cow;

        let signer: PrivateKeySigner = private_key.parse().expect("valid private key");

        let from = Address::from_str(&auth.from).expect("valid from address");
        let to = Address::from_str(&auth.to).expect("valid to address");
        let amount = U256::from_str(&auth.value).expect("valid amount");

        let nonce_hex = auth.nonce.strip_prefix("0x").unwrap_or(&auth.nonce);
        let nonce_bytes = hex::decode(nonce_hex).expect("valid nonce hex");
        let mut nonce_b32 = [0u8; 32];
        nonce_b32[32 - nonce_bytes.len()..].copy_from_slice(&nonce_bytes);
        let nonce_fixed: alloy::primitives::FixedBytes<32> = nonce_b32.into();

        const TYPEHASH_INPUT: &[u8] = b"TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)";
        let type_hash = keccak256(TYPEHASH_INPUT);
        let struct_hash = keccak256(
            (
                type_hash,
                from,
                to,
                amount,
                U256::from(auth.valid_after),
                U256::from(auth.valid_before),
                nonce_fixed,
            )
                .abi_encode(),
        );

        let (domain_name, domain_version) = super::token_eip712_domain(token_address)
            .expect("token must have EIP-712 domain configured");
        let domain = Eip712Domain {
            name: Some(Cow::Borrowed(domain_name)),
            version: Some(Cow::Borrowed(domain_version)),
            chain_id: Some(U256::from(999u64)),
            verifying_contract: Some(token_address),
            salt: None,
        };

        let mut digest_bytes = [0u8; 66];
        digest_bytes[0] = 0x19;
        digest_bytes[1] = 0x01;
        digest_bytes[2..34].copy_from_slice(domain.separator().as_slice());
        digest_bytes[34..66].copy_from_slice(struct_hash.as_slice());
        let digest = keccak256(digest_bytes);

        let sig = signer
            .sign_hash_sync(&digest)
            .expect("signing must succeed");
        format!("0x{}", hex::encode(sig.as_bytes()))
    }
}
