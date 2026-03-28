use crate::types::{EIP3009Authorization, PaymentSignatureHeader};
use alloy::primitives::{Address, U256};
use gateway_common::{GatewayError, GatewayResult, TOKEN_REGISTRY, token_amount_to_usd};
use rust_decimal::Decimal;
use std::str::FromStr;
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

pub struct PaymentVerifier {
    gateway_address: Address,
    accepted_tokens: Vec<Address>,
}

impl PaymentVerifier {
    pub fn new(gateway_address: Address, accepted_tokens: Vec<Address>) -> Self {
        Self {
            gateway_address,
            accepted_tokens,
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
        _signature: &str,
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

fn parse_address(value: &str, error: &str) -> GatewayResult<Address> {
    value.parse::<Address>().map_err(|_| GatewayError::Payment(error.to_string()))
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
    fn verify_payment_dispatches_eip3009_and_accepts_valid_auth() {
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

        assert!(result.valid);
        assert_eq!(
            result.payer,
            Address::from_str(&payer_address()).expect("payer address")
        );
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
}
