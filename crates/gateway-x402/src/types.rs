use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Encodes a serializable value to base64 JSON string
pub fn encode_header<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    use base64::Engine;
    let json = serde_json::to_string(value)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(json))
}

/// Decodes a base64 JSON string to a deserializable type
pub fn decode_header<T: for<'de> Deserialize<'de>>(
    header: &str,
) -> Result<T, Box<dyn std::error::Error + Send + Sync>> {
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD.decode(header)?;
    let json = String::from_utf8(decoded)?;
    Ok(serde_json::from_str(&json)?)
}

/// Information about a protected resource
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceInfo {
    pub url: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// Required payment for accessing a resource
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirement {
    pub scheme: String,
    pub network: String,
    pub amount: String,
    pub asset: String,
    pub pay_to: String,
    pub max_timeout_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<HashMap<String, serde_json::Value>>,
}

/// x402 v2 payment required header
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequiredHeader {
    pub x402_version: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub resource: ResourceInfo,
    pub accepts: Vec<PaymentRequirement>,
}

/// EIP-3009 authorization data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EIP3009Authorization {
    pub from: String,
    pub to: String,
    pub value: String,
    pub valid_after: u64,
    pub valid_before: u64,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Permit2Authorization {
    pub owner: String,
    pub token: String,
    pub amount: String,
    pub nonce: String,
    pub deadline: u64,
}

/// Payment payload containing authorization and signature
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<EIP3009Authorization>,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permit2_authorization: Option<Permit2Authorization>,
}

/// x402 v2 payment signature header
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentSignatureHeader {
    pub x402_version: u8,
    pub resource: ResourceInfo,
    pub accepted: PaymentRequirement,
    pub payload: PaymentPayload,
}

/// Response from settlement
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentResponseHeader {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_resource_info() {
        let resource = ResourceInfo {
            url: "https://api.example.com/data".to_string(),
            description: "Premium data endpoint".to_string(),
            mime_type: Some("application/json".to_string()),
        };

        let encoded = encode_header(&resource).expect("encode failed");
        let decoded: ResourceInfo = decode_header(&encoded).expect("decode failed");

        assert_eq!(decoded.url, resource.url);
        assert_eq!(decoded.description, resource.description);
        assert_eq!(decoded.mime_type, resource.mime_type);
    }

    #[test]
    fn test_encode_decode_payment_required() {
        let header = PaymentRequiredHeader {
            x402_version: 2,
            error: None,
            resource: ResourceInfo {
                url: "https://api.example.com".to_string(),
                description: "API".to_string(),
                mime_type: None,
            },
            accepts: vec![PaymentRequirement {
                scheme: "permit2".to_string(),
                network: "eip155:999".to_string(),
                amount: "100000000000000000".to_string(),
                asset: "0xb88339cb7199b77e23db6e890353e22632ba630f".to_string(),
                pay_to: "0x1234567890123456789012345678901234567890".to_string(),
                max_timeout_seconds: 3600,
                extra: None,
            }],
        };

        let encoded = encode_header(&header).expect("encode failed");
        let decoded: PaymentRequiredHeader = decode_header(&encoded).expect("decode failed");

        assert_eq!(decoded.x402_version, 2);
        assert_eq!(decoded.accepts.len(), 1);
    }

    #[test]
    fn test_payment_signature_header_round_trip() {
        let header = PaymentSignatureHeader {
            x402_version: 2,
            resource: ResourceInfo {
                url: "https://api.example.com/data".to_string(),
                description: "Premium data endpoint".to_string(),
                mime_type: Some("application/json".to_string()),
            },
            accepted: PaymentRequirement {
                scheme: "permit2".to_string(),
                network: "eip155:999".to_string(),
                amount: "1100000".to_string(),
                asset: "0xb88339cb7199b77e23db6e890353e22632ba630f".to_string(),
                pay_to: "0x1234567890123456789012345678901234567890".to_string(),
                max_timeout_seconds: 3600,
                extra: None,
            },
            payload: PaymentPayload {
                authorization: None,
                signature: "0xdeadbeef".to_string(),
                permit2_authorization: Some(Permit2Authorization {
                    owner: "0x1111111111111111111111111111111111111111".to_string(),
                    token: "0xb88339cb7199b77e23db6e890353e22632ba630f".to_string(),
                    amount: "1100000".to_string(),
                    nonce: "123456".to_string(),
                    deadline: 9_999_999_999,
                }),
            },
        };

        let encoded = encode_header(&header).expect("payment signature header should encode");
        let decoded: PaymentSignatureHeader =
            decode_header(&encoded).expect("payment signature header should decode");

        assert_eq!(decoded.x402_version, 2);
        assert_eq!(decoded.accepted.network, "eip155:999");
        assert_eq!(
            decoded.accepted.asset,
            "0xb88339cb7199b77e23db6e890353e22632ba630f"
        );
        assert_eq!(decoded.payload.signature, "0xdeadbeef");
        assert!(decoded.payload.permit2_authorization.is_some());
    }

    #[test]
    fn test_payment_response_header_success_and_failure() {
        let success = PaymentResponseHeader {
            success: true,
            transaction: Some(
                "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            ),
            network: Some("eip155:999".to_string()),
            payer: Some("0x1111111111111111111111111111111111111111".to_string()),
            error_reason: None,
        };

        let failure = PaymentResponseHeader {
            success: false,
            transaction: None,
            network: Some("eip155:999".to_string()),
            payer: Some("0x1111111111111111111111111111111111111111".to_string()),
            error_reason: Some("Insufficient amount".to_string()),
        };

        let success_json = serde_json::to_string(&success)
            .expect("success response header should serialize to JSON");
        let failure_json = serde_json::to_string(&failure)
            .expect("failure response header should serialize to JSON");

        let success_decoded: PaymentResponseHeader = serde_json::from_str(&success_json)
            .expect("success response header should deserialize from JSON");
        let failure_decoded: PaymentResponseHeader = serde_json::from_str(&failure_json)
            .expect("failure response header should deserialize from JSON");

        assert!(success_decoded.success);
        assert!(!failure_decoded.success);
        assert_eq!(
            failure_decoded
                .error_reason
                .expect("failure header should carry error reason"),
            "Insufficient amount"
        );
    }

    #[test]
    fn test_eip3009_authorization_serialization() {
        let auth = EIP3009Authorization {
            from: "0x1111111111111111111111111111111111111111".to_string(),
            to: "0x1234567890123456789012345678901234567890".to_string(),
            value: "1000000".to_string(),
            valid_after: 100,
            valid_before: 200,
            nonce: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        };

        let json = serde_json::to_string(&auth).expect("authorization should serialize");
        let decoded: EIP3009Authorization =
            serde_json::from_str(&json).expect("authorization should deserialize");

        assert_eq!(decoded.from, auth.from);
        assert_eq!(decoded.to, auth.to);
        assert_eq!(decoded.value, auth.value);
        assert_eq!(decoded.valid_after, auth.valid_after);
        assert_eq!(decoded.valid_before, auth.valid_before);
        assert_eq!(decoded.nonce, auth.nonce);
    }

    #[test]
    fn test_permit2_authorization_serialization_round_trip() {
        let auth = Permit2Authorization {
            owner: "0x1111111111111111111111111111111111111111".to_string(),
            token: "0xb88339cb7199b77e23db6e890353e22632ba630f".to_string(),
            amount: "1000000".to_string(),
            nonce: "12345".to_string(),
            deadline: 9_999_999_999,
        };

        let json = serde_json::to_string(&auth).expect("authorization should serialize");
        let decoded: Permit2Authorization =
            serde_json::from_str(&json).expect("authorization should deserialize");

        assert_eq!(decoded, auth);
    }
}
