use std::fmt::{Display, Formatter, Result as FmtResult};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct AccountId(pub Uuid);

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct ApiKeyId(pub Uuid);

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct RequestId(pub String);

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct ModelId(pub String);

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderId(pub String);

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum PaymentMode {
    ApiKey,
    X402,
    HyperCore,
}

impl Display for AccountId {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.0)
    }
}

impl Display for ApiKeyId {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.0)
    }
}

impl Display for RequestId {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.0)
    }
}

impl Display for ModelId {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.0)
    }
}

impl Display for ProviderId {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use uuid::Uuid;

    use super::{AccountId, ApiKeyId, ModelId, PaymentMode, ProviderId, RequestId};

    #[test]
    fn id_types_display_their_inner_values() {
        let account_uuid =
            Uuid::parse_str("11111111-2222-3333-4444-555555555555").expect("valid UUID literal");
        let api_key_uuid =
            Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("valid UUID literal");

        assert_eq!(
            AccountId(account_uuid).to_string(),
            "11111111-2222-3333-4444-555555555555"
        );
        assert_eq!(
            ApiKeyId(api_key_uuid).to_string(),
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        );
        assert_eq!(RequestId("req_123".to_string()).to_string(), "req_123");
        assert_eq!(
            ModelId("gpt-4.1-mini".to_string()).to_string(),
            "gpt-4.1-mini"
        );
        assert_eq!(ProviderId("openai".to_string()).to_string(), "openai");
    }

    #[test]
    fn id_types_serialize_and_deserialize_round_trip() {
        let account_id = AccountId(
            Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").expect("valid UUID literal"),
        );
        let api_key_id = ApiKeyId(
            Uuid::parse_str("123e4567-e89b-12d3-a456-426614174001").expect("valid UUID literal"),
        );
        let request_id = RequestId("req_test_001".to_string());
        let model_id = ModelId("claude-sonnet".to_string());
        let provider_id = ProviderId("anthropic".to_string());

        let account_json = serde_json::to_value(&account_id).expect("serialize AccountId");
        let api_key_json = serde_json::to_value(&api_key_id).expect("serialize ApiKeyId");
        let request_json = serde_json::to_value(&request_id).expect("serialize RequestId");
        let model_json = serde_json::to_value(&model_id).expect("serialize ModelId");
        let provider_json = serde_json::to_value(&provider_id).expect("serialize ProviderId");

        let account_round_trip: AccountId =
            serde_json::from_value(account_json).expect("deserialize AccountId");
        let api_key_round_trip: ApiKeyId =
            serde_json::from_value(api_key_json).expect("deserialize ApiKeyId");
        let request_round_trip: RequestId =
            serde_json::from_value(request_json).expect("deserialize RequestId");
        let model_round_trip: ModelId =
            serde_json::from_value(model_json).expect("deserialize ModelId");
        let provider_round_trip: ProviderId =
            serde_json::from_value(provider_json).expect("deserialize ProviderId");

        assert_eq!(account_round_trip, account_id);
        assert_eq!(api_key_round_trip, api_key_id);
        assert_eq!(request_round_trip, request_id);
        assert_eq!(model_round_trip, model_id);
        assert_eq!(provider_round_trip, provider_id);
    }

    #[test]
    fn payment_mode_serializes_and_deserializes_all_variants() {
        let modes = [
            PaymentMode::ApiKey,
            PaymentMode::X402,
            PaymentMode::HyperCore,
        ];

        for mode in modes {
            let serialized = serde_json::to_value(&mode).expect("serialize PaymentMode");
            let deserialized: PaymentMode =
                serde_json::from_value(serialized).expect("deserialize PaymentMode");
            assert_eq!(deserialized, mode);
        }
    }

    #[test]
    fn payment_mode_uses_expected_serde_representation() {
        let api_key_json =
            serde_json::to_value(PaymentMode::ApiKey).expect("serialize ApiKey mode");
        let x402_json = serde_json::to_value(PaymentMode::X402).expect("serialize X402 mode");
        let hypercore_json =
            serde_json::to_value(PaymentMode::HyperCore).expect("serialize HyperCore mode");

        assert_eq!(api_key_json, json!("ApiKey"));
        assert_eq!(x402_json, json!("X402"));
        assert_eq!(hypercore_json, json!("HyperCore"));
    }
}
