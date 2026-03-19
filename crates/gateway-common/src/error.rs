use thiserror::Error;

#[derive(Error, Debug)]
pub enum GatewayError {
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Redis error: {0}")]
    Redis(#[from] ::redis::RedisError),
    #[error("Provider error: {provider}: {message}")]
    Provider { provider: String, message: String },
    #[error("Authentication error: {0}")]
    Auth(String),
    #[error("Payment error: {0}")]
    Payment(String),
    #[error("Rate limit exceeded")]
    RateLimit,
    #[error("Insufficient credits: required {required}, available {available}")]
    InsufficientCredits {
        required: rust_decimal::Decimal,
        available: rust_decimal::Decimal,
    },
    #[error("Model not found: {0}")]
    ModelNotFound(String),
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    #[error("Upstream timeout after {0}ms")]
    Timeout(u64),
    #[error("Internal error: {0}")]
    Internal(String),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("HTTP client error: {0}")]
    HttpClient(#[from] reqwest::Error),
}

pub type GatewayResult<T> = Result<T, GatewayError>;

#[cfg(test)]
mod tests {
    use rust_decimal::Decimal;

    use super::{GatewayError, GatewayResult};

    #[test]
    fn gateway_error_display_for_string_backed_variants_is_correct() {
        assert_eq!(
            GatewayError::Config("missing host".to_string()).to_string(),
            "Configuration error: missing host"
        );
        assert_eq!(
            GatewayError::Auth("bad token".to_string()).to_string(),
            "Authentication error: bad token"
        );
        assert_eq!(
            GatewayError::Payment("insufficient balance".to_string()).to_string(),
            "Payment error: insufficient balance"
        );
        assert_eq!(
            GatewayError::ModelNotFound("gpt-xyz".to_string()).to_string(),
            "Model not found: gpt-xyz"
        );
        assert_eq!(
            GatewayError::InvalidRequest("missing field".to_string()).to_string(),
            "Invalid request: missing field"
        );
        assert_eq!(
            GatewayError::Internal("something broke".to_string()).to_string(),
            "Internal error: something broke"
        );
    }

    #[test]
    fn gateway_error_display_for_structured_variants_is_correct() {
        assert_eq!(
            GatewayError::Provider {
                provider: "openai".to_string(),
                message: "upstream rejected request".to_string(),
            }
            .to_string(),
            "Provider error: openai: upstream rejected request"
        );

        assert_eq!(GatewayError::RateLimit.to_string(), "Rate limit exceeded");

        assert_eq!(
            GatewayError::InsufficientCredits {
                required: Decimal::new(125, 2),
                available: Decimal::new(50, 2),
            }
            .to_string(),
            "Insufficient credits: required 1.25, available 0.50"
        );

        assert_eq!(
            GatewayError::Timeout(5_000).to_string(),
            "Upstream timeout after 5000ms"
        );
    }

    #[test]
    fn gateway_error_database_and_redis_variants_can_be_constructed() {
        let db_error = GatewayError::Database(sqlx::Error::Protocol("db protocol mismatch".into()));
        assert!(db_error.to_string().starts_with("Database error:"));
        assert!(db_error.to_string().contains("db protocol mismatch"));

        let redis_error =
            ::redis::RedisError::from((::redis::ErrorKind::TypeError, "wrong redis type"));
        let gateway_error = GatewayError::Redis(redis_error);
        assert!(gateway_error.to_string().starts_with("Redis error:"));
        assert!(gateway_error.to_string().contains("wrong redis type"));
    }

    #[test]
    fn gateway_error_from_serde_json_error_maps_to_serialization_variant() {
        let serde_error = serde_json::from_str::<serde_json::Value>("{")
            .expect_err("invalid JSON should produce serde_json::Error");
        let gateway_error: GatewayError = serde_error.into();

        assert!(matches!(gateway_error, GatewayError::Serialization(_)));
        assert!(
            gateway_error
                .to_string()
                .starts_with("Serialization error:")
        );
    }

    #[test]
    fn gateway_error_from_reqwest_error_maps_to_http_client_variant() {
        let reqwest_error = reqwest::Client::new()
            .get("::invalid-url::")
            .build()
            .expect_err("invalid URL should fail request build");
        let gateway_error: GatewayError = reqwest_error.into();

        assert!(matches!(gateway_error, GatewayError::HttpClient(_)));
        assert!(gateway_error.to_string().starts_with("HTTP client error:"));
    }

    #[test]
    fn gateway_result_alias_works_with_gateway_error() {
        let result: GatewayResult<()> = Err(GatewayError::RateLimit);
        assert!(matches!(result, Err(GatewayError::RateLimit)));
    }
}
