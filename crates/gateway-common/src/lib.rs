pub mod config;
pub mod db;
pub mod error;
pub mod redis;
pub mod tokens;
pub mod types;

pub use config::*;
pub use db::*;
pub use error::*;
pub use redis::*;
pub use tokens::*;
pub use types::*;

use ::redis::aio::ConnectionManager;
use sqlx::PgPool;
#[cfg(feature = "swype")]
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub db_pool: PgPool,
    pub redis: ConnectionManager,
    pub config: AppConfig,
    #[cfg(feature = "swype")]
    pub vault_client: Option<Arc<dyn std::any::Any + Send + Sync>>,
    #[cfg(feature = "swype")]
    pub card_processor: Option<Arc<dyn std::any::Any + Send + Sync>>,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use alloy::primitives::U256;
    use rust_decimal::Decimal;
    use uuid::Uuid;

    #[test]
    fn re_exported_error_and_result_types_are_accessible() {
        let error = crate::GatewayError::RateLimit;
        let result: crate::GatewayResult<()> = Err(error);
        assert!(matches!(result, Err(crate::GatewayError::RateLimit)));
    }

    #[test]
    fn re_exported_token_items_are_accessible() {
        let usd = crate::token_amount_to_usd(U256::from(1_000_000u64), 6);
        assert_eq!(usd, Decimal::ONE);

        let amount =
            crate::usd_to_token_amount(Decimal::from_str("2.5").expect("valid decimal literal"), 6);
        assert_eq!(amount, U256::from(2_500_000u64));

        assert!(crate::TOKEN_REGISTRY.contains_key("USDXL_HYPEREVM"));
    }

    #[test]
    fn re_exported_type_items_are_accessible() {
        let account = crate::AccountId(
            Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").expect("valid UUID literal"),
        );
        let mode = crate::PaymentMode::ApiKey;

        assert_eq!(account.to_string(), "123e4567-e89b-12d3-a456-426614174000");
        assert!(matches!(mode, crate::PaymentMode::ApiKey));
    }

    #[test]
    fn re_exported_config_items_are_accessible() {
        let providers = crate::ProviderConfig::default();
        assert!(providers.openai_api_key.is_none());

        let server = crate::ServerConfig {
            host: "0.0.0.0".to_string(),
            port: 3000,
        };
        assert_eq!(server.host, "0.0.0.0");
        assert_eq!(server.port, 3000);
    }
}
