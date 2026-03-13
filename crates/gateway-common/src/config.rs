use config::{Config, Environment};
use serde::Deserialize;

use crate::{GatewayError, GatewayResult};

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub chain: ChainConfig,
    pub hypercore: HyperCoreConfig,
    pub providers: ProviderConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChainConfig {
    pub rpc_url: String,
    pub chain_id: u64,
    pub gateway_address: String,
    pub private_key_env: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HyperCoreConfig {
    pub api_url: String,
    pub ws_url: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ProviderConfig {
    pub openai_api_key: Option<String>,
    pub anthropic_api_key: Option<String>,
    pub google_api_key: Option<String>,
    pub together_api_key: Option<String>,
    pub fireworks_api_key: Option<String>,
    pub groq_api_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    pub requests_per_minute: u32,
    pub enabled: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: 60,
            enabled: true,
        }
    }
}

impl AppConfig {
    pub fn from_env() -> GatewayResult<Self> {
        let settings = Config::builder()
            .add_source(Environment::with_prefix("GATEWAY").separator("__"))
            .build()
            .map_err(|error| GatewayError::Config(error.to_string()))?;

        settings
            .try_deserialize::<Self>()
            .map_err(|error| GatewayError::Config(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AppConfig, ChainConfig, DatabaseConfig, HyperCoreConfig, ProviderConfig, RateLimitConfig,
        RedisConfig, ServerConfig,
    };

    #[test]
    fn provider_config_default_sets_all_api_keys_to_none() {
        let providers = ProviderConfig::default();

        assert!(providers.openai_api_key.is_none());
        assert!(providers.anthropic_api_key.is_none());
        assert!(providers.google_api_key.is_none());
        assert!(providers.together_api_key.is_none());
        assert!(providers.fireworks_api_key.is_none());
        assert!(providers.groq_api_key.is_none());
    }

    #[test]
    fn app_config_fields_are_accessible_and_preserve_values() {
        let config = AppConfig {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8080,
            },
            database: DatabaseConfig {
                url: "postgres://postgres:postgres@localhost:5432/gateway".to_string(),
                max_connections: 20,
            },
            redis: RedisConfig {
                url: "redis://127.0.0.1/".to_string(),
            },
            chain: ChainConfig {
                rpc_url: "https://rpc.example".to_string(),
                chain_id: 9_999,
                gateway_address: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
                private_key_env: "CHAIN_PRIVATE_KEY".to_string(),
            },
            hypercore: HyperCoreConfig {
                api_url: "https://api.hypercore.example".to_string(),
                ws_url: "wss://ws.hypercore.example".to_string(),
            },
            providers: ProviderConfig {
                openai_api_key: Some("openai-key".to_string()),
                anthropic_api_key: Some("anthropic-key".to_string()),
                google_api_key: Some("google-key".to_string()),
                together_api_key: Some("together-key".to_string()),
                fireworks_api_key: Some("fireworks-key".to_string()),
                groq_api_key: Some("groq-key".to_string()),
            },
            rate_limit: RateLimitConfig {
                requests_per_minute: 120,
                enabled: true,
            },
        };

        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 8080);
        assert_eq!(
            config.database.url,
            "postgres://postgres:postgres@localhost:5432/gateway"
        );
        assert_eq!(config.database.max_connections, 20);
        assert_eq!(config.redis.url, "redis://127.0.0.1/");
        assert_eq!(config.chain.rpc_url, "https://rpc.example");
        assert_eq!(config.chain.chain_id, 9_999);
        assert_eq!(
            config.chain.gateway_address,
            "0x1234567890abcdef1234567890abcdef12345678"
        );
        assert_eq!(config.chain.private_key_env, "CHAIN_PRIVATE_KEY");
        assert_eq!(config.hypercore.api_url, "https://api.hypercore.example");
        assert_eq!(config.hypercore.ws_url, "wss://ws.hypercore.example");
        assert_eq!(
            config.providers.openai_api_key.as_deref(),
            Some("openai-key")
        );
        assert_eq!(
            config.providers.anthropic_api_key.as_deref(),
            Some("anthropic-key")
        );
        assert_eq!(
            config.providers.google_api_key.as_deref(),
            Some("google-key")
        );
        assert_eq!(
            config.providers.together_api_key.as_deref(),
            Some("together-key")
        );
        assert_eq!(
            config.providers.fireworks_api_key.as_deref(),
            Some("fireworks-key")
        );
        assert_eq!(config.providers.groq_api_key.as_deref(), Some("groq-key"));
        assert_eq!(config.rate_limit.requests_per_minute, 120);
        assert!(config.rate_limit.enabled);
    }

    #[test]
    fn from_env_returns_config_error_when_required_values_are_missing() {
        let error = AppConfig::from_env()
            .expect_err("AppConfig::from_env should fail without complete GATEWAY__* environment");

        let message = error.to_string();
        assert!(message.starts_with("Configuration error:"));
    }

    #[test]
    fn rate_limit_config_default_provides_60_rpm_enabled() {
        let config = RateLimitConfig::default();
        assert_eq!(config.requests_per_minute, 60);
        assert!(config.enabled);
    }
}
