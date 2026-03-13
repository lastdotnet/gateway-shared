use crate::types::{
    ClearinghouseState, SignedAction, SpotClearinghouseState, api_url_for_network,
};
use gateway_common::error::{GatewayError, GatewayResult};
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

/// HyperCore REST API client
pub struct HyperCoreClient {
    client: Client,
    api_url: String,
}

impl HyperCoreClient {
    /// Create a new HyperCore client with an explicit API URL
    pub fn new(api_url: impl Into<String>) -> Self {
        Self {
            client: Client::new(),
            api_url: api_url.into(),
        }
    }

    /// Create a client from a network identifier (e.g. "hyperliquid:mainnet")
    pub fn from_network(network: &str) -> GatewayResult<Self> {
        let url = api_url_for_network(network)
            .ok_or_else(|| GatewayError::Payment(format!("Unsupported network: {network}")))?;
        Ok(Self::new(url))
    }

    fn info_url(&self) -> String {
        format!("{}/info", self.api_url)
    }

    fn exchange_url(&self) -> String {
        format!("{}/exchange", self.api_url)
    }

    async fn post_info<T: DeserializeOwned>(
        &self,
        body: Value,
        error_context: &str,
    ) -> GatewayResult<T> {
        let response = self
            .client
            .post(self.info_url())
            .json(&body)
            .send()
            .await
            .map_err(|error| GatewayError::Provider {
                provider: "HyperCore".to_string(),
                message: format!("{error_context}: {error}"),
            })?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(GatewayError::Provider {
                provider: "HyperCore".to_string(),
                message: format!("{error_context}: HTTP {status} {body}"),
            });
        }

        response.json::<T>().await.map_err(GatewayError::HttpClient)
    }

    /// Get spot balances for an address
    pub async fn get_spot_balances(&self, address: &str) -> GatewayResult<SpotClearinghouseState> {
        self.post_info(
            json!({
            "type": "spotClearinghouseState",
            "user": address
            }),
            "Failed to fetch spot balances",
        )
        .await
    }

    /// Get USDC balance for an address (in decimal form)
    pub async fn get_usdc_balance(&self, address: &str) -> GatewayResult<f64> {
        let state = self.get_spot_balances(address).await?;

        let usdc_balance = state
            .balances
            .iter()
            .find(|b| b.coin == "USDC")
            .map(|b| b.total.parse::<f64>().unwrap_or(0.0))
            .unwrap_or(0.0);

        Ok(usdc_balance)
    }

    /// Get perps clearinghouse state for an address
    pub async fn get_perps_balance(&self, address: &str) -> GatewayResult<ClearinghouseState> {
        self.post_info(
            json!({
                "type": "clearinghouseState",
                "user": address
            }),
            "Failed to fetch perps balance",
        )
        .await
    }

    /// Submit a signed action to the HyperCore exchange API
    pub async fn submit_action(&self, signed_action: &SignedAction) -> GatewayResult<Value> {
        let response = self
            .client
            .post(self.exchange_url())
            .json(signed_action)
            .send()
            .await
            .map_err(|error| GatewayError::Provider {
                provider: "HyperCore".to_string(),
                message: format!("Failed to submit action: {error}"),
            })?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(GatewayError::Provider {
                provider: "HyperCore".to_string(),
                message: format!("Failed to submit action: HTTP {status} {body}"),
            });
        }

        let result = response
            .json::<Value>()
            .await
            .map_err(GatewayError::HttpClient)?;

        let expected = json!({
            "status": "ok",
            "response": {
                "type": "default"
            }
        });

        if result != expected {
            return Err(GatewayError::Payment(format!(
                "HyperCore action rejected: {result}"
            )));
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_client_with_expected_api_url() {
        let client = HyperCoreClient::new("https://api.hyperliquid.xyz");
        assert_eq!(client.api_url, "https://api.hyperliquid.xyz");
    }

    #[test]
    fn from_network_mainnet_resolves_correctly() {
        let client =
            HyperCoreClient::from_network("hyperliquid:mainnet").expect("mainnet should resolve");
        assert_eq!(client.api_url, "https://api.hyperliquid.xyz");
    }

    #[test]
    fn from_network_testnet_resolves_correctly() {
        let client =
            HyperCoreClient::from_network("hyperliquid:testnet").expect("testnet should resolve");
        assert_eq!(client.api_url, "https://api.hyperliquid-testnet.xyz");
    }

    #[test]
    fn from_network_unknown_returns_error() {
        let result = HyperCoreClient::from_network("eip155:999");
        assert!(result.is_err());
        match result {
            Err(GatewayError::Payment(msg)) => {
                assert!(msg.contains("Unsupported network"));
            }
            _ => panic!("Expected Payment error"),
        }
    }
}
