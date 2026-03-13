use crate::types::{PaymentRequiredHeader, PaymentRequirement, ResourceInfo};
use gateway_common::{usd_to_token_amount, Chain, GatewayResult, TOKEN_REGISTRY};
use rust_decimal::Decimal;
use std::str::FromStr;

pub struct PaymentEstimator {
    gateway_address: String,
    network: String,
}

impl PaymentEstimator {
    /// Creates a new payment estimator with a gateway address
    pub fn new(gateway_address: String) -> Self {
        Self {
            gateway_address,
            network: "eip155:999".to_string(),
        }
    }

    /// Builds a payment required header with 10% buffer on estimated cost
    pub fn build_payment_required(
        &self,
        url: String,
        description: String,
        estimated_cost_usd: Decimal,
    ) -> GatewayResult<PaymentRequiredHeader> {
        // Add 10% buffer to estimated cost
        let buffered_cost = estimated_cost_usd
            * Decimal::from_str("1.10").map_err(|_| {
                gateway_common::GatewayError::InvalidRequest(
                    "Failed to calculate buffered cost".to_string(),
                )
            })?;

        let resource = ResourceInfo {
            url,
            description,
            mime_type: None,
        };

        let mut accepts = Vec::new();

        for (_key, token_info) in TOKEN_REGISTRY.iter() {
            let amount = usd_to_token_amount(buffered_cost, token_info.decimals);

            let (scheme, network) = match token_info.chain {
                Chain::HyperEvm => ("permit2", self.network.clone()),
                Chain::HyperCore => ("hypercore", "hypercore:mainnet".to_string()),
            };

            accepts.push(PaymentRequirement {
                scheme: scheme.to_string(),
                network,
                amount: amount.to_string(),
                asset: if token_info.chain == Chain::HyperCore {
                    format!(
                        "{}:{}",
                        token_info.symbol,
                        token_info.token_id.as_deref().unwrap_or("0")
                    )
                } else {
                    token_info.address.to_string()
                },
                pay_to: self.gateway_address.clone(),
                max_timeout_seconds: 3600,
                extra: None,
            });
        }

        Ok(PaymentRequiredHeader {
            x402_version: 2,
            error: None,
            resource,
            accepts,
        })
    }

    /// Calculates token cost based on model pricing
    pub fn estimate_cost(
        &self,
        _model_id: String,
        input_tokens: u64,
        max_output_tokens: u64,
        input_price: Decimal,
        output_price: Decimal,
    ) -> Decimal {
        let input_cost = Decimal::from(input_tokens) * input_price;
        let output_cost = Decimal::from(max_output_tokens) * output_price;
        input_cost + output_cost
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GATEWAY_ADDRESS: &str = "0x1234567890123456789012345678901234567890";
    const USDC_ADDRESS: &str = "0xb88339cb7199b77e23db6e890353e22632ba630f";

    #[test]
    fn test_payment_estimator_creation() {
        let estimator = PaymentEstimator::new(GATEWAY_ADDRESS.to_string());
        assert_eq!(estimator.network, "eip155:999");
    }

    #[test]
    fn test_estimate_cost() {
        let estimator = PaymentEstimator::new(GATEWAY_ADDRESS.to_string());
        let cost = estimator.estimate_cost(
            "gpt-4".to_string(),
            1000,
            500,
            Decimal::from_str("0.00003").expect("input price should parse"),
            Decimal::from_str("0.00006").expect("output price should parse"),
        );

        let expected = Decimal::from_str("0.06").expect("expected decimal should parse");
        assert_eq!(cost, expected);
    }

    #[test]
    fn test_build_payment_required() {
        let estimator = PaymentEstimator::new(GATEWAY_ADDRESS.to_string());
        let header = estimator
            .build_payment_required(
                "https://api.example.com".to_string(),
                "Test API".to_string(),
                Decimal::from_str("1.00").expect("cost decimal should parse"),
            )
            .expect("build failed");

        assert_eq!(header.x402_version, 2);
        assert!(header.accepts.len() > 0);
        assert_eq!(header.resource.url, "https://api.example.com");
    }

    #[test]
    fn build_payment_required_creates_one_option_per_hyperevm_token() {
        let estimator = PaymentEstimator::new(GATEWAY_ADDRESS.to_string());
        let header = estimator
            .build_payment_required(
                "https://api.example.com/usage".to_string(),
                "Usage endpoint".to_string(),
                Decimal::from_str("1.00").expect("cost decimal should parse"),
            )
            .expect("build payment required should succeed");

        assert_eq!(header.accepts.len(), 7);
    }

    #[test]
    fn build_payment_required_applies_ten_percent_buffer() {
        let estimator = PaymentEstimator::new(GATEWAY_ADDRESS.to_string());
        let header = estimator
            .build_payment_required(
                "https://api.example.com/usage".to_string(),
                "Usage endpoint".to_string(),
                Decimal::from_str("1.00").expect("cost decimal should parse"),
            )
            .expect("build payment required should succeed");

        let usdc_requirement = header
            .accepts
            .iter()
            .find(|req| req.asset.eq_ignore_ascii_case(USDC_ADDRESS))
            .expect("USDC payment option should exist");

        assert_eq!(usdc_requirement.scheme, "permit2");
        assert_eq!(usdc_requirement.amount, "1100000");
    }

    #[test]
    fn build_payment_required_includes_hypercore_usdc() {
        let estimator = PaymentEstimator::new(GATEWAY_ADDRESS.to_string());
        let header = estimator
            .build_payment_required(
                "https://api.example.com/usage".to_string(),
                "Usage endpoint".to_string(),
                Decimal::from_str("1.00").expect("cost decimal should parse"),
            )
            .expect("build payment required should succeed");

        let hypercore = header
            .accepts
            .iter()
            .find(|req| {
                req.scheme == "hypercore" && req.asset == "USDC:0x6d1e7cde53ba9467b783cb7c530ce054"
            })
            .expect("hypercore USDC payment option should exist");

        assert_eq!(hypercore.network, "hypercore:mainnet");
        assert_eq!(hypercore.asset, "USDC:0x6d1e7cde53ba9467b783cb7c530ce054");
        assert_eq!(hypercore.amount, "1100000");
    }

    #[test]
    fn build_payment_required_includes_hypercore_usdxl() {
        let estimator = PaymentEstimator::new(GATEWAY_ADDRESS.to_string());
        let header = estimator
            .build_payment_required(
                "https://api.example.com/usage".to_string(),
                "Usage endpoint".to_string(),
                Decimal::from_str("1.00").expect("cost decimal should parse"),
            )
            .expect("build payment required should succeed");

        let hypercore_usdxl = header
            .accepts
            .iter()
            .find(|req| {
                req.scheme == "hypercore" && req.asset == "USDXL:0xf448c3cad413cdf0feb1746d7b057967"
            })
            .expect("hypercore USDXL payment option should exist");

        assert_eq!(hypercore_usdxl.network, "hypercore:mainnet");
        assert_eq!(
            hypercore_usdxl.asset,
            "USDXL:0xf448c3cad413cdf0feb1746d7b057967"
        );
        assert_eq!(hypercore_usdxl.amount, "110");
    }

    #[test]
    fn build_payment_required_includes_hypercore_usdh() {
        let estimator = PaymentEstimator::new(GATEWAY_ADDRESS.to_string());
        let header = estimator
            .build_payment_required(
                "https://api.example.com/usage".to_string(),
                "Usage endpoint".to_string(),
                Decimal::from_str("1.00").expect("cost decimal should parse"),
            )
            .expect("build payment required should succeed");

        let hypercore_usdh = header
            .accepts
            .iter()
            .find(|req| {
                req.scheme == "hypercore" && req.asset == "USDH:0x54e00a5988577cb0b0c9ab0cb6ef7f4b"
            })
            .expect("hypercore USDH payment option should exist");

        assert_eq!(hypercore_usdh.network, "hypercore:mainnet");
        assert_eq!(
            hypercore_usdh.asset,
            "USDH:0x54e00a5988577cb0b0c9ab0cb6ef7f4b"
        );
        assert_eq!(hypercore_usdh.amount, "110");
    }

    #[test]
    fn estimate_cost_handles_zero_tokens() {
        let estimator = PaymentEstimator::new(GATEWAY_ADDRESS.to_string());
        let cost = estimator.estimate_cost(
            "gpt-4".to_string(),
            0,
            0,
            Decimal::from_str("0.00003").expect("input price should parse"),
            Decimal::from_str("0.00006").expect("output price should parse"),
        );

        assert_eq!(cost, Decimal::ZERO);
    }

    #[test]
    fn estimate_cost_handles_large_token_counts() {
        let estimator = PaymentEstimator::new(GATEWAY_ADDRESS.to_string());
        let cost = estimator.estimate_cost(
            "gpt-4".to_string(),
            1_000_000_000,
            2_000_000_000,
            Decimal::from_str("0.000001").expect("input price should parse"),
            Decimal::from_str("0.000002").expect("output price should parse"),
        );

        assert_eq!(
            cost,
            Decimal::from_str("5000").expect("expected decimal should parse")
        );
    }
}
