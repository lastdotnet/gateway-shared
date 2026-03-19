use std::{collections::HashMap, str::FromStr, sync::LazyLock};

use alloy::primitives::{Address, U256, address};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    pub address: Address,
    pub symbol: String,
    pub decimals: u8,
    pub chain: Chain,
    pub token_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub enum Chain {
    HyperEvm,
    HyperCore,
}

pub static TOKEN_REGISTRY: LazyLock<HashMap<String, TokenInfo>> = LazyLock::new(|| {
    let mut registry = HashMap::new();

    registry.insert(
        "USDXL_HYPEREVM".to_string(),
        TokenInfo {
            address: address!("ca79db4b49f608ef54a5cb813fbed3a6387bc645"),
            symbol: "USDXL".to_string(),
            decimals: 18,
            chain: Chain::HyperEvm,
            token_id: None,
        },
    );

    registry.insert(
        "USDC_HYPEREVM".to_string(),
        TokenInfo {
            address: address!("b88339cb7199b77e23db6e890353e22632ba630f"),
            symbol: "USDC".to_string(),
            decimals: 6,
            chain: Chain::HyperEvm,
            token_id: None,
        },
    );

    registry.insert(
        "USDT0_HYPEREVM".to_string(),
        TokenInfo {
            address: address!("b8ce59fc3717ada4c02eadf9682a9e934f625ebb"),
            symbol: "USDT0".to_string(),
            decimals: 6,
            chain: Chain::HyperEvm,
            token_id: None,
        },
    );

    registry.insert(
        "USDH_HYPEREVM".to_string(),
        TokenInfo {
            address: address!("111111a1a0667d36bd57c0a9f569b98057111111"),
            symbol: "USDH".to_string(),
            decimals: 6,
            chain: Chain::HyperEvm,
            token_id: None,
        },
    );

    registry.insert(
        "USDC_HYPERCORE".to_string(),
        TokenInfo {
            address: Address::ZERO,
            symbol: "USDC".to_string(),
            decimals: 6,
            chain: Chain::HyperCore,
            token_id: Some("0x6d1e7cde53ba9467b783cb7c530ce054".to_string()),
        },
    );

    registry.insert(
        "USDXL_HYPERCORE".to_string(),
        TokenInfo {
            address: Address::ZERO,
            symbol: "USDXL".to_string(),
            decimals: 2,
            chain: Chain::HyperCore,
            token_id: Some("0xf448c3cad413cdf0feb1746d7b057967".to_string()),
        },
    );

    registry.insert(
        "USDH_HYPERCORE".to_string(),
        TokenInfo {
            address: Address::ZERO,
            symbol: "USDH".to_string(),
            decimals: 2,
            chain: Chain::HyperCore,
            token_id: Some("0x54e00a5988577cb0b0c9ab0cb6ef7f4b".to_string()),
        },
    );

    registry
});

pub fn token_amount_to_usd(amount: U256, decimals: u8) -> Decimal {
    let parsed = match Decimal::from_str(&amount.to_string()) {
        Ok(value) => value,
        Err(_) => return Decimal::ZERO,
    };

    if decimals == 0 {
        return parsed;
    }

    let mut scale = Decimal::ONE;
    for _ in 0..decimals {
        scale *= Decimal::TEN;
    }

    parsed / scale
}

pub fn usd_to_token_amount(usd: Decimal, decimals: u8) -> U256 {
    if usd <= Decimal::ZERO {
        return U256::ZERO;
    }

    let mut scale = Decimal::ONE;
    for _ in 0..decimals {
        scale *= Decimal::TEN;
    }

    let scaled = (usd * scale).trunc();
    let scaled_str = scaled.to_string();

    match U256::from_str(&scaled_str) {
        Ok(value) => value,
        Err(_) => U256::ZERO,
    }
}

#[cfg(test)]
mod tests {
    use std::{panic, str::FromStr};

    use alloy::primitives::{U256, address};
    use rust_decimal::Decimal;

    use super::{Chain, TOKEN_REGISTRY, token_amount_to_usd, usd_to_token_amount};

    #[test]
    fn token_registry_contains_expected_entries_with_expected_metadata() {
        assert_eq!(TOKEN_REGISTRY.len(), 7);

        let usdxl = TOKEN_REGISTRY
            .get("USDXL_HYPEREVM")
            .expect("USDXL_HYPEREVM should exist in registry");
        assert_eq!(usdxl.symbol, "USDXL");
        assert_eq!(
            usdxl.address,
            address!("ca79db4b49f608ef54a5cb813fbed3a6387bc645")
        );
        assert_eq!(usdxl.decimals, 18);
        assert_eq!(usdxl.chain, Chain::HyperEvm);
        assert_eq!(usdxl.token_id, None);

        let usdc_hyperevm = TOKEN_REGISTRY
            .get("USDC_HYPEREVM")
            .expect("USDC_HYPEREVM should exist in registry");
        assert_eq!(usdc_hyperevm.symbol, "USDC");
        assert_eq!(
            usdc_hyperevm.address,
            address!("b88339cb7199b77e23db6e890353e22632ba630f")
        );
        assert_eq!(usdc_hyperevm.decimals, 6);
        assert_eq!(usdc_hyperevm.chain, Chain::HyperEvm);
        assert_eq!(usdc_hyperevm.token_id, None);

        let usdt0 = TOKEN_REGISTRY
            .get("USDT0_HYPEREVM")
            .expect("USDT0_HYPEREVM should exist in registry");
        assert_eq!(usdt0.symbol, "USDT0");
        assert_eq!(
            usdt0.address,
            address!("b8ce59fc3717ada4c02eadf9682a9e934f625ebb")
        );
        assert_eq!(usdt0.decimals, 6);
        assert_eq!(usdt0.chain, Chain::HyperEvm);
        assert_eq!(usdt0.token_id, None);

        let usdh_hyperevm = TOKEN_REGISTRY
            .get("USDH_HYPEREVM")
            .expect("USDH_HYPEREVM should exist in registry");
        assert_eq!(usdh_hyperevm.symbol, "USDH");
        assert_eq!(
            usdh_hyperevm.address,
            address!("111111a1a0667d36bd57c0a9f569b98057111111")
        );
        assert_eq!(usdh_hyperevm.decimals, 6);
        assert_eq!(usdh_hyperevm.chain, Chain::HyperEvm);
        assert_eq!(usdh_hyperevm.token_id, None);

        let usdc_hypercore = TOKEN_REGISTRY
            .get("USDC_HYPERCORE")
            .expect("USDC_HYPERCORE should exist in registry");
        assert_eq!(usdc_hypercore.symbol, "USDC");
        assert_eq!(usdc_hypercore.address, alloy::primitives::Address::ZERO);
        assert_eq!(usdc_hypercore.decimals, 6);
        assert_eq!(usdc_hypercore.chain, Chain::HyperCore);
        assert_eq!(
            usdc_hypercore.token_id.as_deref(),
            Some("0x6d1e7cde53ba9467b783cb7c530ce054")
        );

        let usdxl_hypercore = TOKEN_REGISTRY
            .get("USDXL_HYPERCORE")
            .expect("USDXL_HYPERCORE should exist in registry");
        assert_eq!(usdxl_hypercore.symbol, "USDXL");
        assert_eq!(usdxl_hypercore.address, alloy::primitives::Address::ZERO);
        assert_eq!(usdxl_hypercore.decimals, 2);
        assert_eq!(usdxl_hypercore.chain, Chain::HyperCore);
        assert_eq!(
            usdxl_hypercore.token_id.as_deref(),
            Some("0xf448c3cad413cdf0feb1746d7b057967")
        );

        let usdh_hypercore = TOKEN_REGISTRY
            .get("USDH_HYPERCORE")
            .expect("USDH_HYPERCORE should exist in registry");
        assert_eq!(usdh_hypercore.symbol, "USDH");
        assert_eq!(usdh_hypercore.address, alloy::primitives::Address::ZERO);
        assert_eq!(usdh_hypercore.decimals, 2);
        assert_eq!(usdh_hypercore.chain, Chain::HyperCore);
        assert_eq!(
            usdh_hypercore.token_id.as_deref(),
            Some("0x54e00a5988577cb0b0c9ab0cb6ef7f4b")
        );
    }

    #[test]
    fn token_amount_to_usd_converts_known_values() {
        assert_eq!(
            token_amount_to_usd(U256::from(1_000_000_000_000_000_000u128), 18),
            Decimal::ONE
        );
        assert_eq!(
            token_amount_to_usd(U256::from(1_000_000u64), 6),
            Decimal::ONE
        );
        assert_eq!(token_amount_to_usd(U256::ZERO, 18), Decimal::ZERO);
    }

    #[test]
    fn token_amount_to_usd_with_zero_decimals_returns_raw_amount() {
        assert_eq!(
            token_amount_to_usd(U256::from(42u64), 0),
            Decimal::from(42u64)
        );
    }

    #[test]
    fn token_amount_to_usd_returns_zero_for_values_too_large_for_decimal() {
        assert_eq!(token_amount_to_usd(U256::MAX, 18), Decimal::ZERO);
    }

    #[test]
    fn usd_to_token_amount_converts_known_values() {
        assert_eq!(
            usd_to_token_amount(Decimal::ONE, 18),
            U256::from(1_000_000_000_000_000_000u128)
        );
        assert_eq!(
            usd_to_token_amount(Decimal::ONE, 6),
            U256::from(1_000_000u64)
        );
    }

    #[test]
    fn usd_to_token_amount_round_trips_with_token_amount_to_usd() {
        let usd_six = Decimal::from_str("1234.567890").expect("valid decimal literal");
        let amount_six = usd_to_token_amount(usd_six, 6);
        let round_trip_six = token_amount_to_usd(amount_six, 6);
        assert_eq!(round_trip_six, usd_six);

        let usd_eighteen =
            Decimal::from_str("98765.123456789123456789").expect("valid decimal literal");
        let amount_eighteen = usd_to_token_amount(usd_eighteen, 18);
        let round_trip_eighteen = token_amount_to_usd(amount_eighteen, 18);
        assert_eq!(round_trip_eighteen, usd_eighteen);
    }

    #[test]
    fn usd_to_token_amount_handles_zero_decimal_negative_and_zero_values() {
        assert_eq!(usd_to_token_amount(Decimal::ZERO, 6), U256::ZERO);
        assert_eq!(usd_to_token_amount(Decimal::new(-1234, 2), 6), U256::ZERO);
        assert_eq!(
            usd_to_token_amount(
                Decimal::from_str("42.99").expect("valid decimal literal"),
                0
            ),
            U256::from(42u64)
        );
    }

    #[test]
    fn usd_to_token_amount_overflow_edge_case_panics_for_extreme_decimals() {
        let result = panic::catch_unwind(|| {
            let _ = usd_to_token_amount(Decimal::MAX, 40);
        });
        assert!(result.is_err());
    }
}
