use std::sync::Arc;

use alloy::primitives::{Address, B256, U256, keccak256};
use alloy::providers::{Provider, ProviderBuilder, WsConnect};
use alloy::rpc::types::Filter;
use gateway_common::{GatewayError, GatewayResult, TOKEN_REGISTRY, token_amount_to_usd};
use serde_json::Value;
use tokio_stream::StreamExt;

use crate::{credits::CreditService, deposits::DepositService};

#[derive(Clone, Debug)]
pub struct EvmDepositWatcher {
    pub rpc_url: String,
    pub chain_id: u64,
    pub gateway_address: Address,
    pub watched_token_addresses: Vec<Address>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ParsedTransferLog {
    token_address: Address,
    from: Address,
    to: Address,
    amount: U256,
    tx_hash: String,
}

impl EvmDepositWatcher {
    pub fn new(
        rpc_url: impl Into<String>,
        chain_id: u64,
        gateway_address: Address,
        watched_token_addresses: Vec<Address>,
    ) -> Self {
        Self {
            rpc_url: rpc_url.into(),
            chain_id,
            gateway_address,
            watched_token_addresses,
        }
    }

    pub async fn watch(
        &self,
        deposit_service: Arc<DepositService>,
        credit_service: Arc<CreditService>,
    ) -> GatewayResult<()> {
        let ws = WsConnect::new(self.rpc_url.clone());
        let provider =
            ProviderBuilder::new()
                .connect_ws(ws)
                .await
                .map_err(|err| GatewayError::Provider {
                    provider: "EVM Watcher".to_string(),
                    message: format!("Failed to connect websocket provider: {err}"),
                })?;

        let filter = build_transfer_filter(self.gateway_address, &self.watched_token_addresses);
        let subscription =
            provider
                .subscribe_logs(&filter)
                .await
                .map_err(|err| GatewayError::Provider {
                    provider: "EVM Watcher".to_string(),
                    message: format!("Failed to subscribe logs: {err}"),
                })?;

        let mut stream = subscription.into_stream();

        while let Some(log) = stream.next().await {
            let parsed = match extract_transfer_log(log) {
                Some(parsed) => parsed,
                None => continue,
            };

            if parsed.to != self.gateway_address {
                continue;
            }

            let Some(token_info) = TOKEN_REGISTRY
                .values()
                .find(|info| info.address == parsed.token_address)
            else {
                continue;
            };

            let amount_usd = token_amount_to_usd(parsed.amount, token_info.decimals);
            if amount_usd <= rust_decimal::Decimal::ZERO {
                continue;
            }

            let from_address = format!("{:#x}", parsed.from);
            let Some(account_id) = deposit_service
                .find_account_by_evm_address(&from_address)
                .await?
            else {
                continue;
            };

            let deposit_id = deposit_service
                .record_deposit(
                    account_id.clone(),
                    "hyperevm",
                    &parsed.tx_hash,
                    Some(&format!("{:#x}", parsed.token_address)),
                    &parsed.amount.to_string(),
                    amount_usd,
                )
                .await?;

            let _ = deposit_service
                .credit_deposit(&credit_service, account_id, deposit_id, amount_usd)
                .await?;
        }

        Ok(())
    }
}

fn transfer_event_topic() -> B256 {
    keccak256("Transfer(address,address,uint256)")
}

fn build_transfer_filter(gateway_address: Address, watched_token_addresses: &[Address]) -> Filter {
    Filter::new()
        .address(watched_token_addresses.to_vec())
        .event_signature(transfer_event_topic())
        .topic2(gateway_address.into_word())
}

fn extract_transfer_log<T>(log: T) -> Option<ParsedTransferLog>
where
    T: serde::Serialize,
{
    let json = serde_json::to_value(log).ok()?;
    extract_transfer_log_from_value(&json)
}

fn extract_transfer_log_from_value(value: &Value) -> Option<ParsedTransferLog> {
    let tx_hash = value
        .get("transactionHash")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| {
            value
                .get("transaction_hash")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })?;

    let token_address = value
        .get("address")
        .and_then(Value::as_str)
        .and_then(parse_address)?;

    let topics = value.get("topics")?.as_array()?;
    if topics.len() < 3 {
        return None;
    }

    let topic0 = topics[0].as_str()?;
    if parse_b256(topic0)? != transfer_event_topic() {
        return None;
    }

    let from = parse_topic_address(topics[1].as_str()?)?;
    let to = parse_topic_address(topics[2].as_str()?)?;

    let data = value.get("data").and_then(Value::as_str)?;
    let amount = parse_u256(data)?;

    Some(ParsedTransferLog {
        token_address,
        from,
        to,
        amount,
        tx_hash,
    })
}

fn parse_address(value: &str) -> Option<Address> {
    value.parse().ok()
}

fn parse_b256(value: &str) -> Option<B256> {
    value.parse().ok()
}

fn parse_topic_address(topic: &str) -> Option<Address> {
    let normalized = topic.strip_prefix("0x").unwrap_or(topic);
    if normalized.len() != 64 {
        return None;
    }

    let address_hex = &normalized[24..64];
    parse_address(&format!("0x{address_hex}"))
}

fn parse_u256(data: &str) -> Option<U256> {
    let normalized = data.strip_prefix("0x").unwrap_or(data);
    U256::from_str_radix(normalized, 16).ok()
}

#[cfg(test)]
mod tests {
    use alloy::primitives::address;
    use serde_json::json;

    use super::*;

    fn transfer_topic_hex() -> String {
        format!("{:#x}", transfer_event_topic())
    }

    fn transfer_topic_word(addr: Address) -> String {
        format!("0x{:0>64}", hex::encode(addr.as_slice()))
    }

    #[test]
    fn watcher_constructor_sets_fields() {
        let watcher = EvmDepositWatcher::new(
            "ws://localhost:8545",
            999,
            address!("1111111111111111111111111111111111111111"),
            vec![address!("b88339cb7199b77e23db6e890353e22632ba630f")],
        );

        assert_eq!(watcher.rpc_url, "ws://localhost:8545");
        assert_eq!(watcher.chain_id, 999);
        assert_eq!(watcher.watched_token_addresses.len(), 1);
    }

    #[test]
    fn transfer_topic_matches_expected_keccak() {
        assert_eq!(
            format!("{:#x}", transfer_event_topic()),
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        );
    }

    #[test]
    fn parse_topic_address_extracts_last_20_bytes() {
        let topic = "0x0000000000000000000000001111111111111111111111111111111111111111";
        let parsed = parse_topic_address(topic).expect("topic should parse");
        assert_eq!(
            format!("{:#x}", parsed),
            "0x1111111111111111111111111111111111111111"
        );
    }

    #[test]
    fn parse_topic_address_rejects_wrong_length() {
        assert!(parse_topic_address("0x1234").is_none());
    }

    #[test]
    fn parse_u256_parses_hex_values() {
        let amount = parse_u256("0x0de0b6b3a7640000").expect("u256 should parse");
        assert_eq!(amount, U256::from(1_000_000_000_000_000_000_u128));
    }

    #[test]
    fn parse_u256_rejects_invalid_hex() {
        assert!(parse_u256("0xgg").is_none());
    }

    #[test]
    fn extract_transfer_log_from_valid_value() {
        let token = "0xb88339cb7199b77e23db6e890353e22632ba630f";
        let from = address!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let to = address!("1111111111111111111111111111111111111111");

        let value = json!({
            "address": token,
            "topics": [
                transfer_topic_hex(),
                transfer_topic_word(from),
                transfer_topic_word(to)
            ],
            "data": "0x00000000000000000000000000000000000000000000000000000000000f4240",
            "transactionHash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        });

        let parsed = extract_transfer_log_from_value(&value).expect("log should parse");
        assert_eq!(format!("{:#x}", parsed.token_address), token);
        assert_eq!(parsed.from, from);
        assert_eq!(parsed.to, to);
        assert_eq!(parsed.amount, U256::from(1_000_000_u64));
    }

    #[test]
    fn extract_transfer_log_rejects_non_transfer_topic() {
        let value = json!({
            "address": "0xb88339cb7199b77e23db6e890353e22632ba630f",
            "topics": [
                "0x0000000000000000000000000000000000000000000000000000000000000000",
                "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "0x0000000000000000000000001111111111111111111111111111111111111111"
            ],
            "data": "0x00",
            "transactionHash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        });

        assert!(extract_transfer_log_from_value(&value).is_none());
    }

    #[test]
    fn extract_transfer_log_rejects_missing_topics() {
        let value = json!({
            "address": "0xb88339cb7199b77e23db6e890353e22632ba630f",
            "topics": [transfer_topic_hex()],
            "data": "0x01",
            "transactionHash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        });

        assert!(extract_transfer_log_from_value(&value).is_none());
    }

    #[test]
    fn extract_transfer_log_accepts_snake_case_transaction_hash() {
        let value = json!({
            "address": "0xb88339cb7199b77e23db6e890353e22632ba630f",
            "topics": [
                transfer_topic_hex(),
                "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "0x0000000000000000000000001111111111111111111111111111111111111111"
            ],
            "data": "0x0000000000000000000000000000000000000000000000000000000000000001",
            "transaction_hash": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        });

        let parsed = extract_transfer_log_from_value(&value).expect("log should parse");
        assert_eq!(
            parsed.tx_hash,
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }

    #[test]
    fn build_filter_includes_watched_tokens() {
        let gateway = address!("1111111111111111111111111111111111111111");
        let tokens = vec![
            address!("b88339cb7199b77e23db6e890353e22632ba630f"),
            address!("ca79db4b49f608ef54a5cb813fbed3a6387bc645"),
        ];

        let filter = build_transfer_filter(gateway, &tokens);
        let filter_json = serde_json::to_string(&filter).expect("filter should serialize");

        assert!(filter_json.contains("b88339cb7199b77e23db6e890353e22632ba630f"));
        assert!(filter_json.contains("ca79db4b49f608ef54a5cb813fbed3a6387bc645"));
    }
}
