use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Spot balance types ─────────────────────────────────────────────

/// Spot clearinghouse state with balances
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpotClearinghouseState {
    pub balances: Vec<SpotBalance>,
}

/// Individual spot balance entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpotBalance {
    pub coin: String,
    pub token: u32,
    pub hold: String,
    pub total: String,
    pub entry_ntl: String,
}

// ── Perps clearinghouse types ──────────────────────────────────────

/// Perps clearinghouse state (for perps USDC balance)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClearinghouseState {
    pub margin_summary: MarginSummary,
}

/// Margin summary from perps clearinghouse
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MarginSummary {
    pub account_value: String,
    pub total_margin_used: String,
    pub total_ntl_pos: String,
    pub total_raw_usd: String,
}

// ── Spot transfer events ───────────────────────────────────────────

/// Spot transfer event
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpotTransfer {
    pub usdc: String,
    pub user: String,
    pub destination: String,
    pub fee: String,
    pub nonce: u64,
    pub time: u64,
    pub hash: String,
}

// ── sendAsset action types (per x402 exact scheme spec) ────────────

/// HyperCore sendAsset action — matches the Hyperliquid exchange API format.
///
/// Ref: <https://gist.github.com/janklimo/ac7ef72e85fb20c8aaaf66124eb91d3e>
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendAssetAction {
    /// Always "sendAsset"
    #[serde(rename = "type")]
    pub action_type: String,
    /// "Mainnet" or "Testnet"
    pub hyperliquid_chain: String,
    /// Hex chain ID: "0x3e7" (mainnet/999) or "0x3e6" (testnet/998)
    pub signature_chain_id: String,
    /// 42-char hex recipient address
    pub destination: String,
    /// Source balance: "spot" for spot, "" for perps
    pub source_dex: String,
    /// Destination balance: "spot" for spot, "" for perps
    pub destination_dex: String,
    /// Token identifier: "USDC:0x6d1e7cde53ba9467b783cb7c530ce054"
    pub token: String,
    /// Human-readable amount: "1.5"
    pub amount: String,
    /// Always "" — sub-account transfers not supported
    pub from_sub_account: String,
    /// Millisecond timestamp acting as nonce
    pub nonce: u64,
}

/// Signed sendAsset action for exchange API submission
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedAction {
    pub action: SendAssetAction,
    /// Must equal action.nonce
    pub nonce: u64,
    pub signature: HyperCoreSignature,
}

/// EIP-712 signature components
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HyperCoreSignature {
    pub r: String,
    pub s: String,
    pub v: u8,
}

// ── x402 v2 payment types for HyperCore exact scheme ──────────────

/// The action portion of the x402 PaymentPayload for HyperCore.
/// This is what the client signed and what gets verified.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HyperCorePaymentAction {
    pub destination: String,
    pub source_dex: String,
    pub destination_dex: String,
    pub token: String,
    pub amount: String,
    pub nonce: u64,
}

/// The payload field of the x402 PaymentPayload for HyperCore
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HyperCorePaymentPayload {
    pub signature: HyperCoreSignature,
    pub action: HyperCorePaymentAction,
}

/// Resource information in x402 header
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HyperCoreResource {
    pub url: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// Extra fields in payment requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HyperCoreExtra {
    /// Destination balance — "spot" (default) or "" (perps)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_dex: Option<String>,
}

/// Payment requirements in x402 header for HyperCore exact scheme
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HyperCorePaymentRequirement {
    /// Must be "exact"
    pub scheme: String,
    /// "hyperliquid:mainnet" or "hyperliquid:testnet"
    pub network: String,
    pub amount: String,
    /// Token identifier: "USDC:0x6d1e7cde53ba9467b783cb7c530ce054"
    pub asset: String,
    /// 42-char hex recipient address
    pub pay_to: String,
    pub max_timeout_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<HyperCoreExtra>,
}

/// Full x402 v2 payment header for HyperCore exact scheme
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HyperCorePaymentHeader {
    /// Must be 2
    pub x402_version: u8,
    pub resource: HyperCoreResource,
    pub accepted: HyperCorePaymentRequirement,
    pub payload: HyperCorePaymentPayload,
}

/// Settlement result returned after verification + submission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HyperCoreSettlementResult {
    pub success: bool,
    pub network: String,
    /// Address recovered from EIP-712 signature
    pub payer: String,
    /// Empty string — sendAsset doesn't return a tx hash
    pub transaction: String,
}

/// WebSocket subscription request
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WsSubscription {
    pub method: String,
    pub subscription: WsSubType,
}

/// WebSocket subscription type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WsSubType {
    #[serde(rename = "userEvents")]
    UserEvents { user: String },
    #[serde(rename = "userFills")]
    UserFills { user: String },
}

/// WebSocket event from server
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WsEvent {
    #[serde(rename_all = "camelCase")]
    UserEvents {
        channel: String,
        #[serde(default)]
        data: UserEventsData,
    },
    #[serde(rename_all = "camelCase")]
    SubscriptionResponse {
        channel: String,
        data: Value,
    },
    Unknown(Value),
}

/// User events data wrapper
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserEventsData {
    pub events: Vec<UserEvent>,
}

/// Individual user event
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum UserEvent {
    #[serde(rename = "spotTransfer")]
    SpotTransfer(SpotTransfer),
    #[serde(other)]
    Other,
}

// ── Constants ──────────────────────────────────────────────────────

pub const MAINNET_CHAIN_ID: u64 = 999;
pub const TESTNET_CHAIN_ID: u64 = 998;
pub const MAINNET_CHAIN_ID_HEX: &str = "0x3e7";
pub const TESTNET_CHAIN_ID_HEX: &str = "0x3e6";
pub const MAINNET_API_URL: &str = "https://api.hyperliquid.xyz";
pub const TESTNET_API_URL: &str = "https://api.hyperliquid-testnet.xyz";
pub const CLOCK_SKEW_TOLERANCE_MS: u64 = 5_000;

pub fn chain_id_for_network(network: &str) -> Option<u64> {
    match network {
        "hyperliquid:mainnet" => Some(MAINNET_CHAIN_ID),
        "hyperliquid:testnet" => Some(TESTNET_CHAIN_ID),
        _ => None,
    }
}

pub fn hyperliquid_chain_for_network(network: &str) -> Option<&'static str> {
    match network {
        "hyperliquid:mainnet" => Some("Mainnet"),
        "hyperliquid:testnet" => Some("Testnet"),
        _ => None,
    }
}

pub fn api_url_for_network(network: &str) -> Option<&'static str> {
    match network {
        "hyperliquid:mainnet" => Some(MAINNET_API_URL),
        "hyperliquid:testnet" => Some(TESTNET_API_URL),
        _ => None,
    }
}

pub fn signature_chain_id_for_network(network: &str) -> Option<&'static str> {
    match network {
        "hyperliquid:mainnet" => Some(MAINNET_CHAIN_ID_HEX),
        "hyperliquid:testnet" => Some(TESTNET_CHAIN_ID_HEX),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spot_transfer_serde_round_trip() {
        let transfer = SpotTransfer {
            usdc: "1250.50".to_string(),
            user: "0x1111222233334444555566667777888899990000".to_string(),
            destination: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            fee: "0.0025".to_string(),
            nonce: 1_735_000_123,
            time: 1_735_000_456,
            hash: "0xabcdef".to_string(),
        };
        let json = serde_json::to_string(&transfer).expect("serialize");
        let decoded: SpotTransfer = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.usdc, transfer.usdc);
        assert_eq!(decoded.nonce, transfer.nonce);
    }

    #[test]
    fn spot_balance_serde_round_trip() {
        let balance = SpotBalance {
            coin: "USDC".to_string(),
            token: 0,
            hold: "5.10".to_string(),
            total: "100.25".to_string(),
            entry_ntl: "0.00".to_string(),
        };
        let json = serde_json::to_string(&balance).expect("serialize");
        let decoded: SpotBalance = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.coin, balance.coin);
        assert_eq!(decoded.total, balance.total);
    }

    #[test]
    fn send_asset_action_serializes_to_spec_field_names() {
        let action = SendAssetAction {
            action_type: "sendAsset".to_string(),
            hyperliquid_chain: "Mainnet".to_string(),
            signature_chain_id: "0x3e7".to_string(),
            destination: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C".to_string(),
            source_dex: "spot".to_string(),
            destination_dex: "spot".to_string(),
            token: "USDC:0x6d1e7cde53ba9467b783cb7c530ce054".to_string(),
            amount: "1.5".to_string(),
            from_sub_account: String::new(),
            nonce: 1716531066415,
        };

        let value = serde_json::to_value(&action).expect("serialize");
        assert_eq!(value["type"], "sendAsset");
        assert_eq!(value["hyperliquidChain"], "Mainnet");
        assert_eq!(value["signatureChainId"], "0x3e7");
        assert_eq!(value["sourceDex"], "spot");
        assert_eq!(value["destinationDex"], "spot");
        assert_eq!(value["fromSubAccount"], "");
        assert_eq!(value["nonce"], 1716531066415_u64);
        assert!(value.get("actionType").is_none());
    }

    #[test]
    fn signed_action_matches_exchange_api_format() {
        let signed = SignedAction {
            action: SendAssetAction {
                action_type: "sendAsset".to_string(),
                hyperliquid_chain: "Mainnet".to_string(),
                signature_chain_id: "0x3e7".to_string(),
                destination: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C".to_string(),
                source_dex: "spot".to_string(),
                destination_dex: "spot".to_string(),
                token: "USDC:0x6d1e7cde53ba9467b783cb7c530ce054".to_string(),
                amount: "1.5".to_string(),
                from_sub_account: String::new(),
                nonce: 1716531066415,
            },
            nonce: 1716531066415,
            signature: HyperCoreSignature {
                r: "0x2d6a".to_string(),
                s: "0xa2ce".to_string(),
                v: 28,
            },
        };

        let value = serde_json::to_value(&signed).expect("serialize");
        assert_eq!(value["action"]["type"], "sendAsset");
        assert_eq!(value["nonce"], 1716531066415_u64);
        assert_eq!(value["signature"]["v"], 28);
    }

    #[test]
    fn hypercore_payment_header_round_trip() {
        let header = HyperCorePaymentHeader {
            x402_version: 2,
            resource: HyperCoreResource {
                url: "https://example.com/data".to_string(),
                description: "Premium data".to_string(),
                mime_type: Some("application/json".to_string()),
            },
            accepted: HyperCorePaymentRequirement {
                scheme: "exact".to_string(),
                network: "hyperliquid:mainnet".to_string(),
                amount: "1.5".to_string(),
                asset: "USDC:0x6d1e7cde53ba9467b783cb7c530ce054".to_string(),
                pay_to: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C".to_string(),
                max_timeout_seconds: 60,
                extra: Some(HyperCoreExtra {
                    destination_dex: Some("spot".to_string()),
                }),
            },
            payload: HyperCorePaymentPayload {
                signature: HyperCoreSignature {
                    r: "0xaaa".to_string(),
                    s: "0xbbb".to_string(),
                    v: 27,
                },
                action: HyperCorePaymentAction {
                    destination: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C".to_string(),
                    source_dex: "spot".to_string(),
                    destination_dex: "spot".to_string(),
                    token: "USDC:0x6d1e7cde53ba9467b783cb7c530ce054".to_string(),
                    amount: "1.5".to_string(),
                    nonce: 1716531066415,
                },
            },
        };

        let json = serde_json::to_string(&header).expect("serialize");
        let decoded: HyperCorePaymentHeader = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.x402_version, 2);
        assert_eq!(decoded.accepted.scheme, "exact");
        assert_eq!(decoded.accepted.network, "hyperliquid:mainnet");
        assert_eq!(decoded.payload.action.nonce, 1716531066415);
    }

    #[test]
    fn network_helpers() {
        assert_eq!(chain_id_for_network("hyperliquid:mainnet"), Some(999));
        assert_eq!(chain_id_for_network("hyperliquid:testnet"), Some(998));
        assert_eq!(chain_id_for_network("eip155:999"), None);
        assert_eq!(
            hyperliquid_chain_for_network("hyperliquid:mainnet"),
            Some("Mainnet")
        );
        assert_eq!(
            api_url_for_network("hyperliquid:mainnet"),
            Some("https://api.hyperliquid.xyz")
        );
        assert_eq!(
            signature_chain_id_for_network("hyperliquid:mainnet"),
            Some("0x3e7")
        );
    }

    #[test]
    fn clearinghouse_state_deserializes() {
        let raw = r#"{
            "marginSummary": {
                "accountValue": "1000.50",
                "totalMarginUsed": "200.00",
                "totalNtlPos": "500.00",
                "totalRawUsd": "800.50"
            }
        }"#;
        let state: ClearinghouseState = serde_json::from_str(raw).expect("deserialize");
        assert_eq!(state.margin_summary.account_value, "1000.50");
    }

    #[test]
    fn ws_subscription_serializes_user_events() {
        let subscription = WsSubscription {
            method: "subscribe".to_string(),
            subscription: WsSubType::UserEvents {
                user: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            },
        };
        let value = serde_json::to_value(&subscription).expect("serialize");
        assert_eq!(value["subscription"]["type"], "userEvents");
    }
}
