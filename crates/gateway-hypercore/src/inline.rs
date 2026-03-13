use std::{str::FromStr, time::{SystemTime, UNIX_EPOCH}};

use alloy::{
    dyn_abi::Eip712Domain,
    primitives::{Address, PrimitiveSignature, keccak256},
    sol_types::{SolValue, eip712_domain},
};
use gateway_common::error::{GatewayError, GatewayResult};
use rust_decimal::Decimal;

use crate::{
    client::HyperCoreClient,
    types::{
        HyperCorePaymentAction, HyperCorePaymentHeader, HyperCorePaymentPayload,
        HyperCorePaymentRequirement, HyperCoreSettlementResult, SendAssetAction, SignedAction,
        CLOCK_SKEW_TOLERANCE_MS, HyperCoreSignature, chain_id_for_network,
        hyperliquid_chain_for_network, signature_chain_id_for_network,
    },
};

const EXACT_SCHEME: &str = "exact";
const SPOT_DEX: &str = "spot";
const PERPS_DEX: &str = "";
const SEND_ASSET_PRIMARY_TYPE: &str = "HyperliquidTransaction:SendAsset(string hyperliquidChain,string destination,string sourceDex,string destinationDex,string token,string amount,string fromSubAccount,uint64 nonce)";

pub struct HyperCoreInlineVerifier {
    client: HyperCoreClient,
    gateway_address: String,
}

impl HyperCoreInlineVerifier {
    pub fn new(client: HyperCoreClient, gateway_address: impl Into<String>) -> Self {
        Self {
            client,
            gateway_address: gateway_address.into(),
        }
    }

    pub async fn verify_and_settle(
        &self,
        payment: &HyperCorePaymentHeader,
    ) -> GatewayResult<HyperCoreSettlementResult> {
        validate_protocol(payment)?;
        validate_requirement_destination(&payment.accepted, &self.gateway_address)?;
        validate_transfer_correctness(&payment.payload.action, &payment.accepted)?;
        validate_temporal_validity(
            payment.payload.action.nonce,
            payment.accepted.max_timeout_seconds,
        )?;

        let payer = recover_eip712_signer(
            &payment.accepted.network,
            &payment.payload.action,
            &payment.payload.signature,
        )?;

        verify_balance(&self.client, &payer, &payment.payload.action).await?;

        let signed_action = build_signed_action(&payment.accepted.network, &payment.payload)?;
        self.client.submit_action(&signed_action).await?;

        Ok(HyperCoreSettlementResult {
            success: true,
            network: payment.accepted.network.clone(),
            payer,
            transaction: String::new(),
        })
    }

    pub async fn verify_and_submit(
        &self,
        payment: &HyperCorePaymentHeader,
    ) -> GatewayResult<HyperCoreSettlementResult> {
        self.verify_and_settle(payment).await
    }
}

fn validate_protocol(payment: &HyperCorePaymentHeader) -> GatewayResult<()> {
    if payment.x402_version != 2 {
        return Err(GatewayError::Payment(format!(
            "Invalid x402Version: expected 2, got {}",
            payment.x402_version
        )));
    }

    if payment.accepted.scheme != EXACT_SCHEME {
        return Err(GatewayError::Payment(format!(
            "Invalid payment scheme: expected exact, got {}",
            payment.accepted.scheme
        )));
    }

    if chain_id_for_network(&payment.accepted.network).is_none() {
        return Err(GatewayError::Payment(format!(
            "Unsupported network: {}",
            payment.accepted.network
        )));
    }

    Ok(())
}

fn validate_requirement_destination(
    requirement: &HyperCorePaymentRequirement,
    gateway_address: &str,
) -> GatewayResult<()> {
    let expected = parse_hex_address(gateway_address, "Invalid gateway address")?;
    let pay_to = parse_hex_address(&requirement.pay_to, "Invalid HyperCore payTo address")?;

    if pay_to != expected {
        return Err(GatewayError::Payment(
            "Payment requirement payTo does not match gateway address".to_string(),
        ));
    }

    Ok(())
}

fn validate_transfer_correctness(
    action: &HyperCorePaymentAction,
    requirement: &HyperCorePaymentRequirement,
) -> GatewayResult<()> {
    if action.token != requirement.asset {
        return Err(GatewayError::Payment(format!(
            "Token mismatch: expected {}, got {}",
            requirement.asset, action.token
        )));
    }

    if action.amount != requirement.amount {
        return Err(GatewayError::Payment(format!(
            "Amount mismatch: expected {}, got {}",
            requirement.amount, action.amount
        )));
    }

    let destination = parse_hex_address(&action.destination, "Invalid HyperCore destination address")?;
    let pay_to = parse_hex_address(&requirement.pay_to, "Invalid HyperCore payTo address")?;
    if destination != pay_to {
        return Err(GatewayError::Payment(format!(
            "Destination mismatch: expected {}, got {}",
            requirement.pay_to, action.destination
        )));
    }

    let expected_destination_dex = requirement
        .extra
        .as_ref()
        .and_then(|extra| extra.destination_dex.as_deref())
        .unwrap_or(SPOT_DEX);
    if action.destination_dex != expected_destination_dex {
        return Err(GatewayError::Payment(format!(
            "destinationDex mismatch: expected {expected_destination_dex}, got {}",
            action.destination_dex
        )));
    }

    if action.source_dex != SPOT_DEX && action.source_dex != PERPS_DEX {
        return Err(GatewayError::Payment(format!(
            "Invalid sourceDex: {}",
            action.source_dex
        )));
    }

    Ok(())
}

fn validate_temporal_validity(nonce: u64, max_timeout_seconds: u64) -> GatewayResult<()> {
    let current_time_ms = current_time_ms()?;

    if current_time_ms.saturating_sub(nonce) > max_timeout_seconds.saturating_mul(1_000) {
        return Err(GatewayError::Payment(format!(
            "Payment nonce expired: currentTimeMs={current_time_ms}, nonce={nonce}",
        )));
    }

    if nonce.saturating_sub(current_time_ms) > CLOCK_SKEW_TOLERANCE_MS {
        return Err(GatewayError::Payment(format!(
            "Payment nonce is too far in the future: currentTimeMs={current_time_ms}, nonce={nonce}",
        )));
    }

    Ok(())
}

async fn verify_balance(
    client: &HyperCoreClient,
    payer: &str,
    action: &HyperCorePaymentAction,
) -> GatewayResult<()> {
    let required_amount = parse_decimal(&action.amount, "HyperCore action amount")?;
    let token_symbol = token_symbol(&action.token)?;

    match action.source_dex.as_str() {
        SPOT_DEX => {
            let state = client.get_spot_balances(payer).await?;
            let balance = state
                .balances
                .iter()
                .find(|balance| balance.coin == token_symbol)
                .map(|balance| parse_decimal(&balance.total, "HyperCore spot balance"))
                .transpose()?
                .unwrap_or(Decimal::ZERO);

            if balance < required_amount {
                return Err(GatewayError::Payment(format!(
                    "Insufficient spot balance: required {required_amount}, available {balance}",
                )));
            }
        }
        PERPS_DEX => {
            if token_symbol != "USDC" {
                return Err(GatewayError::Payment(
                    "Perps sourceDex only supports USDC transfers".to_string(),
                ));
            }

            let state = client.get_perps_balance(payer).await?;
            let account_value = parse_decimal(
                &state.margin_summary.account_value,
                "HyperCore perps accountValue",
            )?;
            let total_margin_used = parse_decimal(
                &state.margin_summary.total_margin_used,
                "HyperCore perps totalMarginUsed",
            )?;
            let withdrawable = account_value - total_margin_used;

            if withdrawable < required_amount {
                return Err(GatewayError::Payment(format!(
                    "Insufficient perps balance: required {required_amount}, available {withdrawable}",
                )));
            }
        }
        other => {
            return Err(GatewayError::Payment(format!("Invalid sourceDex: {other}")));
        }
    }

    Ok(())
}

fn build_signed_action(
    network: &str,
    payload: &HyperCorePaymentPayload,
) -> GatewayResult<SignedAction> {
    let hyperliquid_chain = hyperliquid_chain_for_network(network)
        .ok_or_else(|| GatewayError::Payment(format!("Unsupported network: {network}")))?;
    let signature_chain_id = signature_chain_id_for_network(network)
        .ok_or_else(|| GatewayError::Payment(format!("Unsupported network: {network}")))?;

    Ok(SignedAction {
        action: SendAssetAction {
            action_type: "sendAsset".to_string(),
            hyperliquid_chain: hyperliquid_chain.to_string(),
            signature_chain_id: signature_chain_id.to_string(),
            destination: payload.action.destination.clone(),
            source_dex: payload.action.source_dex.clone(),
            destination_dex: payload.action.destination_dex.clone(),
            token: payload.action.token.clone(),
            amount: payload.action.amount.clone(),
            from_sub_account: String::new(),
            nonce: payload.action.nonce,
        },
        nonce: payload.action.nonce,
        signature: payload.signature.clone(),
    })
}

fn recover_eip712_signer(
    network: &str,
    action: &HyperCorePaymentAction,
    signature: &HyperCoreSignature,
) -> GatewayResult<String> {
    let digest = send_asset_signing_hash(network, action)?;
    let signature = primitive_signature(signature)?;
    let payer = signature
        .recover_address_from_prehash(&digest)
        .map_err(|error| GatewayError::Payment(format!("Signature recovery failed: {error}")))?;

    Ok(format!("{payer:#x}"))
}

fn eip712_domain(chain_id: u64) -> Eip712Domain {
    eip712_domain! {
        name: "HyperliquidSignTransaction",
        version: "1",
        chain_id: chain_id,
        verifying_contract: Address::ZERO,
    }
}

fn send_asset_signing_hash(
    network: &str,
    action: &HyperCorePaymentAction,
) -> GatewayResult<alloy::primitives::B256> {
    let chain_id = chain_id_for_network(network)
        .ok_or_else(|| GatewayError::Payment(format!("Unsupported network: {network}")))?;
    let hyperliquid_chain = hyperliquid_chain_for_network(network)
        .ok_or_else(|| GatewayError::Payment(format!("Unsupported network: {network}")))?;

    let domain = eip712_domain(chain_id);
    let struct_hash = send_asset_struct_hash(hyperliquid_chain, action);

    let mut digest_bytes = Vec::with_capacity(66);
    digest_bytes.extend_from_slice(&[0x19, 0x01]);
    digest_bytes.extend_from_slice(domain.separator().as_slice());
    digest_bytes.extend_from_slice(struct_hash.as_slice());
    Ok(keccak256(digest_bytes))
}

fn send_asset_struct_hash(hyperliquid_chain: &str, action: &HyperCorePaymentAction) -> alloy::primitives::B256 {
    let items = (
        keccak256(SEND_ASSET_PRIMARY_TYPE),
        keccak256(hyperliquid_chain),
        keccak256(&action.destination),
        keccak256(&action.source_dex),
        keccak256(&action.destination_dex),
        keccak256(&action.token),
        keccak256(&action.amount),
        keccak256(""),
        &action.nonce,
    );

    keccak256(items.abi_encode())
}

fn primitive_signature(signature: &HyperCoreSignature) -> GatewayResult<PrimitiveSignature> {
    let r = decode_signature_component(&signature.r, "r")?;
    let s = decode_signature_component(&signature.s, "s")?;

    let mut raw = [0u8; 65];
    raw[..32].copy_from_slice(&r);
    raw[32..64].copy_from_slice(&s);
    raw[64] = signature.v;

    PrimitiveSignature::from_raw_array(&raw)
        .map_err(|error| GatewayError::Payment(format!("Invalid HyperCore signature: {error}")))
}

fn decode_signature_component(value: &str, name: &str) -> GatewayResult<[u8; 32]> {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|_| GatewayError::Payment(format!("Invalid signature {name}")))?;

    if bytes.len() != 32 {
        return Err(GatewayError::Payment(format!(
            "Invalid signature {name}: expected 32 bytes, got {}",
            bytes.len()
        )));
    }

    let mut output = [0u8; 32];
    output.copy_from_slice(&bytes);
    Ok(output)
}

fn parse_hex_address(value: &str, error: &str) -> GatewayResult<Address> {
    let normalized = value.strip_prefix("0x").unwrap_or(value);
    Address::from_str(normalized).map_err(|_| GatewayError::Payment(error.to_string()))
}

fn parse_decimal(value: &str, field: &str) -> GatewayResult<Decimal> {
    Decimal::from_str(value)
        .map_err(|_| GatewayError::Payment(format!("Invalid {field}: {value}")))
}

fn token_symbol(token: &str) -> GatewayResult<&str> {
    token
        .split_once(':')
        .map(|(symbol, _)| symbol)
        .ok_or_else(|| GatewayError::Payment(format!("Invalid HyperCore token identifier: {token}")))
}

fn current_time_ms() -> GatewayResult<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| GatewayError::Internal("Failed to get current time".to_string()))?
        .as_millis() as u64)
}

#[cfg(test)]
mod tests {}
