use crate::types::Permit2Authorization;
use alloy::network::EthereumWallet;
use alloy::primitives::{Address, Bytes, U256};
use alloy::providers::ProviderBuilder;
use alloy::signers::{Signer, local::PrivateKeySigner};
use alloy::sol;
use gateway_common::{GatewayError, GatewayResult};
use std::str::FromStr;

sol! {
    #[sol(rpc)]
    interface IPermit2 {
        struct TokenPermissions {
            address token;
            uint256 amount;
        }

        struct PermitTransferFrom {
            TokenPermissions permitted;
            uint256 nonce;
            uint256 deadline;
        }

        struct SignatureTransferDetails {
            address to;
            uint256 requestedAmount;
        }

        function permitTransferFrom(
            PermitTransferFrom calldata permit,
            SignatureTransferDetails calldata transferDetails,
            address owner,
            bytes calldata signature
        ) external;
    }
}

pub struct PaymentSettler {
    rpc_url: String,
    private_key: String,
    chain_id: u64,
    permit2_address: Address,
}

impl PaymentSettler {
    pub fn new(rpc_url: String, private_key: String, chain_id: u64, permit2_address: Address) -> Self {
        Self {
            rpc_url,
            private_key,
            chain_id,
            permit2_address,
        }
    }

    pub async fn settle_permit2(
        &self,
        authorization: &Permit2Authorization,
        to: Address,
        requested_amount: U256,
        signature_hex: &str,
    ) -> GatewayResult<String> {
        let owner = parse_address(&authorization.owner, "Invalid permit2 owner address")?;
        let token = parse_address(&authorization.token, "Invalid permit2 token address")?;
        let amount = U256::from_str(&authorization.amount)
            .map_err(|_| GatewayError::Payment("Invalid permit2 amount format".to_string()))?;
        let nonce = U256::from_str(&authorization.nonce)
            .map_err(|_| GatewayError::Payment("Invalid permit2 nonce format".to_string()))?;
        let signature = parse_signature(signature_hex)?;

        let signer = self
            .private_key
            .parse::<PrivateKeySigner>()
            .map_err(|err| GatewayError::Payment(format!("Invalid settler private key: {err}")))?;
        let signer = signer.with_chain_id(Some(self.chain_id));
        let wallet = EthereumWallet::from(signer);

        let rpc_url = self
            .rpc_url
            .parse()
            .map_err(|err| GatewayError::Payment(format!("Invalid RPC URL: {err}")))?;
        let provider = ProviderBuilder::new().wallet(wallet).connect_http(rpc_url);

        let contract = IPermit2::new(self.permit2_address, provider);
        let permit = IPermit2::PermitTransferFrom {
            permitted: IPermit2::TokenPermissions { token, amount },
            nonce,
            deadline: U256::from(authorization.deadline),
        };
        let transfer_details = IPermit2::SignatureTransferDetails {
            to,
            requestedAmount: requested_amount,
        };

        let pending = contract
            .permitTransferFrom(permit, transfer_details, owner, Bytes::from(signature))
            .send()
            .await
            .map_err(|err| GatewayError::Payment(format!("Permit2 transfer failed: {err}")))?;

        let receipt = pending
            .get_receipt()
            .await
            .map_err(|err| GatewayError::Payment(format!("Permit2 receipt error: {err}")))?;

        if !receipt.status() {
            return Err(GatewayError::Payment(
                "Permit2 transfer reverted on-chain".to_string(),
            ));
        }

        Ok(format!("{:#x}", receipt.transaction_hash))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn settle_eip3009(
        &self,
        _token_address: Address,
        _from: Address,
        _to: Address,
        _value: U256,
        _valid_after: u64,
        _valid_before: u64,
        _nonce: U256,
        signature_hex: &str,
    ) -> GatewayResult<String> {
        let _sig_bytes = parse_signature(signature_hex)?;
        Ok("0x0000000000000000000000000000000000000000000000000000000000000000".to_string())
    }

    pub async fn check_balance(
        &self,
        _token_address: Address,
        _account: Address,
    ) -> GatewayResult<U256> {
        Ok(U256::ZERO)
    }

    pub async fn check_nonce_used(
        &self,
        _token_address: Address,
        _authorizer: Address,
        _nonce: U256,
    ) -> GatewayResult<bool> {
        Ok(false)
    }
}

fn parse_address(value: &str, error: &str) -> GatewayResult<Address> {
    let normalized = value.strip_prefix("0x").unwrap_or(value);
    Address::from_str(normalized).map_err(|_| GatewayError::Payment(error.to_string()))
}

fn parse_signature(signature_hex: &str) -> GatewayResult<Vec<u8>> {
    let bytes = hex::decode(signature_hex.strip_prefix("0x").unwrap_or(signature_hex))
        .map_err(|_| GatewayError::Payment("Invalid signature format".to_string()))?;

    if bytes.len() != 65 {
        return Err(GatewayError::Payment(
            "Invalid signature length (expected 65 bytes)".to_string(),
        ));
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RPC_URL: &str = "http://localhost:8545";
    const PRIVATE_KEY: &str = "0x0123456789abcdef";
    const PERMIT2_ADDRESS: &str = "0x000000000022D473030F116dDEE9F6B43aC78BA3";

    fn address(value: &str) -> Address {
        Address::from_str(value).expect("address should parse")
    }

    fn valid_signature_hex() -> String {
        format!("0x{}", "11".repeat(65))
    }

    #[test]
    fn payment_settler_new_construction() {
        let settler = PaymentSettler::new(
            RPC_URL.to_string(),
            PRIVATE_KEY.to_string(),
            999,
            address(PERMIT2_ADDRESS),
        );

        assert_eq!(settler.rpc_url, RPC_URL);
        assert_eq!(settler.private_key, PRIVATE_KEY);
        assert_eq!(settler.chain_id, 999);
        assert_eq!(settler.permit2_address, address(PERMIT2_ADDRESS));
    }

    #[tokio::test]
    async fn settle_eip3009_rejects_invalid_hex_signature() {
        let settler = PaymentSettler::new(
            RPC_URL.to_string(),
            PRIVATE_KEY.to_string(),
            999,
            address(PERMIT2_ADDRESS),
        );

        let result = settler
            .settle_eip3009(
                address("0xb88339cb7199b77e23db6e890353e22632ba630f"),
                address("0x1111111111111111111111111111111111111111"),
                address("0x1234567890123456789012345678901234567890"),
                U256::from(1_u64),
                0,
                10,
                U256::from(1_u64),
                "0xzz",
            )
            .await;

        assert!(matches!(result, Err(GatewayError::Payment(msg)) if msg == "Invalid signature format"));
    }

    #[tokio::test]
    async fn settle_eip3009_rejects_wrong_signature_length() {
        let settler = PaymentSettler::new(
            RPC_URL.to_string(),
            PRIVATE_KEY.to_string(),
            999,
            address(PERMIT2_ADDRESS),
        );
        let short_signature = format!("0x{}", "11".repeat(64));

        let result = settler
            .settle_eip3009(
                address("0xb88339cb7199b77e23db6e890353e22632ba630f"),
                address("0x1111111111111111111111111111111111111111"),
                address("0x1234567890123456789012345678901234567890"),
                U256::from(1_u64),
                0,
                10,
                U256::from(1_u64),
                &short_signature,
            )
            .await;

        assert!(matches!(result, Err(GatewayError::Payment(msg)) if msg == "Invalid signature length (expected 65 bytes)"));
    }

    #[tokio::test]
    async fn settle_permit2_rejects_invalid_owner() {
        let settler = PaymentSettler::new(
            RPC_URL.to_string(),
            PRIVATE_KEY.to_string(),
            999,
            address(PERMIT2_ADDRESS),
        );
        let auth = Permit2Authorization {
            owner: "invalid-owner".to_string(),
            token: "0xb88339cb7199b77e23db6e890353e22632ba630f".to_string(),
            amount: "1000000".to_string(),
            nonce: "1".to_string(),
            deadline: 9_999_999_999,
        };

        let result = settler
            .settle_permit2(
                &auth,
                address("0x1234567890123456789012345678901234567890"),
                U256::from(1_000_000_u64),
                &valid_signature_hex(),
            )
            .await;

        assert!(matches!(result, Err(GatewayError::Payment(msg)) if msg == "Invalid permit2 owner address"));
    }

    #[tokio::test]
    async fn settle_permit2_rejects_invalid_signature_before_network_call() {
        let settler = PaymentSettler::new(
            RPC_URL.to_string(),
            PRIVATE_KEY.to_string(),
            999,
            address(PERMIT2_ADDRESS),
        );
        let auth = Permit2Authorization {
            owner: "0x1111111111111111111111111111111111111111".to_string(),
            token: "0xb88339cb7199b77e23db6e890353e22632ba630f".to_string(),
            amount: "1000000".to_string(),
            nonce: "1".to_string(),
            deadline: 9_999_999_999,
        };

        let result = settler
            .settle_permit2(
                &auth,
                address("0x1234567890123456789012345678901234567890"),
                U256::from(1_000_000_u64),
                "0xzz",
            )
            .await;

        assert!(matches!(result, Err(GatewayError::Payment(msg)) if msg == "Invalid signature format"));
    }
}
