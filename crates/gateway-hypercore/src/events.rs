use crate::types::SpotTransfer;
use rust_decimal::Decimal;

/// Parse transfer amount in USD from a SpotTransfer
pub fn parse_transfer_amount_usd(transfer: &SpotTransfer) -> Decimal {
    transfer.usdc.parse::<Decimal>().unwrap_or(Decimal::ZERO)
}

/// Validate a transfer is a valid deposit to the gateway address
pub fn is_valid_deposit(transfer: &SpotTransfer, gateway_address: &str) -> bool {
    transfer.destination == gateway_address && !transfer.usdc.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transfer_with(usdc: &str, destination: &str) -> SpotTransfer {
        SpotTransfer {
            usdc: usdc.to_string(),
            user: "0x1111222233334444555566667777888899990000".to_string(),
            destination: destination.to_string(),
            fee: "0.001".to_string(),
            nonce: 1,
            time: 1_735_000_000,
            hash: "0xabc".to_string(),
        }
    }

    #[test]
    fn parse_transfer_amount_usd_valid_usdc() {
        let transfer = transfer_with("100.125", "0xgateway");

        let amount = parse_transfer_amount_usd(&transfer);

        assert_eq!(
            amount,
            Decimal::from_str_exact("100.125").expect("valid decimal literal")
        );
    }

    #[test]
    fn parse_transfer_amount_usd_invalid_or_empty_is_zero() {
        let invalid_transfer = transfer_with("not-a-number", "0xgateway");
        let empty_transfer = transfer_with("", "0xgateway");

        assert_eq!(parse_transfer_amount_usd(&invalid_transfer), Decimal::ZERO);
        assert_eq!(parse_transfer_amount_usd(&empty_transfer), Decimal::ZERO);
    }

    #[test]
    fn is_valid_deposit_true_for_matching_destination_and_non_empty_usdc() {
        let gateway = "0xgateway";
        let transfer = transfer_with("50.00", gateway);

        assert!(is_valid_deposit(&transfer, gateway));
    }

    #[test]
    fn is_valid_deposit_false_for_non_matching_destination() {
        let transfer = transfer_with("50.00", "0xother");

        assert!(!is_valid_deposit(&transfer, "0xgateway"));
    }

    #[test]
    fn is_valid_deposit_false_for_empty_usdc() {
        let transfer = transfer_with("", "0xgateway");

        assert!(!is_valid_deposit(&transfer, "0xgateway"));
    }
}
