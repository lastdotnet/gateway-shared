use crate::credits::CreditService;
use gateway_common::{AccountId, GatewayError, GatewayResult};
use rust_decimal::Decimal;
use sqlx::{PgPool, Row};
use std::str::FromStr;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Deposit {
    pub id: Uuid,
    pub account_id: AccountId,
    pub chain: String,
    pub tx_hash: String,
    pub token_address: Option<String>,
    pub amount_raw: String,
    pub amount_usd: Decimal,
    pub status: String,
    pub created_at: OffsetDateTime,
}

#[derive(Clone)]
pub struct DepositService {
    pool: PgPool,
}

impl DepositService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn record_deposit(
        &self,
        account_id: AccountId,
        chain: &str,
        tx_hash: &str,
        token_address: Option<&str>,
        amount_raw: &str,
        amount_usd: Decimal,
    ) -> GatewayResult<Uuid> {
        let row = sqlx::query(
            "INSERT INTO deposits \
             (account_id, chain, tx_hash, token_address, amount_raw, amount_usd) \
             VALUES ($1, $2, $3, $4, $5::numeric, $6::numeric) RETURNING id",
        )
        .bind(account_id.0)
        .bind(chain)
        .bind(tx_hash)
        .bind(token_address)
        .bind(amount_raw)
        .bind(amount_usd.to_string())
        .fetch_one(&self.pool)
        .await?;

        Ok(row.try_get("id")?)
    }

    pub async fn credit_deposit(
        &self,
        credit_service: &CreditService,
        account_id: AccountId,
        deposit_id: Uuid,
        amount_usd: Decimal,
    ) -> GatewayResult<Decimal> {
        credit_service
            .credit(
                account_id,
                None,
                amount_usd,
                "deposit",
                &deposit_id.to_string(),
                "Deposit credit",
            )
            .await
    }

    pub async fn get_deposits(
        &self,
        account_id: AccountId,
        limit: i64,
    ) -> GatewayResult<Vec<Deposit>> {
        let rows = sqlx::query(
            "SELECT id, account_id, chain, tx_hash, token_address, amount_raw::text AS amount_raw, \
             amount_usd::text AS amount_usd, status, created_at \
             FROM deposits WHERE account_id = $1 ORDER BY created_at DESC LIMIT $2",
        )
        .bind(account_id.0)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                Ok(Deposit {
                    amount_usd: parse_decimal_field(
                        &row.try_get::<String, _>("amount_usd")?,
                        "amount_usd",
                    )?,
                    id: row.try_get("id")?,
                    account_id: AccountId(row.try_get("account_id")?),
                    chain: row.try_get("chain")?,
                    tx_hash: row.try_get("tx_hash")?,
                    token_address: row.try_get("token_address")?,
                    amount_raw: row.try_get("amount_raw")?,
                    status: row.try_get("status")?,
                    created_at: row.try_get("created_at")?,
                })
            })
            .collect()
    }

    pub async fn find_account_by_evm_address(
        &self,
        evm_address: &str,
    ) -> GatewayResult<Option<AccountId>> {
        let row = sqlx::query("SELECT account_id FROM deposit_addresses WHERE evm_address = $1")
            .bind(evm_address)
            .fetch_optional(&self.pool)
            .await?;

        Ok(row.map(|r| AccountId(r.get("account_id"))))
    }
}

fn parse_decimal_field(value: &str, field_name: &str) -> GatewayResult<Decimal> {
    Decimal::from_str(value).map_err(|err| {
        GatewayError::Internal(format!("Failed to parse {field_name} as decimal: {err}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deposit_struct_creation_works() {
        let id = Uuid::new_v4();
        let account_id = AccountId(Uuid::new_v4());
        let created_at = OffsetDateTime::now_utc();

        let deposit = Deposit {
            id,
            account_id: account_id.clone(),
            chain: "hyperevm".to_string(),
            tx_hash: "0xabc".to_string(),
            token_address: Some("0xdef".to_string()),
            amount_raw: "1000000".to_string(),
            amount_usd: Decimal::ONE,
            status: "confirmed".to_string(),
            created_at,
        };

        assert_eq!(deposit.id, id);
        assert_eq!(deposit.account_id, account_id);
        assert_eq!(deposit.amount_usd, Decimal::ONE);
    }

    #[tokio::test]
    async fn deposit_service_is_constructible() {
        let pool = PgPool::connect_lazy("postgres://localhost/test")
            .expect("connect_lazy should construct pool");
        let _service = DepositService::new(pool);
    }

    #[test]
    fn deposit_optional_token_address_can_be_none() {
        let deposit = Deposit {
            id: Uuid::new_v4(),
            account_id: AccountId(Uuid::new_v4()),
            chain: "hyperevm".to_string(),
            tx_hash: "0xtx".to_string(),
            token_address: None,
            amount_raw: "42".to_string(),
            amount_usd: Decimal::new(42, 0),
            status: "confirmed".to_string(),
            created_at: OffsetDateTime::now_utc(),
        };

        assert!(deposit.token_address.is_none());
    }

    #[tokio::test]
    #[ignore]
    async fn record_deposit_inserts_row() {
        let pool = PgPool::connect("postgres://localhost/x402_gateway")
            .await
            .expect("local db required for ignored test");
        let service = DepositService::new(pool);
        let result = service
            .record_deposit(
                AccountId(Uuid::new_v4()),
                "hyperevm",
                "0x123",
                Some("0xabc"),
                "1000",
                Decimal::ONE,
            )
            .await;

        let _ = result;
    }

    #[tokio::test]
    #[ignore]
    async fn get_deposits_queries_rows() {
        let pool = PgPool::connect("postgres://localhost/x402_gateway")
            .await
            .expect("local db required for ignored test");
        let service = DepositService::new(pool);

        let result = service.get_deposits(AccountId(Uuid::new_v4()), 10).await;
        let _ = result;
    }
}
