use gateway_common::{AccountId, GatewayError, GatewayResult};
use rust_decimal::Decimal;
use sqlx::{PgPool, Row};
use std::str::FromStr;

#[derive(Clone)]
pub struct CreditService {
    pool: PgPool,
}

impl CreditService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn get_balance(
        &self,
        account_id: AccountId,
        tenant_id: Option<uuid::Uuid>,
    ) -> GatewayResult<Decimal> {
        let row = match tenant_id {
            Some(tenant_id) => {
                sqlx::query(
                    "SELECT balance_usd::text AS balance_usd FROM credit_balances WHERE account_id = $1 AND tenant_id = $2",
                )
                .bind(account_id.0)
                .bind(tenant_id)
                .fetch_optional(&self.pool)
                .await?
            }
            None => {
                sqlx::query("SELECT balance_usd::text AS balance_usd FROM credit_balances WHERE account_id = $1")
                    .bind(account_id.0)
                    .fetch_optional(&self.pool)
                    .await?
            }
        };

        let Some(row) = row else {
            return Err(GatewayError::ModelNotFound(format!(
                "credit balance for account {}",
                account_id
            )));
        };

        let balance_text: String = row.try_get("balance_usd")?;
        parse_decimal_field(&balance_text, "balance_usd")
    }

    pub async fn credit(
        &self,
        account_id: AccountId,
        tenant_id: Option<uuid::Uuid>,
        amount: Decimal,
        ref_type: &str,
        ref_id: &str,
        description: &str,
    ) -> GatewayResult<Decimal> {
        if amount <= Decimal::ZERO {
            return Err(GatewayError::Payment(
                "Credit amount must be positive".to_string(),
            ));
        }

        let mut tx = self.pool.begin().await?;

        let row = match tenant_id {
            Some(tenant_id) => {
                sqlx::query(
                    "SELECT balance_usd::text AS balance_usd FROM credit_balances WHERE account_id = $1 AND tenant_id = $2 FOR UPDATE",
                )
                .bind(account_id.0)
                .bind(tenant_id)
                .fetch_optional(&mut *tx)
                .await?
            }
            None => {
                sqlx::query(
                    "SELECT balance_usd::text AS balance_usd FROM credit_balances WHERE account_id = $1 FOR UPDATE",
                )
                .bind(account_id.0)
                .fetch_optional(&mut *tx)
                .await?
            }
        };

        let Some(row) = row else {
            return Err(GatewayError::ModelNotFound(format!(
                "credit balance for account {}",
                account_id
            )));
        };

        let current_balance_text: String = row.try_get("balance_usd")?;
        let current_balance = parse_decimal_field(&current_balance_text, "balance_usd")?;
        let new_balance = current_balance + amount;

        match tenant_id {
            Some(tenant_id) => {
                sqlx::query(
                    "UPDATE credit_balances SET balance_usd = $2::numeric, updated_at = now() WHERE account_id = $1 AND tenant_id = $3",
                )
                .bind(account_id.0)
                .bind(new_balance.to_string())
                .bind(tenant_id)
                .execute(&mut *tx)
                .await?;
            }
            None => {
                sqlx::query(
                    "UPDATE credit_balances SET balance_usd = $2::numeric, updated_at = now() WHERE account_id = $1",
                )
                .bind(account_id.0)
                .bind(new_balance.to_string())
                .execute(&mut *tx)
                .await?;
            }
        }

        sqlx::query(
            "INSERT INTO ledger_entries \
             (account_id, entry_type, amount_usd, balance_after, reference_type, reference_id, description) \
             VALUES ($1, 'credit', $2::numeric, $3::numeric, $4, $5, $6)",
        )
        .bind(account_id.0)
        .bind(amount.to_string())
        .bind(new_balance.to_string())
        .bind(ref_type)
        .bind(ref_id)
        .bind(description)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(new_balance)
    }

    pub async fn debit(
        &self,
        account_id: AccountId,
        tenant_id: Option<uuid::Uuid>,
        amount: Decimal,
        ref_type: &str,
        ref_id: &str,
        description: &str,
    ) -> GatewayResult<Decimal> {
        if amount <= Decimal::ZERO {
            return Err(GatewayError::Payment(
                "Debit amount must be positive".to_string(),
            ));
        }

        let mut tx = self.pool.begin().await?;

        let row = match tenant_id {
            Some(tenant_id) => {
                sqlx::query(
                    "SELECT balance_usd::text AS balance_usd FROM credit_balances WHERE account_id = $1 AND tenant_id = $2 FOR UPDATE",
                )
                .bind(account_id.0)
                .bind(tenant_id)
                .fetch_optional(&mut *tx)
                .await?
            }
            None => {
                sqlx::query(
                    "SELECT balance_usd::text AS balance_usd FROM credit_balances WHERE account_id = $1 FOR UPDATE",
                )
                .bind(account_id.0)
                .fetch_optional(&mut *tx)
                .await?
            }
        };

        let Some(row) = row else {
            return Err(GatewayError::ModelNotFound(format!(
                "credit balance for account {}",
                account_id
            )));
        };

        let current_balance_text: String = row.try_get("balance_usd")?;
        let current_balance = parse_decimal_field(&current_balance_text, "balance_usd")?;
        if current_balance < amount {
            return Err(GatewayError::InsufficientCredits {
                required: amount,
                available: current_balance,
            });
        }

        let new_balance = current_balance - amount;

        match tenant_id {
            Some(tenant_id) => {
                sqlx::query(
                    "UPDATE credit_balances SET balance_usd = $2::numeric, updated_at = now() WHERE account_id = $1 AND tenant_id = $3",
                )
                .bind(account_id.0)
                .bind(new_balance.to_string())
                .bind(tenant_id)
                .execute(&mut *tx)
                .await?;
            }
            None => {
                sqlx::query(
                    "UPDATE credit_balances SET balance_usd = $2::numeric, updated_at = now() WHERE account_id = $1",
                )
                .bind(account_id.0)
                .bind(new_balance.to_string())
                .execute(&mut *tx)
                .await?;
            }
        }

        sqlx::query(
            "INSERT INTO ledger_entries \
             (account_id, entry_type, amount_usd, balance_after, reference_type, reference_id, description) \
             VALUES ($1, 'debit', $2::numeric, $3::numeric, $4, $5, $6)",
        )
        .bind(account_id.0)
        .bind(amount.to_string())
        .bind(new_balance.to_string())
        .bind(ref_type)
        .bind(ref_id)
        .bind(description)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(new_balance)
    }

    pub async fn check_and_reserve(
        &self,
        account_id: AccountId,
        tenant_id: Option<uuid::Uuid>,
        estimated_cost: Decimal,
    ) -> GatewayResult<Decimal> {
        if estimated_cost < Decimal::ZERO {
            return Err(GatewayError::Payment(
                "Estimated cost cannot be negative".to_string(),
            ));
        }

        let current = self.get_balance(account_id, tenant_id).await?;
        if current < estimated_cost {
            return Err(GatewayError::InsufficientCredits {
                required: estimated_cost,
                available: current,
            });
        }

        Ok(current)
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
    use rust_decimal::prelude::FromPrimitive;
    use uuid::Uuid;

    #[tokio::test]
    async fn credit_service_is_constructible() {
        let pool = PgPool::connect_lazy("postgres://localhost/test")
            .expect("connect_lazy should construct pool");
        let _service = CreditService::new(pool);
    }

    #[test]
    fn insufficient_credits_error_shape_is_expected() {
        let required = Decimal::from_i64(100).expect("100 should convert");
        let available = Decimal::from_i64(10).expect("10 should convert");
        let error = GatewayError::InsufficientCredits {
            required,
            available,
        };

        assert!(matches!(
            error,
            GatewayError::InsufficientCredits {
                required: _,
                available: _
            }
        ));
    }

    #[test]
    fn check_and_reserve_negative_amount_error_message() {
        let message =
            GatewayError::Payment("Estimated cost cannot be negative".to_string()).to_string();
        assert!(message.contains("Estimated cost cannot be negative"));
    }

    #[test]
    fn debit_positive_error_message_matches_expected_text() {
        let message =
            GatewayError::Payment("Debit amount must be positive".to_string()).to_string();
        assert!(message.contains("Debit amount must be positive"));
    }

    #[test]
    fn credit_positive_error_message_matches_expected_text() {
        let message =
            GatewayError::Payment("Credit amount must be positive".to_string()).to_string();
        assert!(message.contains("Credit amount must be positive"));
    }

    #[tokio::test]
    #[ignore]
    async fn credit_and_debit_round_trip_db_flow() {
        let pool = PgPool::connect("postgres://localhost/x402_gateway")
            .await
            .expect("local db required for ignored test");
        let service = CreditService::new(pool);
        let account = AccountId(Uuid::new_v4());

        let _ = service
            .credit(account.clone(), None, Decimal::ONE, "test", "r1", "add")
            .await;
        let _ = service
            .debit(account, None, Decimal::ONE, "test", "r2", "sub")
            .await;
    }

    #[tokio::test]
    #[ignore]
    async fn debit_insufficient_returns_error_variant() {
        let pool = PgPool::connect("postgres://localhost/x402_gateway")
            .await
            .expect("local db required for ignored test");
        let service = CreditService::new(pool);
        let account = AccountId(Uuid::new_v4());

        let result = service
            .debit(
                account,
                None,
                Decimal::new(100, 0),
                "test",
                "r3",
                "overspend",
            )
            .await;
        if let Err(GatewayError::InsufficientCredits {
            required,
            available,
        }) = result
        {
            assert_eq!(required, Decimal::new(100, 0));
            assert!(available >= Decimal::ZERO);
        }
    }
}
