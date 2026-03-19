use gateway_common::{AccountId, GatewayError, GatewayResult};
use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Account {
    pub id: AccountId,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Clone)]
pub struct AccountService {
    pool: PgPool,
}

impl AccountService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create_account(&self) -> GatewayResult<AccountId> {
        let mut tx = self.pool.begin().await?;

        let row = sqlx::query("INSERT INTO accounts DEFAULT VALUES RETURNING id")
            .fetch_one(&mut *tx)
            .await?;

        let account_id = AccountId(row.try_get::<Uuid, _>("id")?);

        sqlx::query("INSERT INTO credit_balances (account_id, balance_usd) VALUES ($1, 0)")
            .bind(account_id.0)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        Ok(account_id)
    }

    pub async fn get_account(&self, id: AccountId) -> GatewayResult<Account> {
        let row = sqlx::query("SELECT id, created_at, updated_at FROM accounts WHERE id = $1")
            .bind(id.0)
            .fetch_optional(&self.pool)
            .await?;

        let Some(row) = row else {
            return Err(GatewayError::ModelNotFound(format!("account {}", id)));
        };

        Ok(Account {
            id: AccountId(row.try_get::<Uuid, _>("id")?),
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_struct_holds_expected_values() {
        let id = AccountId(Uuid::new_v4());
        let now = OffsetDateTime::now_utc();
        let account = Account {
            id: id.clone(),
            created_at: now,
            updated_at: now,
        };

        assert_eq!(account.id, id);
        assert_eq!(account.created_at, now);
        assert_eq!(account.updated_at, now);
    }

    #[tokio::test]
    async fn account_service_is_cloneable() {
        let pool = PgPool::connect_lazy("postgres://localhost/test")
            .expect("connect_lazy should construct pool");
        let service = AccountService::new(pool);
        let cloned = service.clone();
        let _ = cloned;
    }

    #[tokio::test]
    #[ignore]
    async fn create_account_inserts_account_and_zero_balance() {
        let pool = PgPool::connect("postgres://localhost/x402_gateway")
            .await
            .expect("local db required for ignored test");
        let service = AccountService::new(pool.clone());

        let account_id = service
            .create_account()
            .await
            .expect("account should be created");

        let account = service
            .get_account(account_id.clone())
            .await
            .expect("created account should exist");
        assert_eq!(account.id, account_id);
    }

    #[tokio::test]
    #[ignore]
    async fn get_account_nonexistent_returns_error() {
        let pool = PgPool::connect("postgres://localhost/x402_gateway")
            .await
            .expect("local db required for ignored test");
        let service = AccountService::new(pool);

        let missing = AccountId(Uuid::nil());
        let result = service.get_account(missing).await;

        assert!(matches!(result, Err(GatewayError::ModelNotFound(_))));
    }
}
