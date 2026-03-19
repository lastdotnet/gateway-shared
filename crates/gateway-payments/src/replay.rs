use gateway_common::GatewayResult;
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use sqlx::PgPool;
use tracing::warn;

const USED_PAYMENTS_SET_KEY: &str = "used_payments";

#[derive(Clone)]
pub struct ReplayProtector {
    pool: PgPool,
    redis: Option<ConnectionManager>,
}

impl ReplayProtector {
    pub fn new(pool: PgPool, redis: Option<ConnectionManager>) -> Self {
        Self { pool, redis }
    }

    pub async fn is_used(&self, payment_key: &str) -> GatewayResult<bool> {
        if let Some(redis) = &self.redis {
            let mut conn = redis.clone();
            if let Ok(is_used) = conn
                .sismember::<_, _, bool>(USED_PAYMENTS_SET_KEY, payment_key)
                .await
                && is_used
            {
                return Ok(true);
            }
        }

        let found = sqlx::query_scalar::<_, String>(
            "SELECT payment_key FROM used_payments WHERE payment_key = $1",
        )
        .bind(payment_key)
        .fetch_optional(&self.pool)
        .await?
        .is_some();

        if found && let Some(redis) = &self.redis {
            let mut conn = redis.clone();
            if let Err(err) = conn
                .sadd::<_, _, usize>(USED_PAYMENTS_SET_KEY, payment_key)
                .await
            {
                warn!(%err, payment_key, "failed to backfill replay key into redis");
            }
        }

        Ok(found)
    }

    pub async fn mark_used(&self, record: UsedPaymentRecord) -> GatewayResult<()> {
        sqlx::query(
            "INSERT INTO used_payments (payment_key, scheme, payer, token, amount_raw, tx_hash)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (payment_key) DO NOTHING",
        )
        .bind(&record.payment_key)
        .bind(&record.scheme)
        .bind(&record.payer)
        .bind(&record.token)
        .bind(&record.amount_raw)
        .bind(&record.tx_hash)
        .execute(&self.pool)
        .await?;

        if let Some(redis) = &self.redis {
            let mut conn = redis.clone();
            if let Err(err) = conn
                .sadd::<_, _, usize>(USED_PAYMENTS_SET_KEY, &record.payment_key)
                .await
            {
                warn!(%err, payment_key = %record.payment_key, "failed to record replay key in redis");
            }
        }

        Ok(())
    }

    pub fn permit2_key(owner: &str, nonce: &str) -> String {
        format!("permit2:{}:{}", owner.to_lowercase(), nonce)
    }

    pub fn eip3009_key(from: &str, nonce: &str) -> String {
        format!("eip3009:{}:{}", from.to_lowercase(), nonce)
    }

    pub fn hypercore_key(transfer_id: &str) -> String {
        format!("hypercore:{}", transfer_id.to_lowercase())
    }
}

pub struct UsedPaymentRecord {
    pub payment_key: String,
    pub scheme: String,
    pub payer: String,
    pub token: Option<String>,
    pub amount_raw: Option<String>,
    pub tx_hash: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::{ReplayProtector, UsedPaymentRecord};
    use sqlx::PgPool;

    #[tokio::test]
    async fn replay_protector_is_constructible() {
        let pool = PgPool::connect_lazy("postgres://localhost/test")
            .expect("connect_lazy should construct pool");
        let _service = ReplayProtector::new(pool, None);
    }

    #[test]
    fn permit2_key_format_is_correct() {
        let key = ReplayProtector::permit2_key("0xABCDEF", "123");
        assert_eq!(key, "permit2:0xabcdef:123");
    }

    #[test]
    fn eip3009_key_format_is_correct() {
        let key = ReplayProtector::eip3009_key("0xAbCdEf", "0xdeadbeef");
        assert_eq!(key, "eip3009:0xabcdef:0xdeadbeef");
    }

    #[test]
    fn hypercore_key_format_is_correct() {
        let key = ReplayProtector::hypercore_key("0xABC123");
        assert_eq!(key, "hypercore:0xabc123");
    }

    #[test]
    fn key_functions_lowercase_addresses() {
        let permit2 = ReplayProtector::permit2_key("0xABCD", "7");
        let eip3009 = ReplayProtector::eip3009_key("0xABCD", "0x01");
        let hypercore = ReplayProtector::hypercore_key("0xABCD");

        assert_eq!(permit2, "permit2:0xabcd:7");
        assert_eq!(eip3009, "eip3009:0xabcd:0x01");
        assert_eq!(hypercore, "hypercore:0xabcd");
    }

    fn test_record(payment_key: &str) -> UsedPaymentRecord {
        UsedPaymentRecord {
            payment_key: payment_key.to_string(),
            scheme: "permit2".to_string(),
            payer: "0x1111111111111111111111111111111111111111".to_string(),
            token: Some("0x2222222222222222222222222222222222222222".to_string()),
            amount_raw: Some("1000000".to_string()),
            tx_hash: Some(
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            ),
        }
    }

    #[tokio::test]
    #[ignore]
    async fn mark_and_check_replay_postgres() {
        let pool = PgPool::connect("postgres://localhost/x402_gateway")
            .await
            .expect("local db required for ignored test");
        let protector = ReplayProtector::new(pool, None);
        let key = ReplayProtector::permit2_key("0x1111111111111111111111111111111111111111", "999");

        protector
            .mark_used(test_record(&key))
            .await
            .expect("mark_used should succeed");
        let used = protector
            .is_used(&key)
            .await
            .expect("is_used should succeed");

        assert!(used);
    }

    #[tokio::test]
    #[ignore]
    async fn is_used_returns_false_for_unknown_key() {
        let pool = PgPool::connect("postgres://localhost/x402_gateway")
            .await
            .expect("local db required for ignored test");
        let protector = ReplayProtector::new(pool, None);
        let used = protector
            .is_used("permit2:0x0000000000000000000000000000000000000000:123456")
            .await
            .expect("is_used should succeed");

        assert!(!used);
    }

    #[tokio::test]
    #[ignore]
    async fn mark_used_is_idempotent() {
        let pool = PgPool::connect("postgres://localhost/x402_gateway")
            .await
            .expect("local db required for ignored test");
        let protector = ReplayProtector::new(pool, None);
        let key =
            ReplayProtector::permit2_key("0x1111111111111111111111111111111111111111", "1000");

        protector
            .mark_used(test_record(&key))
            .await
            .expect("first mark_used should succeed");
        protector
            .mark_used(test_record(&key))
            .await
            .expect("second mark_used should succeed");
    }
}
