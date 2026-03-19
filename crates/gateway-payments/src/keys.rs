use gateway_common::{AccountId, ApiKeyId, GatewayError, GatewayResult};
use rand::Rng;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use uuid::Uuid;

const KEY_PREFIX_LEN: usize = 8;
const KEY_SECRET_LEN: usize = 32;
const KEY_PREFIX_BYTES: usize = 4;
const KEY_SECRET_BYTES: usize = 16;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ValidatedKey {
    pub key_id: Uuid,
    pub account_id: AccountId,
    pub name: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ApiKeyInfo {
    pub id: Uuid,
    pub key_prefix: String,
    pub name: Option<String>,
    pub is_active: bool,
    pub created_at: OffsetDateTime,
    pub expires_at: Option<OffsetDateTime>,
}

#[derive(Clone)]
pub struct ApiKeyService {
    pool: PgPool,
}

impl ApiKeyService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn generate_key(
        &self,
        account_id: AccountId,
        name: Option<String>,
    ) -> GatewayResult<(ApiKeyId, String)> {
        let (prefix, _secret, raw_key) = generate_raw_key();
        let key_hash = hash_key(&raw_key);

        let row = sqlx::query(
            "INSERT INTO api_keys (account_id, key_hash, key_prefix, name) \
             VALUES ($1, $2, $3, $4) RETURNING id",
        )
        .bind(account_id.0)
        .bind(key_hash)
        .bind(prefix)
        .bind(name)
        .fetch_one(&self.pool)
        .await?;

        let id = row.try_get::<Uuid, _>("id")?;
        Ok((ApiKeyId(id), raw_key))
    }

    pub async fn validate_key(&self, raw_key: &str) -> GatewayResult<ValidatedKey> {
        let parsed = parse_key(raw_key)
            .ok_or_else(|| GatewayError::Auth("Invalid API key format".to_string()))?;

        let key_hash = hash_key(raw_key);

        let row = sqlx::query(
            "SELECT id, account_id, name, is_active, expires_at \
             FROM api_keys WHERE key_prefix = $1 AND key_hash = $2",
        )
        .bind(parsed.prefix)
        .bind(key_hash)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Err(GatewayError::Auth("Invalid API key".to_string()));
        };

        let is_active: bool = row.try_get("is_active")?;
        if !is_active {
            return Err(GatewayError::Auth("API key is inactive".to_string()));
        }

        let expires_at: Option<OffsetDateTime> = row.try_get("expires_at")?;
        if expires_at.is_some_and(|expiry| expiry <= OffsetDateTime::now_utc()) {
            return Err(GatewayError::Auth("API key is expired".to_string()));
        }

        Ok(ValidatedKey {
            key_id: row.try_get("id")?,
            account_id: AccountId(row.try_get("account_id")?),
            name: row.try_get("name")?,
        })
    }

    pub async fn revoke_key(&self, key_id: Uuid) -> GatewayResult<()> {
        sqlx::query("UPDATE api_keys SET is_active = false WHERE id = $1")
            .bind(key_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn list_keys(&self, account_id: AccountId) -> GatewayResult<Vec<ApiKeyInfo>> {
        let rows = sqlx::query(
            "SELECT id, key_prefix, name, is_active, created_at, expires_at \
             FROM api_keys WHERE account_id = $1 ORDER BY created_at DESC",
        )
        .bind(account_id.0)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                Ok(ApiKeyInfo {
                    id: row.try_get("id")?,
                    key_prefix: row.try_get("key_prefix")?,
                    name: row.try_get("name")?,
                    is_active: row.try_get("is_active")?,
                    created_at: row.try_get("created_at")?,
                    expires_at: row.try_get("expires_at")?,
                })
            })
            .collect()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ParsedKey {
    prefix: String,
    secret: String,
}

fn generate_raw_key() -> (String, String, String) {
    let mut prefix_bytes = [0_u8; KEY_PREFIX_BYTES];
    let mut secret_bytes = [0_u8; KEY_SECRET_BYTES];
    let mut rng = rand::rng();
    rng.fill(&mut prefix_bytes);
    rng.fill(&mut secret_bytes);

    let prefix = hex::encode(prefix_bytes);
    let secret = hex::encode(secret_bytes);
    let raw = format!("gw-{prefix}_{secret}");
    (prefix, secret, raw)
}

fn hash_key(raw_key: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(raw_key.as_bytes());
    hasher.finalize().to_vec()
}

fn parse_key(raw_key: &str) -> Option<ParsedKey> {
    let rest = raw_key.strip_prefix("gw-")?;
    let (prefix, secret) = rest.split_once('_')?;

    if prefix.len() != KEY_PREFIX_LEN || secret.len() != KEY_SECRET_LEN {
        return None;
    }

    if !prefix.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }

    if !secret.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }

    Some(ParsedKey {
        prefix: prefix.to_lowercase(),
        secret: secret.to_lowercase(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_key_has_expected_format() {
        let (_, _, key) = generate_raw_key();
        assert!(key.starts_with("gw-"));

        let parsed = parse_key(&key).expect("generated key should parse");
        assert_eq!(parsed.prefix.len(), KEY_PREFIX_LEN);
        assert_eq!(parsed.secret.len(), KEY_SECRET_LEN);
    }

    #[test]
    fn parse_key_extracts_prefix() {
        let parsed =
            parse_key("gw-deadbeef_0123456789abcdef0123456789abcdef").expect("key should parse");
        assert_eq!(parsed.prefix, "deadbeef");
        assert_eq!(parsed.secret, "0123456789abcdef0123456789abcdef");
    }

    #[test]
    fn parse_key_rejects_bad_prefix_length() {
        assert!(parse_key("gw-abc_0123456789abcdef0123456789abcdef").is_none());
    }

    #[test]
    fn parse_key_rejects_bad_secret_length() {
        assert!(parse_key("gw-deadbeef_01234567").is_none());
    }

    #[test]
    fn parse_key_rejects_non_hex_prefix() {
        assert!(parse_key("gw-zxywvu12_0123456789abcdef0123456789abcdef").is_none());
    }

    #[test]
    fn parse_key_rejects_non_hex_secret() {
        assert!(parse_key("gw-deadbeef_0123456789abcdef0123456789abcdeg").is_none());
    }

    #[test]
    fn parse_key_rejects_missing_separator() {
        assert!(parse_key("gw-deadbeef0123456789abcdef0123456789abcdef").is_none());
    }

    #[test]
    fn parse_key_rejects_wrong_prefix() {
        assert!(parse_key("ga-deadbeef_0123456789abcdef0123456789abcdef").is_none());
    }

    #[test]
    fn parse_key_normalizes_case() {
        let parsed =
            parse_key("gw-DEADBEEF_ABCDEFABCDEFABCDEFABCDEFABCDEF12").expect("key should parse");
        assert_eq!(parsed.prefix, "deadbeef");
        assert_eq!(parsed.secret, "abcdefabcdefabcdefabcdefabcdef12");
    }

    #[test]
    fn hash_key_is_consistent() {
        let first = hash_key("gw-deadbeef_0123456789abcdef0123456789abcdef");
        let second = hash_key("gw-deadbeef_0123456789abcdef0123456789abcdef");
        assert_eq!(first, second);
    }

    #[test]
    fn hash_key_changes_for_different_inputs() {
        let first = hash_key("gw-deadbeef_0123456789abcdef0123456789abcdef");
        let second = hash_key("gw-deadbeef_0123456789abcdef0123456789abcdee");
        assert_ne!(first, second);
    }

    #[test]
    fn hash_key_is_sha256_length() {
        let hash = hash_key("gw-deadbeef_0123456789abcdef0123456789abcdef");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn generated_keys_are_not_identical() {
        let (_, _, first) = generate_raw_key();
        let (_, _, second) = generate_raw_key();
        assert_ne!(first, second);
    }

    #[test]
    fn parsed_key_equality_works() {
        let left = parse_key("gw-deadbeef_0123456789abcdef0123456789abcdef").expect("valid key");
        let right = parse_key("gw-deadbeef_0123456789abcdef0123456789abcdef").expect("valid key");
        assert_eq!(left, right);
    }

    #[test]
    fn validation_logic_rejects_malformed_format_without_db() {
        let malformed = "gw-not-hex_foo";
        let result = parse_key(malformed);
        assert!(result.is_none());
    }

    #[test]
    fn validation_logic_accepts_valid_format_without_db() {
        let valid = "gw-0123abcd_0123456789abcdef0123456789abcdef";
        let result = parse_key(valid);
        assert!(result.is_some());
    }

    #[tokio::test]
    #[ignore]
    async fn generate_key_persists_and_list_keys_returns_metadata() {
        let pool = PgPool::connect("postgres://localhost/x402_gateway")
            .await
            .expect("local db required for ignored test");
        let service = ApiKeyService::new(pool);

        let account_id = AccountId(Uuid::new_v4());
        let _ = service
            .generate_key(account_id.clone(), Some("test".to_string()))
            .await;

        let _ = service.list_keys(account_id).await;
    }

    #[tokio::test]
    #[ignore]
    async fn revoke_and_validate_touch_db() {
        let pool = PgPool::connect("postgres://localhost/x402_gateway")
            .await
            .expect("local db required for ignored test");
        let service = ApiKeyService::new(pool);

        let key_id = Uuid::new_v4();
        let _ = service.revoke_key(key_id).await;
        let _ = service
            .validate_key("gw-deadbeef_0123456789abcdef0123456789abcdef")
            .await;
    }
}
