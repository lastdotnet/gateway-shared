use sqlx::{PgPool, postgres::PgPoolOptions};

use crate::{DatabaseConfig, GatewayError, GatewayResult};

pub async fn create_pool(config: &DatabaseConfig) -> GatewayResult<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(config.max_connections)
        .connect(&config.url)
        .await?;

    Ok(pool)
}

pub async fn run_migrations(pool: &PgPool) -> GatewayResult<()> {
    sqlx::migrate!("../../migrations")
        .run(pool)
        .await
        .map_err(|error| GatewayError::Internal(format!("Migration error: {error}")))?;
    Ok(())
}
