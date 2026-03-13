use ::redis::aio::ConnectionManager;

use crate::{GatewayResult, RedisConfig};

pub async fn create_redis_pool(config: &RedisConfig) -> GatewayResult<ConnectionManager> {
    let client = ::redis::Client::open(config.url.as_str())?;
    let connection = client.get_connection_manager().await?;
    Ok(connection)
}
