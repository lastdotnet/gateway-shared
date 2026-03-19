use crate::types::{SpotTransfer, UserEvent, WsEvent, WsSubType, WsSubscription};
use futures::SinkExt;
use gateway_common::error::{GatewayError, GatewayResult};
use tokio::sync::mpsc;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{debug, error, warn};

/// WebSocket client for HyperCore transfers
pub struct HyperCoreWs {
    ws_url: String,
    gateway_address: String,
}

impl HyperCoreWs {
    /// Create a new WebSocket connection handler
    pub fn new(ws_url: impl Into<String>, gateway_address: impl Into<String>) -> Self {
        Self {
            ws_url: ws_url.into(),
            gateway_address: gateway_address.into(),
        }
    }

    /// Subscribe to transfers, returns a receiver channel
    pub async fn subscribe_transfers(&self) -> GatewayResult<mpsc::Receiver<SpotTransfer>> {
        let (tx, rx) = mpsc::channel(100);
        let ws_url = self.ws_url.clone();
        let gateway_address = self.gateway_address.clone();

        tokio::spawn(async move {
            let mut retry_count = 0;
            const MAX_RETRIES: u32 = 10;

            loop {
                match Self::run_subscription(ws_url.clone(), gateway_address.clone(), tx.clone())
                    .await
                {
                    Ok(_) => {
                        debug!("WebSocket subscription ended gracefully");
                        retry_count = 0;
                    }
                    Err(e) => {
                        error!("WebSocket error: {}", e);
                        retry_count += 1;

                        if retry_count > MAX_RETRIES {
                            error!("Max retries exceeded");
                            break;
                        }

                        debug!("Reconnecting in 5 seconds...");
                        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    }
                }
            }
        });

        Ok(rx)
    }

    /// Run the WebSocket subscription loop
    async fn run_subscription(
        ws_url: String,
        gateway_address: String,
        tx: mpsc::Sender<SpotTransfer>,
    ) -> GatewayResult<()> {
        let (ws_stream, _) = connect_async(&ws_url)
            .await
            .map_err(|e| GatewayError::Provider {
                provider: "HyperCore WS".to_string(),
                message: format!("Failed to connect: {}", e),
            })?;

        use futures::stream::StreamExt;
        let (mut write, mut read) = ws_stream.split();

        let subscription = WsSubscription {
            method: "subscribe".to_string(),
            subscription: WsSubType::UserEvents {
                user: gateway_address.clone(),
            },
        };

        let sub_msg = serde_json::to_string(&subscription).map_err(GatewayError::Serialization)?;

        write
            .send(Message::Text(sub_msg.into()))
            .await
            .map_err(|e| GatewayError::Provider {
                provider: "HyperCore WS".to_string(),
                message: format!("Failed to send subscription: {}", e),
            })?;

        debug!("Subscribed to userEvents for {}", gateway_address);

        while let Some(msg_result) = read.next().await {
            let msg = msg_result.map_err(|e| GatewayError::Provider {
                provider: "HyperCore WS".to_string(),
                message: format!("WebSocket error: {}", e),
            })?;

            match msg {
                Message::Text(text) => {
                    if let Ok(WsEvent::UserEvents { data, .. }) =
                        serde_json::from_str::<WsEvent>(&text)
                    {
                        for user_event in data.events {
                            if let UserEvent::SpotTransfer(transfer) = user_event
                                && transfer.destination == gateway_address
                                && tx.send(transfer).await.is_err()
                            {
                                return Ok(());
                            }
                        }
                    }
                }
                Message::Ping(data) => {
                    let _ = write.send(Message::Pong(data)).await;
                }
                Message::Close(_) => {
                    warn!("WebSocket closed by server");
                    return Err(GatewayError::Provider {
                        provider: "HyperCore WS".to_string(),
                        message: "Connection closed".to_string(),
                    });
                }
                _ => {}
            }
        }

        Ok(())
    }
}
