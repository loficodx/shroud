use anyhow::{Context, Result};
use shroud_client::socks5;
use shroud_core::config::{ClientConfig, TransportEndpointConfig};
use tracing::info;

use crate::runtime;

pub async fn run(cfg: ClientConfig) -> Result<()> {
    let socks = cfg
        .inbounds
        .socks
        .as_ref()
        .filter(|socks| socks.enabled)
        .context("no enabled SOCKS inbound configured")?;

    info!(listen = %socks.listen, "starting shroud client");

    let endpoint = TransportEndpointConfig::from(&cfg.transport);
    let session = runtime::build_session(&cfg, endpoint)?;

    socks5::serve(socks.listen, session, cfg.limits.max_concurrent_connections).await
}
