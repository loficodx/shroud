use anyhow::{Context, Result};
use shroud_client::{routing, session, transport};
use shroud_core::config::{ClientConfig, TransportEndpointConfig};

pub fn build_session(
    cfg: &ClientConfig,
    endpoint: TransportEndpointConfig,
) -> Result<session::SessionCore> {
    let router = routing::Router::try_new(cfg.routing.clone()).context("invalid routing config")?;

    let tcp_transport = transport::build_tcp_transport(
        cfg.transport.mode,
        endpoint,
        cfg.auth.clone(),
        cfg.timeouts,
    )
    .context("failed to build TCP transport")?;

    Ok(session::SessionCore::new(
        router,
        tcp_transport,
        cfg.dns.clone(),
        cfg.timeouts,
        cfg.relay,
    ))
}
