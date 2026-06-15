use anyhow::{Context, Result};
use shroud_client::tun as client_tun;
use shroud_core::config::{ClientConfig, TransportEndpointConfig};
use tracing::info;

use crate::runtime;

pub async fn run(cfg: ClientConfig) -> Result<()> {
    let mut endpoint = TransportEndpointConfig::from(&cfg.transport);

    if cfg.inbounds.tun.auto_route {
        endpoint = client_tun::route::prepare_auto_route_outbound(endpoint)?;
    }

    let session = runtime::build_session(&cfg, endpoint.clone())?;

    let device = client_tun::device::open(&cfg.inbounds.tun)
        .with_context(|| format!("failed to set up TUN device {}", cfg.inbounds.tun.name))?;

    info!(
        tun = device.name(),
        address = %cfg.inbounds.tun.address,
        mtu = cfg.inbounds.tun.mtu,
        auto_route = cfg.inbounds.tun.auto_route,
        "TUN device opened; starting smoltcp-backed packet engine"
    );

    let _route_guard =
        client_tun::route::setup_before_packet_engine(device.name(), &cfg.inbounds.tun, &endpoint)?;

    let fake_dns = client_tun::dns::FakeDns::new();
    let fake_dns_addr = client_tun::dns::listen_addr(&cfg.inbounds.tun);

    info!(
        listen = %fake_dns_addr,
        "starting TUN fake DNS listener"
    );

    tokio::spawn(client_tun::dns::serve(fake_dns_addr, fake_dns.clone()));

    info!(tun = device.name(), "starting TUN packet engine");

    client_tun::engine::TunEngine::new(
        device,
        session,
        fake_dns,
        cfg.inbounds.tun.mtu,
        cfg.limits.max_concurrent_connections,
    )
    .run()
    .await
}
