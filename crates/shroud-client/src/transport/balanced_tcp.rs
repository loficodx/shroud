use crate::transport::{TcpTransport, TcpTransportConnect};
use anyhow::{Result, bail};
use futures_util::future::BoxFuture;
use shroud_core::config::{ClientAuthConfig, OutboundConfig};

#[derive(Clone)]
pub struct BalancedTcpTransport {
    _outbound: OutboundConfig,
    _auth: ClientAuthConfig,
}

impl BalancedTcpTransport {
    pub fn new(outbound: OutboundConfig, auth: ClientAuthConfig) -> Self {
        Self {
            _outbound: outbound,
            _auth: auth,
        }
    }
}

impl TcpTransport for BalancedTcpTransport {
    fn connect<'a>(
        &'a self,
        _target_host: &'a str,
        _target_port: u16,
    ) -> BoxFuture<'a, Result<TcpTransportConnect>> {
        Box::pin(async move { bail!("balanced_tcp transport is not implemented yet") })
    }
}
