use anyhow::{Result, anyhow};
use shroud_core::config::ServerSecurityConfig;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::{TcpStream, lookup_host};
use tokio::time::timeout;

pub(crate) async fn connect_target(
    host: &str,
    port: u16,
    security: &ServerSecurityConfig,
    connect_timeout: Duration,
) -> Result<ConnectedTarget, TargetConnectError> {
    let started = Instant::now();
    match timeout(connect_timeout, connect_target_inner(host, port, security)).await {
        Ok(Ok(stream)) => Ok(ConnectedTarget {
            stream,
            connect_ms: elapsed_millis(started.elapsed()),
        }),
        Ok(Err(err)) => Err(err.with_connect_ms(elapsed_millis(started.elapsed()))),
        Err(_) => Err(TargetConnectError::Timeout {
            connect_ms: elapsed_millis(started.elapsed()),
        }),
    }
}

async fn connect_target_inner(
    host: &str,
    port: u16,
    security: &ServerSecurityConfig,
) -> Result<TcpStream, TargetConnectError> {
    if !security.allow_ports.is_empty() && !security.allow_ports.contains(&port) {
        return Err(TargetConnectError::forbidden(
            "target port is not in security.allow_ports".to_string(),
        ));
    }

    let addresses: Vec<SocketAddr> = lookup_host((host, port))
        .await
        .map_err(|err| TargetConnectError::connect(anyhow!(err).context("target DNS failed")))?
        .collect();

    if addresses.is_empty() {
        return Err(TargetConnectError::connect(anyhow!(
            "target DNS returned no addresses"
        )));
    }

    let mut allowed_addresses = Vec::with_capacity(addresses.len());
    for address in addresses {
        if target_ip_denied(address.ip(), security) {
            continue;
        }
        allowed_addresses.push(address);
    }

    if allowed_addresses.is_empty() {
        return Err(TargetConnectError::forbidden(
            "all resolved target addresses are denied".to_string(),
        ));
    }

    let mut last_error = None;
    for address in allowed_addresses {
        match TcpStream::connect(address).await {
            Ok(stream) => return Ok(stream),
            Err(err) => last_error = Some(err),
        }
    }

    Err(TargetConnectError::connect(match last_error {
        Some(err) => anyhow!(err).context("failed to connect to allowed target addresses"),
        None => anyhow!("target DNS returned no allowed addresses"),
    }))
}

pub(crate) struct ConnectedTarget {
    pub(crate) stream: TcpStream,
    pub(crate) connect_ms: u64,
}

fn target_ip_denied(ip: IpAddr, security: &ServerSecurityConfig) -> bool {
    if !security.deny_private_ips {
        return false;
    }

    match ip {
        IpAddr::V4(ip) => ip.is_loopback() || ip.is_private() || ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local(),
    }
}

#[derive(Debug)]
pub(crate) enum TargetConnectError {
    Forbidden {
        reason: String,
        connect_ms: u64,
    },
    Timeout {
        connect_ms: u64,
    },
    Connect {
        source: anyhow::Error,
        connect_ms: u64,
    },
}

impl fmt::Display for TargetConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Forbidden { reason, .. } => write!(f, "{reason}"),
            Self::Timeout { .. } => write!(f, "target connect timed out"),
            Self::Connect { source, .. } => write!(f, "{source}"),
        }
    }
}

impl std::error::Error for TargetConnectError {}

impl TargetConnectError {
    fn forbidden(reason: String) -> Self {
        Self::Forbidden {
            reason,
            connect_ms: 0,
        }
    }

    fn connect(source: anyhow::Error) -> Self {
        Self::Connect {
            source,
            connect_ms: 0,
        }
    }

    pub(crate) fn connect_ms(&self) -> u64 {
        match self {
            Self::Forbidden { connect_ms, .. }
            | Self::Timeout { connect_ms }
            | Self::Connect { connect_ms, .. } => *connect_ms,
        }
    }

    fn with_connect_ms(self, connect_ms: u64) -> Self {
        match self {
            Self::Forbidden { reason, .. } => Self::Forbidden { reason, connect_ms },
            Self::Timeout { .. } => Self::Timeout { connect_ms },
            Self::Connect { source, .. } => Self::Connect { source, connect_ms },
        }
    }
}

fn elapsed_millis(elapsed: Duration) -> u64 {
    elapsed.as_millis().min(u128::from(u64::MAX)) as u64
}
