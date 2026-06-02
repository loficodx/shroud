use anyhow::{Result, bail};
use tokio::io::{AsyncRead, AsyncWrite};

pub async fn handle_balanced_tcp_connection<S>(_inbound: S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    bail!("balanced_tcp server transport is not implemented yet")
}
