use anyhow::{Result, anyhow, bail};
use bytes::Bytes;
use shroud_core::protocol::{FrameType, read_frame, write_frame};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;
use tracing::debug;

const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const UDP_DISABLED_MESSAGE: &[u8] = b"UDP ASSOCIATE is not supported in current MVP";

pub async fn relay_tunnel<S>(mut tunnel_stream: S, peer: SocketAddr) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let first_frame = timeout(RELAY_IDLE_TIMEOUT, read_frame(&mut tunnel_stream))
        .await
        .map_err(|_| anyhow!("timed out waiting for first tunnel frame"))??;

    write_frame(
        &mut tunnel_stream,
        FrameType::ErrorFrame,
        first_frame.stream_id,
        0,
        Bytes::from_static(UDP_DISABLED_MESSAGE),
    )
    .await?;

    debug!(
        %peer,
        first_frame_type = %first_frame.frame_type,
        stream_id = first_frame.stream_id,
        "legacy HTTP tunnel request rejected"
    );
    bail!("UDP ASSOCIATE is not supported in current MVP")
}

#[cfg(test)]
mod tests {
    use super::*;
    use shroud_core::protocol::{FrameType, read_frame, write_frame};
    use tokio::io::duplex;

    #[tokio::test]
    async fn legacy_http_tunnel_frame_is_rejected() -> Result<()> {
        let (mut client_side, server_side) = duplex(1024);
        let peer = "127.0.0.1:12345".parse().expect("peer addr");
        let relay_task = tokio::spawn(relay_tunnel(server_side, peer));

        write_frame(&mut client_side, FrameType::Ping, 1, 0, Bytes::new()).await?;

        let response = read_frame(&mut client_side).await?;
        assert_eq!(response.frame_type, FrameType::ErrorFrame);
        assert_eq!(response.stream_id, 1);
        assert_eq!(response.payload, Bytes::from_static(UDP_DISABLED_MESSAGE));

        let err = relay_task
            .await
            .expect("relay task joins")
            .expect_err("rejects");
        assert!(
            err.to_string()
                .contains("UDP ASSOCIATE is not supported in current MVP")
        );
        Ok(())
    }
}
