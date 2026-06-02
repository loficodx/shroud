use crate::transport;
use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use shroud_core::config::{ClientAuthConfig, OutboundConfig};
use shroud_core::protocol::{
    FrameType, UdpDatagram, decode_udp_associate_response_payload, decode_udp_datagram,
    encode_udp_datagram, read_frame, write_frame,
};
use std::time::Duration;
use tokio::io::{ReadHalf, WriteHalf, split};
use tokio::time::timeout;

const UDP_LOGICAL_ID: u64 = 1;
const CONNECT_OK_FLAG: u16 = 0x0001;
const UDP_ASSOCIATE_REPLY_TIMEOUT: Duration = Duration::from_secs(10);
const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

pub type TunnelStream = transport::BoxedIo;

#[derive(Debug, Clone, Copy)]
pub struct RelayStats {
    pub client_to_upstream_bytes: u64,
    pub upstream_to_client_bytes: u64,
}

impl RelayStats {
    pub fn total_bytes(self) -> u64 {
        self.client_to_upstream_bytes + self.upstream_to_client_bytes
    }

    pub fn mbps(self, elapsed: Duration) -> f64 {
        let seconds = elapsed.as_secs_f64();
        if seconds > 0.0 {
            (self.total_bytes() as f64 * 8.0) / seconds / 1_000_000.0
        } else {
            0.0
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpAssociationInfo {
    pub remote_bind_host: String,
    pub remote_bind_port: u16,
}

pub struct UdpTunnel {
    stream: TunnelStream,
    stream_id: u64,
    pub association: UdpAssociationInfo,
}

pub struct UdpTunnelReadHalf {
    reader: ReadHalf<TunnelStream>,
    stream_id: u64,
}

pub struct UdpTunnelWriteHalf {
    writer: WriteHalf<TunnelStream>,
    stream_id: u64,
}

impl UdpTunnel {
    pub fn into_split(self) -> (UdpTunnelReadHalf, UdpTunnelWriteHalf) {
        let stream_id = self.stream_id;
        let (reader, writer) = split(self.stream);
        (
            UdpTunnelReadHalf { reader, stream_id },
            UdpTunnelWriteHalf { writer, stream_id },
        )
    }
}

impl UdpTunnelReadHalf {
    pub async fn recv_datagram(&mut self) -> Result<UdpDatagram> {
        let frame = timeout(RELAY_IDLE_TIMEOUT, read_frame(&mut self.reader))
            .await
            .context("udp relay idle timeout while reading from tunnel")??;
        if frame.stream_id != self.stream_id {
            bail!(
                "unexpected stream id in UDP_DATAGRAM: expected={}, got={}",
                self.stream_id,
                frame.stream_id
            );
        }

        match frame.frame_type {
            FrameType::UdpDatagram => decode_udp_datagram(frame.payload.as_ref())
                .map_err(|err| anyhow!("invalid UDP_DATAGRAM payload: {err}")),
            FrameType::ErrorFrame => {
                let message = String::from_utf8_lossy(frame.payload.as_ref()).into_owned();
                bail!("server returned ERROR frame during UDP relay: {message}");
            }
            other => bail!("unexpected frame type from server during UDP relay: {other}"),
        }
    }
}

impl UdpTunnelWriteHalf {
    pub async fn send_datagram(&mut self, datagram: &UdpDatagram) -> Result<()> {
        let payload = encode_udp_datagram(datagram)
            .map_err(|err| anyhow!("failed to encode UDP_DATAGRAM payload: {err}"))?;
        timeout(
            RELAY_IDLE_TIMEOUT,
            write_frame(
                &mut self.writer,
                FrameType::UdpDatagram,
                self.stream_id,
                0,
                payload,
            ),
        )
        .await
        .context("udp relay timeout while writing UDP_DATAGRAM to tunnel")??;
        Ok(())
    }
}

#[derive(Clone)]
pub struct TunnelClient {
    outbound: OutboundConfig,
    auth: ClientAuthConfig,
}

impl TunnelClient {
    pub fn new(outbound: OutboundConfig, auth: ClientAuthConfig) -> Self {
        Self { outbound, auth }
    }

    pub(crate) fn transport_parts(&self) -> (OutboundConfig, ClientAuthConfig) {
        (self.outbound.clone(), self.auth.clone())
    }

    pub async fn open_udp_association(&self) -> Result<UdpTunnel> {
        let mut stream = self
            .open_tunnel_transport("<udp-associate>", 0)
            .await
            .context("failed to open tunnel transport for UDP associate")?;

        write_frame(
            &mut stream,
            FrameType::UdpAssociateRequest,
            UDP_LOGICAL_ID,
            0,
            Bytes::new(),
        )
        .await?;

        let response = timeout(UDP_ASSOCIATE_REPLY_TIMEOUT, read_frame(&mut stream))
            .await
            .context("timed out waiting for UDP_ASSOCIATE response")??;
        if response.stream_id != UDP_LOGICAL_ID {
            bail!(
                "unexpected stream id in UDP associate response: {}",
                response.stream_id
            );
        }

        match response.frame_type {
            FrameType::UdpAssociateResponse if (response.flags & CONNECT_OK_FLAG) != 0 => {
                let (remote_bind_host, remote_bind_port) =
                    decode_udp_associate_response_payload(response.payload.as_ref())
                        .map_err(|err| anyhow!("invalid UDP_ASSOCIATE response payload: {err}"))?;
                Ok(UdpTunnel {
                    stream,
                    stream_id: UDP_LOGICAL_ID,
                    association: UdpAssociationInfo {
                        remote_bind_host,
                        remote_bind_port,
                    },
                })
            }
            FrameType::UdpAssociateResponse => {
                let message = String::from_utf8_lossy(response.payload.as_ref()).into_owned();
                bail!(
                    "server refused UDP_ASSOCIATE: flags={}, message={message}",
                    response.flags
                );
            }
            FrameType::ErrorFrame => {
                let message = String::from_utf8_lossy(response.payload.as_ref()).into_owned();
                bail!("server refused UDP_ASSOCIATE: {message}");
            }
            other => bail!("unexpected frame type instead of UDP associate response: {other}"),
        }
    }

    async fn open_tunnel_transport(
        &self,
        target_host: &str,
        target_port: u16,
    ) -> Result<TunnelStream> {
        let transport = transport::http::open_legacy_http_upgrade_transport(
            &self.outbound,
            &self.auth,
            target_host,
            target_port,
        )
        .await?;

        Ok(transport.stream)
    }
}
