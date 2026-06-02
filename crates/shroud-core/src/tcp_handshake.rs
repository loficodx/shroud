//! Binary handshake for `fast_tcp`.

use crate::auth::AUTH_TAG_LEN;
use std::fmt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const FAST_TCP_MAGIC: [u8; 4] = *b"SHRD";
pub const FAST_TCP_VERSION: u8 = 1;
pub const FAST_TCP_COMMAND_CONNECT: u8 = 1;
pub const MAX_FAST_TCP_AUTH_LEN: usize = u8::MAX as usize;
pub const MAX_FAST_TCP_HOST_LEN: usize = u8::MAX as usize;
pub const MAX_FAST_TCP_NONCE_LEN: usize = u8::MAX as usize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientAuthProof {
    pub client_id: String,
    pub timestamp: i64,
    pub nonce: Vec<u8>,
    pub auth_tag: [u8; AUTH_TAG_LEN],
}

impl ClientAuthProof {
    pub fn new(
        client_id: impl Into<String>,
        timestamp: i64,
        nonce: Vec<u8>,
        auth_tag: [u8; AUTH_TAG_LEN],
    ) -> Self {
        Self {
            client_id: client_id.into(),
            timestamp,
            nonce,
            auth_tag,
        }
    }

    fn encode(&self) -> Result<Vec<u8>, TcpHandshakeError> {
        validate_client_id(&self.client_id)?;
        validate_nonce(&self.nonce)?;

        let client_id = self.client_id.as_bytes();
        let encoded_len = 1 + client_id.len() + 8 + 1 + self.nonce.len() + AUTH_TAG_LEN;
        if encoded_len > MAX_FAST_TCP_AUTH_LEN {
            return Err(TcpHandshakeError::AuthTooLong(encoded_len));
        }

        let mut out = Vec::with_capacity(encoded_len);
        out.push(client_id.len() as u8);
        out.extend_from_slice(client_id);
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.push(self.nonce.len() as u8);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.auth_tag);
        Ok(out)
    }

    fn decode(raw: &[u8]) -> Result<Self, TcpHandshakeError> {
        let Some((&client_id_len, rest)) = raw.split_first() else {
            return Err(TcpHandshakeError::InvalidAuthProof("missing client_id_len"));
        };
        let client_id_len = client_id_len as usize;
        if client_id_len == 0 {
            return Err(TcpHandshakeError::EmptyClientId);
        }
        if rest.len() < client_id_len + 8 + 1 + AUTH_TAG_LEN {
            return Err(TcpHandshakeError::InvalidAuthProof("auth proof too short"));
        }

        let (client_id_raw, rest) = rest.split_at(client_id_len);
        let client_id = std::str::from_utf8(client_id_raw)
            .map_err(|_| TcpHandshakeError::InvalidClientIdUtf8)?
            .to_string();

        let (timestamp_raw, rest) = rest.split_at(8);
        let timestamp = i64::from_be_bytes(
            timestamp_raw
                .try_into()
                .expect("timestamp split guarantees exact length"),
        );

        let Some((&nonce_len, rest)) = rest.split_first() else {
            return Err(TcpHandshakeError::InvalidAuthProof("missing nonce_len"));
        };
        let nonce_len = nonce_len as usize;
        if nonce_len == 0 {
            return Err(TcpHandshakeError::EmptyNonce);
        }
        if rest.len() != nonce_len + AUTH_TAG_LEN {
            return Err(TcpHandshakeError::InvalidAuthProof(
                "auth proof length mismatch",
            ));
        }

        let (nonce, auth_tag_raw) = rest.split_at(nonce_len);
        let auth_tag = auth_tag_raw
            .try_into()
            .expect("auth tag split guarantees exact length");

        Ok(Self {
            client_id,
            timestamp,
            nonce: nonce.to_vec(),
            auth_tag,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpConnectRequest {
    pub host: String,
    pub port: u16,
    pub auth: ClientAuthProof,
}

impl TcpConnectRequest {
    pub fn new(host: impl Into<String>, port: u16, auth: ClientAuthProof) -> Self {
        Self {
            host: host.into(),
            port,
            auth,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TcpConnectStatus {
    Ok = 0x00,
    AuthFailed = 0x01,
    InvalidRequest = 0x02,
    ConnectFailed = 0x03,
    Forbidden = 0x04,
}

impl TryFrom<u8> for TcpConnectStatus {
    type Error = TcpHandshakeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Ok),
            0x01 => Ok(Self::AuthFailed),
            0x02 => Ok(Self::InvalidRequest),
            0x03 => Ok(Self::ConnectFailed),
            0x04 => Ok(Self::Forbidden),
            _ => Err(TcpHandshakeError::UnknownStatus(value)),
        }
    }
}

impl fmt::Display for TcpConnectStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => write!(f, "ok"),
            Self::AuthFailed => write!(f, "auth_failed"),
            Self::InvalidRequest => write!(f, "invalid_request"),
            Self::ConnectFailed => write!(f, "connect_failed"),
            Self::Forbidden => write!(f, "forbidden"),
        }
    }
}

pub async fn write_fast_connect_request<W>(
    writer: &mut W,
    req: &TcpConnectRequest,
) -> Result<(), TcpHandshakeError>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    validate_host(&req.host)?;
    validate_port(req.port)?;

    let auth = req.auth.encode()?;
    let host = req.host.as_bytes();

    writer.write_all(&FAST_TCP_MAGIC).await?;
    writer.write_all(&[FAST_TCP_VERSION]).await?;
    writer.write_all(&[FAST_TCP_COMMAND_CONNECT]).await?;
    writer.write_all(&[auth.len() as u8]).await?;
    writer.write_all(&auth).await?;
    writer.write_all(&[host.len() as u8]).await?;
    writer.write_all(host).await?;
    writer.write_all(&req.port.to_be_bytes()).await?;
    Ok(())
}

pub async fn read_fast_connect_request<R>(
    reader: &mut R,
) -> Result<TcpConnectRequest, TcpHandshakeError>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic).await?;
    if magic != FAST_TCP_MAGIC {
        return Err(TcpHandshakeError::InvalidMagic(magic));
    }

    let version = read_u8(reader).await?;
    if version != FAST_TCP_VERSION {
        return Err(TcpHandshakeError::UnsupportedVersion(version));
    }

    let command = read_u8(reader).await?;
    if command != FAST_TCP_COMMAND_CONNECT {
        return Err(TcpHandshakeError::UnsupportedCommand(command));
    }

    let auth_len = read_u8(reader).await? as usize;
    let mut auth = vec![0u8; auth_len];
    reader.read_exact(&mut auth).await?;
    let auth = ClientAuthProof::decode(&auth)?;

    let host_len = read_u8(reader).await? as usize;
    let mut host = vec![0u8; host_len];
    reader.read_exact(&mut host).await?;
    let host = String::from_utf8(host).map_err(|_| TcpHandshakeError::InvalidHostUtf8)?;
    validate_host(&host)?;

    let mut port = [0u8; 2];
    reader.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);
    validate_port(port)?;

    Ok(TcpConnectRequest { host, port, auth })
}

pub async fn write_fast_connect_status<W>(
    writer: &mut W,
    status: TcpConnectStatus,
) -> Result<(), TcpHandshakeError>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    writer.write_all(&[status as u8]).await?;
    Ok(())
}

pub async fn read_fast_connect_status<R>(
    reader: &mut R,
) -> Result<TcpConnectStatus, TcpHandshakeError>
where
    R: AsyncRead + Unpin + ?Sized,
{
    TcpConnectStatus::try_from(read_u8(reader).await?)
}

async fn read_u8<R>(reader: &mut R) -> Result<u8, TcpHandshakeError>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut byte = [0u8; 1];
    reader.read_exact(&mut byte).await?;
    Ok(byte[0])
}

fn validate_host(host: &str) -> Result<(), TcpHandshakeError> {
    let len = host.len();
    if len == 0 {
        return Err(TcpHandshakeError::EmptyHost);
    }
    if len > MAX_FAST_TCP_HOST_LEN {
        return Err(TcpHandshakeError::HostTooLong(len));
    }
    Ok(())
}

fn validate_port(port: u16) -> Result<(), TcpHandshakeError> {
    if port == 0 {
        return Err(TcpHandshakeError::InvalidPort(port));
    }
    Ok(())
}

fn validate_client_id(client_id: &str) -> Result<(), TcpHandshakeError> {
    let len = client_id.len();
    if len == 0 {
        return Err(TcpHandshakeError::EmptyClientId);
    }
    if len > u8::MAX as usize {
        return Err(TcpHandshakeError::ClientIdTooLong(len));
    }
    Ok(())
}

fn validate_nonce(nonce: &[u8]) -> Result<(), TcpHandshakeError> {
    let len = nonce.len();
    if len == 0 {
        return Err(TcpHandshakeError::EmptyNonce);
    }
    if len > MAX_FAST_TCP_NONCE_LEN {
        return Err(TcpHandshakeError::NonceTooLong(len));
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum TcpHandshakeError {
    #[error("invalid fast_tcp magic: {0:?}")]
    InvalidMagic([u8; 4]),
    #[error("unsupported fast_tcp version: {0}")]
    UnsupportedVersion(u8),
    #[error("unsupported fast_tcp command: {0}")]
    UnsupportedCommand(u8),
    #[error("unknown fast_tcp status: {0:#04x}")]
    UnknownStatus(u8),
    #[error("fast_tcp auth proof too long: {0} bytes")]
    AuthTooLong(usize),
    #[error("fast_tcp auth proof is invalid: {0}")]
    InvalidAuthProof(&'static str),
    #[error("fast_tcp client_id is empty")]
    EmptyClientId,
    #[error("fast_tcp client_id is not valid utf-8")]
    InvalidClientIdUtf8,
    #[error("fast_tcp client_id is too long: {0} bytes")]
    ClientIdTooLong(usize),
    #[error("fast_tcp nonce is empty")]
    EmptyNonce,
    #[error("fast_tcp nonce is too long: {0} bytes")]
    NonceTooLong(usize),
    #[error("fast_tcp host is empty")]
    EmptyHost,
    #[error("fast_tcp host is not valid utf-8")]
    InvalidHostUtf8,
    #[error("fast_tcp host is too long: {0} bytes")]
    HostTooLong(usize),
    #[error("fast_tcp port is invalid: {0}")]
    InvalidPort(u16),
    #[error("fast_tcp handshake IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    fn proof() -> ClientAuthProof {
        ClientAuthProof::new(
            "11111111-1111-1111-1111-111111111111",
            1_800_000_000,
            vec![7u8; 16],
            [9u8; AUTH_TAG_LEN],
        )
    }

    async fn roundtrip(req: TcpConnectRequest) -> Result<TcpConnectRequest, TcpHandshakeError> {
        let mut bytes = Vec::new();
        write_fast_connect_request(&mut bytes, &req).await?;
        let mut reader = bytes.as_slice();
        read_fast_connect_request(&mut reader).await
    }

    #[tokio::test]
    async fn roundtrips_valid_domain() {
        let req = TcpConnectRequest::new("example.com", 443, proof());
        assert_eq!(roundtrip(req.clone()).await.unwrap(), req);
    }

    #[tokio::test]
    async fn roundtrips_valid_ipv4_string() {
        let req = TcpConnectRequest::new("203.0.113.7", 8080, proof());
        assert_eq!(roundtrip(req.clone()).await.unwrap(), req);
    }

    #[tokio::test]
    async fn rejects_empty_host() {
        let req = TcpConnectRequest::new("", 443, proof());
        let err = roundtrip(req).await.unwrap_err();
        assert!(matches!(err, TcpHandshakeError::EmptyHost));
    }

    #[tokio::test]
    async fn rejects_too_long_host() {
        let req = TcpConnectRequest::new("a".repeat(MAX_FAST_TCP_HOST_LEN + 1), 443, proof());
        let err = roundtrip(req).await.unwrap_err();
        assert!(matches!(err, TcpHandshakeError::HostTooLong(256)));
    }

    #[tokio::test]
    async fn rejects_port_zero() {
        let req = TcpConnectRequest::new("example.com", 0, proof());
        let err = roundtrip(req).await.unwrap_err();
        assert!(matches!(err, TcpHandshakeError::InvalidPort(0)));
    }

    #[tokio::test]
    async fn roundtrips_auth_failed_status() {
        let mut bytes = Vec::new();
        write_fast_connect_status(&mut bytes, TcpConnectStatus::AuthFailed)
            .await
            .unwrap();

        let mut reader = bytes.as_slice();
        let status = read_fast_connect_status(&mut reader).await.unwrap();
        assert_eq!(status, TcpConnectStatus::AuthFailed);
    }

    #[tokio::test]
    async fn partial_read_fails_safely() {
        let mut bytes = Vec::new();
        write_fast_connect_request(
            &mut bytes,
            &TcpConnectRequest::new("example.com", 443, proof()),
        )
        .await
        .unwrap();
        bytes.truncate(bytes.len() - 1);

        let mut reader = bytes.as_slice();
        let err = read_fast_connect_request(&mut reader).await.unwrap_err();
        assert!(matches!(err, TcpHandshakeError::Io(_)));
    }

    #[tokio::test]
    async fn rejects_unknown_status() {
        let mut reader = [0xff].as_slice();
        let err = read_fast_connect_status(&mut reader).await.unwrap_err();
        assert!(matches!(err, TcpHandshakeError::UnknownStatus(0xff)));
    }

    #[tokio::test]
    async fn rejects_partial_status_read() {
        let (client, mut server) = tokio::io::duplex(1);
        drop(client);
        let err = read_fast_connect_status(&mut server).await.unwrap_err();
        assert!(matches!(err, TcpHandshakeError::Io(_)));
    }

    #[tokio::test]
    async fn rejects_malformed_auth_proof() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&FAST_TCP_MAGIC);
        bytes.push(FAST_TCP_VERSION);
        bytes.push(FAST_TCP_COMMAND_CONNECT);
        bytes.push(1);
        bytes.push(0);
        bytes.push(11);
        bytes.extend_from_slice(b"example.com");
        bytes.extend_from_slice(&443u16.to_be_bytes());

        let mut reader = bytes.as_slice();
        let err = read_fast_connect_request(&mut reader).await.unwrap_err();
        assert!(matches!(err, TcpHandshakeError::EmptyClientId));
    }

    #[tokio::test]
    async fn write_status_flushes_single_byte() {
        let (mut client, mut server) = tokio::io::duplex(1);
        let writer = tokio::spawn(async move {
            write_fast_connect_status(&mut client, TcpConnectStatus::Forbidden)
                .await
                .unwrap();
            client.shutdown().await.unwrap();
        });

        let status = read_fast_connect_status(&mut server).await.unwrap();
        writer.await.unwrap();
        assert_eq!(status, TcpConnectStatus::Forbidden);
    }
}
