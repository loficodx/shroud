use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::fmt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PROTOCOL_VERSION: u8 = 1;
pub const HEADER_LEN: usize = 16;
pub const MAX_FRAME_PAYLOAD_LEN: usize = 32 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    AuthChallenge = 0x01,
    AuthResponse = 0x02,
    Ping = 0x20,
    Pong = 0x21,
    ErrorFrame = 0x7F,
}

impl TryFrom<u8> for FrameType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let frame_type = match value {
            0x01 => Self::AuthChallenge,
            0x02 => Self::AuthResponse,
            0x20 => Self::Ping,
            0x21 => Self::Pong,
            0x7F => Self::ErrorFrame,
            _ => return Err(ProtocolError::UnknownFrameType(value)),
        };
        Ok(frame_type)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub frame_type: FrameType,
    pub stream_id: u64,
    pub flags: u16,
    pub payload: Bytes,
}

impl Frame {
    pub fn encode(&self) -> Bytes {
        assert!(
            self.payload.len() <= MAX_FRAME_PAYLOAD_LEN,
            "frame payload exceeds maximum size"
        );
        let mut out = BytesMut::with_capacity(HEADER_LEN + self.payload.len());
        out.put_u8(PROTOCOL_VERSION);
        out.put_u8(self.frame_type as u8);
        out.put_u64(self.stream_id);
        out.put_u16(self.flags);
        out.put_u32(self.payload.len() as u32);
        out.extend_from_slice(&self.payload);
        out.freeze()
    }

    pub fn decode(mut src: Bytes) -> Result<Self, ProtocolError> {
        if src.len() < HEADER_LEN {
            return Err(ProtocolError::FrameTooShort(src.len()));
        }

        let version = src.get_u8();
        if version != PROTOCOL_VERSION {
            return Err(ProtocolError::VersionMismatch {
                got: version,
                expected: PROTOCOL_VERSION,
            });
        }

        let frame_type = FrameType::try_from(src.get_u8())?;
        let stream_id = src.get_u64();
        let flags = src.get_u16();
        let length = src.get_u32() as usize;

        if length > MAX_FRAME_PAYLOAD_LEN {
            return Err(ProtocolError::FramePayloadTooLarge {
                max: MAX_FRAME_PAYLOAD_LEN,
                got: length,
            });
        }

        if src.len() != length {
            return Err(ProtocolError::PayloadLengthMismatch {
                expected: length,
                got: src.len(),
            });
        }

        Ok(Self {
            frame_type,
            stream_id,
            flags,
            payload: src,
        })
    }
}

pub async fn write_frame<W>(
    writer: &mut W,
    frame_type: FrameType,
    stream_id: u64,
    flags: u16,
    payload: Bytes,
) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    if payload.len() > MAX_FRAME_PAYLOAD_LEN {
        return Err(ProtocolError::FramePayloadTooLarge {
            max: MAX_FRAME_PAYLOAD_LEN,
            got: payload.len(),
        });
    }

    let frame = Frame {
        frame_type,
        stream_id,
        flags,
        payload,
    };
    writer.write_all(frame.encode().as_ref()).await?;
    Ok(())
}

pub async fn read_frame<R>(reader: &mut R) -> Result<Frame, ProtocolError>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header).await?;

    let payload_len = u32::from_be_bytes([header[12], header[13], header[14], header[15]]) as usize;
    if payload_len > MAX_FRAME_PAYLOAD_LEN {
        return Err(ProtocolError::FramePayloadTooLarge {
            max: MAX_FRAME_PAYLOAD_LEN,
            got: payload_len,
        });
    }

    let mut raw = Vec::with_capacity(HEADER_LEN + payload_len);
    raw.extend_from_slice(&header);

    if payload_len > 0 {
        let mut payload = vec![0u8; payload_len];
        reader.read_exact(&mut payload).await?;
        raw.extend_from_slice(&payload);
    }

    Frame::decode(Bytes::from(raw))
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("unknown frame type: {0:#04x}")]
    UnknownFrameType(u8),
    #[error("frame too short: {0} bytes")]
    FrameTooShort(usize),
    #[error("protocol version mismatch: got={got}, expected={expected}")]
    VersionMismatch { got: u8, expected: u8 },
    #[error("payload length mismatch: expected={expected}, got={got}")]
    PayloadLengthMismatch { expected: usize, got: usize },
    #[error("frame payload too large: max={max}, got={got}")]
    FramePayloadTooLarge { max: usize, got: usize },
    #[error("frame IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl fmt::Display for FrameType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthChallenge => write!(f, "AUTH_CHALLENGE"),
            Self::AuthResponse => write!(f, "AUTH_RESPONSE"),
            Self::Ping => write!(f, "PING"),
            Self::Pong => write!(f, "PONG"),
            Self::ErrorFrame => write!(f, "ERROR"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn roundtrip_frame() {
        let frame = Frame {
            frame_type: FrameType::Ping,
            stream_id: 42,
            flags: 1,
            payload: Bytes::from_static(b"hello"),
        };

        let encoded = frame.encode();
        let decoded = Frame::decode(encoded).expect("decode");

        assert_eq!(decoded.frame_type, FrameType::Ping);
        assert_eq!(decoded.stream_id, 42);
        assert_eq!(decoded.flags, 1);
        assert_eq!(decoded.payload, Bytes::from_static(b"hello"));
    }

    #[tokio::test]
    async fn read_write_frame_preserves_non_default_stream_id() {
        let (mut writer, mut reader) = tokio::io::duplex(1024);

        write_frame(
            &mut writer,
            FrameType::Ping,
            7,
            0x0002,
            Bytes::from_static(b"payload"),
        )
        .await
        .expect("write frame");

        let decoded = read_frame(&mut reader).await.expect("read frame");

        assert_eq!(decoded.frame_type, FrameType::Ping);
        assert_eq!(decoded.stream_id, 7);
        assert_eq!(decoded.flags, 0x0002);
        assert_eq!(decoded.payload, Bytes::from_static(b"payload"));
    }

    #[tokio::test]
    async fn write_frame_rejects_oversized_payload() {
        let (mut writer, _reader) = tokio::io::duplex(1024);
        let payload = Bytes::from(vec![0u8; MAX_FRAME_PAYLOAD_LEN + 1]);

        let err = write_frame(&mut writer, FrameType::Ping, 1, 0, payload)
            .await
            .expect_err("oversized frame must fail");

        assert!(matches!(err, ProtocolError::FramePayloadTooLarge { .. }));
    }

    #[test]
    fn decode_rejects_oversized_payload_length() {
        let mut encoded = BytesMut::with_capacity(HEADER_LEN);
        encoded.put_u8(PROTOCOL_VERSION);
        encoded.put_u8(FrameType::Ping as u8);
        encoded.put_u64(1);
        encoded.put_u16(0);
        encoded.put_u32((MAX_FRAME_PAYLOAD_LEN + 1) as u32);

        let err = Frame::decode(encoded.freeze()).expect_err("oversized frame must fail");
        assert!(matches!(err, ProtocolError::FramePayloadTooLarge { .. }));
    }

    #[test]
    fn decode_rejects_short_header() {
        let err = Frame::decode(Bytes::from_static(b"\x01\x11"))
            .expect_err("short frame header must fail");
        assert!(matches!(err, ProtocolError::FrameTooShort(2)));
    }

    #[test]
    fn decode_rejects_truncated_payload() {
        let mut encoded = BytesMut::with_capacity(HEADER_LEN + 2);
        encoded.put_u8(PROTOCOL_VERSION);
        encoded.put_u8(FrameType::Ping as u8);
        encoded.put_u64(1);
        encoded.put_u16(0);
        encoded.put_u32(3);
        encoded.extend_from_slice(b"ab");

        let err = Frame::decode(encoded.freeze()).expect_err("truncated payload must fail");
        assert!(matches!(
            err,
            ProtocolError::PayloadLengthMismatch {
                expected: 3,
                got: 2
            }
        ));
    }

    #[test]
    fn decode_rejects_payload_length_with_trailing_bytes() {
        let mut encoded = BytesMut::with_capacity(HEADER_LEN + 3);
        encoded.put_u8(PROTOCOL_VERSION);
        encoded.put_u8(FrameType::Ping as u8);
        encoded.put_u64(1);
        encoded.put_u16(0);
        encoded.put_u32(2);
        encoded.extend_from_slice(b"abc");

        let err = Frame::decode(encoded.freeze()).expect_err("trailing payload bytes must fail");
        assert!(matches!(
            err,
            ProtocolError::PayloadLengthMismatch {
                expected: 2,
                got: 3
            }
        ));
    }
}
