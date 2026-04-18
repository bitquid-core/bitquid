
use crate::error::NetworkError;
use crate::protocol::{NetworkMessage, NETWORK_MAGIC, PROTOCOL_VERSION, MAX_MESSAGE_SIZE};

/// Frame format:
/// [4 bytes magic][2 bytes version][4 bytes length][payload...]
const HEADER_SIZE: usize = 10;

/// Encode a network message into a framed byte buffer
pub fn encode_message(msg: &NetworkMessage) -> Result<Vec<u8>, NetworkError> {
    let payload =
        bincode::serialize(msg).map_err(|e| NetworkError::Serialization(e.to_string()))?;

    if payload.len() > MAX_MESSAGE_SIZE {
        return Err(NetworkError::MessageTooLarge {
            size: payload.len(),
            max: MAX_MESSAGE_SIZE,
        });
    }

    let mut buf = Vec::with_capacity(HEADER_SIZE + payload.len());
    buf.extend_from_slice(&NETWORK_MAGIC);
    buf.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(&payload);

    Ok(buf)
}

/// Decode a network message from a byte buffer.
/// Returns (message, bytes_consumed) or None if more data is needed.
pub fn decode_message(buf: &[u8]) -> Result<Option<(NetworkMessage, usize)>, NetworkError> {
    if buf.len() < HEADER_SIZE {
        return Ok(None);
    }

    if &buf[..4] != &NETWORK_MAGIC {
        return Err(NetworkError::Protocol("invalid magic bytes".into()));
    }

    let version = u16::from_be_bytes([buf[4], buf[5]]);
    if version != PROTOCOL_VERSION {
        return Err(NetworkError::Protocol(format!(
            "protocol version mismatch: ours={}, theirs={version}",
            PROTOCOL_VERSION
        )));
    }

    let length = u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]]) as usize;

    if length > MAX_MESSAGE_SIZE {
        return Err(NetworkError::MessageTooLarge {
            size: length,
            max: MAX_MESSAGE_SIZE,
        });
    }

    let total = HEADER_SIZE + length;
    if buf.len() < total {
        return Ok(None);
    }

    let payload = &buf[HEADER_SIZE..total];
    let msg: NetworkMessage =
        bincode::deserialize(payload).map_err(|e| NetworkError::Serialization(e.to_string()))?;

    Ok(Some((msg, total)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let msg = NetworkMessage::Ping(42);
        let encoded = encode_message(&msg).unwrap();
        let (decoded, consumed) = decode_message(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        match decoded {
            NetworkMessage::Ping(n) => assert_eq!(n, 42),
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn test_partial_data_returns_none() {
        let result = decode_message(&[0xBF, 0x51]).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_invalid_magic_returns_error() {
        let result = decode_message(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert!(result.is_err());
    }
}
