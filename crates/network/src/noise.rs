//! Post-Quantum Noise Transport — ML-KEM-768 key exchange + ChaCha20-Poly1305 AEAD.
//!
//! Replaces the classical secp256k1 ECDH with NIST FIPS 203 ML-KEM-768
//! key encapsulation for quantum-resistant key agreement.
//!
//! Handshake (KEM-based mutual key exchange):
//!   -> ek_i                        (initiator ephemeral encapsulation key)
//!   <- ek_r || ct_to_i             (responder ephemeral ek + ciphertext)
//!   -> ct_to_r                     (initiator ciphertext for responder)
//!
//! Both sides derive: transport_keys = BLAKE3(ss1 || ss2)

use ml_kem::{MlKem768, KemCore, EncodedSizeUser};
use ml_kem::kem::{Encapsulate, Decapsulate};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, AeadInPlace, Nonce};
use rand::rngs::OsRng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;

use crate::error::NetworkError;

type EK = ml_kem::kem::EncapsulationKey<ml_kem::MlKem768Params>;
type DK = ml_kem::kem::DecapsulationKey<ml_kem::MlKem768Params>;

const AEAD_TAG_SIZE: usize = 16;
const MAX_NOISE_MSG: usize = 65535;
const EK_SIZE: usize = 1184;
const CT_SIZE: usize = 1088;

/// Symmetric cipher state using ChaCha20-Poly1305 (RFC 8439).
pub struct CipherState {
    cipher: ChaCha20Poly1305,
    nonce: u64,
}

impl CipherState {
    fn new(key: [u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(&key.into()),
            nonce: 0,
        }
    }

    fn next_nonce(&mut self) -> Nonce {
        let n = self.nonce;
        self.nonce = self.nonce.checked_add(1).expect("nonce exhausted");
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&n.to_le_bytes());
        nonce_bytes.into()
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let nonce = self.next_nonce();
        let mut buf = plaintext.to_vec();
        self.cipher.encrypt_in_place(&nonce, b"", &mut buf)
            .expect("encryption cannot fail for valid inputs");
        buf
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NetworkError> {
        if ciphertext.len() < AEAD_TAG_SIZE {
            return Err(NetworkError::Protocol("noise: ciphertext too short".into()));
        }
        let nonce = self.next_nonce();
        let mut buf = ciphertext.to_vec();
        self.cipher.decrypt_in_place(&nonce, b"", &mut buf)
            .map_err(|_| NetworkError::Protocol("noise: AEAD decryption failed".into()))?;
        Ok(buf)
    }
}

fn mix_key(ck: &[u8; 32], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut input = Vec::with_capacity(32 + ikm.len());
    input.extend_from_slice(ck);
    input.extend_from_slice(ikm);
    let derived = blake3::hash(&input);

    let mut second_input = [0u8; 33];
    second_input[..32].copy_from_slice(derived.as_bytes());
    second_input[32] = 0x01;
    let h1 = blake3::hash(&second_input);
    let k1 = *h1.as_bytes();

    second_input[..32].copy_from_slice(h1.as_bytes());
    second_input[32] = 0x02;
    let h2 = blake3::hash(&second_input);
    let k2 = *h2.as_bytes();

    (k1, k2)
}

/// Result of a completed PQ Noise handshake.
pub struct NoiseTransport {
    pub send_cipher: CipherState,
    pub recv_cipher: CipherState,
    pub remote_identity: Vec<u8>,
}

async fn write_noise_msg<W: AsyncWrite + Unpin>(
    w: &mut W,
    data: &[u8],
) -> Result<(), NetworkError> {
    let len = (data.len() as u32).to_be_bytes();
    w.write_all(&len).await?;
    w.write_all(data).await?;
    Ok(())
}

async fn read_noise_msg<R: AsyncRead + Unpin>(
    r: &mut R,
) -> Result<Vec<u8>, NetworkError> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_NOISE_MSG {
        return Err(NetworkError::Protocol("noise message too large".into()));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Serialize an encapsulation key to bytes for network transport.
fn ek_to_vec(ek: &EK) -> Vec<u8> {
    let encoded = ek.as_bytes();
    let slice: &[u8] = encoded.as_ref();
    slice.to_vec()
}

/// PQ Noise handshake as the **initiator** (client).
pub async fn handshake_initiator<RW: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut RW,
    static_identity: &[u8],
) -> Result<NoiseTransport, NetworkError> {
    let protocol_name = b"Noise_KEM_MlKem768_BLAKE3";
    let mut ck: [u8; 32] = *blake3::hash(protocol_name).as_bytes();

    // Generate ephemeral KEM keypair
    let (dk_i, ek_i): (DK, EK) = MlKem768::generate(&mut OsRng);
    let ek_i_vec = ek_to_vec(&ek_i);

    // -> ek_i
    write_noise_msg(stream, &ek_i_vec).await?;
    debug!("noise-pq initiator: sent ephemeral encapsulation key");

    // <- ek_r || ct_to_i || encrypted(remote_identity)
    let msg2 = read_noise_msg(stream).await?;
    if msg2.len() < EK_SIZE + CT_SIZE {
        return Err(NetworkError::HandshakeFailed("noise msg2 too short".into()));
    }

    let ek_r_raw = &msg2[..EK_SIZE];
    let ct_to_i_raw = &msg2[EK_SIZE..EK_SIZE + CT_SIZE];
    let encrypted_remote_id = &msg2[EK_SIZE + CT_SIZE..];

    // Decapsulate ct_to_i → ss1
    let ct_to_i = ct_to_i_raw.try_into()
        .map_err(|_| NetworkError::HandshakeFailed("invalid ciphertext".into()))?;
    let ss1 = dk_i.decapsulate(&ct_to_i)
        .map_err(|_| NetworkError::HandshakeFailed("decapsulation failed".into()))?;
    let ss1_arr: [u8; 32] = ss1.into();
    let (new_ck, transport_key_1) = mix_key(&ck, &ss1_arr);
    ck = new_ck;

    // Decrypt remote identity
    let mut dec_cipher = CipherState::new(transport_key_1);
    let remote_identity = dec_cipher.decrypt(encrypted_remote_id)
        .map_err(|_| NetworkError::HandshakeFailed("identity decryption failed".into()))?;

    // Encapsulate to ek_r → ct_to_r, ss2
    let ek_r_enc = ek_r_raw.try_into()
        .map_err(|_| NetworkError::HandshakeFailed("invalid encap key".into()))?;
    let ek_r_key = EK::from_bytes(&ek_r_enc);
    let (ct_to_r, ss2) = ek_r_key.encapsulate(&mut OsRng)
        .map_err(|_| NetworkError::HandshakeFailed("encapsulation failed".into()))?;

    let ss2_arr: [u8; 32] = ss2.into();
    let ct_to_r_slice: &[u8] = ct_to_r.as_ref();
    let (new_ck, transport_key_2) = mix_key(&ck, &ss2_arr);
    ck = new_ck;

    // Encrypt our identity
    let mut enc_cipher = CipherState::new(transport_key_2);
    let encrypted_our_id = enc_cipher.encrypt(static_identity);

    // -> ct_to_r || encrypted(our_identity)
    let mut msg3 = Vec::with_capacity(CT_SIZE + encrypted_our_id.len());
    msg3.extend_from_slice(ct_to_r_slice);
    msg3.extend_from_slice(&encrypted_our_id);
    write_noise_msg(stream, &msg3).await?;
    debug!("noise-pq initiator: handshake complete");

    let (send_key, recv_key) = mix_key(&ck, &[0u8; 32]);

    Ok(NoiseTransport {
        send_cipher: CipherState::new(send_key),
        recv_cipher: CipherState::new(recv_key),
        remote_identity,
    })
}

/// PQ Noise handshake as the **responder** (server).
pub async fn handshake_responder<RW: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut RW,
    static_identity: &[u8],
) -> Result<NoiseTransport, NetworkError> {
    let protocol_name = b"Noise_KEM_MlKem768_BLAKE3";
    let mut ck: [u8; 32] = *blake3::hash(protocol_name).as_bytes();

    // <- ek_i
    let msg1 = read_noise_msg(stream).await?;
    if msg1.len() < EK_SIZE {
        return Err(NetworkError::HandshakeFailed("noise msg1 too short".into()));
    }
    debug!("noise-pq responder: received initiator encapsulation key");

    // Generate ephemeral KEM keypair
    let (dk_r, ek_r): (DK, EK) = MlKem768::generate(&mut OsRng);
    let ek_r_vec = ek_to_vec(&ek_r);

    // Encapsulate to ek_i → ct_to_i, ss1
    let ek_i_enc = msg1.as_slice().try_into()
        .map_err(|_| NetworkError::HandshakeFailed("invalid encap key".into()))?;
    let ek_i_key = EK::from_bytes(&ek_i_enc);
    let (ct_to_i, ss1) = ek_i_key.encapsulate(&mut OsRng)
        .map_err(|_| NetworkError::HandshakeFailed("encapsulation failed".into()))?;

    let ss1_arr: [u8; 32] = ss1.into();
    let ct_to_i_slice: &[u8] = ct_to_i.as_ref();
    let (new_ck, transport_key_1) = mix_key(&ck, &ss1_arr);
    ck = new_ck;

    // Encrypt our identity
    let mut enc_cipher = CipherState::new(transport_key_1);
    let encrypted_our_id = enc_cipher.encrypt(static_identity);

    // -> ek_r || ct_to_i || encrypted(our_identity)
    let mut msg2 = Vec::with_capacity(EK_SIZE + CT_SIZE + encrypted_our_id.len());
    msg2.extend_from_slice(&ek_r_vec);
    msg2.extend_from_slice(ct_to_i_slice);
    msg2.extend_from_slice(&encrypted_our_id);
    write_noise_msg(stream, &msg2).await?;
    debug!("noise-pq responder: sent msg2");

    // <- ct_to_r || encrypted(remote_identity)
    let msg3 = read_noise_msg(stream).await?;
    if msg3.len() < CT_SIZE {
        return Err(NetworkError::HandshakeFailed("noise msg3 too short".into()));
    }

    let ct_to_r_raw = &msg3[..CT_SIZE];
    let encrypted_remote_id = &msg3[CT_SIZE..];

    // Decapsulate ct_to_r → ss2
    let ct_to_r = ct_to_r_raw.try_into()
        .map_err(|_| NetworkError::HandshakeFailed("invalid ciphertext".into()))?;
    let ss2 = dk_r.decapsulate(&ct_to_r)
        .map_err(|_| NetworkError::HandshakeFailed("decapsulation failed".into()))?;

    let ss2_arr: [u8; 32] = ss2.into();
    let (new_ck, transport_key_2) = mix_key(&ck, &ss2_arr);
    ck = new_ck;

    // Decrypt remote identity
    let mut dec_cipher = CipherState::new(transport_key_2);
    let remote_identity = dec_cipher.decrypt(encrypted_remote_id)
        .map_err(|_| NetworkError::HandshakeFailed("identity decryption failed".into()))?;

    let (recv_key, send_key) = mix_key(&ck, &[0u8; 32]);

    Ok(NoiseTransport {
        send_cipher: CipherState::new(send_key),
        recv_cipher: CipherState::new(recv_key),
        remote_identity,
    })
}

/// Encrypted framed writer.
pub async fn write_encrypted<W: AsyncWrite + Unpin>(
    w: &mut W,
    cipher: &mut CipherState,
    plaintext: &[u8],
) -> Result<(), NetworkError> {
    let ct = cipher.encrypt(plaintext);
    let len = (ct.len() as u32).to_be_bytes();
    w.write_all(&len).await?;
    w.write_all(&ct).await?;
    Ok(())
}

/// Encrypted framed reader.
pub async fn read_encrypted<R: AsyncRead + Unpin>(
    r: &mut R,
    cipher: &mut CipherState,
) -> Result<Vec<u8>, NetworkError> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_NOISE_MSG + AEAD_TAG_SIZE {
        return Err(NetworkError::Protocol("encrypted frame too large".into()));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    cipher.decrypt(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_roundtrip() {
        let key = *blake3::hash(b"test-key").as_bytes();
        let mut enc = CipherState::new(key);
        let mut dec = CipherState::new(key);
        let plaintext = b"Hello, Bitquid-Fi PQ Noise transport!";
        let ciphertext = enc.encrypt(plaintext);
        let decrypted = dec.decrypt(&ciphertext).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_cipher_tamper_detection() {
        let key = *blake3::hash(b"test-key-2").as_bytes();
        let mut enc = CipherState::new(key);
        let mut dec = CipherState::new(key);
        let mut ciphertext = enc.encrypt(b"secret data");
        ciphertext[0] ^= 0xFF;
        assert!(dec.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn test_cipher_wrong_key() {
        let key1 = *blake3::hash(b"key-a").as_bytes();
        let key2 = *blake3::hash(b"key-b").as_bytes();
        let mut enc = CipherState::new(key1);
        let mut dec = CipherState::new(key2);
        let ciphertext = enc.encrypt(b"data");
        assert!(dec.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn test_cipher_replay_fails() {
        let key = *blake3::hash(b"replay-test").as_bytes();
        let mut enc = CipherState::new(key);
        let mut dec = CipherState::new(key);
        let ct = enc.encrypt(b"msg");
        assert!(dec.decrypt(&ct).is_ok());
        assert!(dec.decrypt(&ct).is_err());
    }

    #[tokio::test]
    async fn test_encrypted_framed_io() {
        let key = *blake3::hash(b"framed-test").as_bytes();
        let mut enc = CipherState::new(key);
        let mut dec = CipherState::new(key);

        let (client, server) = tokio::io::duplex(8192);
        let (_cr, mut cw) = tokio::io::split(client);
        let (mut sr, _sw) = tokio::io::split(server);

        let msg = b"encrypted frame payload";
        let write_handle = tokio::spawn(async move {
            write_encrypted(&mut cw, &mut enc, msg).await.unwrap();
        });
        let read_handle = tokio::spawn(async move {
            let plaintext = read_encrypted(&mut sr, &mut dec).await.unwrap();
            assert_eq!(plaintext, msg);
        });
        write_handle.await.unwrap();
        read_handle.await.unwrap();
    }
}
