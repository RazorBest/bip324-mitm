use std::cmp;
use std::collections::VecDeque;
use std::error::Error;
use std::io::{Read, Write};

use bip324::Role;
use secp256k1::{SecretKey, ellswift::ElligatorSwift};

use crate::external::bip324::fschacha20poly1305::{FSChaCha20Poly1305, FSChaCha20Stream};
use crate::external::bip324::{InboundCipher, OutboundCipher, SessionKeyMaterial};

/// A wrapper over Err(std::io::Error(..))
#[allow(non_snake_case)]
fn IOError<T, E>(kind: std::io::ErrorKind, error: E) -> std::io::Result<T>
where
    E: Into<Box<dyn Error + Send + Sync>>,
{
    Err(std::io::Error::new(kind, error))
}

/// A point on the curve used to complete the handshake.
#[derive(Clone)]
pub struct EcdhPoint {
    pub(crate) secret_key: SecretKey,
    pub(crate) elligator_swift: ElligatorSwift,
}

/// Manages cipher state for a BIP-324 encrypted connection.
#[derive(Debug, Clone)]
pub struct CipherSession {
    /// A unique identifier for the communication session.
    id: [u8; 32],
    /// Decrypts inbound packets.
    pub(crate) inbound: InboundCipher,
    /// Encrypts outbound packets.
    pub(crate) outbound: OutboundCipher,
}

impl CipherSession {
    pub(crate) fn new(mut materials: SessionKeyMaterial, role: Role) -> Self {
        if role == Role::Responder {
            std::mem::swap(
                &mut materials.initiator_length_key,
                &mut materials.responder_length_key,
            );
            std::mem::swap(
                &mut materials.initiator_packet_key,
                &mut materials.responder_packet_key,
            );
        }

        let outbound_length_cipher = FSChaCha20Stream::new(materials.initiator_length_key);
        let inbound_length_cipher = FSChaCha20Stream::new(materials.responder_length_key);
        let outbound_packet_cipher = FSChaCha20Poly1305::new(materials.initiator_packet_key);
        let inbound_packet_cipher = FSChaCha20Poly1305::new(materials.responder_packet_key);

        CipherSession {
            id: materials.session_id,
            inbound: InboundCipher {
                length_cipher: inbound_length_cipher,
                packet_cipher: inbound_packet_cipher,
            },
            outbound: OutboundCipher {
                length_cipher: outbound_length_cipher,
                packet_cipher: outbound_packet_cipher,
            },
        }
    }

    /// Unique session ID.
    pub fn id(&self) -> &[u8; 32] {
        &self.id
    }

    /// Get a mutable reference to the inbound cipher for decryption operations.
    pub fn inbound(&mut self) -> &mut InboundCipher {
        &mut self.inbound
    }

    /// Get a mutable reference to the outbound cipher for encryption operations.
    pub fn outbound(&mut self) -> &mut OutboundCipher {
        &mut self.outbound
    }

    /// Split the session into separate inbound and outbound ciphers.
    pub fn into_split(self) -> (InboundCipher, OutboundCipher) {
        (self.inbound, self.outbound)
    }
}

fn read_vec_dequeue_u8(stream: &mut VecDeque<u8>, buf: &mut [u8]) -> usize {
    let limit = cmp::min(buf.len(), stream.len());

    let data: Vec<_> = stream.drain(..limit).collect();
    buf[..limit].copy_from_slice(&data);

    limit
}

pub struct ProtocolBuffer {
    buf: VecDeque<u8>,
    eof: bool,
}

impl ProtocolBuffer {
    pub fn new() -> Self {
        Self {
            buf: VecDeque::new(),
            eof: false,
        }
    }

    /*
    pub fn write(&mut self, data: &[u8]) {
        self.buf.extend(data);
    }
    */

    pub fn try_consume(&mut self, amount: usize) -> Option<Vec<u8>> {
        if amount > self.buf.len() {
            return None;
        }

        Some(self.buf.drain(0..amount).collect())
    }

    pub fn consume_all(&mut self) -> Vec<u8> {
        self.buf.drain(..).collect()
    }

    pub fn buf_ref<'a>(&'a mut self) -> &'a [u8] {
        self.buf.make_contiguous()
    }

    pub fn is_eof(&self) -> bool {
        self.eof
    }

    pub fn set_eof(&mut self) {
        self.eof = true;
    }

    pub fn peek_len(&self) -> usize {
        self.buf.len()
    }
}

impl Read for ProtocolBuffer {
    fn read(&mut self, data: &mut [u8]) -> std::io::Result<usize> {
        Ok(read_vec_dequeue_u8(&mut self.buf, data))
    }
}

impl Write for ProtocolBuffer {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.eof {
            return IOError(
                std::io::ErrorKind::Other,
                "Can't write. Eof was already reached.",
            );
        }
        self.buf.extend(data);

        Ok(data.len())
    }

    /// Doesn't actually flush because there's no buffering
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
