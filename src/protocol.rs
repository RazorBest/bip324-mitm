use std::cmp;
use std::collections::VecDeque;
use std::error::Error;
use std::io::{Read, Write};

use secp256k1::{SecretKey, ellswift::ElligatorSwift};

/// Number of bytes for the header holding protocol flags.
pub const NUM_HEADER_BYTES: usize = 1;
/// Number of bytes for the encrypted length prefix of a packet.
pub const NUM_LENGTH_BYTES: usize = 3;
// Number of bytes for the authentication tag of a packet.
pub const NUM_TAG_BYTES: usize = 16;
/// Number of bytes per packet for static layout, everything not including contents.
pub const NUM_PACKET_OVERHEAD_BYTES: usize = NUM_LENGTH_BYTES + NUM_HEADER_BYTES + NUM_TAG_BYTES;
/// Value for header byte with the decoy flag flipped to true.
pub const DECOY_BYTE: u8 = 128;
// Number of bytes for the garbage terminator.
pub const NUM_GARBAGE_TERMINATOR_BYTES: usize = 16;

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
    pub secret_key: SecretKey,
    pub elligator_swift: ElligatorSwift,
}

/// Role in the handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Started the handshake with a peer.
    Initiator,
    /// Responding to a handshake.
    Responder,
}

/// A decoy packet contains bogus information, but can be
/// used to hide the shape of the data being communicated
/// over an encrypted channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketType {
    /// Genuine packet contains information.
    Genuine,
    /// Decoy packet contains bogus information.
    Decoy,
}

impl PacketType {
    /// Check if header byte has the decoy flag flipped.
    pub fn from_byte(header: &u8) -> Self {
        if header == &DECOY_BYTE {
            PacketType::Decoy
        } else {
            PacketType::Genuine
        }
    }

    /// Returns header byte based on the type.
    #[allow(clippy::wrong_self_convention)]
    pub fn to_byte(&self) -> u8 {
        match self {
            PacketType::Genuine => 0,
            PacketType::Decoy => DECOY_BYTE,
        }
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

    pub fn try_consume(&mut self, amount: usize) -> Option<Vec<u8>> {
        if amount > self.buf.len() {
            return None;
        }

        Some(self.buf.drain(0..amount).collect())
    }

    pub fn consume_all(&mut self) -> Vec<u8> {
        self.buf.drain(..).collect()
    }

    pub fn buf_ref(&mut self) -> &[u8] {
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

impl Default for ProtocolBuffer {
    fn default() -> Self {
        Self::new()
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

pub struct PartialPacket {
    pub length_bytes: Option<VecDeque<u8>>,
    pub data: Option<VecDeque<u8>>,
    pub tag: Option<VecDeque<u8>>,
    pub aad: Option<VecDeque<u8>>,
}

impl PartialPacket {
    pub fn new() -> Self {
        Self {
            length_bytes: None,
            data: None,
            tag: None,
            aad: None,
        }
    }

    pub fn read_length_bytes(&mut self, buf: &mut [u8]) -> usize {
        let Some(length_bytes) = &mut self.length_bytes else {
            return 0;
        };

        read_vec_dequeue_u8(length_bytes, buf)
    }

    pub fn read_data_bytes(&mut self, buf: &mut [u8]) -> usize {
        let Some(data) = &mut self.data else {
            return 0;
        };

        read_vec_dequeue_u8(data, buf)
    }

    pub fn read_tag_bytes(&mut self, buf: &mut [u8]) -> usize {
        let Some(tag) = &mut self.tag else {
            return 0;
        };

        read_vec_dequeue_u8(tag, buf)
    }

    pub fn set_aad(&mut self, data: &[u8]) {
        if self.aad.is_some() {
            panic!("AAD can only be set once");
        }
        let mut aad = VecDeque::new();
        aad.extend(data);
        self.aad = Some(aad);
    }

    pub fn read_aad(&mut self) -> Option<Vec<u8>> {
        self.aad.take().map(Vec::<_>::from)
    }

    pub fn is_empty(&self) -> bool {
        (self.length_bytes.is_none() || self.length_bytes.as_ref().unwrap().len() == 0)
            && (self.data.is_none() || self.data.as_ref().unwrap().len() == 0)
            && (self.aad.is_none() || self.aad.as_ref().unwrap().len() == 0)
            && (self.tag.is_none() || self.tag.as_ref().unwrap().len() == 0)
    }
}

impl Default for PartialPacket {
    fn default() -> Self {
        Self::new()
    }
}

pub fn find_garbage(
    buf: &[u8],
    terminator: [u8; NUM_GARBAGE_TERMINATOR_BYTES],
) -> Option<(&[u8], &[u8])> {
    for (i, window) in buf.windows(NUM_GARBAGE_TERMINATOR_BYTES).enumerate() {
        if window == terminator {
            return Some((
                &buf[..i + NUM_GARBAGE_TERMINATOR_BYTES],
                &buf[i + NUM_GARBAGE_TERMINATOR_BYTES..],
            ));
        }
    }

    None
}
