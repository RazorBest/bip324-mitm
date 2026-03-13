mod external;
mod fmt_utils;

use std::cell::RefCell;
use std::cmp::min;
use std::collections::VecDeque;
use std::error::Error;
use std::io::{Read, Write};
use std::mem;
use std::rc::Rc;

use bip324::NUM_LENGTH_BYTES;
use bip324::Role;
use secp256k1::{
    PublicKey, Secp256k1, SecretKey,
    ellswift::{ElligatorSwift, ElligatorSwiftParty},
    rand::CryptoRng,
};

use crate::external::bip324::fschacha20poly1305::{FSChaCha20Poly1305, FSChaCha20Stream};
use crate::external::bip324::{
    FillBytes, InboundCipher, OutboundCipher, PacketType, SessionKeyMaterial,
};
use crate::external::chacha20_poly1305::ChaCha20Poly1305Stream;

// Number of bytes in elligator swift key.
const NUM_ELLIGATOR_SWIFT_BYTES: usize = 64;
// Number of bytes for the garbage terminator.
const NUM_GARBAGE_TERMINATOR_BYTES: usize = 16;
// Maximum packet size for automatic allocation.
// Bitcoin Core's MAX_PROTOCOL_MESSAGE_LENGTH is 4,000,000 bytes (~4 MiB).
// 14 extra bytes are for the BIP-324 header byte and 13 serialization header bytes (message type).
const MAX_PACKET_SIZE_FOR_ALLOCATION: usize = 4000014;
// Maximum number of garbage bytes before the terminator.
const MAX_NUM_GARBAGE_BYTES: usize = 4095;
// The size in bytes of the length segment of a packet
const LENGTH_BYTES_SIZE: usize = 3;

type GarbageType = Vec<u8>;
type GarbageTerminatorType = [u8; NUM_GARBAGE_TERMINATOR_BYTES];
type MagicType = [u8; 4];

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
    secret_key: SecretKey,
    elligator_swift: ElligatorSwift,
}

/// Manages cipher state for a BIP-324 encrypted connection.
#[derive(Debug, Clone)]
pub struct CipherSession {
    /// A unique identifier for the communication session.
    id: [u8; 32],
    /// Decrypts inbound packets.
    inbound: InboundCipher,
    /// Encrypts outbound packets.
    outbound: OutboundCipher,
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

#[derive(Debug)]
enum HandshakeBIP324State {
    Initialized(MagicType, Role),
    ReceivedKey(GarbageTerminatorType),
    ReceivedGarbage(Vec<u8>),
    ReceivedPacketLen(usize, ChaCha20Poly1305Stream, Vec<u8>),
    ReceivedPacketContent(PacketType, Vec<u8>),
    ReceivedVersion,
    Invalid,
}

impl HandshakeBIP324State {
    fn take(&mut self) -> Self {
        mem::replace(self, Self::Invalid)
    }
}

#[derive(Debug)]
enum SessionState {
    SendingKey,
    SendingRest,
}

struct SessionEntityTrackerBIP324 {
    state: SessionState,

    write_buf: Vec<u8>,
    key: Option<[u8; NUM_ELLIGATOR_SWIFT_BYTES]>,
}

impl SessionEntityTrackerBIP324 {
    pub fn new() -> Self {
        Self {
            state: SessionState::SendingKey,
            write_buf: vec![],
            key: None,
        }
    }
    pub fn pass_payload(&mut self, data: &[u8]) -> Result<(), String> {
        use SessionState::*;

        self.write_buf.extend_from_slice(data);
        match self.state {
            SendingKey => {
                if self.write_buf.len() < 64 {
                    return Ok(());
                }

                let key: Vec<_> = self.write_buf.drain(0..64).collect();

                self.key = Some(key.try_into().unwrap());
                self.state = SendingRest;
                return self.pass_payload(&[]);
            }
            SendingRest => (),
        }

        Ok(())
    }

    pub fn consume_bytes(&mut self, amount: usize) -> Result<Vec<u8>, String> {
        if amount > self.write_buf.len() {
            return Err("Can't consume. Requested amount exceeds the available data".to_string());
        }

        Ok(self.write_buf.drain(0..amount).collect())
    }

    pub fn consume_all_bytes(&mut self) -> Vec<u8> {
        self.write_buf.drain(..).collect()
    }

    pub fn available_bytes(&self) -> usize {
        self.write_buf.len()
    }

    pub fn undo_consume(&mut self, data: Vec<u8>) {
        self.write_buf.splice(0..0, data);
    }
}

fn read_vec_dequeue_u8(stream: &mut VecDeque<u8>, buf: &mut [u8]) -> usize {
    let limit = min(buf.len(), stream.len());

    let data: Vec<_> = stream.drain(..limit).collect();
    buf[..limit].copy_from_slice(&data);

    limit
}

struct DataToSend {
    stream: VecDeque<u8>,
    eof: bool,
}

impl DataToSend {
    fn new() -> Self {
        Self {
            stream: VecDeque::new(),
            eof: false,
        }
    }

    fn is_eof(&self) -> bool {
        self.eof
    }

    fn set_eof(&mut self) {
        self.eof = true;
    }

    fn peek_len(&self) -> usize {
        self.stream.len()
    }
}

impl Read for DataToSend {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        Ok(read_vec_dequeue_u8(&mut self.stream, buf))
    }
}

impl Write for DataToSend {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.eof {
            return IOError(
                std::io::ErrorKind::Other,
                "Can't write. Eof was already reached.",
            );
        }
        self.stream.extend(data);

        Ok(data.len())
    }

    /// Doesn't actually flush, because it needs a consumer to call read
    fn flush(&mut self) -> std::io::Result<()> {
        if self.eof {
            return IOError(
                std::io::ErrorKind::Other,
                "Can't flush. Eof was already reached.",
            );
        }
        Ok(())
    }
}

struct PartialPacket {
    length_bytes: Option<VecDeque<u8>>,
    data: Option<VecDeque<u8>>,
    tag: Option<VecDeque<u8>>,
    aad: Option<VecDeque<u8>>,
}

impl PartialPacket {
    fn new() -> Self {
        Self {
            length_bytes: None,
            data: None,
            tag: None,
            aad: None,
        }
    }

    fn read_length_bytes(&mut self, buf: &mut [u8]) -> usize {
        let Some(length_bytes) = &mut self.length_bytes else {
            return 0;
        };

        read_vec_dequeue_u8(length_bytes, buf)
    }

    fn read_data_bytes(&mut self, buf: &mut [u8]) -> usize {
        let Some(data) = &mut self.data else {
            return 0;
        };

        read_vec_dequeue_u8(data, buf)
    }

    fn read_tag_bytes(&mut self, buf: &mut [u8]) -> usize {
        let Some(tag) = &mut self.tag else {
            return 0;
        };

        read_vec_dequeue_u8(tag, buf)
    }

    fn set_aad(&mut self, data: &[u8]) {
        if self.aad.is_some() {
            panic!("AAD can only be set once");
        }
        let mut aad = VecDeque::new();
        aad.extend(data);
        self.aad = Some(aad);
    }

    fn read_aad(&mut self) -> Option<Vec<u8>> {
        self.aad.take().map(Vec::<_>::from)
    }

    fn is_empty(&self) -> bool {
        (self.length_bytes.is_none() || self.length_bytes.as_ref().unwrap().len() == 0)
            && (self.data.is_none() || self.data.as_ref().unwrap().len() == 0)
            && (self.aad.is_none() || self.aad.as_ref().unwrap().len() == 0)
            && (self.tag.is_none() || self.tag.as_ref().unwrap().len() == 0)
    }
}

struct FakePeerRelay {
    key: DataToSend,
    garbage: DataToSend,
    terminator: DataToSend,
    packets: Vec<PartialPacket>,
}

impl FakePeerRelay {
    fn remove_first_packet_if_consumed(&mut self) {
        if self.packets.is_empty() {
            return;
        }
        let packet = &self.packets[0];
        let packet_is_empty = packet.is_empty();
        let is_consumed = packet_is_empty && self.packets.len() > 1;

        if is_consumed {
            self.packets.splice(..1, []);
        }
    }
}

impl FakePeerRelay {
    fn new() -> Self {
        Self {
            key: DataToSend::new(),
            garbage: DataToSend::new(),
            terminator: DataToSend::new(),
            packets: vec![],
        }
    }
}

trait FakePeerRelayWriter {
    fn write_key(&mut self, data: &[u8]) -> std::io::Result<usize>;
    fn set_eof_key(&mut self);

    fn write_garbage(&mut self, data: &[u8]) -> std::io::Result<usize>;
    fn set_eof_garbage(&mut self);

    fn write_terminator(&mut self, data: &[u8]) -> std::io::Result<usize>;
    fn set_eof_terminator(&mut self);

    /// Writes the length section of a packet. BIP-324 decodes it as a 3 byte little-endian integer.
    fn write_length_bytes(&mut self, data: &[u8]);
    /// Writes the payload section of a packet
    fn write_packet_bytes(&mut self, data: &[u8]);
    fn write_tag_bytes(&mut self, data: &[u8]);
    fn set_aad(&mut self, data: &[u8]);
}

impl FakePeerRelayWriter for FakePeerRelay {
    fn write_key(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.key.write(data)
    }

    fn set_eof_key(&mut self) {
        self.key.set_eof();
    }

    fn write_garbage(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.garbage.write(data)
    }

    fn set_eof_garbage(&mut self) {
        self.garbage.set_eof();
    }

    fn write_terminator(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.terminator.write(data)
    }

    fn set_eof_terminator(&mut self) {
        self.terminator.set_eof();
    }

    fn write_length_bytes(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        if self.packets.is_empty()
            || self.packets[self.packets.len() - 1].data.is_some()
            || self.packets[self.packets.len() - 1].tag.is_some()
        {
            self.packets.push(PartialPacket::new());
        }

        let packets_len = self.packets.len();
        let last_packet = &mut self.packets[packets_len - 1];

        if last_packet.length_bytes.is_none() {
            last_packet.length_bytes = Some(VecDeque::new());
        }

        let length_bytes = &mut last_packet.length_bytes.as_mut().unwrap();
        length_bytes.extend(data);
    }

    fn write_packet_bytes(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        if self.packets.is_empty() || self.packets[self.packets.len() - 1].tag.is_some() {
            self.packets.push(PartialPacket::new());
        }

        let packets_len = self.packets.len();
        let last_packet = &mut self.packets[packets_len - 1];

        if last_packet.data.is_none() {
            last_packet.data = Some(VecDeque::new());
        }

        let packet_data = &mut last_packet.data.as_mut().unwrap();
        packet_data.extend(data);
    }

    fn write_tag_bytes(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        if self.packets.is_empty() {
            self.packets.push(PartialPacket::new());
        }

        let packets_len = self.packets.len();
        let last_packet = &mut self.packets[packets_len - 1];

        if last_packet.tag.is_none() {
            last_packet.tag = Some(VecDeque::new());
        }

        let packet_tag = &mut last_packet.tag.as_mut().unwrap();
        packet_tag.extend(data);
    }

    fn set_aad(&mut self, aad: &[u8]) {
        if self.packets.is_empty() {
            self.packets.push(PartialPacket::new());
        }

        let packets_len = self.packets.len();
        let last_packet = &mut self.packets[packets_len - 1];

        last_packet.set_aad(aad);
    }
}

trait FakePeerRelayReader {
    fn read_key(&mut self, data: &mut [u8]) -> std::io::Result<usize>;
    fn is_eof_key(&self) -> bool;
    fn peek_len_key(&self) -> usize;

    fn read_garbage(&mut self, data: &mut [u8]) -> std::io::Result<usize>;
    fn is_eof_garbage(&self) -> bool;
    fn peek_len_garbage(&self) -> usize;

    fn read_terminator(&mut self, data: &mut [u8]) -> std::io::Result<usize>;
    fn is_eof_terminator(&self) -> bool;
    fn peek_len_terminator(&self) -> usize;

    fn read_length_bytes(&mut self, data: &mut [u8]) -> usize;
    fn read_data_bytes(&mut self, buf: &mut [u8]) -> usize;
    fn read_tag_bytes(&mut self, buf: &mut [u8]) -> usize;
    fn read_aad(&mut self) -> Option<Vec<u8>>;
}

impl FakePeerRelayReader for FakePeerRelay {
    fn read_key(&mut self, data: &mut [u8]) -> std::io::Result<usize> {
        self.key.read(data)
    }

    fn is_eof_key(&self) -> bool {
        self.key.is_eof()
    }

    fn peek_len_key(&self) -> usize {
        self.key.peek_len()
    }

    fn read_garbage(&mut self, data: &mut [u8]) -> std::io::Result<usize> {
        self.garbage.read(data)
    }

    fn is_eof_garbage(&self) -> bool {
        self.garbage.is_eof()
    }

    fn peek_len_garbage(&self) -> usize {
        self.garbage.peek_len()
    }

    fn read_terminator(&mut self, data: &mut [u8]) -> std::io::Result<usize> {
        self.terminator.read(data)
    }

    fn is_eof_terminator(&self) -> bool {
        self.terminator.is_eof()
    }

    fn peek_len_terminator(&self) -> usize {
        self.terminator.peek_len()
    }

    fn read_length_bytes(&mut self, data: &mut [u8]) -> usize {
        if self.packets.is_empty() {
            return 0;
        }

        let packet = &mut self.packets[0];
        let size = packet.read_length_bytes(data);

        self.remove_first_packet_if_consumed();

        size
    }

    fn read_data_bytes(&mut self, data: &mut [u8]) -> usize {
        if self.packets.is_empty() {
            return 0;
        }

        let packet = &mut self.packets[0];
        let size = packet.read_data_bytes(data);

        self.remove_first_packet_if_consumed();

        size
    }

    fn read_tag_bytes(&mut self, data: &mut [u8]) -> usize {
        if self.packets.is_empty() {
            return 0;
        }

        let packet = &mut self.packets[0];
        let size = packet.read_tag_bytes(data);

        self.remove_first_packet_if_consumed();

        size
    }

    fn read_aad(&mut self) -> Option<Vec<u8>> {
        if self.packets.is_empty() {
            return None;
        }

        let packet = &mut self.packets[0];
        let aad = packet.read_aad();

        let packet_is_empty = packet.is_empty();
        let is_consumed = packet_is_empty && self.packets.len() > 1;

        if is_consumed {
            self.packets.splice(..1, []);
        }

        aad
    }
}

fn key_from_rng<Rng: FillBytes + CryptoRng>(rng: &mut Rng) -> Result<EcdhPoint, Box<dyn Error>> {
    let curve = Secp256k1::signing_only();
    let mut secret_key_buffer = [0u8; 32];
    rng.fill_bytes(&mut secret_key_buffer);
    debug_assert_ne!([0u8; 32], secret_key_buffer);
    let sk = SecretKey::from_slice(&secret_key_buffer)?;
    let pk = PublicKey::from_secret_key(&curve, &sk);
    let es = ElligatorSwift::from_pubkey(pk);

    Ok(EcdhPoint {
        secret_key: sk,
        elligator_swift: es,
    })
}

fn split_garbage_by_terminator(
    buf: &[u8],
    terminator: [u8; NUM_GARBAGE_TERMINATOR_BYTES],
) -> Option<(&[u8], &[u8])> {
    for (i, window) in buf.windows(NUM_GARBAGE_TERMINATOR_BYTES).enumerate() {
        if window == terminator {
            return Some((&buf[..i], &buf[i + NUM_GARBAGE_TERMINATOR_BYTES..]));
        }
    }

    None
}

enum RelayPeerState {
    SendingKey,
    SendingGarbage,
    SendingGarbageTerminator,
    SendingLength(usize, Vec<u8>),
    SendingPayload(usize, ChaCha20Poly1305Stream),
    SendingTag(Vec<u8>),
    Invalid,
}

impl RelayPeerState {
    fn new() -> Self {
        Self::SendingKey
    }

    fn take(&mut self) -> Self {
        mem::replace(self, Self::Invalid)
    }
}

fn generate_session_keys_ecdh(
    magic: [u8; 4],
    role: Role,
    point: &EcdhPoint,
    client_key: [u8; NUM_ELLIGATOR_SWIFT_BYTES],
) -> Result<SessionKeyMaterial, String> {
    let their_ellswift = ElligatorSwift::from_array(client_key);

    let (initiator_ellswift, responder_ellswift, secret, party) = match role {
        Role::Initiator => (
            point.elligator_swift,
            their_ellswift,
            point.secret_key,
            ElligatorSwiftParty::A,
        ),
        Role::Responder => (
            their_ellswift,
            point.elligator_swift,
            point.secret_key,
            ElligatorSwiftParty::B,
        ),
    };

    SessionKeyMaterial::from_ecdh(initiator_ellswift, responder_ellswift, secret, party, magic)
        .map_err(|_| "Error creating the shared key".to_string())
}

struct MitmImpersonatorLeg {
    state: HandshakeBIP324State,
    server_state: RelayPeerState,

    peer: SessionEntityTrackerBIP324,

    point: EcdhPoint,
    key_to_send: Vec<u8>,
    garbage_terminator_to_send: Vec<u8>,
    cipher: Option<CipherSession>,

    relay_in: Rc<RefCell<dyn FakePeerRelayReader>>,
    relay_out: Rc<RefCell<dyn FakePeerRelayWriter>>,
}

impl MitmImpersonatorLeg {
    pub fn new(
        role: Role,
        magic: MagicType,
        relay_in: Rc<RefCell<dyn FakePeerRelayReader>>,
        relay_out: Rc<RefCell<dyn FakePeerRelayWriter>>,
        secret_key: EcdhPoint,
    ) -> Result<Self, Box<dyn Error>> {
        let point = secret_key;
        let key_buffer = point.elligator_swift.to_array();

        // We know the fake server's public key, so we can already prepare it for sending
        let mut key_to_send = vec![];
        key_to_send.extend_from_slice(&key_buffer);

        Ok(Self {
            state: HandshakeBIP324State::Initialized(magic, role),
            server_state: RelayPeerState::new(),
            point,
            peer: SessionEntityTrackerBIP324::new(),
            key_to_send,
            garbage_terminator_to_send: vec![],
            cipher: None,
            relay_in,
            relay_out,
        })
    }

    pub fn new_fake_server(
        magic: MagicType,
        relay_in: Rc<RefCell<dyn FakePeerRelayReader>>,
        relay_out: Rc<RefCell<dyn FakePeerRelayWriter>>,
        secret_key: EcdhPoint,
    ) -> Result<Self, Box<dyn Error>> {
        Self::new(Role::Responder, magic, relay_in, relay_out, secret_key)
    }

    pub fn new_fake_client(
        magic: MagicType,
        relay_in: Rc<RefCell<dyn FakePeerRelayReader>>,
        relay_out: Rc<RefCell<dyn FakePeerRelayWriter>>,
        secret_key: EcdhPoint,
    ) -> Result<Self, Box<dyn Error>> {
        Self::new(Role::Initiator, magic, relay_in, relay_out, secret_key)
    }

    pub fn pass_peer_data(&mut self, data: &[u8]) -> Result<(), String> {
        use HandshakeBIP324State::*;

        self.peer.pass_payload(data)?;

        let curr_state = self.state.take();
        let (new_state, incomplete) = match curr_state {
            state @ Initialized(magic, role) => {
                if let Some(client_key) = self.peer.key {
                    let session_keys =
                        generate_session_keys_ecdh(magic, role, &self.point, client_key)?;

                    let (garbage_terminator, other_garbage_terminator) = match role {
                        Role::Initiator => (
                            session_keys.initiator_garbage_terminator,
                            session_keys.responder_garbage_terminator,
                        ),
                        Role::Responder => (
                            session_keys.responder_garbage_terminator,
                            session_keys.initiator_garbage_terminator,
                        ),
                    };

                    self.cipher = Some(CipherSession::new(session_keys, role));

                    self.garbage_terminator_to_send
                        .extend_from_slice(&garbage_terminator);

                    (ReceivedKey(other_garbage_terminator), true)
                } else {
                    (state, false)
                }
            }
            state @ ReceivedKey(other_garbage_terminator) => {
                let buf = self.peer.consume_all_bytes();

                if let Some((garbage, rest)) =
                    split_garbage_by_terminator(&buf, other_garbage_terminator)
                {
                    self.peer.undo_consume(rest.to_vec());
                    self.relay_out
                        .borrow_mut()
                        .write_garbage(garbage)
                        .map_err(|_| "Error writing garbage to relay")?;

                    let aad = garbage.to_vec();
                    (ReceivedGarbage(aad), true)
                } else {
                    // The last bytes might be part of a truncated garbage terminator
                    let size = min(other_garbage_terminator.len() - 1, buf.len());
                    self.peer.undo_consume(buf[buf.len() - size..].to_vec());

                    let partial_garbage = &buf[..buf.len() - size];
                    self.relay_out
                        .borrow_mut()
                        .write_garbage(partial_garbage)
                        .map_err(|_| "Error writing garbage to relay")?;

                    (state, false)
                }
            }
            ReceivedGarbage(aad) => {
                if self.peer.available_bytes() >= NUM_LENGTH_BYTES {
                    let length_bytes: [u8; NUM_LENGTH_BYTES] = self
                        .peer
                        .consume_bytes(NUM_LENGTH_BYTES)?
                        .try_into()
                        .unwrap();
                    let mut packet_len = self
                        .cipher
                        .as_mut()
                        .unwrap()
                        .inbound()
                        .decrypt_packet_len(length_bytes);
                    if packet_len > MAX_PACKET_SIZE_FOR_ALLOCATION {
                        return Err("Packet too big".to_string());
                    }
                    // Add 1 for the header byte, which is not included in the length
                    packet_len += 1;
                    let packet_len = packet_len;

                    let length_bytes_decrypted = {
                        let bytes = (packet_len as u32).to_le_bytes();

                        [bytes[0], bytes[1], bytes[2]]
                    };

                    self.relay_out
                        .borrow_mut()
                        .write_length_bytes(&length_bytes_decrypted);

                    let stream_cipher = self
                        .cipher
                        .as_mut()
                        .unwrap()
                        .inbound()
                        .packet_cipher
                        .start_one_payload_stream_encryption();

                    (ReceivedPacketLen(packet_len, stream_cipher, aad), true)
                } else {
                    (ReceivedGarbage(aad), false)
                }
            }
            ReceivedPacketLen(packet_len, mut stream_cipher, aad) => {
                if self.peer.available_bytes() >= packet_len {
                    let mut packet_bytes = self.peer.consume_bytes(packet_len).unwrap();

                    stream_cipher.decrypt_and_store_chunk(&mut packet_bytes);

                    let packet_type = PacketType::from_byte(&packet_bytes[0]);

                    let tag = stream_cipher.get_tag(Some(&aad));
                    /*
                    let stream_cipher = self.cipher
                        .as_mut().unwrap()
                        .inbound()
                        .packet_cipher
                        .end_current_stream(&aad);
                    */
                    self.relay_out
                        .borrow_mut()
                        .write_packet_bytes(&packet_bytes);

                    (ReceivedPacketContent(packet_type, tag.to_vec()), true)
                } else {
                    (ReceivedPacketLen(packet_len, stream_cipher, aad), false)
                }
            }
            ReceivedPacketContent(packet_type, expected_tag) => {
                if self.peer.available_bytes() >= expected_tag.len() {
                    let tag_bytes = self.peer.consume_bytes(expected_tag.len()).unwrap();

                    if tag_bytes != *expected_tag {
                        return Err("AEAD tag check fail".to_string());
                    }

                    match packet_type {
                        PacketType::Genuine => (ReceivedVersion, true),
                        PacketType::Decoy => (ReceivedGarbage(vec![]), true),
                    }
                } else {
                    (ReceivedPacketContent(packet_type, expected_tag), false)
                }
            }
            state @ ReceivedVersion => (state, false),
            Invalid => {
                panic!("Invalid protocol state");
            } // let (inbound_cipher, outbound_cipher) = self.cipher.take().unwrap().into_split();
        };

        self.state = new_state;
        if incomplete {
            return self.pass_peer_data(&[]);
        }

        Ok(())
    }

    /// Writes the data from the impersonator to the peer
    pub fn write_data(&mut self, buf: &mut [u8]) -> Result<usize, Box<dyn Error>> {
        use RelayPeerState::*;

        let server_state = self.server_state.take();
        let (new_state, size, incomplete) = match server_state {
            state @ SendingKey => {
                let limit = min(buf.len(), self.key_to_send.len());
                let _key_buf = &mut buf[..limit];
                let size = self.relay_in.borrow_mut().read_key(_key_buf)?;

                // The key is replaced by ours. We're not using the original one
                let data_to_send: Vec<u8> = self.key_to_send.drain(..size).collect();
                buf[..size].copy_from_slice(&data_to_send);

                if self.key_to_send.is_empty() {
                    (SendingGarbage, size, true)
                } else {
                    (state, size, false)
                }
            }
            state @ SendingGarbage => {
                let size = self.relay_in.borrow_mut().read_garbage(buf)?;

                if self.relay_in.borrow().peek_len_garbage() == 0
                    && self.relay_in.borrow().is_eof_garbage()
                {
                    (SendingGarbageTerminator, size, true)
                } else {
                    (state, size, false)
                }
            }
            state @ SendingGarbageTerminator => {
                let limit = min(buf.len(), self.garbage_terminator_to_send.len());
                let _terminator_buf = &mut buf[..limit];
                let size = self
                    .relay_in
                    .borrow_mut()
                    .read_terminator(_terminator_buf)?;

                // The terminator is replaced by ours. We're not using the original one
                let data_to_send: Vec<u8> = self.garbage_terminator_to_send.drain(..size).collect();
                buf[..size].copy_from_slice(&data_to_send);

                if self.garbage_terminator_to_send.is_empty() {
                    (SendingLength(LENGTH_BYTES_SIZE, vec![]), size, true)
                } else {
                    (state, size, false)
                }
            }
            SendingLength(remaining, data) => {
                let size = self.relay_in.borrow_mut().read_length_bytes(buf);
                if size > remaining {
                    return Err("Received too many length bytes from the input relay".into());
                }

                // Append the written data before encrypting it
                let new_data = [&data[..], &buf[..size]].concat();

                self.cipher
                    .as_mut()
                    .unwrap()
                    .outbound()
                    .encrypt_len_part_inplace(&mut buf[..size]);

                if size == remaining {
                    let length_bytes: [u8; 8] =
                        [new_data, vec![0u8; 5]].concat().try_into().unwrap();
                    // Add 1 for the header, which is not included in the length
                    let payload_len = 1 + usize::from_le_bytes(length_bytes);
                    let stream_cipher = self
                        .cipher
                        .as_mut()
                        .unwrap()
                        .outbound()
                        .packet_cipher
                        .start_one_payload_stream_encryption();

                    (SendingPayload(payload_len, stream_cipher), size, true)
                } else {
                    let new_remaining = remaining - size;
                    (SendingLength(new_remaining, new_data), size, false)
                }
            }
            SendingPayload(remaining, mut stream_cipher) => {
                let size = self.relay_in.borrow_mut().read_data_bytes(buf);
                if size > remaining {
                    return Err("Received too many data bytes from the input relay".into());
                }

                stream_cipher.encrypt_and_store_chunk(&mut buf[..size]);

                if size == remaining {
                    let aad = self.relay_in.borrow_mut().read_aad().unwrap_or(vec![]);
                    let tag = stream_cipher.get_tag(Some(&aad));
                    self.cipher
                        .as_mut()
                        .unwrap()
                        .outbound()
                        .packet_cipher
                        .end_current_stream(&aad);
                    (SendingTag(tag.to_vec()), size, true)
                } else {
                    (SendingPayload(remaining - size, stream_cipher), size, false)
                }
            }
            SendingTag(mut tag) => {
                let size = self.relay_in.borrow_mut().read_tag_bytes(buf);
                if size > tag.len() {
                    return Err("Received too many tag bytes from the input relay".into());
                }

                // Overwrite with our own tag
                buf[..size].copy_from_slice(&tag.drain(0..size).collect::<Vec<_>>());

                if tag.is_empty() {
                    (SendingLength(LENGTH_BYTES_SIZE, vec![]), size, true)
                } else {
                    (SendingTag(tag), size, false)
                }
            }
            Invalid => {
                panic!("Invalid server state")
            }
        };

        self.server_state = new_state;
        if incomplete {
            return Ok(size + self.write_data(&mut buf[size..])?);
        }

        Ok(size)
    }
}

#[allow(non_upper_case_globals)]
#[cfg(test)]
mod mitmfakeserverbip324_tests {
    use super::*;
    use std::str::FromStr;
    use hex_literal::hex;
    use secp256k1::rand::RngCore;
    use secp256k1::rand::rngs::mock::StepRng;

    use crate::external::bip324::impl_fill_bytes;

    macro_rules! test_data {
        ($varname:ident, $name:ident { $($field:ident: $ty:ty = $val:expr),* $(,)? }) => {
            struct $name {
                $($field: $ty),*
            }

            const $varname: $name = $name {
                $($field: $val),*
            };
        };
    }

    const DEFAULT_MAGIC: [u8; 4] = [0xF9, 0xBE, 0xB4, 0xD9];
    const HEADER_LEN: usize = 1;
    const TAG_LEN: usize = 16;

    struct TestHandshakeParams {
        /// The seed used to derive the server key
        server_seed: u64,
        /// Server's elligator swift encoded key
        server_key: [u8; NUM_ELLIGATOR_SWIFT_BYTES],
        server_garbage_terminator: [u8; NUM_GARBAGE_TERMINATOR_BYTES],

        /// Client's elligator swift encoded key
        client_key: [u8; NUM_ELLIGATOR_SWIFT_BYTES],
        client_garbage_terminator: [u8; NUM_GARBAGE_TERMINATOR_BYTES],

        /// The ChaCha20 key used to encrypt the client's length segments
        initiator_l: [u8; 32],
        /// The ChaCha20 key used to encrypt the client's data payloads
        initiator_p: [u8; 32],
        /// The ChaCha20 key used to encrypt the server's length segments
        responder_l: [u8; 32],
        /// The ChaCha20 key used to encrypt the server's data payloads
        responder_p: [u8; 32],
    }

    const HANDSHAKE_PARAMS1: TestHandshakeParams = TestHandshakeParams {
        server_seed: 32890322278,
        server_key: hex!(
            "6a34b0f8757abbd31934ce6375857b06000d1a4528274eaec46c6e11a243366dcb14d23c315b7305fb4bd7c11ddc515785061f2a9402c867f2550a7e8e5496ca"
        ),
        server_garbage_terminator: hex!("7064cc9fe99282b77afbe58925e2cf2b"),

        // Client seed: 992983889292929773;
        client_key: hex!(
            "61a5de62da81aec5967d511fec1f08f98e9c1108bffaaf304b5b31876bec2cbc2d20736f19f93b3f3fd7b9bbf7d1306da07d13218b90fae8c22276846848ad0c"
        ),
        client_garbage_terminator: hex!("e2b91cf5fae994f1e81c361ce00d110d"),

        initiator_l: hex!("ab7e81f5d65d97c015f71bab4506dd93f6dfca7b182f30cd27896afbc4855c3a"),
        initiator_p: hex!("48d22cd6fb02fe202ddc668d2dcade20a9c5500566acb804d18806b5cac44595"),
        responder_l: hex!("42e672f539b95ec5950bb2d97b45a3cb9ac4b58244b05b35fb8ed1315aab8e6d"),
        responder_p: hex!("0c71faf552c2883beebfb82b557593a60caa0f38749bb393dd5bb656ed768a01"),
    };

    test_data!(
        HANDSHAKE_PARAMS2,
        TestParams2 {
            in_idx: u64 = 1,
            in_priv_ours: [u8; 32] =
                hex!("61062ea5071d800bbfd59e2e8b53d47d194b095ae5a4df04936b49772ef0d4d7"),
            in_ellswift_ours: [u8; 64] = hex!(
                "ec0adff257bbfe500c188c80b4fdd640f6b45a482bbc15fc7cef5931deff0aa186f6eb9bba7b85dc4dcc28b28722de1e3d9108b985e2967045668f66098e475b"
            ),
            in_ellswift_theirs: [u8; 64] = hex!(
                "a4a94dfce69b4a2a0a099313d10f9f7e7d649d60501c9e1d274c300e0d89aafaffffffffffffffffffffffffffffffffffffffffffffffffffffffff8faf88d5"
            ),
            in_initiating: u64 = 1,
            in_contents: [u8; 1] = hex!("8e"),
            in_multiply: u64 = 1,
            in_aad: [u8; 0] = hex!(""),
            in_ignore: u64 = 0,
            mid_x_ours: [u8; 32] =
                hex!("19e965bc20fc40614e33f2f82d4eeff81b5e7516b12a5c6c0d6053527eba0923"),
            mid_x_theirs: [u8; 32] =
                hex!("0c71defa3fafd74cb835102acd81490963f6b72d889495e06561375bd65f6ffc"),
            mid_x_shared: [u8; 32] =
                hex!("4eb2bf85bd00939468ea2abb25b63bc642e3d1eb8b967fb90caa2d89e716050e"),
            mid_shared_secret: [u8; 32] =
                hex!("c6992a117f5edbea70c3f511d32d26b9798be4b81a62eaee1a5acaa8459a3592"),
            mid_initiator_l: [u8; 32] =
                hex!("9a6478b5fbab1f4dd2f78994b774c03211c78312786e602da75a0d1767fb55cf"),
            mid_initiator_p: [u8; 32] =
                hex!("7d0c7820ba6a4d29ce40baf2caa6035e04f1e1cefd59f3e7e59e9e5af84f1f51"),
            mid_responder_l: [u8; 32] =
                hex!("17bc726421e4054ac6a1d54915085aaa766f4d3cf67bbd168e6080eac289d15e"),
            mid_responder_p: [u8; 32] =
                hex!("9f0fc1c0e85fd9a8eee07e6fc41dba2ff54c7729068a239ac97c37c524cca1c0"),
            mid_send_garbage_terminator: [u8; 16] = hex!("faef555dfcdb936425d84aba524758f3"),
            mid_recv_garbage_terminator: [u8; 16] = hex!("02cb8ff24307a6e27de3b4e7ea3fa65b"),
            out_session_id: [u8; 32] =
                hex!("ce72dffb015da62b0d0f5474cab8bc72605225b0cee3f62312ec680ec5f41ba5"),
            out_ciphertext: [u8; 21] = hex!("7530d2a18720162ac09c25329a60d75adf36eda3c3"),
            out_ciphertext_endswith: [u8; 0] = hex!(""),
        }
    );

    const DEFAULT_HEADER: [u8; 1] = hex!("00");
    const DECOY_HEADER: [u8; 1] = hex!("80");

    struct TestRng(StepRng);
    impl_fill_bytes!(TestRng);
    // For passing the type checks
    impl CryptoRng for TestRng {}

    impl TestRng {
        fn new(initial: u64, increment: u64) -> Self {
            Self(StepRng::new(initial, increment))
        }
    }

    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.0.next_u32()
        }

        fn next_u64(&mut self) -> u64 {
            self.0.next_u64()
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.0.fill_bytes(dest)
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), secp256k1::rand::Error> {
            self.0.try_fill_bytes(dest)
        }
    }

    fn secret_key_bytes_from_rng<Rng: FillBytes + CryptoRng>(rng: &mut Rng) -> [u8; 32] {
        let mut secret_key_buffer = [0u8; 32];
        rng.fill_bytes(&mut secret_key_buffer);
        debug_assert_ne!([0u8; 32], secret_key_buffer);

        secret_key_buffer
    }

    fn get_mitm_impersonator_from_secret_key(
        secret_key_bytes: [u8; 32],
        ellswift_bytes: Option<[u8; 64]>,
        role: Role,
    ) -> (
        MitmImpersonatorLeg,
        Rc<RefCell<FakePeerRelay>>,
        Rc<RefCell<FakePeerRelay>>,
    ) {
        let relay_in = Rc::new(RefCell::new(FakePeerRelay::new()));
        let relay_out = Rc::new(RefCell::new(FakePeerRelay::new()));

        // Initialize the secret key with the given bytes
        let sk = SecretKey::from_slice(&secret_key_bytes).unwrap();
        let curve = Secp256k1::signing_only();
        let pk = PublicKey::from_secret_key(&curve, &sk);

        let elligator_swift = if let Some(ellswift_bytes) = ellswift_bytes {
            let elg_key = ElligatorSwift::from_array(ellswift_bytes);

            let elg_pk = PublicKey::from_ellswift(elg_key);
            assert!(
                elg_pk == pk || elg_pk == pk.negate(&Secp256k1::verification_only()),
                "The given elligatorswift key does not correspond with the private key"
            );

            elg_key
        } else {
            ElligatorSwift::from_pubkey(pk)
        };

        let secret_key = EcdhPoint {
            secret_key: sk,
            elligator_swift,
        };

        let server = MitmImpersonatorLeg::new(
            role,
            DEFAULT_MAGIC,
            relay_in.clone(),
            relay_out.clone(),
            secret_key,
        )
        .expect("Error creating the MitmImpersonatorLeg");

        (server, relay_in, relay_out)
    }

    fn get_mitm_fake_server_from_secret_key(
        secret_key_bytes: [u8; 32],
        ellswift_bytes: Option<[u8; 64]>,
    ) -> (
        MitmImpersonatorLeg,
        Rc<RefCell<FakePeerRelay>>,
        Rc<RefCell<FakePeerRelay>>,
    ) {
        get_mitm_impersonator_from_secret_key(secret_key_bytes, ellswift_bytes, Role::Responder)
    }

    fn get_mitm_fake_client_from_secret_key(
        secret_key_bytes: [u8; 32],
        ellswift_bytes: Option<[u8; 64]>,
    ) -> (
        MitmImpersonatorLeg,
        Rc<RefCell<FakePeerRelay>>,
        Rc<RefCell<FakePeerRelay>>,
    ) {
        get_mitm_impersonator_from_secret_key(secret_key_bytes, ellswift_bytes, Role::Initiator)
    }

    fn get_mitm_fake_server() -> (
        MitmImpersonatorLeg,
        Rc<RefCell<FakePeerRelay>>,
        Rc<RefCell<FakePeerRelay>>,
    ) {
        let mut rng = secp256k1::rand::thread_rng();
        let secret_key = secret_key_bytes_from_rng(&mut rng);

        get_mitm_fake_server_from_secret_key(secret_key, None)
    }

    fn get_mitm_fake_client() -> (
        MitmImpersonatorLeg,
        Rc<RefCell<FakePeerRelay>>,
        Rc<RefCell<FakePeerRelay>>,
    ) {
        let mut rng = secp256k1::rand::thread_rng();
        let secret_key = secret_key_bytes_from_rng(&mut rng);

        get_mitm_fake_client_from_secret_key(secret_key, None)
    }

    fn insecurerng(seed: u64) -> TestRng {
        TestRng::new(seed, seed / 2 + 1)
    }

    fn get_mitm_fake_server_deterministic_insecurerng(
        seed: u64,
    ) -> (
        MitmImpersonatorLeg,
        Rc<RefCell<FakePeerRelay>>,
        Rc<RefCell<FakePeerRelay>>,
    ) {
        let mut insecure_rng = insecurerng(seed);
        let secret_key = secret_key_bytes_from_rng(&mut insecure_rng);

        get_mitm_fake_server_from_secret_key(secret_key, None)
    }

    fn get_mitm_fake_client_deterministic_insecurerng(
        seed: u64,
    ) -> (
        MitmImpersonatorLeg,
        Rc<RefCell<FakePeerRelay>>,
        Rc<RefCell<FakePeerRelay>>,
    ) {
        let mut insecure_rng = insecurerng(seed);
        let secret_key = secret_key_bytes_from_rng(&mut insecure_rng);

        get_mitm_fake_client_from_secret_key(secret_key, None)
    }

    #[test]
    fn client_key_by_parts() {
        let (mut server, _, _) = get_mitm_fake_server();

        // Send one key byte
        server
            .pass_peer_data(&[0xa3])
            .expect("Error on pass_peer_data");
        assert!(matches!(
            server.state,
            HandshakeBIP324State::Initialized(..)
        ));

        // Send another key byte
        server
            .pass_peer_data(&[0xa3])
            .expect("Error on pass_peer_data");
        assert!(matches!(
            server.state,
            HandshakeBIP324State::Initialized(..)
        ));

        // Send all the key bytes, except for the last one
        server
            .pass_peer_data(&[0x73; NUM_ELLIGATOR_SWIFT_BYTES - 2 - 1])
            .expect("Error on pass_peer_data");
        assert!(matches!(
            server.state,
            HandshakeBIP324State::Initialized(..)
        ));

        // Send all the key bytes, except for the last one
        server
            .pass_peer_data(&[0x29])
            .expect("Error on pass_peer_data");
        assert!(matches!(
            server.state,
            HandshakeBIP324State::ReceivedKey(..)
        ));
    }

    #[test]
    fn client_key_direct() {
        let (mut server, _, _) = get_mitm_fake_server();

        // Send all the key bytes
        server
            .pass_peer_data(&[0x73; NUM_ELLIGATOR_SWIFT_BYTES])
            .expect("Error on pass_peer_data");
        assert!(matches!(
            server.state,
            HandshakeBIP324State::ReceivedKey(..)
        ));
    }

    #[test]
    fn client_key_overflow() {
        let (mut server, _, _) = get_mitm_fake_server();

        // Send more than the key bytes
        server
            .pass_peer_data(&[0x73; NUM_ELLIGATOR_SWIFT_BYTES + 10])
            .expect("Error on pass_peer_data");
        assert!(matches!(
            server.state,
            HandshakeBIP324State::ReceivedKey(..)
        ));
    }

    // Tests that the fake server doesn't relay the key if the real server
    // didn't send its key yet
    #[test]
    fn server_key_not_relayed() {
        let (mut server, _, _) = get_mitm_fake_server();

        // Send all the key bytes
        server
            .pass_peer_data(&[0x73; NUM_ELLIGATOR_SWIFT_BYTES])
            .expect("Error on pass_peer_data");
        assert!(matches!(
            server.state,
            HandshakeBIP324State::ReceivedKey(..)
        ));

        let mut buf = vec![0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        let initial_buf = buf.clone();
        let size = server.write_data(&mut buf).expect("Error on write_data");
        assert_eq!(size, 0, "Expected write_data to not write anything");
        assert_eq!(buf, initial_buf, "Expected the buffer to stay empty");
    }

    #[test]
    fn shared_key_generation() {
        let TestHandshakeParams {
            server_seed,
            server_key,
            client_key,
            client_garbage_terminator,
            initiator_l,
            initiator_p,
            responder_l,
            responder_p,
            ..
        } = HANDSHAKE_PARAMS1;

        let (mut server, _, _) = get_mitm_fake_server_deterministic_insecurerng(server_seed);
        assert_eq!(
            server.key_to_send, server_key,
            "The generated secret key is different from the expected one"
        );

        server
            .pass_peer_data(&client_key)
            .expect("Error on pass_peer_data");
        let HandshakeBIP324State::ReceivedKey(other_garbage_terminator) = server.state else {
            panic!("Wrong state after receiving key");
        };

        let cipher = &server.cipher.expect("Expected a cipher object");
        assert_eq!(cipher.inbound.length_cipher.key_bytes, initiator_l);
        assert_eq!(cipher.inbound.packet_cipher.key_bytes, initiator_p);
        assert_eq!(cipher.outbound.length_cipher.key_bytes, responder_l);
        assert_eq!(cipher.outbound.packet_cipher.key_bytes, responder_p);
        assert_eq!(other_garbage_terminator, client_garbage_terminator);
    }

    // Tests that, when the fake server is ready to send the key, it can send it
    // byte by byte, corresponding to each byte sent by the real server.
    #[test]
    fn server_key_partially_relayed() {
        let (mut server, relay_in, _) = get_mitm_fake_server();

        // Send all the key bytes
        server
            .pass_peer_data(&[0x73; NUM_ELLIGATOR_SWIFT_BYTES])
            .expect("Error on pass_peer_data");
        assert!(matches!(
            server.state,
            HandshakeBIP324State::ReceivedKey(..)
        ));

        let buf = [0u8];
        let mut out_buf = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        // Send one byte at a time
        for i in 0..NUM_ELLIGATOR_SWIFT_BYTES {
            relay_in
                .borrow_mut()
                .write_key(&buf)
                .expect("Write to relay_in must to fail");
            let size = server
                .write_data(&mut out_buf[i..])
                .expect("Error on write_data");
            assert_eq!(size, 1, "Expected write_data to write one byte at step {i}");

            let size = server
                .write_data(&mut out_buf[i..])
                .expect("Error on write_data");
            assert_eq!(size, 0, "Expected write_data to not write byte at step {i}");
        }

        // Verifies that the fake server actually replaced the key bytes with its own bytes
        assert_ne!(out_buf, [0u8; NUM_ELLIGATOR_SWIFT_BYTES]);
    }

    // Tests the case where the client doesn't send the key, and the real server
    // sends the entire key.
    #[test]
    fn key_sent_only_from_server() {
        let (mut server, relay_in, _) = get_mitm_fake_server();

        let buf = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        relay_in
            .borrow_mut()
            .write_key(&buf)
            .expect("Write must not fail");

        let mut sent_key = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        let size = server
            .write_data(&mut sent_key)
            .expect("Error on write_data");
        assert_eq!(
            size, NUM_ELLIGATOR_SWIFT_BYTES,
            "Fake server must send the entire key"
        )
    }

    #[test]
    fn key_sent_partially_from_server_when_client_sent_key_partially() {
        let (mut server, relay_in, _) = get_mitm_fake_server();

        // Server sends something
        relay_in
            .borrow_mut()
            .write_key(&[0u8; 2])
            .expect("Write must not fail");

        // Client sends something
        server
            .pass_peer_data(&[0x73; 3])
            .expect("Error on pass_peer_data");

        // Server sends something again
        relay_in
            .borrow_mut()
            .write_key(&[0u8; 2])
            .expect("Write must not fail");

        // Client sends something again
        server
            .pass_peer_data(&[0x73; 4])
            .expect("Error on pass_peer_data");

        let mut sent_key = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        let size = server
            .write_data(&mut sent_key)
            .expect("Error on write_data");
        assert_eq!(size, 4, "Fake server must send 4 byte keys")
    }

    #[test]
    fn server_correct_public_key() {
        let TestHandshakeParams {
            server_seed,
            server_key,
            ..
        } = HANDSHAKE_PARAMS1;

        let (mut server, relay_in, _) = get_mitm_fake_server_deterministic_insecurerng(server_seed);
        assert_eq!(
            server.key_to_send, server_key,
            "The generated secret key is different from the expected one"
        );

        // Real server sends the key
        let buf = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        relay_in
            .borrow_mut()
            .write_key(&buf)
            .expect("Write must not fail");

        let mut sent_key = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        let size = server
            .write_data(&mut sent_key)
            .expect("Error on write_data");
        assert_eq!(
            size, NUM_ELLIGATOR_SWIFT_BYTES,
            "Fake server must send the entire key"
        );
        assert_eq!(sent_key, server_key, "Incorrect server key");
    }

    #[test]
    fn real_server_sends_garbage_before_client_start_sending_key() {
        let (mut server, relay_in, _) = get_mitm_fake_server();

        // Real server sends the key
        let buf = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        relay_in
            .borrow_mut()
            .write_key(&buf)
            .expect("Write must not fail");

        // Real server sends some garbage
        let real_garbage = [3u8; 10];
        relay_in
            .borrow_mut()
            .write_garbage(&real_garbage)
            .expect("Write must not fail");

        // Fake server sends key
        let mut sent_key = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        let size = server
            .write_data(&mut sent_key)
            .expect("Error on write_data");
        assert_eq!(
            size, NUM_ELLIGATOR_SWIFT_BYTES,
            "Fake server must send the entire key"
        );

        // Fake server sends garbage
        let mut sent_garbage = [0u8; 128];
        let size = server
            .write_data(&mut sent_garbage)
            .expect("Error on write_data");
        assert_eq!(
            sent_garbage[..size],
            real_garbage,
            "The fake server must preserve the garbage sent by the real server"
        );
    }

    #[test]
    fn real_server_sends_garbage_before_client_sending_entire_key() {
        let (mut server, relay_in, _) = get_mitm_fake_server();

        // Client sends key
        server
            .pass_peer_data(&[0x73; NUM_ELLIGATOR_SWIFT_BYTES - 1])
            .expect("Error on pass_peer_data");

        // Real server sends the key
        let buf = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        relay_in
            .borrow_mut()
            .write_key(&buf)
            .expect("Write must not fail");

        // Real server sends some garbage
        let real_garbage = [3u8; 10];
        relay_in
            .borrow_mut()
            .write_garbage(&real_garbage)
            .expect("Write must not fail");

        // Fake server sends key
        let mut sent_key = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        let size = server
            .write_data(&mut sent_key)
            .expect("Error on write_data");
        assert_eq!(
            size, NUM_ELLIGATOR_SWIFT_BYTES,
            "Fake server must send the entire key"
        );

        // Fake server sends garbage
        let mut sent_garbage = [0u8; 128];
        let size = server
            .write_data(&mut sent_garbage)
            .expect("Error on write_data");
        assert_eq!(
            sent_garbage[..size],
            real_garbage,
            "The fake server must preserve the garbage sent by the real server"
        );
    }

    #[test]
    fn real_server_sends_garbage_before_client_start_sending_garbage() {
        let (mut server, relay_in, _) = get_mitm_fake_server();

        // Client sends partial key
        server
            .pass_peer_data(&[0x73; NUM_ELLIGATOR_SWIFT_BYTES])
            .expect("Error on pass_peer_data");

        // Real server sends the key
        let buf = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        relay_in
            .borrow_mut()
            .write_key(&buf)
            .expect("Write must not fail");

        // Real server sends some garbage
        let real_garbage = [3u8; 10];
        relay_in
            .borrow_mut()
            .write_garbage(&real_garbage)
            .expect("Write must not fail");

        // Fake server sends key
        let mut sent_key = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        let size = server
            .write_data(&mut sent_key)
            .expect("Error on write_data");
        assert_eq!(
            size, NUM_ELLIGATOR_SWIFT_BYTES,
            "Fake server must send the entire key"
        );

        // Fake server sends garbage
        let mut sent_garbage = [0u8; 128];
        let size = server
            .write_data(&mut sent_garbage)
            .expect("Error on write_data");
        assert_eq!(
            sent_garbage[..size],
            real_garbage,
            "The fake server must preserve the garbage sent by the real server"
        );
    }

    #[test]
    fn real_server_sends_entire_garbage() {
        let TestHandshakeParams {
            server_seed,
            server_key,
            server_garbage_terminator,
            client_key,
            ..
        } = HANDSHAKE_PARAMS1;

        let (mut server, relay_in, _) = get_mitm_fake_server_deterministic_insecurerng(server_seed);
        assert_eq!(
            server.key_to_send, server_key,
            "The generated secret key is different from the expected one"
        );

        // Real client sends the key
        server
            .pass_peer_data(&client_key)
            .expect("Error on pass_peer_data");

        // Real server sends the key
        let buf = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        relay_in
            .borrow_mut()
            .write_key(&buf)
            .expect("Write must not fail");

        // Real server sends the entire garbage
        let garbage = [73u8; 84];
        relay_in
            .borrow_mut()
            .write_garbage(&garbage)
            .expect("Write must not fail");
        relay_in.borrow_mut().set_eof_garbage();

        // Real server sends the garbage terminator
        let garbage_terminator = [75u8; NUM_GARBAGE_TERMINATOR_BYTES];
        relay_in
            .borrow_mut()
            .write_terminator(&garbage)
            .expect("Write must not fail");
        relay_in.borrow_mut().set_eof_terminator();

        let mut sent_key = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        let size = server
            .write_data(&mut sent_key)
            .expect("Error on write_data");
        assert_eq!(
            size, NUM_ELLIGATOR_SWIFT_BYTES,
            "Fake server must send the entire key"
        );
        assert_eq!(sent_key, server_key, "Incorrect server key");

        let expected_len = garbage.len() + garbage_terminator.len();
        let mut sent_garbage = [0u8; 200];
        let size = server
            .write_data(&mut sent_garbage)
            .expect("Error on write_data");
        assert_eq!(
            size, expected_len,
            "Fake server must send the entire garbage"
        );
        assert_eq!(
            sent_garbage[..expected_len - NUM_GARBAGE_TERMINATOR_BYTES],
            garbage[..expected_len - NUM_GARBAGE_TERMINATOR_BYTES],
            "Incorrect server garbage"
        );
        assert_eq!(
            sent_garbage[expected_len - NUM_GARBAGE_TERMINATOR_BYTES..expected_len],
            server_garbage_terminator,
            "Incorrect garbage terminator"
        );
    }

    #[test]
    fn real_server_sends_version() {
        let TestParams2 {
            in_idx,
            in_priv_ours,
            in_initiating,
            in_ellswift_ours,
            in_ellswift_theirs,
            in_contents,
            in_aad,
            mid_send_garbage_terminator,
            mid_recv_garbage_terminator,
            out_ciphertext,
            ..
        } = HANDSHAKE_PARAMS2;

        let (mut impersonator, relay_in, _) = if in_initiating != 0 {
            get_mitm_fake_client_from_secret_key(in_priv_ours, Some(in_ellswift_ours))
        } else {
            get_mitm_fake_server_from_secret_key(in_priv_ours, Some(in_ellswift_ours))
        };

        // Other sends the key
        impersonator
            .pass_peer_data(&in_ellswift_theirs)
            .expect("Error on pass_peer_data");

        // Other sends the garbage
        //impersonator.pass_peer_data(&[73u8; 101])
        //    .expect("Error on pass_peer_data");

        // Real self sends the key
        let buf = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        relay_in
            .borrow_mut()
            .write_key(&buf)
            .expect("Write must not fail");

        // Other sends the garbage terminator
        impersonator
            .pass_peer_data(&mid_recv_garbage_terminator)
            .expect("Error on pass_peer_data");

        // Other seends a packet
        impersonator
            .pass_peer_data(&out_ciphertext)
            .expect("Error on pass_peer_data");

        // Real self sends the entire garbage
        let garbage = in_aad;
        relay_in
            .borrow_mut()
            .write_garbage(&garbage)
            .expect("Write must not fail");
        relay_in.borrow_mut().set_eof_garbage();

        // Real self sends the garbage terminator
        relay_in
            .borrow_mut()
            .write_terminator(&mid_send_garbage_terminator)
            .expect("Write must not fail");
        relay_in.borrow_mut().set_eof_terminator();

        // Set the Authenticated Additional Data that is suposedly used to compute the tag
        // relay_in.borrow_mut().set_aad(&VERSION_PACKET);

        // Real self sends decoys
        for _ in 0..in_idx {
            let payload = DECOY_HEADER.to_vec();

            // The packet doesn't have any content
            let packet_len: usize = 0;
            let packet_len_bytes_full = packet_len.to_le_bytes();
            let len_bytes = &packet_len_bytes_full[..3];

            relay_in.borrow_mut().write_length_bytes(len_bytes);
            relay_in.borrow_mut().write_packet_bytes(&payload);
            relay_in.borrow_mut().write_tag_bytes(&[14u8; TAG_LEN]);
        }

        {
            let mut payload = DEFAULT_HEADER.to_vec();
            payload.extend_from_slice(&in_contents);

            // Real self sends the length of the version packet
            {
                let packet_len: usize = in_contents.len();
                let packet_len_bytes_full = packet_len.to_le_bytes();
                let len_bytes = &packet_len_bytes_full[..3];
                relay_in.borrow_mut().write_length_bytes(len_bytes);
            }

            // Self sends the packet
            relay_in.borrow_mut().write_packet_bytes(&payload);
        }

        // Self sends the tag
        relay_in.borrow_mut().write_tag_bytes(&[13u8; TAG_LEN]);

        // Read key
        {
            let buf_len = NUM_ELLIGATOR_SWIFT_BYTES;
            let mut buf = vec![0u8; buf_len];
            let size = impersonator
                .write_data(&mut buf)
                .expect("Error on write_data");
            assert_eq!(size, buf_len, "Buffer was not filled");
            assert_eq!(buf, in_ellswift_ours);
        }

        // Read garbage and garbage terminator
        {
            let buf_len = garbage.len();
            let mut buf = vec![0u8; buf_len];
            let size = impersonator
                .write_data(&mut buf)
                .expect("Error on write_data");
            assert_eq!(size, buf_len, "Buffer was not filled");
            assert_eq!(buf, garbage, "Garbage is incorrect");

            let mut term = vec![0u8; NUM_GARBAGE_TERMINATOR_BYTES];
            let size = impersonator
                .write_data(&mut term)
                .expect("Error on write_data");
            assert_eq!(size, term.len(), "Buffer was not filled");
            assert_eq!(term, mid_send_garbage_terminator);
        }

        for _ in 0..in_idx {
            // Read decoy packet. This includes: packet length (0), header, version contents and aead.
            let expected_len = LENGTH_BYTES_SIZE + HEADER_LEN + TAG_LEN;
            let mut buf = vec![0u8; expected_len];
            let size = impersonator
                .write_data(&mut buf)
                .expect("Error on write_data");
            assert_eq!(
                size, expected_len,
                "Fake peer didn't send the expected amount of bytes"
            );
        }

        // Read packet. This includes: packet length, header, version contents and aead.
        let expected_len = LENGTH_BYTES_SIZE + HEADER_LEN + in_contents.len() + TAG_LEN;
        let mut buf = vec![0u8; expected_len + 100];
        let size = impersonator
            .write_data(&mut buf)
            .expect("Error on write_data");
        assert_eq!(
            size,
            out_ciphertext.len(),
            "The expected cipher text doesn't have the expected length. This is a test setup issue"
        );
        assert_eq!(
            size, expected_len,
            "Fake peer didn't send the expected amount of bytes"
        );
        assert_eq!(
            buf[..size],
            out_ciphertext,
            "Fake peer didn't send the expected encrypted payload"
        );
    }
}
