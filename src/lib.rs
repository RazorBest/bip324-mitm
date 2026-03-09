mod bip324_external_fschacha20poly1305;
mod bip324_external_lib;

use std::cell::RefCell;
use std::cmp::min;
use std::collections::VecDeque;
use std::error::Error;
use std::fmt;
use std::io::{Read, Write};
use std::rc::Rc;

use bip324::NUM_LENGTH_BYTES;
use bip324::Role;
use secp256k1::{
    PublicKey, Secp256k1, SecretKey,
    ellswift::{ElligatorSwift, ElligatorSwiftParty},
    rand::CryptoRng, 
};

use crate::bip324_external_fschacha20poly1305::{FSChaCha20, FSChaCha20Poly1305};
use crate::bip324_external_lib::{
    FillBytes, InboundCipher, OutboundCipher, PacketType, SessionKeyMaterial,
};

// Number of bytes in elligator swift key.
const NUM_ELLIGATOR_SWIFT_BYTES: usize = 64;
// Number of bytes for the garbage terminator.
const NUM_GARBAGE_TERMINTOR_BYTES: usize = 16;
// Maximum packet size for automatic allocation.
// Bitcoin Core's MAX_PROTOCOL_MESSAGE_LENGTH is 4,000,000 bytes (~4 MiB).
// 14 extra bytes are for the BIP-324 header byte and 13 serialization header bytes (message type).
const MAX_PACKET_SIZE_FOR_ALLOCATION: usize = 4000014;
// Maximum number of garbage bytes before the terminator.
const MAX_NUM_GARBAGE_BYTES: usize = 4095;

type GarbageType = Vec<u8>;
type GarbageTerminatorType = [u8; NUM_GARBAGE_TERMINTOR_BYTES];
type MagicType = [u8; 4];

/// A wrapper over Err(std::io::Error(..))
fn IOError<T, E>(kind: std::io::ErrorKind, error: E) -> std::io::Result<T>
where E: Into<Box<dyn Error + Send + Sync>>
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

impl fmt::Debug for InboundCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<InboundCipher>")
    }
}

impl fmt::Debug for OutboundCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<OutboundCipher>")
    }
}

impl CipherSession {
    pub(crate) fn new(materials: SessionKeyMaterial, role: Role) -> Self {
        match role {
            Role::Initiator => {
                let initiator_length_cipher = FSChaCha20::new(materials.initiator_length_key);
                let responder_length_cipher = FSChaCha20::new(materials.responder_length_key);
                let initiator_packet_cipher =
                    FSChaCha20Poly1305::new(materials.initiator_packet_key);
                let responder_packet_cipher =
                    FSChaCha20Poly1305::new(materials.responder_packet_key);
                CipherSession {
                    id: materials.session_id,
                    inbound: InboundCipher {
                        length_cipher: responder_length_cipher,
                        packet_cipher: responder_packet_cipher,
                    },
                    outbound: OutboundCipher {
                        length_cipher: initiator_length_cipher,
                        packet_cipher: initiator_packet_cipher,
                    },
                }
            }
            Role::Responder => {
                let responder_length_cipher = FSChaCha20::new(materials.responder_length_key);
                let initiator_length_cipher = FSChaCha20::new(materials.initiator_length_key);
                let responder_packet_cipher =
                    FSChaCha20Poly1305::new(materials.responder_packet_key);
                let initiator_packet_cipher =
                    FSChaCha20Poly1305::new(materials.initiator_packet_key);
                CipherSession {
                    id: materials.session_id,
                    inbound: InboundCipher {
                        length_cipher: initiator_length_cipher,
                        packet_cipher: initiator_packet_cipher,
                    },
                    outbound: OutboundCipher {
                        length_cipher: responder_length_cipher,
                        packet_cipher: responder_packet_cipher,
                    },
                }
            }
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
    Initialized(MagicType),
    ReceivedKey(CipherSession, GarbageTerminatorType),
    ReceivedGarbage(CipherSession, GarbageType),
    ReceivedPacketLen(CipherSession, GarbageType, usize),
    ReceivedVersion(InboundCipher, OutboundCipher),
}

#[derive(Debug)]
enum SessionState {
    SendingKey,
    SendingRest,
}

struct SessionEntityTrackerBIP324 {
    state: SessionState,

    write_buf: Vec<u8>,
    read_buf: Vec<u8>,
    key: Option<[u8; NUM_ELLIGATOR_SWIFT_BYTES]>,
    rest: Vec<u8>,
}

impl SessionEntityTrackerBIP324 {
    pub fn new() -> Self {
        Self {
            state: SessionState::SendingKey,
            write_buf: vec![],
            read_buf: vec![],
            key: None,
            rest: vec![],
        }
    }
    pub fn pass_payload(&mut self, data: &[u8]) -> Result<(), String> {
        use SessionState::*;

        self.write_buf.extend_from_slice(data);
        self.read_buf.extend_from_slice(data);
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
            SendingRest => {
                let data: Vec<_> = self.write_buf.drain(..).collect();
                if data.len() + self.rest.len() > MAX_NUM_GARBAGE_BYTES {
                    return Err("Garbage buffer limit exceeded".to_string());
                }
                self.rest.extend_from_slice(&data);
            }
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
}

impl Read for DataToSend {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        Ok(read_vec_dequeue_u8(&mut self.stream, buf))
    }
}

impl Write for DataToSend {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.eof {
            return IOError(std::io::ErrorKind::Other, "Can't write. Eof was already reached.");
        }
        self.stream.extend(data);

        Ok(data.len())
    }

    /// Doesn't actually flush, because it needs a consumer to call read
    fn flush(&mut self) -> std::io::Result<()> {
        if self.eof {
            return IOError(std::io::ErrorKind::Other, "Can't flush. Eof was already reached.");
        }
        Ok(())
    }
}

struct PartialPacket {
    length_bytes: Option<Vec<u8>>,
    data: Option<Vec<u8>>,
}

impl PartialPacket {
    fn new() -> Self {
        Self {
            length_bytes: None,
            data: None,
        }
    }
}

struct FakePeerRelay {
    key: DataToSend,
    garbage: DataToSend,
    packets: Vec<PartialPacket>,
}

impl FakePeerRelay {
    fn new() -> Self {
        Self {
            key: DataToSend::new(),
            garbage: DataToSend::new(),
            packets: vec![],
        }
    }
}

trait FakePeerRelayWriter {
    fn write_garbage(&mut self, data: &[u8]) -> std::io::Result<usize>;
    fn set_eof_garbage(&mut self);
    fn write_key(&mut self, data: &[u8]) -> std::io::Result<usize>;
    fn set_eof_key(&mut self);
    fn add_length_bytes(&mut self, data: &[u8]);
    fn add_packet_bytes(&mut self, data: &[u8]);
}

impl FakePeerRelayWriter for FakePeerRelay {
    fn write_garbage(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.garbage.write(data)
    }

    fn set_eof_garbage(&mut self) {
        self.garbage.set_eof();
    }

    fn write_key(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.key.write(data)
    }

    fn set_eof_key(&mut self) {
        self.key.set_eof();
    }

    fn add_length_bytes(&mut self, data: &[u8]) {
        if data.len() == 0 {
            return;
        }

        if self.packets.len() == 0 || self.packets[self.packets.len() - 1].data.is_some() {
            self.packets.push(PartialPacket::new());
        }

        let packets_len = self.packets.len();
        let last_packet = &mut self.packets[packets_len - 1];

        if last_packet.length_bytes.is_none() {
            last_packet.length_bytes = Some(vec![]);
        }

        let length_bytes = &mut last_packet.length_bytes.as_mut().unwrap();
        length_bytes.extend_from_slice(data);
    }

    fn add_packet_bytes(&mut self, data: &[u8]) {
        if data.len() == 0 {
            return;
        }

        if self.packets.len() == 0 {
            self.packets.push(PartialPacket::new());
        }

        let packets_len = self.packets.len();
        let last_packet = &mut self.packets[packets_len - 1];

        if last_packet.data.is_none() {
            last_packet.data = Some(vec![]);
        }

        let packet_data = &mut last_packet.data.as_mut().unwrap();
        packet_data.extend_from_slice(data);
    }
}

trait FakePeerRelayReader {
    fn read_garbage(&mut self, data: &mut [u8]) -> std::io::Result<usize>;
    fn is_eof_garbage(&self) -> bool;
    fn read_key(&mut self, data: &mut [u8]) -> std::io::Result<usize>;
    fn is_eof_key(&self) -> bool;
}

impl FakePeerRelayReader for FakePeerRelay {
    fn read_garbage(&mut self, data: &mut [u8]) -> std::io::Result<usize> {
        self.garbage.read(data)
    }

    fn is_eof_garbage(&self) -> bool {
        self.garbage.is_eof()
    }

    fn read_key(&mut self, data: &mut [u8]) -> std::io::Result<usize> {
        self.key.read(data)
    }

    fn is_eof_key(&self) -> bool {
        self.key.is_eof()
    }
}

fn key_from_rng<Rng: FillBytes + CryptoRng>(
    rng: &mut Rng,
) -> Result<EcdhPoint, Box<dyn Error>> {
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
    terminator: [u8; NUM_GARBAGE_TERMINTOR_BYTES],
) -> Option<(&[u8], &[u8])> {
    for (i, window) in buf.windows(NUM_LENGTH_BYTES).enumerate() {
        if window == terminator {
            return Some((&buf[..i], &buf[i + NUM_LENGTH_BYTES..]));
        }
    }

    None
}

enum RelayServerState {
    SendingKey,
    SendingGarbage,
    SendingGarbageTerminator,
    SendingLength,
}

impl RelayServerState {
    fn new() -> Self {
        Self::SendingKey
    }
}

fn generate_session_keys_ecdh(magic: [u8; 4], role: Role, point: &EcdhPoint, client_key: [u8; NUM_ELLIGATOR_SWIFT_BYTES]) -> Result<SessionKeyMaterial, String> {
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

    let session_keys = SessionKeyMaterial::from_ecdh(
        initiator_ellswift,
        responder_ellswift,
        secret,
        party,
        magic,
    )
    .map_err(|_| "Error creating the shared key".to_string());

    session_keys
}

struct MitmImpersonatorLeg {
    state: HandshakeBIP324State,
    server_state: RelayServerState,

    role: Role,

    peer: SessionEntityTrackerBIP324,

    point: EcdhPoint,
    key_to_send: Vec<u8>,
    garbage_terminator_to_send: Vec<u8>,

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
            state: HandshakeBIP324State::Initialized(magic),
            server_state: RelayServerState::new(),
            role,
            point,
            peer: SessionEntityTrackerBIP324::new(),
            key_to_send,
            garbage_terminator_to_send: vec![],
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

        match &mut self.state {
            Initialized(magic) => {
                if let Some(client_key) = self.peer.key {
                    /*
                    let their_ellswift = ElligatorSwift::from_array(client_key);

                    let (initiator_ellswift, responder_ellswift, secret, party) = match self.role {
                        Role::Initiator => (
                            self.point.elligator_swift,
                            their_ellswift,
                            self.point.secret_key,
                            ElligatorSwiftParty::A,
                        ),
                        Role::Responder => (
                            their_ellswift,
                            self.point.elligator_swift,
                            self.point.secret_key,
                            ElligatorSwiftParty::B,
                        ),
                    };

                    let session_keys = SessionKeyMaterial::from_ecdh(
                        initiator_ellswift,
                        responder_ellswift,
                        secret,
                        party,
                        magic,
                    )
                    .map_err(|_| "Error creating the shared key")?;
                    */
                    let session_keys = generate_session_keys_ecdh(magic.clone(), self.role, &self.point, client_key)?;

                    let cipher = CipherSession::new(session_keys.clone(), self.role);

                    let (garbage_terminator, other_garbage_terminator) = match self.role {
                        Role::Initiator => (
                            session_keys.initiator_garbage_terminator,
                            session_keys.responder_garbage_terminator,
                        ),
                        Role::Responder => (
                            session_keys.responder_garbage_terminator,
                            session_keys.initiator_garbage_terminator,
                        ),
                    };

                    self.garbage_terminator_to_send
                        .extend_from_slice(&garbage_terminator);

                    self.state = ReceivedKey(cipher, other_garbage_terminator);
                }

                if !(matches!(self.state, Initialized(..))) {
                    return self.pass_peer_data(&[]);
                }
            }
            ReceivedKey(cipher, other_garbage_terminator) => {
                let buf = self.peer.consume_all_bytes();

                if let Some((garbage, rest)) =
                    split_garbage_by_terminator(&buf, *other_garbage_terminator)
                {
                    self.state = ReceivedGarbage(cipher.clone(), garbage.to_vec());
                    self.peer.undo_consume(rest.to_vec());

                    self.relay_out.borrow_mut().write_garbage(&garbage).map_err(|_| "Error writing garbage to relay")?;
                } else {
                    // The last bytes might be part of a truncated garbage terminator
                    let size = min(other_garbage_terminator.len() - 1, buf.len());
                    self.peer.undo_consume(buf[buf.len() - size..].to_vec());

                    let partial_garbage = &buf[..buf.len() - size];
                    self.relay_out.borrow_mut().write_garbage(partial_garbage).map_err(|_| "Error writing garbage to relay")?;
                }

                if !(matches!(self.state, ReceivedKey(..))) {
                    return self.pass_peer_data(&[]);
                }
            }
            ReceivedGarbage(cipher, other_garbage) => {
                if self.peer.available_bytes() >= NUM_LENGTH_BYTES {
                    let length_bytes: [u8; NUM_LENGTH_BYTES] = self
                        .peer
                        .consume_bytes(NUM_LENGTH_BYTES)?
                        .try_into()
                        .unwrap();
                    let packet_len = cipher.inbound().decrypt_packet_len(length_bytes);
                    if packet_len > MAX_PACKET_SIZE_FOR_ALLOCATION {
                        return Err("Packet too big".to_string());
                    }

                    let length_bytes_decrypted = {
                        let bytes = (packet_len as u32).to_le_bytes();

                        [bytes[0], bytes[1], bytes[2]]
                    };

                    self.relay_out
                        .borrow_mut()
                        .add_length_bytes(&length_bytes_decrypted);
                    self.state =
                        ReceivedPacketLen(cipher.clone(), other_garbage.clone(), packet_len);
                }
                if !(matches!(self.state, ReceivedGarbage(..))) {
                    return self.pass_peer_data(&[]);
                }
            }
            ReceivedPacketLen(cipher, other_garbage, packet_len) => {
                if self.peer.available_bytes() >= *packet_len {
                    let mut packet_bytes = self.peer.consume_bytes(*packet_len).unwrap();

                    let aad = Some(&other_garbage[..]);
                    let (packet_type, _) = cipher
                        .inbound()
                        .decrypt_in_place(&mut packet_bytes, aad)
                        .expect("Decryption Error");
                    self.relay_out.borrow_mut().add_packet_bytes(&packet_bytes);

                    match packet_type {
                        PacketType::Genuine => {
                            let (inbound_cipher, outbound_cipher) = cipher.clone().into_split();
                            self.state = ReceivedVersion(inbound_cipher, outbound_cipher);
                        }
                        PacketType::Decoy => {
                            self.state = ReceivedGarbage(cipher.clone(), other_garbage.clone());
                        }
                    }
                }

                if !(matches!(self.state, ReceivedPacketLen(..))) {
                    return self.pass_peer_data(&[]);
                }
            }
            ReceivedVersion(..) => (),
        }

        Ok(())
    }

    /// Writes the data from the impersonator to the peer
    pub fn write_data(&mut self, buf: &mut [u8]) -> Result<usize, Box<dyn Error>> {
        use RelayServerState::*;

        match self.server_state {
            SendingKey => {
                let limit = min(buf.len(), self.key_to_send.len());
                let _key_buf = &mut buf[..limit];
                let size = self.relay_in.borrow_mut().read_key(_key_buf)?;

                // The key is replaced by ours. We're not using the original one
                let data_to_send: Vec<u8> = self.key_to_send.drain(..size).collect();
                buf[..size].copy_from_slice(&data_to_send);

                if self.key_to_send.len() == 0 {
                    self.server_state = SendingGarbage;

                    return Ok(size + self.write_data(&mut buf[size..])?);
                }

                Ok(size)
            }
            SendingGarbage => {
                let size = self.relay_in.borrow_mut().read_garbage(buf)?;

                if self.relay_in.borrow().is_eof_garbage() {
                    self.server_state = SendingGarbageTerminator;

                    return Ok(size + self.write_data(&mut buf[size..])?);
                }

                Ok(size)
            }
            SendingGarbageTerminator => {
                let limit = min(buf.len(), self.garbage_terminator_to_send.len());
                let _terminator_buf = &mut buf[..limit];
                let size = self.relay_in.borrow_mut().read_garbage(_terminator_buf)?;

                // The terminator is replaced by ours. We're not using the original one
                let data_to_send: Vec<u8> = self.garbage_terminator_to_send.drain(..size).collect();
                buf[..size].copy_from_slice(&data_to_send);

                if self.garbage_terminator_to_send.len() == 0 {
                    self.server_state = SendingLength;

                    return Ok(size + self.write_data(&mut buf[size..])?);
                }

                Ok(size)
            }
            SendingLength => {
                // TODO
                // let packet_len_bytes
                Ok(0)
            }
        }
    }
}

#[allow(non_upper_case_globals)]
#[cfg(test)]
mod mitmfakeserverbip324_tests {
    use super::*;

    use hex_literal::hex;
    use secp256k1::rand::rngs::mock::StepRng;
    use secp256k1::rand::RngCore;

    use crate::bip324_external_lib::impl_fill_bytes;

    const DEFAULT_MAGIC: [u8; 4] = [0xF9, 0xBE, 0xB4, 0xD9];

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

    fn get_mitm_fake_server() -> (MitmImpersonatorLeg, Rc<RefCell<FakePeerRelay>>, Rc<RefCell<FakePeerRelay>>) {
        let mut rng = secp256k1::rand::thread_rng();

        let relay_in = Rc::new(RefCell::new(FakePeerRelay::new()));
        let relay_out = Rc::new(RefCell::new(FakePeerRelay::new()));
        let secret_key = key_from_rng(&mut rng).expect("Failed generating the secret key");

        let server = MitmImpersonatorLeg::new_fake_server(DEFAULT_MAGIC, relay_in.clone(), relay_out.clone(), secret_key)
            .expect("Error creating the MitmImpersonatorLeg");

        return (server, relay_in, relay_out)
    }

    fn insecurerng(seed: u64) -> TestRng {
        TestRng::new(seed, seed / 2 + 1)
    }

    fn get_mitm_fake_server_deterministic_insecurerng(seed: u64) -> (MitmImpersonatorLeg, Rc<RefCell<FakePeerRelay>>, Rc<RefCell<FakePeerRelay>>) {
        let mut insecure_rng = TestRng::new(seed, seed / 2 + 1);

        let relay_in = Rc::new(RefCell::new(FakePeerRelay::new()));
        let relay_out = Rc::new(RefCell::new(FakePeerRelay::new()));
        let secret_key = key_from_rng(&mut insecure_rng).expect("Failed generating the secret key");

        let server = MitmImpersonatorLeg::new_fake_server(DEFAULT_MAGIC, relay_in.clone(), relay_out.clone(), secret_key)
            .expect("Error creating the MitmImpersonatorLeg");

        return (server, relay_in, relay_out)
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
        server.pass_peer_data(&[0x73; NUM_ELLIGATOR_SWIFT_BYTES])
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
        const seed: u64 = 32890322278;
        const server_key: [u8; NUM_ELLIGATOR_SWIFT_BYTES] = hex!("6a34b0f8757abbd31934ce6375857b06000d1a4528274eaec46c6e11a243366dcb14d23c315b7305fb4bd7c11ddc515785061f2a9402c867f2550a7e8e5496ca");
        // Client seed: 992983889292929773;
        const client_key: [u8; NUM_ELLIGATOR_SWIFT_BYTES] = hex!("61a5de62da81aec5967d511fec1f08f98e9c1108bffaaf304b5b31876bec2cbc2d20736f19f93b3f3fd7b9bbf7d1306da07d13218b90fae8c22276846848ad0c");
        const initiator_l: [u8; 32] = hex!("ab7e81f5d65d97c015f71bab4506dd93f6dfca7b182f30cd27896afbc4855c3a");
        const initiator_p: [u8; 32] = hex!("48d22cd6fb02fe202ddc668d2dcade20a9c5500566acb804d18806b5cac44595");
        const responder_l: [u8; 32] = hex!("42e672f539b95ec5950bb2d97b45a3cb9ac4b58244b05b35fb8ed1315aab8e6d");
        const responder_p: [u8; 32] = hex!("0c71faf552c2883beebfb82b557593a60caa0f38749bb393dd5bb656ed768a01");

        let (mut server, _, _) = get_mitm_fake_server_deterministic_insecurerng(seed);
        assert_eq!(server.key_to_send, server_key, "The generated secret key is different from the expected one");

        server.pass_peer_data(&client_key)
            .expect("Error on pass_peer_data");
        let HandshakeBIP324State::ReceivedKey(cipher, other_garbage_terminator) = server.state else {
            panic!("Wrong state after receiving key");
        };
        assert_eq!(cipher.inbound.length_cipher.key_bytes, initiator_l);
        assert_eq!(cipher.inbound.packet_cipher.key_bytes, initiator_p);
        assert_eq!(cipher.outbound.length_cipher.key_bytes, responder_l);
        assert_eq!(cipher.outbound.packet_cipher.key_bytes, responder_p);
    }

    // Tests that, when the fake server is ready to send the key, it can send it
    // byte by byte, corresponding to each byte sent by the real server.
    #[test]
    fn server_key_partially_relayed() {
        let (mut server, relay_in, _) = get_mitm_fake_server();

        // Send all the key bytes
        server.pass_peer_data(&[0x73; NUM_ELLIGATOR_SWIFT_BYTES])
            .expect("Error on pass_peer_data");
        assert!(matches!(
            server.state,
            HandshakeBIP324State::ReceivedKey(..)
        ));


        let buf = [0u8];
        let mut out_buf = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        // Send one byte at a time
        for i in 0..NUM_ELLIGATOR_SWIFT_BYTES {
            relay_in.borrow_mut().write_key(&buf).expect("Write to relay_in must to fail");
            let size = server.write_data(&mut out_buf[i..]).expect("Error on write_data");
            assert_eq!(size, 1, "Expected write_data to write one byte at step {i}");

            let size = server.write_data(&mut out_buf[i..]).expect("Error on write_data");
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
        relay_in.borrow_mut().write_key(&buf).expect("Write must not fail");

        let mut sent_key = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        let size = server.write_data(&mut sent_key).expect("Error on write_data");
        assert_eq!(size, NUM_ELLIGATOR_SWIFT_BYTES, "Fake server must send the entire key")
    }

    #[test]
    fn key_sent_partially_from_server_when_client_sent_key_partially() {
        let (mut server, relay_in, _) = get_mitm_fake_server();

        // Server sends something
        relay_in.borrow_mut().write_key(&[0u8; 2]).expect("Write must not fail");

        // Client sends something
        server.pass_peer_data(&[0x73; 3])
            .expect("Error on pass_peer_data");

        // Server sends something again
        relay_in.borrow_mut().write_key(&[0u8; 2]).expect("Write must not fail");

        // Client sends something again
        server.pass_peer_data(&[0x73; 4])
            .expect("Error on pass_peer_data");

        let mut sent_key = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        let size = server.write_data(&mut sent_key).expect("Error on write_data");
        assert_eq!(size, 4, "Fake server must send 4 byte keys")
    }

    #[test]
    fn server_correct_public_key() {
        const seed: u64 = 32890322278;
        const server_key: [u8; NUM_ELLIGATOR_SWIFT_BYTES] = hex!("6a34b0f8757abbd31934ce6375857b06000d1a4528274eaec46c6e11a243366dcb14d23c315b7305fb4bd7c11ddc515785061f2a9402c867f2550a7e8e5496ca");

        let (mut server, relay_in, _) = get_mitm_fake_server_deterministic_insecurerng(seed);
        assert_eq!(server.key_to_send, server_key, "The generated secret key is different from the expected one");

        // Real server sends the key
        let buf = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        relay_in.borrow_mut().write_key(&buf).expect("Write must not fail");

        let mut sent_key = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        let size = server.write_data(&mut sent_key).expect("Error on write_data");
        assert_eq!(size, NUM_ELLIGATOR_SWIFT_BYTES, "Fake server must send the entire key");
        assert_eq!(sent_key, server_key, "Incorrect server key");
    }

    #[test]
    fn real_server_sends_garbage_before_client_start_sending_key() {
        let (mut server, relay_in, _) = get_mitm_fake_server();

        // Real server sends the key
        let buf = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        relay_in.borrow_mut().write_key(&buf).expect("Write must not fail");

        // Real server sends some garbage
        let real_garbage = [3u8; 10];
        relay_in.borrow_mut().write_garbage(&real_garbage).expect("Write must not fail");

        // Fake server sends key
        let mut sent_key = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        let size = server.write_data(&mut sent_key).expect("Error on write_data");
        assert_eq!(size, NUM_ELLIGATOR_SWIFT_BYTES, "Fake server must send the entire key");

        // Fake server sends garbage
        let mut sent_garbage = [0u8; 128];
        let size = server.write_data(&mut sent_garbage).expect("Error on write_data");
        assert_eq!(sent_garbage[..size], real_garbage, "The fake server must preserve the garbage sent by the real server");
    }

    #[test]
    fn real_server_sends_garbage_before_client_sending_entire_key() {
        let (mut server, relay_in, _) = get_mitm_fake_server();

        // Client sends partial key
        server.pass_peer_data(&[0x73; NUM_ELLIGATOR_SWIFT_BYTES-1])
            .expect("Error on pass_peer_data");

        // Real server sends the key
        let buf = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        relay_in.borrow_mut().write_key(&buf).expect("Write must not fail");

        // Real server sends some garbage
        let real_garbage = [3u8; 10];
        relay_in.borrow_mut().write_garbage(&real_garbage).expect("Write must not fail");

        // Fake server sends key
        let mut sent_key = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        let size = server.write_data(&mut sent_key).expect("Error on write_data");
        assert_eq!(size, NUM_ELLIGATOR_SWIFT_BYTES, "Fake server must send the entire key");

        // Fake server sends garbage
        let mut sent_garbage = [0u8; 128];
        let size = server.write_data(&mut sent_garbage).expect("Error on write_data");
        assert_eq!(sent_garbage[..size], real_garbage, "The fake server must preserve the garbage sent by the real server");
    }
}
