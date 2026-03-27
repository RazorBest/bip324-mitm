pub mod cipher;
pub mod external;
mod fmt_utils;
pub mod protocol;
mod state_machine;

use std::cell::RefCell;
use std::cmp;
use std::collections::VecDeque;
use std::error::Error;
use std::io::{Read, Write};
use std::mem;
use std::rc::Rc;

use secp256k1::ellswift::ElligatorSwift;
use secp256k1::rand::{CryptoRng, RngCore};
use secp256k1::{PublicKey, Secp256k1, SecretKey};

use crate::cipher::{CipherSession, InboundCipher, LengthDecryptor, OutboundCipher};
use crate::external::chacha20_poly1305::ChaCha20Poly1305Stream;
use crate::protocol::{
    AADType, EcdhPoint, GarbageTerminatorType, MAINNET_MAGIC, MagicType, NUM_ELLIGATOR_SWIFT_BYTES,
    NUM_LENGTH_BYTES, NUM_SECRET_BYTES, NUM_TAG_BYTES, PartialPacket, ProtocolBuffer,
    REGTEST_MAGIC, Role, TESTNET_MAGIC, TagType, find_garbage,
};
use crate::state_machine::{
    BufReader, BufWriter, HasFinal, ProtocolReadParser, ProtocolStatus, ProtocolWriteParser,
    StreamReadParser, StreamWriteParser,
};

// Maximum packet size for automatic allocation.
// Bitcoin Core's MAX_PROTOCOL_MESSAGE_LENGTH is 4,000,000 bytes (~4 MiB).
// 14 extra bytes are for the BIP-324 header byte and 13 serialization header bytes (message type).
const MAX_PACKET_SIZE_FOR_ALLOCATION: usize = 4000014;

struct FakePeerRelay {
    key: ProtocolBuffer,
    garbage: ProtocolBuffer,
    terminator: ProtocolBuffer,
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
            key: ProtocolBuffer::new(),
            garbage: ProtocolBuffer::new(),
            terminator: ProtocolBuffer::new(),
            packets: vec![],
        }
    }
}

pub trait FakePeerRelayWriter {
    fn write_key(&mut self, data: &[u8]) -> std::io::Result<usize>;
    fn set_eof_key(&mut self);

    fn write_garbage(&mut self, data: &[u8]) -> std::io::Result<usize>;
    fn set_eof_garbage(&mut self);

    fn write_terminator(&mut self, data: &[u8]) -> std::io::Result<usize>;
    fn set_eof_terminator(&mut self);

    /// Writes the length section of a packet. BIP-324 decodes it as a 3 byte little-endian integer.
    fn write_length_bytes(&mut self, data: &[u8]);
    /// Writes the payload section of a packet
    fn write_data_bytes(&mut self, data: &[u8]);
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

    fn write_data_bytes(&mut self, data: &[u8]) {
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

pub trait FakePeerRelayReader {
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
    fn peek_length_bytes(&self) -> usize;
    fn read_data_bytes(&mut self, buf: &mut [u8]) -> usize;
    fn peek_data_bytes(&self) -> usize;
    fn read_tag_bytes(&mut self, buf: &mut [u8]) -> usize;
    fn peek_tag_bytes(&self) -> usize;
    fn read_aad(&mut self) -> Option<Vec<u8>>;
    fn peek_aad_bytes(&self) -> usize;
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

    fn peek_length_bytes(&self) -> usize {
        if self.packets.is_empty() {
            return 0;
        }

        self.packets[0].peek_length_bytes()
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

    fn peek_data_bytes(&self) -> usize {
        if self.packets.is_empty() {
            return 0;
        }

        self.packets[0].peek_data_bytes()
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

    fn peek_tag_bytes(&self) -> usize {
        if self.packets.is_empty() {
            return 0;
        }

        self.packets[0].peek_tag_bytes()
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

    fn peek_aad_bytes(&self) -> usize {
        if self.packets.is_empty() {
            return 0;
        }

        self.packets[0].peek_aad()
    }
}

pub enum RelayPeerState {
    SendingLength(usize, Vec<u8>),
    SendingPayload(usize, ChaCha20Poly1305Stream),
    SendingTag(Vec<u8>),
    Invalid,
}

impl RelayPeerState {
    fn new() -> Self {
        Self::SendingLength(NUM_LENGTH_BYTES, vec![])
    }

    fn take(&mut self) -> Self {
        mem::replace(self, Self::Invalid)
    }
}

impl HasFinal for RelayPeerState {
    fn is_final(&self) -> bool {
        false
    }
}

#[derive(PartialEq)]
pub enum HandshakeRelayPeerState {
    SendingKey,
    SendingGarbage,
    SendingGarbageTerminator,
    HandshakeDone,
    Invalid,
}

impl HandshakeRelayPeerState {
    fn new() -> Self {
        Self::SendingKey
    }

    fn take(&mut self) -> Self {
        mem::replace(self, Self::Invalid)
    }
}

impl HasFinal for HandshakeRelayPeerState {
    fn is_final(&self) -> bool {
        matches!(self, Self::HandshakeDone)
    }
}

#[derive(Debug)]
pub enum HandshakeBIP324State {
    ReceivingKey(EcdhPoint, usize),
    ReceivingGarbage(GarbageTerminatorType),
    HandshakeDone(AADType),
    Invalid,
}

impl HandshakeBIP324State {
    pub fn take(&mut self) -> Self {
        mem::replace(self, Self::Invalid)
    }
}

impl HasFinal for HandshakeBIP324State {
    fn is_final(&self) -> bool {
        matches!(self, Self::HandshakeDone(_))
    }
}

pub enum DataBIP324State {
    ReceivingPacketLen(LengthDecryptor),
    ReceivingPacketContent(ChaCha20Poly1305Stream),
    ReceivingPacketTag(TagType),
    Invalid,
}

impl DataBIP324State {
    fn take(&mut self) -> Self {
        mem::replace(self, Self::Invalid)
    }
}

impl HasFinal for DataBIP324State {
    fn is_final(&self) -> bool {
        false
    }
}

pub enum ReaderLegState {
    Handshake(MitmHandshakeImpersonatorLegReader),
    Data(MitmImpersonatorLegReader),
    Invalid,
}

impl ReaderLegState {
    fn take(&mut self) -> Self {
        mem::replace(self, Self::Invalid)
    }
}

impl HasFinal for ReaderLegState {
    fn is_final(&self) -> bool {
        false
    }
}

pub enum WriterLegState {
    Handshake(MitmHandshakeImpersonatorLegWriter),
    Data(MitmImpersonatorLegWriter),
    Invalid,
}

impl WriterLegState {
    fn take(&mut self) -> Self {
        mem::replace(self, Self::Invalid)
    }
}

impl HasFinal for WriterLegState {
    fn is_final(&self) -> bool {
        false
    }
}

pub struct MitmHandshakeImpersonatorLeg {
    reader_leg_state: ReaderLegState,
    writer_leg_state: WriterLegState,
}

impl MitmHandshakeImpersonatorLeg {
    pub fn new(
        role: Role,
        magic: MagicType,
        relay_in: Rc<RefCell<dyn FakePeerRelayReader>>,
        relay_out: Rc<RefCell<dyn FakePeerRelayWriter>>,
        secret_key: EcdhPoint,
    ) -> Self {
        // We know the fake server's public key, so we can already prepare it for sending
        let mut key_to_send_vec = vec![];
        key_to_send_vec.extend_from_slice(&secret_key.elligator_swift.to_array());

        let key_to_send = Rc::new(RefCell::new(key_to_send_vec));
        let cipher = Rc::new(RefCell::new(None));
        let garbage_terminator_to_send = Rc::new(RefCell::new(vec![]));

        let reader_leg = MitmHandshakeImpersonatorLegReader::new(
            role,
            magic,
            relay_out,
            secret_key,
            Rc::clone(&key_to_send),
            Rc::clone(&cipher),
            Rc::clone(&garbage_terminator_to_send),
        );
        let writer_leg = MitmHandshakeImpersonatorLegWriter::new(
            relay_in,
            key_to_send,
            cipher,
            garbage_terminator_to_send,
        );

        Self {
            reader_leg_state: ReaderLegState::Handshake(reader_leg),
            writer_leg_state: WriterLegState::Handshake(writer_leg),
        }
    }

    pub fn new_fake_server(
        magic: MagicType,
        relay_in: Rc<RefCell<dyn FakePeerRelayReader>>,
        relay_out: Rc<RefCell<dyn FakePeerRelayWriter>>,
        secret_key: EcdhPoint,
    ) -> Self {
        Self::new(Role::Responder, magic, relay_in, relay_out, secret_key)
    }

    pub fn new_fake_client(
        magic: MagicType,
        relay_in: Rc<RefCell<dyn FakePeerRelayReader>>,
        relay_out: Rc<RefCell<dyn FakePeerRelayWriter>>,
        secret_key: EcdhPoint,
    ) -> Self {
        Self::new(Role::Initiator, magic, relay_in, relay_out, secret_key)
    }

    pub fn set_secret(&mut self, secret: [u8; NUM_SECRET_BYTES]) -> Result<(), String> {
        match &mut self.reader_leg_state {
            ReaderLegState::Handshake(reader_leg) => reader_leg.set_secret(secret),
            _ => Err("Invalid state for set_secret".to_string()),
        }
    }
}

impl ProtocolReadParser for MitmHandshakeImpersonatorLeg {
    type State = ReaderLegState;
    type Error = ();

    fn transition(
        &mut self,
        state: Self::State,
        data: &mut dyn BufReader,
    ) -> (Self::State, Result<ProtocolStatus, Self::Error>) {
        use ReaderLegState::*;

        match state {
            Handshake(mut reader_leg) => {
                // TODO: replace unwrap
                reader_leg.consume(data).unwrap();

                if reader_leg.is_final() {
                    let new_reader_leg = reader_leg.next_phase().unwrap();
                    (Data(new_reader_leg), Ok(ProtocolStatus::End))
                } else {
                    (Handshake(reader_leg), Ok(ProtocolStatus::End))
                }
            }
            Data(mut reader_leg) => {
                // TODO: replace unwrap
                reader_leg.consume(data).unwrap();

                (Data(reader_leg), Ok(ProtocolStatus::End))
            }
            Invalid => {
                panic!("Invalid state")
            }
        }
    }

    fn take_state(&mut self) -> Self::State {
        self.reader_leg_state.take()
    }

    fn set_state(&mut self, state: Self::State) {
        self.reader_leg_state = state;
    }
}

impl ProtocolWriteParser for MitmHandshakeImpersonatorLeg {
    type State = WriterLegState;
    type Error = ();

    fn transition(
        &mut self,
        state: Self::State,
        data: &mut dyn BufWriter,
    ) -> (Self::State, Result<ProtocolStatus, Self::Error>) {
        use WriterLegState::*;

        match state {
            Handshake(mut writer_leg) => {
                // TODO: replace unwrap
                writer_leg.produce(data).unwrap();

                if writer_leg.is_final() {
                    let new_writer_leg = writer_leg.next_phase().unwrap();
                    (Data(new_writer_leg), Ok(ProtocolStatus::End))
                } else {
                    (Handshake(writer_leg), Ok(ProtocolStatus::End))
                }
            }
            Data(mut writer_leg) => {
                // TODO: replace unwrap
                writer_leg.produce(data).unwrap();

                (Data(writer_leg), Ok(ProtocolStatus::End))
            }
            Invalid => {
                panic!("Invalid state")
            }
        }
    }

    fn take_state(&mut self) -> Self::State {
        self.writer_leg_state.take()
    }

    fn set_state(&mut self, state: Self::State) {
        self.writer_leg_state = state;
    }
}

pub struct MitmHandshakeImpersonatorLegReader {
    role: Role,
    magic: MagicType,
    state: HandshakeBIP324State,

    relay_out: Rc<RefCell<dyn FakePeerRelayWriter>>,

    other_key: Option<[u8; NUM_ELLIGATOR_SWIFT_BYTES]>,

    read_buffer: Vec<u8>,

    key_to_send: Rc<RefCell<Vec<u8>>>,
    cipher: Rc<RefCell<Option<CipherSession>>>,
    garbage_terminator_to_send: Rc<RefCell<Vec<u8>>>,
}

impl MitmHandshakeImpersonatorLegReader {
    pub fn new(
        role: Role,
        magic: MagicType,
        relay_out: Rc<RefCell<dyn FakePeerRelayWriter>>,
        secret_key: EcdhPoint,
        key_to_send: Rc<RefCell<Vec<u8>>>,
        cipher: Rc<RefCell<Option<CipherSession>>>,
        garbage_terminator_to_send: Rc<RefCell<Vec<u8>>>,
    ) -> Self {
        Self {
            role,
            magic,
            state: HandshakeBIP324State::ReceivingKey(secret_key, NUM_ELLIGATOR_SWIFT_BYTES),
            key_to_send,
            garbage_terminator_to_send,
            relay_out,
            other_key: None,
            read_buffer: vec![],
            cipher,
        }
    }

    fn on_share_received(&mut self, point: EcdhPoint) -> Result<GarbageTerminatorType, String> {
        let cipher =
            CipherSession::new_from_shares(self.magic, self.role, point, &self.other_key.unwrap())?;
        let inbound_garbage_terminator = cipher.inbound_garbage_terminator;
        let outbound_garbage_terminator = cipher.outbound_garbage_terminator;

        self.cipher.replace(Some(cipher));
        self.garbage_terminator_to_send
            .replace(outbound_garbage_terminator.to_vec());

        Ok(inbound_garbage_terminator)
    }

    pub fn set_secret(&mut self, secret: [u8; NUM_SECRET_BYTES]) -> Result<(), String> {
        use HandshakeBIP324State::*;

        if self.key_to_send.borrow().len() < NUM_ELLIGATOR_SWIFT_BYTES || self.state.is_final() {
            return Err(
                "Can't change secret. Public key has already started to be sent".to_string(),
            );
        }

        let secret_key = key_from_secret_bytes(secret)
            .map_err(|_| "Can't generate EC scalar from secret key bytes")?;
        let mut key_to_send = vec![];
        key_to_send.extend_from_slice(&secret_key.elligator_swift.to_array());

        self.key_to_send.replace(key_to_send);
        match self.state.take() {
            ReceivingKey(_old_point, remaining) => {
                self.state = ReceivingKey(secret_key, remaining);
            }
            ReceivingGarbage(_old_other_garbage_terminator) => {
                let inbound_garbage_terminator = self.on_share_received(secret_key)?;

                self.state = ReceivingGarbage(inbound_garbage_terminator);
            }
            state => {
                panic!("Can't change secret for state: {state:?}")
            }
        }

        Ok(())
    }

    pub fn is_final(&self) -> bool {
        self.state.is_final()
    }

    pub fn next_phase(self) -> Option<MitmImpersonatorLegReader> {
        let HandshakeBIP324State::HandshakeDone(aad) = self.state else {
            return None;
        };

        // TODO: replace unwrap
        let inbound_cipher = self
            .cipher
            .borrow_mut()
            .as_mut()
            .unwrap()
            .consume_inbound()
            .unwrap();

        Some(MitmImpersonatorLegReader::new(
            aad,
            self.relay_out,
            inbound_cipher,
        ))
    }
}

impl ProtocolReadParser for MitmHandshakeImpersonatorLegReader {
    type State = HandshakeBIP324State;
    type Error = ();

    fn transition(
        &mut self,
        state: Self::State,
        data: &mut dyn BufReader,
    ) -> (Self::State, Result<ProtocolStatus, Self::Error>) {
        use HandshakeBIP324State::*;

        match state {
            ReceivingKey(point, mut remaining) => {
                let mut key_buf = vec![0u8; remaining];
                // TODO: replace unwrap
                let size = data.read(&mut key_buf).unwrap();
                remaining -= size;

                self.read_buffer.extend_from_slice(&key_buf[..size]);
                // TODO: replace unwrap
                self.relay_out
                    .borrow_mut()
                    .write_key(&key_buf[..size])
                    .map_err(|_| "Error writing key to relay")
                    .unwrap();

                if remaining == 0 {
                    self.relay_out.borrow_mut().set_eof_key();

                    let mut other_key = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
                    other_key.copy_from_slice(&std::mem::take(&mut self.read_buffer));
                    self.other_key = Some(other_key);

                    // TODO: remove unwrap
                    let inbound_garbage_terminator = self.on_share_received(point).unwrap();

                    (
                        ReceivingGarbage(inbound_garbage_terminator),
                        Ok(ProtocolStatus::Continue),
                    )
                } else {
                    (ReceivingKey(point, remaining), Ok(ProtocolStatus::End))
                }
            }
            // This uses a peek-then-read strategy
            state @ ReceivingGarbage(other_garbage_terminator) => {
                // The length under which we don't know if an array of data is a garbage terminator
                let insurance_len = other_garbage_terminator.len() - 1;
                let prevlen = self.read_buffer.len();
                let mut relay_out = self.relay_out.borrow_mut();

                // When the read buffer has data that can still be part of the garbage terminator
                let mut found = {
                    let data_buf = data.buf_ref();
                    let mut to_consume = cmp::min(data_buf.len(), insurance_len);

                    self.read_buffer.extend_from_slice(&data_buf[..to_consume]);

                    // If terminator found, actually consume the buffer
                    if let Some((_garbage, rest)) =
                        find_garbage(&self.read_buffer, other_garbage_terminator)
                    {
                        to_consume -= rest.len();
                        // TODO: replace unwrap
                        let _ = data.read(&mut vec![0u8; to_consume]).unwrap();

                        // Remove the final bytes that are not part of the garbage
                        self.read_buffer
                            .resize(self.read_buffer.len() - rest.len(), 0u8);

                        true
                    // If terminator not found, restore the read buffer
                    } else {
                        self.read_buffer
                            .resize(self.read_buffer.len() - to_consume, 0u8);

                        false
                    }
                };

                // If still not found, look for the garbage terminator in the new data
                found = if !found {
                    let data_buf = data.buf_ref();
                    let res = find_garbage(data_buf, other_garbage_terminator);

                    let (to_consume, found) = if let Some((garbage, _rest)) = res {
                        (garbage.len(), true)
                    } else {
                        (data_buf.len(), false)
                    };

                    let mut buf = vec![0u8; to_consume];
                    data.read_exact(&mut buf).unwrap();
                    self.read_buffer.extend(buf);

                    found
                } else {
                    found
                };

                if found {
                    // Here, we expect self.read_buffer to contain the garbage, including the
                    // terminator

                    let currlen = self.read_buffer.len();
                    let garbage_len = currlen - other_garbage_terminator.len();
                    let lhs = cmp::max(prevlen, insurance_len) - insurance_len;
                    let new_range = lhs..garbage_len;
                    relay_out
                        .write_garbage(&self.read_buffer[new_range])
                        // TODO: replace unwrap
                        .map_err(|_| "Error writing garbage terminator to relay")
                        .unwrap();
                    relay_out.set_eof_garbage();

                    relay_out
                        .write_terminator(&self.read_buffer[garbage_len..])
                        // TODO: replace unwrap
                        .map_err(|_| "Error writing garbage terminator to relay")
                        .unwrap();
                    relay_out.set_eof_terminator();

                    let aad: Vec<_> = self.read_buffer.splice(..garbage_len, []).collect();

                    (HandshakeDone(aad), Ok(ProtocolStatus::End))
                } else {
                    let currlen = self.read_buffer.len();
                    let lhs = cmp::max(prevlen, insurance_len) - insurance_len;
                    let rhs = cmp::max(currlen, insurance_len) - insurance_len;
                    // The range of data that wasn't relayed and we're sure it's garbage, and is not part of the terminator
                    let new_range = lhs..rhs;
                    relay_out
                        .write_garbage(&self.read_buffer[new_range])
                        // TODO: replace unwrap
                        .map_err(|_| "Error writing garbage terminator to relay")
                        .unwrap();

                    (state, Ok(ProtocolStatus::End))
                }
            }
            state @ HandshakeDone(_) => (state, Ok(ProtocolStatus::End)),
            Invalid => {
                panic!("Invalid protocol state");
            }
        }
    }

    fn take_state(&mut self) -> Self::State {
        self.state.take()
    }

    fn set_state(&mut self, state: Self::State) {
        self.state = state;
    }
}

pub struct MitmHandshakeImpersonatorLegWriter {
    state: HandshakeRelayPeerState,

    relay_in: Rc<RefCell<dyn FakePeerRelayReader>>,

    key_to_send: Rc<RefCell<Vec<u8>>>,
    cipher: Rc<RefCell<Option<CipherSession>>>,
    garbage_terminator_to_send: Rc<RefCell<Vec<u8>>>,
}

impl MitmHandshakeImpersonatorLegWriter {
    pub fn new(
        relay_in: Rc<RefCell<dyn FakePeerRelayReader>>,
        key_to_send: Rc<RefCell<Vec<u8>>>,
        cipher: Rc<RefCell<Option<CipherSession>>>,
        garbage_terminator_to_send: Rc<RefCell<Vec<u8>>>,
    ) -> Self {
        Self {
            state: HandshakeRelayPeerState::new(),
            relay_in,
            key_to_send,
            cipher,
            garbage_terminator_to_send,
        }
    }

    pub fn is_final(&self) -> bool {
        self.state.is_final()
    }

    pub fn next_phase(self) -> Option<MitmImpersonatorLegWriter> {
        if !self.is_final() {
            return None;
        };

        // TODO: replace unwrap
        let outbound_cipher = self
            .cipher
            .borrow_mut()
            .as_mut()
            .unwrap()
            .consume_outbound()
            .unwrap();

        Some(MitmImpersonatorLegWriter::new(
            self.relay_in,
            outbound_cipher,
        ))
    }
}

impl ProtocolWriteParser for MitmHandshakeImpersonatorLegWriter {
    type State = HandshakeRelayPeerState;
    type Error = ();

    fn transition(
        &mut self,
        state: Self::State,
        data: &mut dyn BufWriter,
    ) -> (Self::State, Result<ProtocolStatus, Self::Error>) {
        use HandshakeRelayPeerState::*;

        match state {
            state @ SendingKey => {
                let mut key_to_send = self.key_to_send.borrow_mut();

                let limit = cmp::min(data.remaining(), key_to_send.len());
                let mut _key_buf = vec![0u8; limit];
                // TODO: replace unwrap
                let size = self.relay_in.borrow_mut().read_key(&mut _key_buf).unwrap();

                data.write_all(&key_to_send[..size]).unwrap();
                key_to_send.splice(..size, []);

                if key_to_send.is_empty() {
                    (SendingGarbage, Ok(ProtocolStatus::Continue))
                } else {
                    (state, Ok(ProtocolStatus::End))
                }
            }
            state @ SendingGarbage => {
                let limit = data.remaining();
                let mut buf = vec![0u8; limit];
                // TODO: replace unwrap
                let size = self.relay_in.borrow_mut().read_garbage(&mut buf).unwrap();

                data.write_all(&buf[..size]).unwrap();

                if self.relay_in.borrow().peek_len_garbage() == 0
                    && self.relay_in.borrow().is_eof_garbage()
                {
                    (SendingGarbageTerminator, Ok(ProtocolStatus::Continue))
                } else {
                    (state, Ok(ProtocolStatus::End))
                }
            }
            state @ SendingGarbageTerminator => {
                let mut garbage_terminator_to_send = self.garbage_terminator_to_send.borrow_mut();
                let limit = cmp::min(data.remaining(), garbage_terminator_to_send.len());
                let mut _terminator_buf = vec![0u8; limit];
                let size = self
                    .relay_in
                    .borrow_mut()
                    // TODO: replace unwrap
                    .read_terminator(&mut _terminator_buf)
                    .unwrap();

                // The terminator is replaced by ours. We're not using the original one
                data.write_all(&garbage_terminator_to_send[..size]).unwrap();
                garbage_terminator_to_send.splice(..size, []);

                if garbage_terminator_to_send.is_empty() {
                    (HandshakeDone, Ok(ProtocolStatus::End))
                } else {
                    (state, Ok(ProtocolStatus::End))
                }
            }
            state @ HandshakeDone => (state, Ok(ProtocolStatus::End)),
            Invalid => {
                panic!("Invalid server state")
            }
        }
    }

    fn take_state(&mut self) -> Self::State {
        self.state.take()
    }

    fn set_state(&mut self, state: Self::State) {
        self.state = state;
    }
}

pub struct MitmImpersonatorLegReader {
    state: DataBIP324State,
    remaining: usize,
    aad: Vec<u8>,

    inbound_cipher: InboundCipher,

    relay_out: Rc<RefCell<dyn FakePeerRelayWriter>>,
}

impl MitmImpersonatorLegReader {
    pub fn new(
        aad: AADType,
        relay_out: Rc<RefCell<dyn FakePeerRelayWriter>>,
        mut inbound_cipher: InboundCipher,
    ) -> Self {
        let length_decryptor = inbound_cipher
            .get_new_length_decryptor()
            .expect("The inbound cipher can't create a length decryptor");
        relay_out.borrow_mut().set_aad(&aad);
        Self {
            state: DataBIP324State::ReceivingPacketLen(length_decryptor),
            remaining: NUM_LENGTH_BYTES,
            aad,
            inbound_cipher,
            relay_out,
        }
    }

    fn consume_aad(&mut self) -> Vec<u8> {
        self.aad.drain(..).collect()
    }

    pub fn set_aad(&mut self, aad: Vec<u8>) {
        self.aad = aad;
    }
}

impl ProtocolReadParser for MitmImpersonatorLegReader {
    type State = DataBIP324State;
    type Error = ();

    fn transition(
        &mut self,
        state: Self::State,
        data: &mut dyn BufReader,
    ) -> (Self::State, Result<ProtocolStatus, Self::Error>) {
        use DataBIP324State::*;

        let data_buf = data.buf_ref();
        let to_consume = cmp::min(self.remaining, data_buf.len());
        let mut data_to_process = data_buf[..to_consume].to_vec();
        self.remaining -= to_consume;

        let (next_state, res) = match state {
            ReceivingPacketLen(mut length_decryptor) => {
                // TODO: replace unwrap
                length_decryptor
                    .decrypt_len_part_inplace(&mut data_to_process)
                    .unwrap();

                self.relay_out
                    .borrow_mut()
                    .write_length_bytes(&data_to_process);

                match length_decryptor.try_end() {
                    Ok((length_cipher, packet_len)) => {
                        // TODO: replace unwrap
                        self.inbound_cipher
                            .reown_length_cipher(length_cipher)
                            .unwrap();

                        if packet_len > MAX_PACKET_SIZE_FOR_ALLOCATION {
                            // TODO: replace panic
                            panic!("Packet too big");
                        }

                        let stream_cipher = self
                            .inbound_cipher
                            .packet_cipher
                            .start_one_payload_stream_encryption();

                        // Add 1 for the header byte, which is not included in the length
                        self.remaining = packet_len + 1;
                        (
                            ReceivingPacketContent(stream_cipher),
                            Ok(ProtocolStatus::Continue),
                        )
                    }
                    // This is just the initial length_decryptor
                    // We have this weird pattern because we want the length decryptor to be
                    // consumed conditionally (only when when length_decryptor received all the
                    // necessary bytes)
                    Err(new_length_decryptor) => (
                        ReceivingPacketLen(new_length_decryptor),
                        Ok(ProtocolStatus::End),
                    ),
                }
            }
            ReceivingPacketContent(mut stream_cipher) => {
                stream_cipher.decrypt_and_store_chunk(&mut data_to_process);
                self.relay_out
                    .borrow_mut()
                    .write_data_bytes(&data_to_process);

                if self.remaining == 0 {
                    let aad = self.consume_aad();
                    let tag = stream_cipher.get_tag(Some(&aad[..]));

                    self.remaining = NUM_TAG_BYTES;
                    (
                        ReceivingPacketTag(tag.to_vec()),
                        Ok(ProtocolStatus::Continue),
                    )
                } else {
                    (
                        ReceivingPacketContent(stream_cipher),
                        Ok(ProtocolStatus::End),
                    )
                }
            }
            ReceivingPacketTag(mut expected_tag) => {
                if data_to_process != expected_tag[..data_to_process.len()] {
                    // TODO: replace panic
                    panic!("AEAD tag check fail");
                }
                expected_tag.drain(..data_to_process.len());

                self.relay_out
                    .borrow_mut()
                    .write_tag_bytes(&data_to_process);
                if self.remaining == 0 {
                    let length_decryptor = self
                        .inbound_cipher
                        .get_new_length_decryptor()
                        .expect("The inbound cipher can't create a length decryptor");

                    self.remaining = NUM_LENGTH_BYTES;
                    (
                        ReceivingPacketLen(length_decryptor),
                        Ok(ProtocolStatus::Continue),
                    )
                } else {
                    (ReceivingPacketTag(expected_tag), Ok(ProtocolStatus::End))
                }
            }
            Invalid => {
                panic!("Invalid protocol state");
            }
        };

        if res.is_ok() {
            let _ = data.read(&mut vec![0u8; to_consume]).unwrap();
        } else {
            // TODO: see if you can represent this through typing
            self.remaining += to_consume;
        }

        (next_state, res)
    }

    fn take_state(&mut self) -> Self::State {
        self.state.take()
    }

    fn set_state(&mut self, state: Self::State) {
        self.state = state;
    }
}

pub struct MitmImpersonatorLegWriter {
    state: RelayPeerState,

    outbound_cipher: OutboundCipher,
    relay_in: Rc<RefCell<dyn FakePeerRelayReader>>,
}

impl MitmImpersonatorLegWriter {
    pub fn new(
        relay_in: Rc<RefCell<dyn FakePeerRelayReader>>,
        outbound_cipher: OutboundCipher,
    ) -> Self {
        Self {
            state: RelayPeerState::new(),
            outbound_cipher,
            relay_in,
        }
    }
}

impl ProtocolWriteParser for MitmImpersonatorLegWriter {
    type State = RelayPeerState;
    type Error = ();

    fn transition(
        &mut self,
        state: Self::State,
        data: &mut dyn BufWriter,
    ) -> (Self::State, Result<ProtocolStatus, Self::Error>) {
        use RelayPeerState::*;

        let mut relay_in = self.relay_in.borrow_mut();

        match state {
            SendingLength(remaining, written) => {
                // TODO: replace unwrap
                let buf = data.prewrite(relay_in.peek_length_bytes()).unwrap();

                let size = relay_in.read_length_bytes(buf);
                if size > remaining {
                    // TODO: replace panic
                    panic!("Received too many length bytes from the input relay");
                }

                // Append the written data before encrypting it
                let new_written = [&written[..], &buf[..size]].concat();

                self.outbound_cipher
                    .encrypt_len_part_inplace(&mut buf[..size]);

                if size == remaining {
                    let length_bytes: [u8; 8] =
                        [new_written, vec![0u8; 5]].concat().try_into().unwrap();
                    // Add 1 for the header, which is not included in the length
                    let payload_len = 1 + usize::from_le_bytes(length_bytes);
                    let stream_cipher = self
                        .outbound_cipher
                        .packet_cipher
                        .start_one_payload_stream_encryption();

                    (
                        SendingPayload(payload_len, stream_cipher),
                        Ok(ProtocolStatus::Continue),
                    )
                } else {
                    let new_remaining = remaining - size;
                    (
                        SendingLength(new_remaining, new_written),
                        Ok(ProtocolStatus::End),
                    )
                }
            }
            SendingPayload(remaining, mut stream_cipher) => {
                // TODO: replace unwrap
                let buf = data.prewrite(relay_in.peek_data_bytes()).unwrap();

                let size = relay_in.read_data_bytes(buf);
                // TODO: replace panic
                if size > remaining {
                    panic!("Received too many data bytes from the input relay");
                }

                stream_cipher.encrypt_and_store_chunk(&mut buf[..size]);

                if size == remaining {
                    let aad = relay_in.read_aad().unwrap_or(vec![]);
                    let tag = stream_cipher.get_tag(Some(&aad));
                    self.outbound_cipher.packet_cipher.end_current_stream(&aad);
                    (SendingTag(tag.to_vec()), Ok(ProtocolStatus::Continue))
                } else {
                    (
                        SendingPayload(remaining - size, stream_cipher),
                        Ok(ProtocolStatus::End),
                    )
                }
            }
            SendingTag(mut tag) => {
                // TODO: replace unwrap
                let buf = data.prewrite(relay_in.peek_tag_bytes()).unwrap();

                let size = relay_in.read_tag_bytes(buf);
                if size > tag.len() {
                    // TODO: replace panic
                    panic!("Received too many tag bytes from the input relay");
                }

                // Overwrite with our own tag
                buf[..size].copy_from_slice(&tag.drain(0..size).collect::<Vec<_>>());

                if tag.is_empty() {
                    (
                        SendingLength(NUM_LENGTH_BYTES, vec![]),
                        Ok(ProtocolStatus::Continue),
                    )
                } else {
                    (SendingTag(tag), Ok(ProtocolStatus::End))
                }
            }
            Invalid => {
                panic!("Invalid peer state")
            }
        }
    }

    fn take_state(&mut self) -> Self::State {
        self.state.take()
    }

    fn set_state(&mut self, state: Self::State) {
        self.state = state;
    }
}

pub fn key_from_rng<Rng: RngCore + CryptoRng>(rng: &mut Rng) -> Result<EcdhPoint, Box<dyn Error>> {
    let mut secret_key_buffer = [0u8; 32];
    RngCore::fill_bytes(rng, &mut secret_key_buffer);
    debug_assert_ne!([0u8; NUM_SECRET_BYTES], secret_key_buffer);

    key_from_secret_bytes(secret_key_buffer)
}

pub fn key_from_secret_bytes(
    secret_key_buffer: [u8; NUM_SECRET_BYTES],
) -> Result<EcdhPoint, Box<dyn Error>> {
    let curve = Secp256k1::signing_only();
    let sk = SecretKey::from_slice(&secret_key_buffer)?;
    let pk = PublicKey::from_secret_key(&curve, &sk);
    let es = ElligatorSwift::from_pubkey(pk);

    Ok(EcdhPoint {
        secret_key: sk,
        elligator_swift: es,
    })
}

pub struct MitmBridge {
    pub client_leg: MitmHandshakeImpersonatorLeg,
    pub server_leg: MitmHandshakeImpersonatorLeg,
}

impl MitmBridge {
    pub fn new_from_secrets(
        magic: MagicType,
        client_secret_key: [u8; NUM_SECRET_BYTES],
        server_secret_key: [u8; NUM_SECRET_BYTES],
    ) -> Result<Self, String> {
        let relay_to_fake_server = Rc::new(RefCell::new(FakePeerRelay::new()));
        let relay_to_fake_client = Rc::new(RefCell::new(FakePeerRelay::new()));
        let client_leg = MitmHandshakeImpersonatorLeg::new_fake_client(
            magic,
            relay_to_fake_client.clone(),
            relay_to_fake_server.clone(),
            key_from_secret_bytes(client_secret_key)
                .map_err(|_| "Can't generate client secret_key")?,
        );
        let server_leg = MitmHandshakeImpersonatorLeg::new_fake_server(
            magic,
            relay_to_fake_server.clone(),
            relay_to_fake_client.clone(),
            key_from_secret_bytes(server_secret_key)
                .map_err(|_| "Can't generate server secret_key")?,
        );
        Ok(Self {
            client_leg,
            server_leg,
        })
    }

    pub fn new_from_ecdh_points(
        magic: MagicType,
        client_secret_key: EcdhPoint,
        server_secret_key: EcdhPoint,
    ) -> Self {
        let relay_to_fake_server = Rc::new(RefCell::new(FakePeerRelay::new()));
        let relay_to_fake_client = Rc::new(RefCell::new(FakePeerRelay::new()));
        let client_leg = MitmHandshakeImpersonatorLeg::new_fake_client(
            magic,
            relay_to_fake_client.clone(),
            relay_to_fake_server.clone(),
            client_secret_key,
        );
        let server_leg = MitmHandshakeImpersonatorLeg::new_fake_server(
            magic,
            relay_to_fake_server.clone(),
            relay_to_fake_client.clone(),
            server_secret_key,
        );
        Self {
            client_leg,
            server_leg,
        }
    }

    pub fn new<Rng: RngCore + CryptoRng>(magic: MagicType, rng: &mut Rng) -> Result<Self, String> {
        let mut client_secret_key = [0u8; 32];
        RngCore::fill_bytes(rng, &mut client_secret_key);
        debug_assert_ne!([0u8; NUM_SECRET_BYTES], client_secret_key);
        let mut server_secret_key = [0u8; 32];
        RngCore::fill_bytes(rng, &mut server_secret_key);
        debug_assert_ne!([0u8; NUM_SECRET_BYTES], server_secret_key);

        Self::new_from_secrets(magic, client_secret_key, server_secret_key)
    }

    pub fn set_server_secret(&mut self, secret: [u8; NUM_SECRET_BYTES]) -> Result<(), String> {
        self.server_leg.set_secret(secret)
    }

    pub fn set_client_secret(&mut self, secret: [u8; NUM_SECRET_BYTES]) -> Result<(), String> {
        self.client_leg.set_secret(secret)
    }

    pub fn client_write(&mut self, mut data: &[u8]) -> Result<(), String> {
        self.server_leg
            .consume(&mut data)
            .map_err(|_| "Server leg error".to_string())
    }

    pub fn server_write(&mut self, mut data: &[u8]) -> Result<(), String> {
        self.client_leg
            .consume(&mut data)
            .map_err(|_| "Client leg error".to_string())
    }

    pub fn client_read(&mut self, mut buf: &mut [u8]) -> Result<usize, Box<dyn Error>> {
        let initial_buf_len = buf.len();
        let res = self.server_leg.produce(&mut buf);
        let written = initial_buf_len - buf.len();

        Ok(res
            .map(|_| written)
            .map_err(|_| "Server leg error".to_string())?)
    }

    pub fn server_read(&mut self, mut buf: &mut [u8]) -> Result<usize, Box<dyn Error>> {
        let initial_buf_len = buf.len();
        let res = self.client_leg.produce(&mut buf);
        let written = initial_buf_len - buf.len();

        Ok(res
            .map(|_| written)
            .map_err(|_| "Client leg error".to_string())?)
    }
}

pub struct UserKeyInfo {
    pub secret: [u8; NUM_SECRET_BYTES],
    pub pubkey_ellswift: Option<[u8; NUM_ELLIGATOR_SWIFT_BYTES]>,
}

impl UserKeyInfo {
    pub fn new(
        secret: [u8; NUM_SECRET_BYTES],
        pubkey_ellswift: Option<[u8; NUM_ELLIGATOR_SWIFT_BYTES]>,
    ) -> Self {
        Self {
            secret,
            pubkey_ellswift,
        }
    }

    pub fn try_into_echd_point(self) -> Result<EcdhPoint, Self> {
        let Ok(sk) = SecretKey::from_slice(&self.secret) else {
            return Err(self);
        };
        let curve = Secp256k1::signing_only();
        let pk = PublicKey::from_secret_key(&curve, &sk);

        // Get the pubkey from the given Elligator Swift encoded key. Otherwise, generate one
        // deterministically
        let elligator_swift = if let Some(ellswift_bytes) = self.pubkey_ellswift {
            let elg_key = ElligatorSwift::from_array(ellswift_bytes);

            let elg_pk = PublicKey::from_ellswift(elg_key);
            if elg_pk != pk && elg_pk != pk.negate(&Secp256k1::verification_only()) {
                return Err(self);
            }

            elg_key
        } else {
            ElligatorSwift::from_pubkey(pk)
        };

        Ok(EcdhPoint {
            secret_key: sk,
            elligator_swift,
        })
    }
}

pub struct MitmBIP324 {
    pub bridge: MitmBridge,
}

impl MitmBIP324 {
    pub fn new<Rng: RngCore + CryptoRng>(rng: &mut Rng) -> Self {
        Self::new_from_magic(MAINNET_MAGIC, rng)
    }

    pub fn new_testnet<Rng: RngCore + CryptoRng>(rng: &mut Rng) -> Self {
        Self::new_from_magic(TESTNET_MAGIC, rng)
    }

    pub fn new_regtest<Rng: RngCore + CryptoRng>(rng: &mut Rng) -> Self {
        Self::new_from_magic(REGTEST_MAGIC, rng)
    }

    pub fn new_from_magic<Rng: RngCore + CryptoRng>(magic: MagicType, rng: &mut Rng) -> Self {
        let bridge = MitmBridge::new(magic, rng).expect("MitmHandshakeBridge creation failed unexpectedly. The chance of generating an invalid key is negligible");
        Self { bridge }
    }

    pub fn new_from_secrets(
        client_secret_key: [u8; NUM_SECRET_BYTES],
        server_secret_key: [u8; NUM_SECRET_BYTES],
    ) -> Result<Self, String> {
        Self::new_from_magic_and_secrets(MAINNET_MAGIC, client_secret_key, server_secret_key)
    }

    pub fn new_testnet_from_secrets(
        client_secret_key: [u8; NUM_SECRET_BYTES],
        server_secret_key: [u8; NUM_SECRET_BYTES],
    ) -> Result<Self, String> {
        Self::new_from_magic_and_secrets(TESTNET_MAGIC, client_secret_key, server_secret_key)
    }

    pub fn new_regtest_from_secrets(
        client_secret_key: [u8; NUM_SECRET_BYTES],
        server_secret_key: [u8; NUM_SECRET_BYTES],
    ) -> Result<Self, String> {
        Self::new_from_magic_and_secrets(REGTEST_MAGIC, client_secret_key, server_secret_key)
    }

    pub fn new_from_magic_and_secrets(
        magic: MagicType,
        client_secret_key: [u8; NUM_SECRET_BYTES],
        server_secret_key: [u8; NUM_SECRET_BYTES],
    ) -> Result<Self, String> {
        let bridge = MitmBridge::new_from_secrets(magic, client_secret_key, server_secret_key)?;
        Ok(Self { bridge })
    }

    pub fn new_from_key_info(
        client_key: UserKeyInfo,
        server_key: UserKeyInfo,
    ) -> Result<Self, String> {
        Self::new_from_magic_and_key_info(MAINNET_MAGIC, client_key, server_key)
    }

    pub fn new_testnet_from_key_info(
        client_key: UserKeyInfo,
        server_key: UserKeyInfo,
    ) -> Result<Self, String> {
        Self::new_from_magic_and_key_info(TESTNET_MAGIC, client_key, server_key)
    }

    pub fn new_regtest_from_key_info(
        client_key: UserKeyInfo,
        server_key: UserKeyInfo,
    ) -> Result<Self, String> {
        Self::new_from_magic_and_key_info(REGTEST_MAGIC, client_key, server_key)
    }

    pub fn new_from_magic_and_key_info(
        magic: MagicType,
        client_key: UserKeyInfo,
        server_key: UserKeyInfo,
    ) -> Result<Self, String> {
        let client_ecdh_key = client_key
            .try_into_echd_point()
            .map_err(|_| "Client KeyInfo is invalid")?;
        let server_ecdh_key = server_key
            .try_into_echd_point()
            .map_err(|_| "Client KeyInfo is invalid")?;

        let bridge = MitmBridge::new_from_ecdh_points(magic, client_ecdh_key, server_ecdh_key);

        Ok(Self { bridge })
    }

    pub fn client_write(&mut self, data: &[u8]) -> Result<(), String> {
        self.bridge.client_write(data)
    }

    pub fn server_write(&mut self, data: &[u8]) -> Result<(), String> {
        self.bridge.server_write(data)
    }

    pub fn client_read(&mut self, buf: &mut [u8]) -> Result<usize, Box<dyn Error>> {
        self.bridge.client_read(buf)
    }

    pub fn server_read(&mut self, buf: &mut [u8]) -> Result<usize, Box<dyn Error>> {
        self.bridge.server_read(buf)
    }
}

#[allow(non_upper_case_globals)]
#[cfg(test)]
mod mitmfakepeerbip324_tests {
    use super::*;
    use hex_literal::hex;
    use secp256k1::ellswift::ElligatorSwiftParty;
    use secp256k1::rand::rngs::mock::StepRng;
    use std::str::FromStr;

    use crate::cipher::{InboundCipher, OutboundCipher, SessionKeyMaterial};
    use crate::protocol::{NUM_GARBAGE_TERMINATOR_BYTES, PacketType};

    macro_rules! test_data {
        ($varname:ident, $name:ident { $($field:ident: $ty:ty = $val:expr),* $(,)? }) => {
            #[allow(dead_code)]
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

    fn secret_key_bytes_from_rng<Rng: RngCore + CryptoRng>(rng: &mut Rng) -> [u8; 32] {
        let mut secret_key_buffer = [0u8; 32];
        RngCore::fill_bytes(rng, &mut secret_key_buffer);
        debug_assert_ne!([0u8; 32], secret_key_buffer);

        secret_key_buffer
    }

    fn get_mitm_impersonator_from_secret_key(
        secret_key_bytes: [u8; 32],
        ellswift_bytes: Option<[u8; 64]>,
        role: Role,
    ) -> (
        MitmHandshakeImpersonatorLeg,
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

        let server = MitmHandshakeImpersonatorLeg::new(
            role,
            DEFAULT_MAGIC,
            relay_in.clone(),
            relay_out.clone(),
            secret_key,
        );

        (server, relay_in, relay_out)
    }

    fn get_mitm_fake_server_from_secret_key(
        secret_key_bytes: [u8; 32],
        ellswift_bytes: Option<[u8; 64]>,
    ) -> (
        MitmHandshakeImpersonatorLeg,
        Rc<RefCell<FakePeerRelay>>,
        Rc<RefCell<FakePeerRelay>>,
    ) {
        get_mitm_impersonator_from_secret_key(secret_key_bytes, ellswift_bytes, Role::Responder)
    }

    fn get_mitm_fake_client_from_secret_key(
        secret_key_bytes: [u8; 32],
        ellswift_bytes: Option<[u8; 64]>,
    ) -> (
        MitmHandshakeImpersonatorLeg,
        Rc<RefCell<FakePeerRelay>>,
        Rc<RefCell<FakePeerRelay>>,
    ) {
        get_mitm_impersonator_from_secret_key(secret_key_bytes, ellswift_bytes, Role::Initiator)
    }

    fn get_mitm_fake_server() -> (
        MitmHandshakeImpersonatorLeg,
        Rc<RefCell<FakePeerRelay>>,
        Rc<RefCell<FakePeerRelay>>,
    ) {
        let mut rng = secp256k1::rand::thread_rng();
        let secret_key = secret_key_bytes_from_rng(&mut rng);

        get_mitm_fake_server_from_secret_key(secret_key, None)
    }

    #[allow(dead_code)]
    fn get_mitm_fake_client() -> (
        MitmHandshakeImpersonatorLeg,
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
        MitmHandshakeImpersonatorLeg,
        Rc<RefCell<FakePeerRelay>>,
        Rc<RefCell<FakePeerRelay>>,
    ) {
        let mut insecure_rng = insecurerng(seed);
        let secret_key = secret_key_bytes_from_rng(&mut insecure_rng);

        get_mitm_fake_server_from_secret_key(secret_key, None)
    }

    #[test]
    fn client_key_by_parts() {
        let (mut server, _, _) = get_mitm_fake_server();

        // Send one key byte
        let buf = [0xa3];
        let mut bufref = &buf[..];
        server
            .consume(&mut bufref)
            .expect("Error on pass_peer_data");
        assert!(matches!(
            server.reader_leg_state,
            ReaderLegState::Handshake(MitmHandshakeImpersonatorLegReader {
                state: HandshakeBIP324State::ReceivingKey(..),
                ..
            })
        ));

        // Send another key byte
        let buf = [0xa3];
        let mut bufref = &buf[..];
        server
            .consume(&mut bufref)
            .expect("Error on pass_peer_data");
        assert!(matches!(
            server.reader_leg_state,
            ReaderLegState::Handshake(MitmHandshakeImpersonatorLegReader {
                state: HandshakeBIP324State::ReceivingKey(..),
                ..
            })
        ));

        // Send all the key bytes, except for the last one
        let buf = [0x73; NUM_ELLIGATOR_SWIFT_BYTES - 2 - 1];
        let mut bufref = &buf[..];
        server
            .consume(&mut bufref)
            .expect("Error on pass_peer_data");
        assert!(matches!(
            server.reader_leg_state,
            ReaderLegState::Handshake(MitmHandshakeImpersonatorLegReader {
                state: HandshakeBIP324State::ReceivingKey(..),
                ..
            })
        ));

        // Send all the key bytes, except for the last one
        let buf = [0x29];
        let mut bufref = &buf[..];
        server
            .consume(&mut bufref)
            .expect("Error on pass_peer_data");
        assert!(matches!(
            server.reader_leg_state,
            ReaderLegState::Handshake(MitmHandshakeImpersonatorLegReader {
                state: HandshakeBIP324State::ReceivingGarbage(..),
                ..
            })
        ));
    }

    #[test]
    fn client_key_direct() {
        let (mut server, _, _) = get_mitm_fake_server();

        // Send all the key bytes
        let buf = [0x73; NUM_ELLIGATOR_SWIFT_BYTES];
        let mut bufref = &buf[..];
        server
            .consume(&mut bufref)
            .expect("Error on pass_peer_data");
        assert!(matches!(
            server.reader_leg_state,
            ReaderLegState::Handshake(MitmHandshakeImpersonatorLegReader {
                state: HandshakeBIP324State::ReceivingGarbage(..),
                ..
            })
        ));
    }

    #[test]
    fn client_key_overflow() {
        let (mut server, _, _) = get_mitm_fake_server();

        // Send more than the key bytes
        let buf = [0x73; NUM_ELLIGATOR_SWIFT_BYTES + 10];
        let mut bufref = &buf[..];
        server
            .consume(&mut bufref)
            .expect("Error on pass_peer_data");
        assert!(matches!(
            server.reader_leg_state,
            ReaderLegState::Handshake(MitmHandshakeImpersonatorLegReader {
                state: HandshakeBIP324State::ReceivingGarbage(..),
                ..
            })
        ));
    }

    // Tests that the fake server doesn't relay the key if the real server
    // didn't send its key yet
    #[test]
    fn server_key_not_relayed() {
        let (mut server, _, _) = get_mitm_fake_server();

        // Send all the key bytes
        let buf = [0x73; NUM_ELLIGATOR_SWIFT_BYTES];
        let mut bufref = &buf[..];
        server
            .consume(&mut bufref)
            .expect("Error on pass_peer_data");
        assert!(matches!(
            server.reader_leg_state,
            ReaderLegState::Handshake(MitmHandshakeImpersonatorLegReader {
                state: HandshakeBIP324State::ReceivingGarbage(..),
                ..
            })
        ));

        let mut buf = vec![0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        let buf_len = buf.len();
        let initial_buf = buf.clone();
        let mut bufref = &mut buf[..];
        server.produce(&mut bufref).expect("Error on produce");
        let size = buf_len - bufref.len();
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

        let ReaderLegState::Handshake(reader_leg) = &server.reader_leg_state else {
            panic!("Wrong leg state");
        };

        assert_eq!(
            *reader_leg.key_to_send.borrow(),
            server_key,
            "The generated secret key is different from the expected one"
        );

        let mut client_keyref = &client_key[..];
        server
            .consume(&mut client_keyref)
            .expect("Error on pass_peer_data");

        let ReaderLegState::Handshake(reader_leg) = &server.reader_leg_state else {
            panic!("Wrong leg state");
        };
        let HandshakeBIP324State::ReceivingGarbage(other_garbage_terminator) = reader_leg.state
        else {
            panic!("Wrong state after receiving key");
        };

        let ReaderLegState::Handshake(reader_leg) = server.reader_leg_state else {
            panic!("Wrong leg state");
        };

        let cipher = reader_leg.cipher.borrow_mut().take().unwrap();
        let (inbound_cipher, outbound_cipher) = cipher.into_split();

        assert_eq!(inbound_cipher.length_cipher.unwrap().key_bytes, initiator_l);
        assert_eq!(inbound_cipher.packet_cipher.key_bytes, initiator_p);
        assert_eq!(outbound_cipher.length_cipher.key_bytes, responder_l);
        assert_eq!(outbound_cipher.packet_cipher.key_bytes, responder_p);
        assert_eq!(other_garbage_terminator, client_garbage_terminator);
    }

    // Tests that, when the fake server is ready to send the key, it can send it
    // byte by byte, corresponding to each byte sent by the real server.
    #[test]
    fn server_key_partially_relayed() {
        let (mut server, relay_in, _) = get_mitm_fake_server();

        // Send all the key bytes
        let buf = [0x73; NUM_ELLIGATOR_SWIFT_BYTES];
        let mut bufref = &buf[..];
        server
            .consume(&mut bufref)
            .expect("Error on pass_peer_data");
        assert!(matches!(
            server.reader_leg_state,
            ReaderLegState::Handshake(MitmHandshakeImpersonatorLegReader {
                state: HandshakeBIP324State::ReceivingGarbage(..),
                ..
            })
        ));

        let buf = [0u8];
        let mut out_buf = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        // Send one byte at a time
        for i in 0..NUM_ELLIGATOR_SWIFT_BYTES {
            relay_in
                .borrow_mut()
                .write_key(&buf)
                .expect("Write to relay_in must to fail");

            let mut writer = &mut out_buf[i..i + 1];
            server.produce(&mut writer).expect("Error on produce");
            let size = 1 - writer.len();
            assert_eq!(size, 1, "Expected write_data to write one byte at step {i}");

            let mut writer = &mut out_buf[i..i + 1];
            server.produce(&mut writer).expect("Error on produce");
            let size = 1 - writer.len();
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
        let sent_key_len = sent_key.len();
        let mut sent_keyref = &mut sent_key[..];
        server.produce(&mut sent_keyref).expect("Error on produce");
        let size = sent_key_len - sent_keyref.len();
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
        let buf = [0x73; 3];
        let mut bufref = &buf[..];
        server
            .consume(&mut bufref)
            .expect("Error on pass_peer_data");

        // Server sends something again
        relay_in
            .borrow_mut()
            .write_key(&[0u8; 2])
            .expect("Write must not fail");

        // Client sends something again
        let buf = [0x73; 4];
        let mut bufref = &buf[..];
        server
            .consume(&mut bufref)
            .expect("Error on pass_peer_data");

        let mut sent_key = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        let sent_key_len = sent_key.len();
        let mut sent_keyref = &mut sent_key[..];
        server.produce(&mut sent_keyref).expect("Error on produce");
        let size = sent_key_len - sent_keyref.len();
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

        // Real server sends the key
        let buf = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        relay_in
            .borrow_mut()
            .write_key(&buf)
            .expect("Write must not fail");

        let mut sent_key = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        let sent_key_len = sent_key.len();
        let mut sent_keyref = &mut sent_key[..];
        server.produce(&mut sent_keyref).expect("Error on produce");
        let size = sent_key_len - sent_keyref.len();
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
        let sent_key_len = sent_key.len();
        let mut sent_keyref = &mut sent_key[..];
        server.produce(&mut sent_keyref).expect("Error on produce");
        let size = sent_key_len - sent_keyref.len();
        assert_eq!(
            size, NUM_ELLIGATOR_SWIFT_BYTES,
            "Fake server must send the entire key"
        );

        // Fake server sends garbage
        let mut sent_garbage = [0u8; 128];
        let sent_garbage_len = sent_garbage.len();
        let mut sent_garbageref = &mut sent_garbage[..];
        server
            .produce(&mut sent_garbageref)
            .expect("Error on produce");
        let size = sent_garbage_len - sent_garbageref.len();
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
        let buf = [0x73; NUM_ELLIGATOR_SWIFT_BYTES - 1];
        let mut bufref = &buf[..];
        server
            .consume(&mut bufref)
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
        let sent_key_len = sent_key.len();
        let mut sent_keyref = &mut sent_key[..];
        server.produce(&mut sent_keyref).expect("Error on produce");
        let size = sent_key_len - sent_keyref.len();
        assert_eq!(
            size, NUM_ELLIGATOR_SWIFT_BYTES,
            "Fake server must send the entire key"
        );

        // Fake server sends garbage
        let mut sent_garbage = [0u8; 128];
        let sent_garbage_len = sent_garbage.len();
        let mut sent_garbageref = &mut sent_garbage[..];
        server
            .produce(&mut sent_garbageref)
            .expect("Error on produce");
        let size = sent_garbage_len - sent_garbageref.len();
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
        let buf = [0x73; NUM_ELLIGATOR_SWIFT_BYTES];
        let mut bufref = &buf[..];
        server
            .consume(&mut bufref)
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
        let sent_key_len = sent_key.len();
        let mut sent_keyref = &mut sent_key[..];
        server.produce(&mut sent_keyref).expect("Error on produce");
        let size = sent_key_len - sent_keyref.len();
        assert_eq!(
            size, NUM_ELLIGATOR_SWIFT_BYTES,
            "Fake server must send the entire key"
        );

        // Fake server sends garbage
        let mut sent_garbage = [0u8; 128];
        let sent_garbage_len = sent_garbage.len();
        let mut sent_garbageref = &mut sent_garbage[..];
        server
            .produce(&mut sent_garbageref)
            .expect("Error on produce");
        let size = sent_garbage_len - sent_garbageref.len();
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

        // Real client sends the key
        let mut client_keyref = &client_key[..];
        server
            .consume(&mut client_keyref)
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
            .write_terminator(&garbage_terminator)
            .expect("Write must not fail");
        relay_in.borrow_mut().set_eof_terminator();

        let mut sent_key = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        let sent_key_len = sent_key.len();
        let mut sent_keyref = &mut sent_key[..];
        server.produce(&mut sent_keyref).expect("Error on produce");
        let size = sent_key_len - sent_keyref.len();
        assert_eq!(
            size, NUM_ELLIGATOR_SWIFT_BYTES,
            "Fake server must send the entire key"
        );
        assert_eq!(sent_key, server_key, "Incorrect server key");

        let expected_len = garbage.len() + garbage_terminator.len();
        let mut sent_garbage = [0u8; 200];
        let sent_garbage_len = sent_garbage.len();
        let mut sent_garbageref = &mut sent_garbage[..];
        server
            .produce(&mut sent_garbageref)
            .expect("Error on produce");
        let size = sent_garbage_len - sent_garbageref.len();
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
        let mut in_ellswift_theirsref = &in_ellswift_theirs[..];
        impersonator
            .consume(&mut in_ellswift_theirsref)
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
        let mut mid_recv_garbage_terminatorref = &mid_recv_garbage_terminator[..];
        impersonator
            .consume(&mut mid_recv_garbage_terminatorref)
            .expect("Error on pass_peer_data");

        // Other seends a packet
        let mut out_ciphertextref = &out_ciphertext[..];
        impersonator
            .consume(&mut out_ciphertextref)
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
            relay_in.borrow_mut().write_data_bytes(&payload);
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
            relay_in.borrow_mut().write_data_bytes(&payload);
        }

        // Self sends the tag
        relay_in.borrow_mut().write_tag_bytes(&[13u8; TAG_LEN]);

        // Read key
        {
            let buf_len = NUM_ELLIGATOR_SWIFT_BYTES;
            let mut buf = vec![0u8; buf_len];
            let buf_len = buf.len();
            let mut bufref = &mut buf[..];
            impersonator.produce(&mut bufref).expect("Error on produce");
            let size = buf_len - bufref.len();
            assert_eq!(size, buf_len, "Buffer was not filled");
            assert_eq!(buf, in_ellswift_ours);
        }

        // Read garbage and garbage terminator
        {
            let buf_len = garbage.len();
            let mut buf = vec![0u8; buf_len];
            let buf_len = buf.len();
            let mut bufref = &mut buf[..];
            impersonator.produce(&mut bufref).expect("Error on produce");
            let size = buf_len - bufref.len();
            assert_eq!(size, buf_len, "Buffer was not filled");
            assert_eq!(buf, garbage, "Garbage is incorrect");

            let mut term = vec![0u8; NUM_GARBAGE_TERMINATOR_BYTES];
            let term_len = term.len();
            let mut termref = &mut term[..];
            impersonator
                .produce(&mut termref)
                .expect("Error on produce");
            let size = term_len - termref.len();
            assert_eq!(size, term.len(), "Buffer was not filled");
            assert_eq!(term, mid_send_garbage_terminator);
        }

        for _ in 0..in_idx {
            // Read decoy packet. This includes: packet length (0), header, version contents and aead.
            let expected_len = NUM_LENGTH_BYTES + HEADER_LEN + TAG_LEN;
            let mut buf = vec![0u8; expected_len];
            let buf_len = buf.len();
            let mut bufref = &mut buf[..];
            impersonator.produce(&mut bufref).expect("Error on produce");
            let size = buf_len - bufref.len();
            assert_eq!(
                size, expected_len,
                "Fake peer didn't send the expected amount of bytes"
            );
        }

        // Read packet. This includes: packet length, header, version contents and aead.
        let expected_len = NUM_LENGTH_BYTES + HEADER_LEN + in_contents.len() + TAG_LEN;
        let mut buf = vec![0u8; expected_len + 100];
        let buf_len = buf.len();
        let mut bufref = &mut buf[..];
        impersonator.produce(&mut bufref).expect("Error on produce");
        let size = buf_len - bufref.len();
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

    // Test copied from https://github.com/rust-bitcoin/bip324
    #[test]
    fn test_cipher_session() {
        let alice =
            SecretKey::from_str("61062ea5071d800bbfd59e2e8b53d47d194b095ae5a4df04936b49772ef0d4d7")
                .unwrap();
        let elliswift_alice = ElligatorSwift::from_str("ec0adff257bbfe500c188c80b4fdd640f6b45a482bbc15fc7cef5931deff0aa186f6eb9bba7b85dc4dcc28b28722de1e3d9108b985e2967045668f66098e475b").unwrap();
        let elliswift_bob = ElligatorSwift::from_str("a4a94dfce69b4a2a0a099313d10f9f7e7d649d60501c9e1d274c300e0d89aafaffffffffffffffffffffffffffffffffffffffffffffffffffffffff8faf88d5").unwrap();
        let session_keys = SessionKeyMaterial::from_ecdh(
            elliswift_alice,
            elliswift_bob,
            alice,
            ElligatorSwiftParty::A,
            DEFAULT_MAGIC,
        )
        .unwrap();
        let mut alice_cipher = CipherSession::new(session_keys.clone(), Role::Initiator);
        let mut bob_cipher = CipherSession::new(session_keys, Role::Responder);
        let message = b"Bitcoin rox!".to_vec();

        let mut enc_packet = vec![0u8; OutboundCipher::encryption_buffer_len(message.len())];
        alice_cipher
            .consume_outbound()
            .unwrap()
            .encrypt(&message, &mut enc_packet, PacketType::Decoy, None)
            .unwrap();

        let mut bob_inbound = bob_cipher.consume_inbound().unwrap();
        let plaintext_len =
            bob_inbound.decrypt_packet_len(enc_packet[0..NUM_LENGTH_BYTES].try_into().unwrap());
        let mut plaintext_buffer = vec![0u8; InboundCipher::decryption_buffer_len(plaintext_len)];
        let packet_type = bob_inbound
            .decrypt(&enc_packet[NUM_LENGTH_BYTES..], &mut plaintext_buffer, None)
            .unwrap();
        assert_eq!(PacketType::Decoy, packet_type);
        assert_eq!(message, plaintext_buffer[1..].to_vec()); // Skip header byte

        let message = b"Windows sox!".to_vec();
        let packet_len = OutboundCipher::encryption_buffer_len(message.len());
        let mut enc_packet = vec![0u8; packet_len];
        bob_cipher
            .consume_outbound()
            .unwrap()
            .encrypt(&message, &mut enc_packet, PacketType::Genuine, None)
            .unwrap();

        let mut alice_inbound = alice_cipher.consume_inbound().unwrap();
        let plaintext_len =
            alice_inbound.decrypt_packet_len(enc_packet[0..NUM_LENGTH_BYTES].try_into().unwrap());
        let mut plaintext_buffer = vec![0u8; InboundCipher::decryption_buffer_len(plaintext_len)];
        let packet_type = alice_inbound
            .decrypt(&enc_packet[NUM_LENGTH_BYTES..], &mut plaintext_buffer, None)
            .unwrap();
        assert_eq!(PacketType::Genuine, packet_type);
        assert_eq!(message, plaintext_buffer[1..].to_vec()); // Skip header byte
    }

    fn example_main() -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
        const BUFSIZE: usize = 2048;

        let fake_client_key = UserKeyInfo::new(
            /* secret */
            hex!("61062ea5071d800bbfd59e2e8b53d47d194b095ae5a4df04936b49772ef0d4d7"),
            /* pubkey_ellswift */
            Some(hex!(
                "ec0adff257bbfe500c188c80b4fdd640f6b45a482bbc15fc7cef5931deff0aa186f6eb9bba7b85dc4dcc28b28722de1e3d9108b985e2967045668f66098e475b"
            )),
        );
        let fake_server_key = UserKeyInfo::new(
            /* secret */
            hex!("6f312890ec83bbb26798abaadd574684a53e74ccef7953b790fcc29409080246"),
            /* pubkey_ellswift */
            Some(hex!(
                "a8785af31c029efc82fa9fc677d7118031358d7c6a25b5779a9b900e5ccd94aac97eb36a3c5dbcdb2ca5843cc4c2fe0aaa46d10eb3d233a81c3dde476da00eef"
            )),
        );

        let mut mitm = MitmBIP324::new_from_key_info(fake_client_key, fake_server_key)?;

        let data_from_client = hex!(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f0000000000000000000000000000000000000000000000000000000000000000ca29b3a35237f8212bd13ed187a1da2e"
        );
        let data_from_server = hex!(
            "a4a94dfce69b4a2a0a099313d10f9f7e7d649d60501c9e1d274c300e0d89aafaffffffffffffffffffffffffffffffffffffffffffffffffffffffff8faf88d52222222222222202cb8ff24307a6e27de3b4e7ea3fa65b"
        );

        mitm.client_write(&data_from_client)?;
        mitm.server_write(&data_from_server)?;

        let mut data_to_client = [0u8; BUFSIZE];
        let mut data_to_server = [0u8; BUFSIZE];
        let size1 = mitm.server_read(&mut data_to_server)?;
        let size2 = mitm.client_read(&mut data_to_client)?;

        Ok((
            data_to_server[..size1].to_vec(),
            data_to_client[..size2].to_vec(),
        ))
    }

    #[test]
    fn usage_example() {
        let (data_to_server, data_to_client) = example_main().unwrap();

        assert_eq!(
            data_to_server,
            hex!(
                "ec0adff257bbfe500c188c80b4fdd640f6b45a482bbc15fc7cef5931deff0aa186f6eb9bba7b85dc4dcc28b28722de1e3d9108b985e2967045668f66098e475bfaef555dfcdb936425d84aba524758f3"
            )
        );
        assert_eq!(
            data_to_client,
            hex!(
                "a8785af31c029efc82fa9fc677d7118031358d7c6a25b5779a9b900e5ccd94aac97eb36a3c5dbcdb2ca5843cc4c2fe0aaa46d10eb3d233a81c3dde476da00eef2222222222222244737108aec5f8b6c1c277b31bbce9c1"
            )
        );
    }
}
