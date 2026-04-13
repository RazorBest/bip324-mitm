use std::cell::RefCell;
use std::cmp;
use std::collections::VecDeque;
use std::rc::Rc;

use crate::cipher::{CipherSession, InboundCipher, LengthDecryptor, OutboundCipher};
use crate::external::chacha20_poly1305::ChaCha20Poly1305Stream;
use crate::protocol::{
    AADType, EcdhPoint, GarbageTerminatorType, MagicType, NUM_ELLIGATOR_SWIFT_BYTES,
    NUM_GARBAGE_CONTENT_LIMIT, NUM_GARBAGE_TERMINATOR_BYTES, NUM_LENGTH_BYTES, NUM_TAG_BYTES,
    Role, TagType, find_garbage,
};
use crate::state_machine::{
    BufReader, BufWriter, HasFinal, ProtocolReadParser, ProtocolStatus, ProtocolWriteParser,
};

#[derive(Debug)]
pub enum Bip324Error {
    ReadError(std::io::Error),
    KeyGenerationError,
    GarbageLimitExceededError,
    IllegalState(String),
}

impl std::fmt::Display for Bip324Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReadError(e) => write!(f, "IO Read error: {e}"),
            Self::KeyGenerationError => write!(f, "Key generation error"),
            Self::GarbageLimitExceededError => write!(f, "Garbage limit exceeded"),
            Self::IllegalState(msg) => write!(f, "Illegal state: {msg}"),
        }
    }
}

impl std::error::Error for Bip324Error {}

/// Shared handshake state owned by both the read and write parsers.
pub struct HandshakeState {
    role: Role,
    magic: MagicType,
    pub(super) our_key: EcdhPoint,
    pub(super) our_ellswift_bytes: [u8; NUM_ELLIGATOR_SWIFT_BYTES],
    peer_key: Option<[u8; NUM_ELLIGATOR_SWIFT_BYTES]>,
    pub(super) cipher_session: Option<CipherSession>,
    pub(super) outbound_garbage_terminator: Option<GarbageTerminatorType>,
    pub(super) writer_started_sending: bool,
    /// Outbound cipher extracted from the cipher session by into_data_reader()
    /// The paired write parser reads this in into_data_writer()
    pub(super) outbound_cipher: Option<OutboundCipher>,
}

/// A reference-counted, interior-mutable handle to `HandshakeState`.
pub type SharedHandshakeState = Rc<RefCell<HandshakeState>>;

impl HandshakeState {
    pub fn new(role: Role, magic: MagicType, our_key: EcdhPoint) -> Self {
        let our_ellswift_bytes = our_key.elligator_swift.to_array();
        Self {
            role,
            magic,
            our_key,
            our_ellswift_bytes,
            peer_key: None,
            cipher_session: None,
            outbound_garbage_terminator: None,
            writer_started_sending: false,
            outbound_cipher: None,
        }
    }

    /// Update the ECDH key used for this handshake.
    ///
    /// Fails if the writer has already started transmitting key bytes, because
    /// changing the key at that point would be inconsistent with what the peer receives.
    /// If the peer's key has already arrived, the cipher session is re-derived immediately.
    pub fn set_ecdh_point(&mut self, point: EcdhPoint) -> Result<(), (EcdhPoint, Bip324Error)> {
        if self.writer_started_sending {
            return Err((
                point,
                Bip324Error::IllegalState(
                    "Can't change key: writer has already started sending".to_string(),
                ),
            ));
        }
        self.our_ellswift_bytes = point.elligator_swift.to_array();
        self.our_key = point;
        if self.peer_key.is_some() {
            self.derive_cipher_session()
                .map_err(|e| (self.our_key.clone(), e))?;
        }
        Ok(())
    }

    /// Record the peer's key and immediately derive the shared cipher session.
    ///
    /// Returns the inbound garbage terminator so the caller can transition
    /// the read-parser state to `ReceivingGarbage`.
    pub(super) fn on_peer_key_received(
        &mut self,
        peer_key: [u8; NUM_ELLIGATOR_SWIFT_BYTES],
    ) -> Result<GarbageTerminatorType, Bip324Error> {
        self.peer_key = Some(peer_key);
        self.derive_cipher_session()
    }

    /// Return the inbound garbage terminator from the derived cipher session, if available.
    pub(super) fn inbound_garbage_terminator(&self) -> Option<GarbageTerminatorType> {
        self.cipher_session
            .as_ref()
            .map(|c| c.inbound_garbage_terminator)
    }

    fn derive_cipher_session(&mut self) -> Result<GarbageTerminatorType, Bip324Error> {
        let peer_key = self.peer_key.as_ref().ok_or_else(|| {
            Bip324Error::IllegalState(
                "derive_cipher_session called without peer_key".to_string(),
            )
        })?;
        let cipher =
            CipherSession::new_from_shares(self.magic, self.role, self.our_key.clone(), peer_key)
                .map_err(|(_, _)| Bip324Error::KeyGenerationError)?;
        let inbound_garbage_terminator = cipher.inbound_garbage_terminator;
        let outbound_garbage_terminator = cipher.outbound_garbage_terminator;
        self.cipher_session = Some(cipher);
        self.outbound_garbage_terminator = Some(outbound_garbage_terminator);
        Ok(inbound_garbage_terminator)
    }
}

#[derive(Debug)]
pub enum HandshakeReadState {
    ReceivingKey(usize),                    // remaining_bytes
    ReceivingGarbage(GarbageTerminatorType), // inbound_garbage_terminator
    HandshakeDone(AADType),                 // garbage content (AAD)
}

impl HasFinal for HandshakeReadState {
    fn is_final(&self) -> bool {
        matches!(self, Self::HandshakeDone(_))
    }
}

pub struct HandshakeReadParser {
    state: Option<HandshakeReadState>,
    read_buffer: Vec<u8>,

    // Output buffers -- drained by caller after each step()
    output_key_bytes: VecDeque<u8>,
    output_garbage_bytes: VecDeque<u8>,
    output_terminator_bytes: VecDeque<u8>,
    key_eof: bool,
    garbage_eof: bool,
    shared: SharedHandshakeState,
}

impl HandshakeReadParser {
    pub(super) fn new_with_state(shared: SharedHandshakeState) -> Self {
        let remaining = NUM_ELLIGATOR_SWIFT_BYTES;
        Self {
            state: Some(HandshakeReadState::ReceivingKey(remaining)),
            read_buffer: vec![],
            output_key_bytes: VecDeque::new(),
            output_garbage_bytes: VecDeque::new(),
            output_terminator_bytes: VecDeque::new(),
            key_eof: false,
            garbage_eof: false,
            shared,
        }
    }

    fn on_share_received(
        &mut self,
        other_key: [u8; NUM_ELLIGATOR_SWIFT_BYTES],
    ) -> Result<GarbageTerminatorType, Bip324Error> {
        self.shared.borrow_mut().on_peer_key_received(other_key)
    }

    pub fn set_ecdh_point(
        &mut self,
        point: EcdhPoint,
    ) -> Result<(), (EcdhPoint, Bip324Error)> {
        use HandshakeReadState::*;

        if self.state.as_ref().is_some_and(|s| s.is_final()) {
            return Err((
                point,
                Bip324Error::IllegalState(
                    "Can't change key. Handshake is already done".to_string(),
                ),
            ));
        }

        let is_receiving_garbage = matches!(self.state, Some(ReceivingGarbage(_)));

        // Delegates to shared state, which enforces the writer_started_sending guard
        // and re-derives the cipher session if the peer's key is already known.
        self.shared.borrow_mut().set_ecdh_point(point)?;

        if is_receiving_garbage {
            // Update the inbound_garbage_terminator in our state to reflect the new ECDH outcome.
            if let Some(inbound_term) = self.shared.borrow().inbound_garbage_terminator() {
                self.state = Some(ReceivingGarbage(inbound_term));
            }
        }

        Ok(())
    }

    pub fn drain_key_bytes(&mut self) -> Vec<u8> {
        self.output_key_bytes.drain(..).collect()
    }

    pub fn drain_garbage_bytes(&mut self) -> Vec<u8> {
        self.output_garbage_bytes.drain(..).collect()
    }

    pub fn drain_terminator_bytes(&mut self) -> Vec<u8> {
        self.output_terminator_bytes.drain(..).collect()
    }

    pub fn is_key_eof(&self) -> bool {
        self.key_eof
    }

    pub fn is_garbage_eof(&self) -> bool {
        self.garbage_eof
    }

    pub fn take_ciphers(&mut self) -> Option<(InboundCipher, OutboundCipher)> {
        self.shared
            .borrow_mut()
            .cipher_session
            .take()
            .map(|c| c.into_split())
    }

    pub fn outbound_garbage_terminator(&self) -> Option<GarbageTerminatorType> {
        self.shared.borrow().outbound_garbage_terminator
    }

    pub fn elligator_swift_bytes(&self) -> [u8; NUM_ELLIGATOR_SWIFT_BYTES] {
        self.shared.borrow().our_ellswift_bytes
    }

    pub fn is_handshake_done(&self) -> bool {
        self.state.as_ref().is_some_and(|s| s.is_final())
    }

    pub fn is_receiving_key(&self) -> bool {
        matches!(self.state, Some(HandshakeReadState::ReceivingKey(..)))
    }

    pub fn is_receiving_garbage(&self) -> bool {
        matches!(self.state, Some(HandshakeReadState::ReceivingGarbage(_)))
    }

    pub fn inbound_garbage_terminator(&self) -> Option<&GarbageTerminatorType> {
        match self.state.as_ref()? {
            HandshakeReadState::ReceivingGarbage(gt) => Some(gt),
            _ => None,
        }
    }

    pub fn take_aad(&mut self) -> Option<AADType> {
        let state = self.state.take()?;
        match state {
            HandshakeReadState::HandshakeDone(aad) => {
                self.state = Some(HandshakeReadState::HandshakeDone(vec![]));
                Some(aad)
            }
            _ => {
                self.state = Some(state);
                None
            }
        }
    }

    pub fn into_data_reader(mut self) -> (DataReadParser, Vec<u8>) {
        assert!(
            self.is_handshake_done(),
            "Handshake must be done before transitioning to data phase"
        );

        let (inbound_cipher, outbound_cipher) = self
            .take_ciphers()
            .expect("Ciphers must be available after handshake");

        let aad = self.take_aad().unwrap_or_default();

        // Store the outbound cipher in shared state so the paired writer can use it.
        self.shared.borrow_mut().outbound_cipher = Some(outbound_cipher);

        (DataReadParser::new(aad.clone(), inbound_cipher), aad)
    }
}

impl ProtocolReadParser for HandshakeReadParser {
    type State = HandshakeReadState;
    type Error = Bip324Error;

    fn transition(
        &mut self,
        state: Self::State,
        data: &mut dyn BufReader,
    ) -> (Self::State, Result<ProtocolStatus, Self::Error>) {
        use HandshakeReadState::*;

        match state {
            ReceivingKey(mut remaining) => {
                let mut key_buf = vec![0u8; remaining];
                let size = match data.read(&mut key_buf) {
                    Ok(size) => size,
                    Err(err) => {
                        return (
                            ReceivingKey(remaining),
                            Err(Bip324Error::ReadError(err)),
                        );
                    }
                };
                remaining -= size;

                self.read_buffer.extend_from_slice(&key_buf[..size]);
                self.output_key_bytes.extend(key_buf[..size].iter().copied());

                if remaining == 0 {
                    self.key_eof = true;

                    let mut other_key = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
                    other_key.copy_from_slice(&std::mem::take(&mut self.read_buffer));

                    let inbound_garbage_terminator = match self.on_share_received(other_key) {
                        Ok(ret) => ret,
                        Err(err) => {
                            return (ReceivingKey(remaining), Err(err));
                        }
                    };

                    (
                        ReceivingGarbage(inbound_garbage_terminator),
                        Ok(ProtocolStatus::Continue),
                    )
                } else {
                    (ReceivingKey(remaining), Ok(ProtocolStatus::End))
                }
            }

            // This uses a peek-then-read strategy
            state @ ReceivingGarbage(other_garbage_terminator) => {
                // The length under which we don't know if an array of data is a garbage terminator
                let insurance_len = other_garbage_terminator.len() - 1;
                let prevlen = self.read_buffer.len();

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

                if self.read_buffer.len() > NUM_GARBAGE_CONTENT_LIMIT + NUM_GARBAGE_TERMINATOR_BYTES
                {
                    return (state, Err(Bip324Error::GarbageLimitExceededError));
                }

                if found {
                    // Here, we expect self.read_buffer to contain the garbage, including the
                    // terminator

                    let currlen = self.read_buffer.len();
                    let garbage_len = currlen - other_garbage_terminator.len();
                    let lhs = cmp::max(prevlen, insurance_len) - insurance_len;
                    let new_range = lhs..garbage_len;

                    // Copy slices to avoid multiple borrows of self
                    let garbage_chunk = self.read_buffer[new_range].to_vec();
                    self.output_garbage_bytes.extend(garbage_chunk.iter().copied());
                    self.garbage_eof = true;

                    let term_chunk = self.read_buffer[garbage_len..].to_vec();
                    self.output_terminator_bytes.extend(term_chunk.iter().copied());

                    let aad: Vec<_> = self.read_buffer.splice(..garbage_len, []).collect();
                    self.read_buffer.clear();

                    (HandshakeDone(aad), Ok(ProtocolStatus::End))
                } else {
                    let currlen = self.read_buffer.len();
                    let lhs = cmp::max(prevlen, insurance_len) - insurance_len;
                    let rhs = cmp::max(currlen, insurance_len) - insurance_len;
                    // The range of data that wasn't relayed and we're sure it's garbage, and is not part of the terminator
                    let new_range = lhs..rhs;

                    let garbage_chunk = self.read_buffer[new_range].to_vec();
                    self.output_garbage_bytes.extend(garbage_chunk.iter().copied());

                    (state, Ok(ProtocolStatus::End))
                }
            }

            state @ HandshakeDone(_) => (state, Ok(ProtocolStatus::End)),
        }
    }

    fn take_state(&mut self) -> Self::State {
        self.state.take().unwrap()
    }

    fn set_state(&mut self, state: Self::State) {
        self.state = Some(state);
    }
}

pub enum HandshakeWriteState {
    SendingKey,
    SendingGarbage,
    SendingGarbageTerminator,
    Done,
}

impl HasFinal for HandshakeWriteState {
    fn is_final(&self) -> bool {
        matches!(self, Self::Done)
    }
}

pub struct HandshakeWriteParser {
    state: Option<HandshakeWriteState>,
    key_bytes_sent: usize,
    garbage_bytes: VecDeque<u8>,
    garbage_eof: bool,
    terminator_bytes_sent: usize,
    outbound_cipher: Option<OutboundCipher>,
    shared: SharedHandshakeState,
}

impl HandshakeWriteParser {
    pub(super) fn new_with_state(shared: SharedHandshakeState) -> Self {
        Self {
            state: Some(HandshakeWriteState::SendingKey),
            key_bytes_sent: 0,
            garbage_bytes: VecDeque::new(),
            garbage_eof: false,
            terminator_bytes_sent: 0,
            outbound_cipher: None,
            shared,
        }
    }

    pub fn push_garbage_bytes(&mut self, bytes: &[u8]) {
        self.garbage_bytes.extend(bytes.iter().copied());
    }

    pub fn set_garbage_eof(&mut self) {
        self.garbage_eof = true;
    }

    pub fn set_outbound_cipher(&mut self, cipher: OutboundCipher) {
        self.outbound_cipher = Some(cipher);
    }

    pub fn take_outbound_cipher(&mut self) -> Option<OutboundCipher> {
        self.outbound_cipher.take()
    }

    pub fn has_outbound_cipher(&self) -> bool {
        self.outbound_cipher.is_some() || self.shared.borrow().outbound_cipher.is_some()
    }

    pub fn is_done(&self) -> bool {
        self.state.as_ref().is_some_and(|s| s.is_final())
    }

    pub fn is_sending_key(&self) -> bool {
        matches!(self.state, Some(HandshakeWriteState::SendingKey))
    }

    pub fn is_sending_garbage(&self) -> bool {
        matches!(self.state, Some(HandshakeWriteState::SendingGarbage))
    }

    pub fn is_sending_terminator(&self) -> bool {
        matches!(self.state, Some(HandshakeWriteState::SendingGarbageTerminator))
    }

    pub fn into_data_writer(mut self) -> DataWriteParser {
        assert!(
            self.is_done(),
            "Handshake must be done before transitioning to data phase"
        );

        let outbound_cipher = self
            .outbound_cipher
            .take()
            .or_else(|| self.shared.borrow_mut().outbound_cipher.take())
            .expect("Outbound cipher must be available for data phase");

        DataWriteParser::new(outbound_cipher)
    }

    /// Inject an outbound garbage terminator directly into shared state.
    /// This is only intended for use in tests. In production the terminator is derived
    /// automatically when the read-parser completes the ECDH exchange.
    #[cfg(test)]
    pub(crate) fn inject_outbound_garbage_terminator_for_test(
        &mut self,
        term: crate::protocol::GarbageTerminatorType,
    ) {
        self.shared.borrow_mut().outbound_garbage_terminator = Some(term);
    }
}

impl ProtocolWriteParser for HandshakeWriteParser {
    type State = HandshakeWriteState;
    type Error = ();

    fn transition(
        &mut self,
        state: Self::State,
        data: &mut dyn BufWriter,
    ) -> (Self::State, Result<ProtocolStatus, Self::Error>) {
        use HandshakeWriteState::*;

        match state {
            state @ SendingKey => {
                // Mark writer as started so that set_ecdh_point is rejected from here on.
                if !self.shared.borrow().writer_started_sending {
                    self.shared.borrow_mut().writer_started_sending = true;
                }

                let ellswift_bytes = self.shared.borrow().our_ellswift_bytes;
                let remaining = NUM_ELLIGATOR_SWIFT_BYTES - self.key_bytes_sent;
                let size = cmp::min(data.remaining(), remaining);
                data.write_all(&ellswift_bytes[self.key_bytes_sent..self.key_bytes_sent + size])
                    .unwrap();
                self.key_bytes_sent += size;

                if self.key_bytes_sent == NUM_ELLIGATOR_SWIFT_BYTES {
                    (SendingGarbage, Ok(ProtocolStatus::Continue))
                } else {
                    (state, Ok(ProtocolStatus::End))
                }
            }
            state @ SendingGarbage => {
                let size = cmp::min(data.remaining(), self.garbage_bytes.len());
                let garbage_chunk: Vec<u8> = self.garbage_bytes.drain(..size).collect();
                data.write_all(&garbage_chunk).unwrap();

                if self.garbage_bytes.is_empty() && self.garbage_eof {
                    (SendingGarbageTerminator, Ok(ProtocolStatus::Continue))
                } else {
                    (state, Ok(ProtocolStatus::End))
                }
            }
            state @ SendingGarbageTerminator => {
                // The outbound terminator is derived via ECDH by the read-parser. If it is
                // not ready yet (peer's key hasn't been fully received), wait.
                let outbound_term = self.shared.borrow().outbound_garbage_terminator;
                let term = match outbound_term {
                    Some(t) => t,
                    None => return (state, Ok(ProtocolStatus::End)),
                };

                let remaining = NUM_GARBAGE_TERMINATOR_BYTES - self.terminator_bytes_sent;
                let size = cmp::min(data.remaining(), remaining);
                data.write_all(&term[self.terminator_bytes_sent..self.terminator_bytes_sent + size])
                    .unwrap();
                self.terminator_bytes_sent += size;

                if self.terminator_bytes_sent == NUM_GARBAGE_TERMINATOR_BYTES {
                    (Done, Ok(ProtocolStatus::End))
                } else {
                    (state, Ok(ProtocolStatus::End))
                }
            }
            state @ Done => (state, Ok(ProtocolStatus::End)),
        }
    }

    fn take_state(&mut self) -> Self::State {
        self.state.take().unwrap()
    }

    fn set_state(&mut self, state: Self::State) {
        self.state = Some(state);
    }
}

// Maximum packet size for automatic allocation.
// Bitcoin Core's MAX_PROTOCOL_MESSAGE_LENGTH is 4,000,000 bytes (~4 MiB).
// 14 extra bytes are for the BIP-324 header byte and 13 serialization header bytes (message type).
const MAX_PACKET_SIZE_FOR_ALLOCATION: usize = 4000014;

pub enum DataReadState {
    ReceivingPacketLen(LengthDecryptor),
    ReceivingPacketContent(ChaCha20Poly1305Stream),
    ReceivingPacketTag(TagType),
}

impl HasFinal for DataReadState {
    /// Always returns false - packet reading loops forever
    fn is_final(&self) -> bool {
        false
    }
}

pub struct DataReadParser {
    state: Option<DataReadState>,
    remaining: usize,
    aad: Vec<u8>,
    inbound_cipher: InboundCipher,

    // Output buffers
    output_length_bytes: VecDeque<u8>,
    output_data_bytes: VecDeque<u8>,
    output_tag_bytes: VecDeque<u8>,
    output_aad: Option<Vec<u8>>,
}

impl DataReadParser {
    pub fn new(aad: AADType, mut inbound_cipher: InboundCipher) -> Self {
        let length_decryptor = inbound_cipher
            .get_new_length_decryptor()
            .expect("The inbound cipher can't create a length decryptor");
        Self {
            state: Some(DataReadState::ReceivingPacketLen(length_decryptor)),
            remaining: NUM_LENGTH_BYTES,
            aad,
            inbound_cipher,
            output_length_bytes: VecDeque::new(),
            output_data_bytes: VecDeque::new(),
            output_tag_bytes: VecDeque::new(),
            output_aad: None,
        }
    }

    pub fn drain_length_bytes(&mut self) -> Vec<u8> {
        self.output_length_bytes.drain(..).collect()
    }

    pub fn drain_data_bytes(&mut self) -> Vec<u8> {
        self.output_data_bytes.drain(..).collect()
    }

    pub fn drain_tag_bytes(&mut self) -> Vec<u8> {
        self.output_tag_bytes.drain(..).collect()
    }

    pub fn take_aad(&mut self) -> Option<Vec<u8>> {
        self.output_aad.take()
    }

    pub fn set_aad(&mut self, aad: Vec<u8>) {
        self.aad = aad;
    }

    fn consume_aad(&mut self) -> Vec<u8> {
        self.aad.drain(..).collect()
    }
}

impl ProtocolReadParser for DataReadParser {
    type State = DataReadState;
    type Error = ();

    fn transition(
        &mut self,
        state: Self::State,
        data: &mut dyn BufReader,
    ) -> (Self::State, Result<ProtocolStatus, Self::Error>) {
        use DataReadState::*;

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

                self.output_length_bytes.extend(data_to_process.iter().copied());

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

                        // packet_len = plaintext_len + NUM_HEADER_BYTES + NUM_TAG_BYTES (from try_end).
                        // Content phase reads header + plaintext only (not the tag).
                        self.remaining = packet_len - NUM_TAG_BYTES;
                        (
                            ReceivingPacketContent(stream_cipher),
                            Ok(ProtocolStatus::Continue),
                        )
                    }
                    // Haven't received all 3 length bytes yet
                    Err(new_length_decryptor) => (
                        ReceivingPacketLen(new_length_decryptor),
                        Ok(ProtocolStatus::End),
                    ),
                }
            }
            ReceivingPacketContent(mut stream_cipher) => {
                stream_cipher.decrypt_and_store_chunk(&mut data_to_process);
                self.output_data_bytes.extend(data_to_process.iter().copied());

                if self.remaining == 0 {
                    let aad = self.consume_aad();
                    let tag = stream_cipher.get_tag(Some(&aad[..]));
                    self.inbound_cipher.packet_cipher.end_current_stream(&aad);

                    if !aad.is_empty() {
                        self.output_aad = Some(aad);
                    }

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

                self.output_tag_bytes.extend(data_to_process.iter().copied());

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
        self.state.take().unwrap()
    }

    fn set_state(&mut self, state: Self::State) {
        self.state = Some(state);
    }
}

pub enum DataWriteState {
    SendingLength(usize, Vec<u8>),
    SendingPayload(usize, ChaCha20Poly1305Stream),
    SendingTag(Vec<u8>),
}

impl HasFinal for DataWriteState {
    /// Always returns false -- packet writing loops forever
    fn is_final(&self) -> bool {
        false
    }
}

pub struct DataWriteParser {
    state: Option<DataWriteState>,
    outbound_cipher: OutboundCipher,

    // Input buffers (pushed by caller)
    input_length_bytes: VecDeque<u8>,
    input_data_bytes: VecDeque<u8>,
    input_tag_bytes: VecDeque<u8>,
    input_aad: Option<Vec<u8>>,
}

impl DataWriteParser {
    pub fn new(outbound_cipher: OutboundCipher) -> Self {
        Self {
            state: Some(DataWriteState::SendingLength(NUM_LENGTH_BYTES, vec![])),
            outbound_cipher,
            input_length_bytes: VecDeque::new(),
            input_data_bytes: VecDeque::new(),
            input_tag_bytes: VecDeque::new(),
            input_aad: None,
        }
    }

    pub fn push_length_bytes(&mut self, bytes: &[u8]) {
        self.input_length_bytes.extend(bytes.iter().copied());
    }

    pub fn push_data_bytes(&mut self, bytes: &[u8]) {
        self.input_data_bytes.extend(bytes.iter().copied());
    }

    pub fn push_tag_bytes(&mut self, bytes: &[u8]) {
        self.input_tag_bytes.extend(bytes.iter().copied());
    }

    pub fn set_aad(&mut self, aad: &[u8]) {
        self.input_aad = Some(aad.to_vec());
    }

    pub fn peek_input_length_bytes(&self) -> usize {
        self.input_length_bytes.len()
    }

    pub fn peek_input_data_bytes(&self) -> usize {
        self.input_data_bytes.len()
    }

    pub fn peek_input_tag_bytes(&self) -> usize {
        self.input_tag_bytes.len()
    }
}

impl ProtocolWriteParser for DataWriteParser {
    type State = DataWriteState;
    type Error = ();

    fn transition(
        &mut self,
        state: Self::State,
        data: &mut dyn BufWriter,
    ) -> (Self::State, Result<ProtocolStatus, Self::Error>) {
        use DataWriteState::*;

        match state {
            SendingLength(remaining, written) => {
                if self.input_length_bytes.is_empty() {
                    return (SendingLength(remaining, written), Ok(ProtocolStatus::End));
                }

                // TODO: replace unwrap
                let buf = data.prewrite(self.input_length_bytes.len()).unwrap();
                let size = buf.len();

                if size > remaining {
                    // TODO: replace panic
                    panic!("Received too many length bytes from the input buffer");
                }

                // Capture plaintext before encrypting
                let contiguous = self.input_length_bytes.make_contiguous();
                let new_written = [&written[..], &contiguous[..size]].concat();
                buf.copy_from_slice(&contiguous[..size]);
                self.input_length_bytes.drain(..size);

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
                    (
                        SendingLength(remaining - size, new_written),
                        Ok(ProtocolStatus::End),
                    )
                }
            }
            SendingPayload(remaining, mut stream_cipher) => {
                if self.input_data_bytes.is_empty() {
                    return (
                        SendingPayload(remaining, stream_cipher),
                        Ok(ProtocolStatus::End),
                    );
                }

                // TODO: replace unwrap
                let buf = data.prewrite(self.input_data_bytes.len()).unwrap();
                let size = buf.len();

                // TODO: replace panic
                if size > remaining {
                    panic!("Received too many data bytes from the input buffer");
                }

                buf.copy_from_slice(&self.input_data_bytes.make_contiguous()[..size]);
                self.input_data_bytes.drain(..size);

                stream_cipher.encrypt_and_store_chunk(&mut buf[..size]);

                if size == remaining {
                    let aad = self.input_aad.take().unwrap_or(vec![]);
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
                if self.input_tag_bytes.is_empty() {
                    return (SendingTag(tag), Ok(ProtocolStatus::End));
                }

                // TODO: replace unwrap
                let buf = data.prewrite(self.input_tag_bytes.len()).unwrap();
                let size = buf.len();

                if size > tag.len() {
                    // TODO: replace panic
                    panic!("Received too many tag bytes from the input buffer");
                }

                // Consume relay tag bytes for pacing, then overwrite with computed tag
                self.input_tag_bytes.drain(..size);
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
        }
    }

    fn take_state(&mut self) -> Self::State {
        // TODO: remove unwrap
        self.state.take().unwrap()
    }

    fn set_state(&mut self, state: Self::State) {
        self.state = Some(state);
    }
}

pub fn new_handshake_pair(
    role: Role,
    magic: MagicType,
    our_key: EcdhPoint,
) -> (HandshakeReadParser, HandshakeWriteParser) {
    let state = Rc::new(RefCell::new(HandshakeState::new(role, magic, our_key)));
    let reader = HandshakeReadParser::new_with_state(Rc::clone(&state));
    let writer = HandshakeWriteParser::new_with_state(state);
    (reader, writer)
}

#[cfg(test)]
mod tests;
