pub mod bip324;
pub mod cipher;
pub mod external;
mod fmt_utils;
pub mod protocol;
pub mod relay;
pub mod state_machine;

use std::cell::RefCell;
use std::cmp;
use std::error::Error;
use std::io;
use std::io::Write;
use std::rc::Rc;

use secp256k1::ellswift::ElligatorSwift;
use secp256k1::rand::{CryptoRng, RngCore};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use thiserror::Error;

use crate::bip324::{DataReadParser, DataWriteParser, HandshakeReadParser, HandshakeWriteParser};
use crate::cipher::{InboundCipher, OutboundCipher};
use crate::protocol::{
    AADType, EcdhPoint, GarbageTerminatorType, MAINNET_MAGIC, MagicType, NUM_ELLIGATOR_SWIFT_BYTES,
    NUM_SECRET_BYTES, REGTEST_MAGIC, Role, TESTNET_MAGIC,
};
use crate::relay::{FakePeerRelay, FakePeerRelayReader, FakePeerRelayWriter};
use crate::state_machine::{
    BufReader, BufWriter, HasFinal, ProtocolReadParser, ProtocolStatus, ProtocolWriteParser,
    StreamReadParser, StreamWriteParser,
};

#[derive(Error, Debug)]
pub enum BIP324MitmError {
    #[error("IO Read error")]
    ReadError(std::io::Error),

    #[error("IO Write error")]
    WriteError(std::io::Error),

    #[error("Key generation error")]
    KeyGenerationError,

    #[error("Garbage limit exceeded error")]
    GarbageLimitExceededError,

    #[error("Illegal state")]
    IllegalState(String),
}

use BIP324MitmError::*;

impl From<crate::bip324::Bip324Error> for BIP324MitmError {
    fn from(e: crate::bip324::Bip324Error) -> Self {
        use crate::bip324::Bip324Error as E;
        match e {
            E::ReadError(err) => BIP324MitmError::ReadError(err),
            E::KeyGenerationError => BIP324MitmError::KeyGenerationError,
            E::GarbageLimitExceededError => BIP324MitmError::GarbageLimitExceededError,
            E::IllegalState(msg) => BIP324MitmError::IllegalState(msg),
        }
    }
}

// A BufWriter wrapper that limits how many bytes can be written per step().
// Used to implement relay-channel pacing in handshake writers.
struct LimitedWriter<'a> {
    inner: &'a mut dyn BufWriter,
    limit: usize,
}

impl Write for LimitedWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let to_write = cmp::min(buf.len(), self.limit);
        if to_write == 0 {
            return Ok(0);
        }
        let written = self.inner.write(&buf[..to_write])?;
        self.limit -= written;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl BufWriter for LimitedWriter<'_> {
    fn remaining(&self) -> usize {
        cmp::min(self.limit, self.inner.remaining())
    }

    fn prewrite(&mut self, amount: usize) -> io::Result<&mut [u8]> {
        let size = cmp::min(amount, self.remaining());
        self.limit -= size;
        self.inner.prewrite(size)
    }
}

#[allow(clippy::large_enum_variant)]
pub enum ReaderLegState {
    Handshake(MitmHandshakeImpersonatorLegReader),
    Data(MitmImpersonatorLegReader),
}

impl HasFinal for ReaderLegState {
    /// Always returns false
    fn is_final(&self) -> bool {
        false
    }
}

#[allow(clippy::large_enum_variant)]
pub enum WriterLegState {
    Handshake(MitmHandshakeImpersonatorLegWriter),
    Data(MitmImpersonatorLegWriter),
}

impl HasFinal for WriterLegState {
    fn is_final(&self) -> bool {
        false
    }
}

pub struct MitmImpersonatorLeg {
    reader_leg_state: Option<ReaderLegState>,
    writer_leg_state: Option<WriterLegState>,
}

impl MitmImpersonatorLeg {
    pub fn new(
        role: Role,
        magic: MagicType,
        relay_in: Rc<RefCell<dyn FakePeerRelayReader>>,
        relay_out: Rc<RefCell<dyn FakePeerRelayWriter>>,
        secret_key: EcdhPoint,
    ) -> Self {
        let (bip324_reader, bip324_writer) = bip324::new_handshake_pair(role, magic, secret_key);
        let reader_leg = MitmHandshakeImpersonatorLegReader::new(relay_out, bip324_reader);
        let writer_leg = MitmHandshakeImpersonatorLegWriter::new(relay_in, bip324_writer);

        Self {
            reader_leg_state: Some(ReaderLegState::Handshake(reader_leg)),
            writer_leg_state: Some(WriterLegState::Handshake(writer_leg)),
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

    pub fn set_secret(
        &mut self,
        secret: [u8; NUM_SECRET_BYTES],
    ) -> Result<(), ([u8; NUM_SECRET_BYTES], BIP324MitmError)> {
        match (&mut self.reader_leg_state, &mut self.writer_leg_state) {
            (
                Some(ReaderLegState::Handshake(reader_leg)),
                Some(WriterLegState::Handshake(writer_leg)),
            ) => {
                if writer_leg.writer_started_sending() {
                    return Err((
                        secret,
                        IllegalState(
                            "Can't change secret: writer has already started sending".to_string(),
                        ),
                    ));
                }
                reader_leg.set_secret(secret)?;
                Ok(())
            }
            _ => Err((
                secret,
                IllegalState("Invalid state for set_secret".to_string()),
            )),
        }
    }
}

impl ProtocolReadParser for MitmImpersonatorLeg {
    type State = ReaderLegState;
    type Error = BIP324MitmError;

    fn transition(
        &mut self,
        state: Self::State,
        data: &mut dyn BufReader,
    ) -> (Self::State, Result<ProtocolStatus, Self::Error>) {
        use ReaderLegState::*;

        match state {
            Handshake(mut reader_leg) => {
                // TODO: replace unwrap
                if let Err(err) = reader_leg.consume(data) {
                    return (Handshake(reader_leg), Err(err));
                }

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
        }
    }

    fn take_state(&mut self) -> Self::State {
        self.reader_leg_state.take().unwrap()
    }

    fn set_state(&mut self, state: Self::State) {
        self.reader_leg_state = Some(state);
    }
}

impl ProtocolWriteParser for MitmImpersonatorLeg {
    type State = WriterLegState;
    type Error = BIP324MitmError;

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
                    if writer_leg.parser.has_outbound_cipher() {
                        let new_writer_leg = writer_leg.next_phase().unwrap();
                        (Data(new_writer_leg), Ok(ProtocolStatus::End))
                    } else {
                        // Cipher not yet forwarded from reader; stay in handshake
                        (Handshake(writer_leg), Ok(ProtocolStatus::End))
                    }
                } else {
                    (Handshake(writer_leg), Ok(ProtocolStatus::End))
                }
            }
            Data(mut writer_leg) => {
                // TODO: replace unwrap
                writer_leg.produce(data).unwrap();

                (Data(writer_leg), Ok(ProtocolStatus::End))
            }
        }
    }

    fn take_state(&mut self) -> Self::State {
        self.writer_leg_state.take().unwrap()
    }

    fn set_state(&mut self, state: Self::State) {
        self.writer_leg_state = Some(state);
    }
}

pub struct MitmHandshakeImpersonatorLegReader {
    pub parser: HandshakeReadParser,
    relay_out: Rc<RefCell<dyn FakePeerRelayWriter>>,
}

impl MitmHandshakeImpersonatorLegReader {
    pub fn new(
        relay_out: Rc<RefCell<dyn FakePeerRelayWriter>>,
        parser: HandshakeReadParser,
    ) -> Self {
        Self { parser, relay_out }
    }

    pub fn set_secret(
        &mut self,
        secret: [u8; NUM_SECRET_BYTES],
    ) -> Result<(), ([u8; NUM_SECRET_BYTES], BIP324MitmError)> {
        if self.parser.is_handshake_done() {
            return Err((
                secret,
                IllegalState("Can't change secret. Handshake is already done".to_string()),
            ));
        }

        let secret_key = key_from_secret_bytes(secret).map_err(|_| {
            (
                secret,
                IllegalState("Can't generate EC scalar from secret key bytes".to_string()),
            )
        })?;

        self.parser
            .set_ecdh_point(secret_key)
            .map_err(|(_, err)| (secret, err.into()))?;

        Ok(())
    }

    pub fn is_final(&self) -> bool {
        self.parser.is_handshake_done()
    }

    pub fn is_receiving_key(&self) -> bool {
        self.parser.is_receiving_key()
    }

    pub fn is_receiving_garbage(&self) -> bool {
        self.parser.is_receiving_garbage()
    }

    pub fn inbound_garbage_terminator(&self) -> Option<&GarbageTerminatorType> {
        self.parser.inbound_garbage_terminator()
    }

    pub fn next_phase(self) -> Option<MitmImpersonatorLegReader> {
        if !self.parser.is_handshake_done() {
            return None;
        }
        let (data_parser, aad) = self.parser.into_data_reader();
        Some(MitmImpersonatorLegReader::new_from_parser(
            self.relay_out,
            data_parser,
            &aad,
        ))
    }
}

impl StreamReadParser for MitmHandshakeImpersonatorLegReader {
    type Error = BIP324MitmError;

    fn step(&mut self, data: &mut dyn BufReader) -> Result<ProtocolStatus, Self::Error> {
        let status = self.parser.step(data)?;

        // Forward key bytes to relay
        let key_bytes = self.parser.drain_key_bytes();
        if !key_bytes.is_empty() {
            self.relay_out
                .borrow_mut()
                .write_key(&key_bytes)
                .map_err(ReadError)?;
        }
        if self.parser.is_key_eof() {
            self.relay_out.borrow_mut().set_eof_key();
        }

        // Forward garbage bytes to relay
        let garbage_bytes = self.parser.drain_garbage_bytes();
        if !garbage_bytes.is_empty() {
            self.relay_out
                .borrow_mut()
                .write_garbage(&garbage_bytes)
                .map_err(ReadError)?;
        }
        if self.parser.is_garbage_eof() {
            self.relay_out.borrow_mut().set_eof_garbage();
        }

        // Forward terminator bytes to relay
        let terminator_bytes = self.parser.drain_terminator_bytes();
        if !terminator_bytes.is_empty() {
            self.relay_out
                .borrow_mut()
                .write_terminator(&terminator_bytes)
                .map_err(ReadError)?;
            self.relay_out.borrow_mut().set_eof_terminator();
        }

        Ok(status)
    }
}

pub struct MitmHandshakeImpersonatorLegWriter {
    pub parser: HandshakeWriteParser,
    relay_in: Rc<RefCell<dyn FakePeerRelayReader>>,
}

impl MitmHandshakeImpersonatorLegWriter {
    pub fn new(
        relay_in: Rc<RefCell<dyn FakePeerRelayReader>>,
        parser: HandshakeWriteParser,
    ) -> Self {
        Self { parser, relay_in }
    }

    pub fn is_final(&self) -> bool {
        self.parser.is_done()
    }

    pub fn writer_started_sending(&self) -> bool {
        self.parser.writer_started_sending()
    }

    pub fn next_phase(self) -> Option<MitmImpersonatorLegWriter> {
        if !self.parser.has_outbound_cipher() {
            return None;
        }
        let data_writer = self.parser.into_data_writer();
        Some(MitmImpersonatorLegWriter::new_from_parser(
            self.relay_in,
            data_writer,
        ))
    }
}

impl StreamWriteParser for MitmHandshakeImpersonatorLegWriter {
    type Error = ();

    fn step(&mut self, data: &mut dyn BufWriter) -> Result<ProtocolStatus, Self::Error> {
        if self.parser.is_sending_key() {
            // Pacing: only write as many key bytes as the real peer has signalled
            let available = self.relay_in.borrow().peek_len_key();
            if available == 0 {
                return Ok(ProtocolStatus::End);
            }
            let limit = cmp::min(available, data.remaining());
            let mut pacing_buf = vec![0u8; limit];
            let size = self
                .relay_in
                .borrow_mut()
                .read_key(&mut pacing_buf)
                .unwrap();
            if size == 0 {
                return Ok(ProtocolStatus::End);
            }
            let mut limited = LimitedWriter {
                inner: data,
                limit: size,
            };
            return self.parser.step(&mut limited);
        }

        if self.parser.is_sending_garbage() {
            // Push available relay garbage into parser, then step
            let available = self.relay_in.borrow().peek_len_garbage();
            if available > 0 {
                let mut buf = vec![0u8; available];
                let size = self.relay_in.borrow_mut().read_garbage(&mut buf).unwrap();
                self.parser.push_garbage_bytes(&buf[..size]);
            }
            if self.relay_in.borrow().is_eof_garbage() {
                self.parser.set_garbage_eof();
            }
        }

        if self.parser.is_sending_terminator() {
            // Pacing: only write as many terminator bytes as the real peer has sent
            let available = self.relay_in.borrow().peek_len_terminator();
            if available == 0 {
                return Ok(ProtocolStatus::End);
            }
            let limit = cmp::min(available, data.remaining());
            let mut pacing_buf = vec![0u8; limit];
            let size = self
                .relay_in
                .borrow_mut()
                .read_terminator(&mut pacing_buf)
                .unwrap();
            if size == 0 {
                return Ok(ProtocolStatus::End);
            }
            let mut limited = LimitedWriter {
                inner: data,
                limit: size,
            };
            return self.parser.step(&mut limited);
        }

        self.parser.step(data)
    }
}

pub struct MitmImpersonatorLegReader {
    parser: DataReadParser,
    relay_out: Rc<RefCell<dyn FakePeerRelayWriter>>,
}

impl MitmImpersonatorLegReader {
    pub fn new(
        aad: AADType,
        relay_out: Rc<RefCell<dyn FakePeerRelayWriter>>,
        inbound_cipher: InboundCipher,
    ) -> Self {
        let parser = DataReadParser::new(aad.clone(), inbound_cipher);
        relay_out.borrow_mut().set_aad(&aad);
        Self { parser, relay_out }
    }

    /// Create a data-phase reader from an already-built `DataReadParser`.
    ///
    /// `aad` must be the same garbage content that was fed to `DataReadParser::new()` so that
    /// the relay is informed of the connection's AAD before the first packet arrives.
    pub(crate) fn new_from_parser(
        relay_out: Rc<RefCell<dyn FakePeerRelayWriter>>,
        parser: DataReadParser,
        aad: &[u8],
    ) -> Self {
        relay_out.borrow_mut().set_aad(aad);
        Self { parser, relay_out }
    }
}

impl StreamReadParser for MitmImpersonatorLegReader {
    type Error = ();

    fn step(&mut self, data: &mut dyn BufReader) -> Result<ProtocolStatus, Self::Error> {
        let status = self.parser.step(data)?;

        let length_bytes = self.parser.drain_length_bytes();
        if !length_bytes.is_empty() {
            self.relay_out
                .borrow_mut()
                .write_length_bytes(&length_bytes);
        }

        let data_bytes = self.parser.drain_data_bytes();
        if !data_bytes.is_empty() {
            self.relay_out.borrow_mut().write_data_bytes(&data_bytes);
        }

        let tag_bytes = self.parser.drain_tag_bytes();
        if !tag_bytes.is_empty() {
            self.relay_out.borrow_mut().write_tag_bytes(&tag_bytes);
        }

        if let Some(aad) = self.parser.take_aad() {
            self.relay_out.borrow_mut().set_aad(&aad);
        }

        Ok(status)
    }
}

pub struct MitmImpersonatorLegWriter {
    parser: DataWriteParser,
    relay_in: Rc<RefCell<dyn FakePeerRelayReader>>,
}

impl MitmImpersonatorLegWriter {
    pub fn new(
        relay_in: Rc<RefCell<dyn FakePeerRelayReader>>,
        outbound_cipher: OutboundCipher,
    ) -> Self {
        let parser = DataWriteParser::new(outbound_cipher);
        Self { parser, relay_in }
    }

    pub(crate) fn new_from_parser(
        relay_in: Rc<RefCell<dyn FakePeerRelayReader>>,
        parser: DataWriteParser,
    ) -> Self {
        Self { parser, relay_in }
    }
}

impl StreamWriteParser for MitmImpersonatorLegWriter {
    type Error = ();

    fn step(&mut self, data: &mut dyn BufWriter) -> Result<ProtocolStatus, Self::Error> {
        // Only push new bytes from relay when the parser has consumed the previous segment.
        // This prevents mixing bytes from different packets into the same parser input buffer.
        if self.parser.peek_input_length_bytes() == 0 {
            let available = self.relay_in.borrow().peek_length_bytes();
            if available > 0 {
                let mut buf = vec![0u8; available];
                let size = self.relay_in.borrow_mut().read_length_bytes(&mut buf);
                self.parser.push_length_bytes(&buf[..size]);
            }
        }
        if self.parser.peek_input_data_bytes() == 0 {
            let available = self.relay_in.borrow().peek_data_bytes();
            if available > 0 {
                let mut buf = vec![0u8; available];
                let size = self.relay_in.borrow_mut().read_data_bytes(&mut buf);
                self.parser.push_data_bytes(&buf[..size]);
            }
        }
        if self.parser.peek_input_tag_bytes() == 0 {
            let available = self.relay_in.borrow().peek_tag_bytes();
            if available > 0 {
                let mut buf = vec![0u8; available];
                let size = self.relay_in.borrow_mut().read_tag_bytes(&mut buf);
                self.parser.push_tag_bytes(&buf[..size]);
            }
        }
        if let Some(aad) = self.relay_in.borrow_mut().read_aad() {
            self.parser.set_aad(&aad);
        }

        self.parser.step(data)
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

pub struct MitmBIP324 {
    pub client_leg: MitmImpersonatorLeg,
    pub server_leg: MitmImpersonatorLeg,
}

impl MitmBIP324 {
    pub fn new_from_magic_and_secrets(
        magic: MagicType,
        client_secret_key: [u8; NUM_SECRET_BYTES],
        server_secret_key: [u8; NUM_SECRET_BYTES],
    ) -> Result<Self, String> {
        let relay_to_fake_server = Rc::new(RefCell::new(FakePeerRelay::default()));
        let relay_to_fake_client = Rc::new(RefCell::new(FakePeerRelay::default()));
        let client_leg = MitmImpersonatorLeg::new_fake_client(
            magic,
            relay_to_fake_client.clone(),
            relay_to_fake_server.clone(),
            key_from_secret_bytes(client_secret_key)
                .map_err(|_| "Can't generate client secret_key")?,
        );
        let server_leg = MitmImpersonatorLeg::new_fake_server(
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

    pub fn new_from_ecdh_points(
        magic: MagicType,
        client_secret_key: EcdhPoint,
        server_secret_key: EcdhPoint,
    ) -> Self {
        let relay_to_fake_server = Rc::new(RefCell::new(FakePeerRelay::default()));
        let relay_to_fake_client = Rc::new(RefCell::new(FakePeerRelay::default()));
        let client_leg = MitmImpersonatorLeg::new_fake_client(
            magic,
            relay_to_fake_client.clone(),
            relay_to_fake_server.clone(),
            client_secret_key,
        );
        let server_leg = MitmImpersonatorLeg::new_fake_server(
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

        Ok(Self::new_from_ecdh_points(
            magic,
            client_ecdh_key,
            server_ecdh_key,
        ))
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

    pub fn new<Rng: RngCore + CryptoRng>(rng: &mut Rng) -> Result<Self, String> {
        Self::new_from_magic(MAINNET_MAGIC, rng)
    }

    pub fn new_testnet<Rng: RngCore + CryptoRng>(rng: &mut Rng) -> Result<Self, String> {
        Self::new_from_magic(TESTNET_MAGIC, rng)
    }

    pub fn new_regtest<Rng: RngCore + CryptoRng>(rng: &mut Rng) -> Result<Self, String> {
        Self::new_from_magic(REGTEST_MAGIC, rng)
    }

    pub fn new_from_magic<Rng: RngCore + CryptoRng>(
        magic: MagicType,
        rng: &mut Rng,
    ) -> Result<Self, String> {
        let mut client_secret_key = [0u8; 32];
        RngCore::fill_bytes(rng, &mut client_secret_key);
        debug_assert_ne!([0u8; NUM_SECRET_BYTES], client_secret_key);
        let mut server_secret_key = [0u8; 32];
        RngCore::fill_bytes(rng, &mut server_secret_key);
        debug_assert_ne!([0u8; NUM_SECRET_BYTES], server_secret_key);

        Self::new_from_magic_and_secrets(magic, client_secret_key, server_secret_key)
    }

    pub fn set_server_secret(
        &mut self,
        secret: [u8; NUM_SECRET_BYTES],
    ) -> Result<(), ([u8; NUM_SECRET_BYTES], BIP324MitmError)> {
        self.server_leg.set_secret(secret)
    }

    pub fn set_client_secret(
        &mut self,
        secret: [u8; NUM_SECRET_BYTES],
    ) -> Result<(), ([u8; NUM_SECRET_BYTES], BIP324MitmError)> {
        self.client_leg.set_secret(secret)
    }

    pub fn client_write(&mut self, mut data: &[u8]) -> Result<(), BIP324MitmError> {
        self.server_leg.consume(&mut data)
    }

    pub fn server_write(&mut self, mut data: &[u8]) -> Result<(), BIP324MitmError> {
        self.client_leg.consume(&mut data)
    }

    pub fn client_read(&mut self, mut buf: &mut [u8]) -> Result<usize, BIP324MitmError> {
        let initial_buf_len = buf.len();
        let res = self.server_leg.produce(&mut buf);
        let written = initial_buf_len - buf.len();

        res.map(|_| written)
    }

    pub fn server_read(&mut self, mut buf: &mut [u8]) -> Result<usize, BIP324MitmError> {
        let initial_buf_len = buf.len();
        let res = self.client_leg.produce(&mut buf);
        let written = initial_buf_len - buf.len();

        res.map(|_| written)
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

#[allow(non_upper_case_globals)]
#[cfg(test)]
mod mitmfakepeerbip324_tests {
    use super::*;
    use hex_literal::hex;
    use secp256k1::ellswift::ElligatorSwiftParty;
    use secp256k1::rand::rngs::mock::StepRng;
    use std::str::FromStr;

    use crate::cipher::{CipherSession, InboundCipher, OutboundCipher, SessionKeyMaterial};
    use crate::protocol::{NUM_GARBAGE_TERMINATOR_BYTES, NUM_LENGTH_BYTES, PacketType};

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
        MitmImpersonatorLeg,
        Rc<RefCell<FakePeerRelay>>,
        Rc<RefCell<FakePeerRelay>>,
    ) {
        let relay_in = Rc::new(RefCell::new(FakePeerRelay::default()));
        let relay_out = Rc::new(RefCell::new(FakePeerRelay::default()));

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
        );

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

    #[allow(dead_code)]
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

    #[test]
    fn client_key_by_parts() {
        let (mut server, _, _) = get_mitm_fake_server();

        // Send one key byte
        let buf = [0xa3];
        let mut bufref = &buf[..];
        server
            .consume(&mut bufref)
            .expect("Error on pass_peer_data");
        let Some(ReaderLegState::Handshake(ref reader_leg)) = server.reader_leg_state else {
            panic!("Expected handshake state");
        };
        assert!(reader_leg.is_receiving_key());

        // Send another key byte
        let buf = [0xa3];
        let mut bufref = &buf[..];
        server
            .consume(&mut bufref)
            .expect("Error on pass_peer_data");
        let Some(ReaderLegState::Handshake(ref reader_leg)) = server.reader_leg_state else {
            panic!("Expected handshake state");
        };
        assert!(reader_leg.is_receiving_key());

        // Send all the key bytes, except for the last one
        let buf = [0x73; NUM_ELLIGATOR_SWIFT_BYTES - 2 - 1];
        let mut bufref = &buf[..];
        server
            .consume(&mut bufref)
            .expect("Error on pass_peer_data");
        let Some(ReaderLegState::Handshake(ref reader_leg)) = server.reader_leg_state else {
            panic!("Expected handshake state");
        };
        assert!(reader_leg.is_receiving_key());

        // Send all the key bytes, except for the last one
        let buf = [0x29];
        let mut bufref = &buf[..];
        server
            .consume(&mut bufref)
            .expect("Error on pass_peer_data");
        let Some(ReaderLegState::Handshake(ref reader_leg)) = server.reader_leg_state else {
            panic!("Expected handshake state");
        };
        assert!(reader_leg.is_receiving_garbage());
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
        let Some(ReaderLegState::Handshake(ref reader_leg)) = server.reader_leg_state else {
            panic!("Expected handshake state");
        };
        assert!(reader_leg.is_receiving_garbage());
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
        let Some(ReaderLegState::Handshake(ref reader_leg)) = server.reader_leg_state else {
            panic!("Expected handshake state");
        };
        assert!(reader_leg.is_receiving_garbage());
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
        let Some(ReaderLegState::Handshake(ref reader_leg)) = server.reader_leg_state else {
            panic!("Expected handshake state");
        };
        assert!(reader_leg.is_receiving_garbage());

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

        let Some(ReaderLegState::Handshake(reader_leg)) = &server.reader_leg_state else {
            panic!("Wrong leg state");
        };

        assert_eq!(
            reader_leg.parser.elligator_swift_bytes(),
            server_key,
            "The generated secret key is different from the expected one"
        );

        let mut client_keyref = &client_key[..];
        server
            .consume(&mut client_keyref)
            .expect("Error on pass_peer_data");

        let Some(ReaderLegState::Handshake(ref reader_leg)) = server.reader_leg_state else {
            panic!("Wrong leg state");
        };
        assert!(reader_leg.is_receiving_garbage());
        let other_garbage_terminator = *reader_leg
            .inbound_garbage_terminator()
            .expect("Expected garbage terminator to be set");

        let Some(ReaderLegState::Handshake(ref mut reader_leg)) = server.reader_leg_state else {
            panic!("Wrong leg state");
        };

        let inbound_cipher = reader_leg.parser.take_inbound_cipher().unwrap();
        let outbound_cipher = reader_leg.parser.take_outbound_cipher().unwrap();

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
        let Some(ReaderLegState::Handshake(ref reader_leg)) = server.reader_leg_state else {
            panic!("Expected handshake state");
        };
        assert!(reader_leg.is_receiving_garbage());

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

    #[test]
    fn random_data_1() {
        let mut rng = secp256k1::rand::thread_rng();
        let mut mitm = MitmBIP324::new(&mut rng).unwrap();

        mitm.client_write(&hex!("b4916771c194e010218a41e980586d27ae39e8432c9c33c0158fc0f8aba7dc9446b96091e73ea8b85e072d6cb7d420836bb84dc1c90a0e472c6f74bfff16c4b6")).unwrap();
        mitm.server_write(&hex!("262a2fb35253bc482fccd412c2a4203cc69071a0c67f0da66fb4b0439fd2ac17622a8e252cbddae6094440cd5a5458db28c285d57e1e436417d1eaf6541d58d3")).unwrap();

        let garbage = vec![38u8; 4112];
        let res = mitm.client_write(&garbage);
        assert!(matches!(res, Err(GarbageLimitExceededError)));

        let garbage = vec![28u8; 4112];
        let res = mitm.server_write(&garbage);
        assert!(matches!(res, Err(GarbageLimitExceededError)));
    }

    #[test]
    fn random_data_2() {
        let mut rng = secp256k1::rand::thread_rng();
        let mut mitm = MitmBIP324::new(&mut rng).unwrap();

        mitm.client_write(&hex!("b4916771c194e010218a41e980586d27ae39e8432c9c33c0158fc0f8aba7dc9446b96091e73ea8b85e072d6cb7d420836bb84dc1c90a0e472c6f74bfff16c4b6")).unwrap();

        let garbage = vec![38u8; 4112];
        let res = mitm.client_write(&garbage);
        assert!(matches!(res, Err(GarbageLimitExceededError)));
    }

    #[test]
    fn random_data_3() {
        let mut rng = secp256k1::rand::thread_rng();
        let mut mitm = MitmBIP324::new(&mut rng).unwrap();

        mitm.client_write(&hex!("b4916771c194e010218a41e980586d27ae39e8432c9c33c0158fc0f8aba7dc9446b96091e73ea8b85e072d6cb7d420836bb84dc1c90a0e472c6f74bfff16c4b6")).unwrap();

        let garbage = vec![38u8; 4111];
        mitm.client_write(&garbage).unwrap();

        let last_byte = vec![1u8; 1];
        let res = mitm.client_write(&last_byte);
        assert!(matches!(res, Err(GarbageLimitExceededError)));
    }

    #[test]
    fn test_server_sends_one_message_after_terminator() {
        let mut rng = secp256k1::rand::thread_rng();
        let mut mitm = MitmBIP324::new(&mut rng).unwrap();

        let bytes = secret_key_bytes_from_rng(&mut rng);
        let client_key = key_from_secret_bytes(bytes).unwrap();
        let (mut client_reader, mut client_writer) =
            bip324::new_handshake_pair(protocol::Role::Initiator, MAINNET_MAGIC, client_key);

        let bytes = secret_key_bytes_from_rng(&mut rng);
        let server_key = key_from_secret_bytes(bytes).unwrap();
        let (mut server_reader, mut server_writer) =
            bip324::new_handshake_pair(protocol::Role::Responder, MAINNET_MAGIC, server_key);

        client_writer.push_garbage_bytes(&[0x77u8; 1301]);
        client_writer.set_garbage_eof();
        let server_garbage = [0x59u8; 1577];
        server_writer.push_garbage_bytes(&server_garbage);
        server_writer.set_garbage_eof();

        let mut buf = [0u8; 8192];
        let buf_len = buf.len();
        // Client -- key + garbage --> MITM
        {
            let mut bufref = &mut buf[..];
            client_writer.produce(&mut bufref).unwrap();
            let written = buf_len - bufref.len();
            mitm.client_write(&buf[..written]).unwrap();
        }

        // MITM -- key + garbage --> Server
        {
            let size = mitm.server_read(&mut buf[..]).unwrap();
            let mut bufref = &buf[..size];
            server_reader.consume(&mut bufref).unwrap();
            assert!(
                bufref.is_empty(),
                "buffer was not emptied for server_writer.consume"
            );
        }

        let mut bufref = &mut buf[..];
        // Writes key + garbage + terminator
        server_writer.produce(&mut bufref).unwrap();
        let server_handshake_size = buf_len - bufref.len();
        let mut server_writer = server_writer.into_data_writer();

        // Writes [msg1]
        server_writer.push_length_bytes(&[10u8, 0u8, 0u8]);
        server_writer.push_data_bytes(&[1u8; 11]);
        server_writer.push_tag_bytes(&[0u8; 16]);
        server_writer.produce(&mut bufref).unwrap();

        // Server -- key + garbage + terminator + [msg1] --> MITM
        {
            let written = buf_len - bufref.len();
            mitm.server_write(&buf[..written]).unwrap();
        }

        // MITM -- key + garbage + terminator --> Client
        {
            let bufref = &mut buf[..server_handshake_size];
            let size = mitm.client_read(bufref).unwrap();
            assert_eq!(size, server_handshake_size);
            let mut bufref = &buf[..size];
            client_reader.consume(&mut bufref).unwrap();
            assert!(
                bufref.is_empty(),
                "handshake was not emptied for client_reader.consume"
            );
        }

        assert_eq!(client_reader.drain_key_bytes().len(), 64);
        assert!(client_reader.is_key_eof());
        assert_eq!(client_reader.drain_garbage_bytes(), server_garbage);
        assert_eq!(client_reader.drain_terminator_bytes().len(), 16);
        assert!(client_reader.is_garbage_eof());

        let (mut client_reader, _aad) = client_reader.into_data_reader();

        // MITM -- [msg1] --> Client
        {
            let size = mitm.client_read(&mut buf[..]).unwrap();
            let mut bufref = &buf[..size];
            client_reader.consume(&mut bufref).unwrap();
            assert!(
                bufref.is_empty(),
                "data not emptied for client_reader.consume"
            );
        }
        assert_eq!(client_reader.drain_length_bytes(), vec![10u8, 0u8, 0u8]);
        assert_eq!(client_reader.drain_data_bytes(), vec![1u8; 11]);
        assert_eq!(client_reader.drain_tag_bytes().len(), 16);

        // Writes to the buffer [msg2] [msg3]
        let mut bufref = &mut buf[..];
        for _ in 0..2 {
            server_writer.push_length_bytes(&[10u8, 0u8, 0u8]);
            server_writer.push_data_bytes(&[1u8; 11]);
            server_writer.push_tag_bytes(&[0u8; 16]);
            server_writer.produce(&mut bufref).unwrap();
        }

        // Server -- [msg2] [msg3] --> MITM
        {
            let written = buf_len - bufref.len();
            mitm.server_write(&buf[..written]).unwrap();
        }

        // MITM -- [msg2] [msg3] --> Client
        {
            let size = mitm.client_read(&mut buf[..]).unwrap();
            let mut bufref = &buf[..size];
            client_reader.consume(&mut bufref).unwrap();
            assert!(
                bufref.is_empty(),
                "data not emptied for client_reader.consume"
            );
        }
        assert_eq!(
            client_reader.drain_length_bytes(),
            vec![10u8, 0u8, 0u8, 10u8, 0u8, 0u8]
        );
        assert_eq!(client_reader.drain_data_bytes(), vec![1u8; 11 * 2]);
        assert_eq!(client_reader.drain_tag_bytes().len(), 32);
    }

    #[test]
    fn test_client_sends_one_message_after_terminator() {
        let mut rng = secp256k1::rand::thread_rng();
        let mut mitm = MitmBIP324::new(&mut rng).unwrap();

        let bytes = secret_key_bytes_from_rng(&mut rng);
        let client_key = key_from_secret_bytes(bytes).unwrap();
        let (mut client_reader, mut client_writer) =
            bip324::new_handshake_pair(protocol::Role::Initiator, MAINNET_MAGIC, client_key);

        let bytes = secret_key_bytes_from_rng(&mut rng);
        let server_key = key_from_secret_bytes(bytes).unwrap();
        let (mut server_reader, mut server_writer) =
            bip324::new_handshake_pair(protocol::Role::Responder, MAINNET_MAGIC, server_key);

        let client_garbage = [0x77u8; 1301];
        client_writer.push_garbage_bytes(&client_garbage);
        client_writer.set_garbage_eof();
        let server_garbage = [0x59u8; 1577];
        server_writer.push_garbage_bytes(&server_garbage);
        server_writer.set_garbage_eof();

        let mut buf = [0u8; 8192];
        let buf_len = buf.len();
        // Client -- key + garbage --> MITM
        {
            let mut bufref = &mut buf[..];
            client_writer.produce(&mut bufref).unwrap();
            let written = buf_len - bufref.len();
            mitm.client_write(&buf[..written]).unwrap();
        }

        // MITM -- key + garbage --> Server
        {
            println!("Mitm server_read");
            let size = mitm.server_read(&mut buf[..]).unwrap();
            println!("-------");
            println!("Csize1: {}", size);
            let mut bufref = &buf[..size];
            server_reader.consume(&mut bufref).unwrap();
            assert!(
                bufref.is_empty(),
                "buffer was not emptied for server_writer.consume"
            );
        }

        let mut bufref = &mut buf[..];
        // Writes key + garbage + terminator
        server_writer.produce(&mut bufref).unwrap();
        let server_handshake_size = buf_len - bufref.len();
        let mut server_writer = server_writer.into_data_writer();

        // Writes [msg1]
        {
            server_writer.push_length_bytes(&[10u8, 0u8, 0u8]);
            server_writer.push_data_bytes(&[1u8; 11]);
            server_writer.push_tag_bytes(&[0u8; 16]);
            server_writer.produce(&mut bufref).unwrap();
        }

        // Server -- key + garbage + terminator + [msg1] --> MITM
        {
            let written = buf_len - bufref.len();
            mitm.server_write(&buf[..written]).unwrap();
        }

        // MITM -- key + garbage + terminator --> Client
        {
            let bufref = &mut buf[..server_handshake_size];
            let size = mitm.client_read(bufref).unwrap();
            assert_eq!(size, server_handshake_size);
            let mut bufref = &buf[..size];
            client_reader.consume(&mut bufref).unwrap();
            assert!(
                bufref.is_empty(),
                "handshake was not emptied for client_reader.consume"
            );
        }

        assert_eq!(client_reader.drain_key_bytes().len(), 64);
        assert!(client_reader.is_key_eof());
        assert_eq!(client_reader.drain_garbage_bytes(), server_garbage);
        assert_eq!(client_reader.drain_terminator_bytes().len(), 16);
        assert!(client_reader.is_garbage_eof());

        let (mut client_reader, _aad) = client_reader.into_data_reader();

        // MITM -- [msg1] --> Client
        {
            let size = mitm.client_read(&mut buf[..]).unwrap();
            let mut bufref = &buf[..size];
            client_reader.consume(&mut bufref).unwrap();
            assert!(
                bufref.is_empty(),
                "data not emptied for client_reader.consume"
            );
        }
        assert_eq!(client_reader.drain_length_bytes(), vec![10u8, 0u8, 0u8]);
        assert_eq!(client_reader.drain_data_bytes(), vec![1u8; 11]);
        assert_eq!(client_reader.drain_tag_bytes().len(), 16);

        // Writes terminator to the buffer
        let mut bufref = &mut buf[..];
        client_writer.produce(&mut bufref).unwrap();

        // Client -- terminator --> MITM
        {
            let written = buf_len - bufref.len();
            mitm.client_write(&buf[..written]).unwrap();
        }

        // MITM -- [15 byte garbage] terminator --> Server
        {
            println!("Mitm server_read");
            let size = mitm.server_read(&mut buf[..]).unwrap();
            println!("-------");
            println!("CSize2: {}", size);
            let mut bufref = &buf[..size];
            server_reader.consume(&mut bufref).unwrap();
            assert!(
                bufref.is_empty(),
                "data not emptied for server_reader.consume"
            );
        }
        assert_eq!(server_reader.drain_key_bytes().len(), 64);
        assert!(server_reader.is_key_eof());
        assert_eq!(server_reader.drain_garbage_bytes(), client_garbage);
        assert_eq!(server_reader.drain_terminator_bytes().len(), 16);
        assert!(server_reader.is_garbage_eof());

        let mut client_writer = client_writer.into_data_writer();
        let (mut server_reader, _aad) = server_reader.into_data_reader();

        // Writes to the buffer [msg1] [msg2]
        let mut bufref = &mut buf[..];
        for _ in 0..2 {
            client_writer.push_length_bytes(&[10u8, 0u8, 0u8]);
            client_writer.push_data_bytes(&[1u8; 11]);
            client_writer.push_tag_bytes(&[0u8; 16]);
            client_writer.produce(&mut bufref).unwrap();
        }

        // Client -- [msg2] [msg3] --> MITM
        {
            let written = buf_len - bufref.len();
            mitm.client_write(&buf[..written]).unwrap();
        }

        // MITM -- [msg2] [msg3] --> Server
        {
            let size = mitm.server_read(&mut buf[..]).unwrap();
            let mut bufref = &buf[..size];
            server_reader.consume(&mut bufref).unwrap();
            assert!(
                bufref.is_empty(),
                "data not emptied for server_reader.consume"
            );
        }
        assert_eq!(
            server_reader.drain_length_bytes(),
            vec![10u8, 0u8, 0u8, 10u8, 0u8, 0u8]
        );
        assert_eq!(server_reader.drain_data_bytes(), vec![1u8; 11 * 2]);
        assert_eq!(server_reader.drain_tag_bytes().len(), 32);
    }
}
