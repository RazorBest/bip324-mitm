use std::cell::RefCell;
use std::rc::Rc;

use crate::cipher::{CipherSession, OutboundCipher};
use crate::protocol::{EcdhPoint, GarbageTerminatorType, MagicType, NUM_ELLIGATOR_SWIFT_BYTES, Role};

pub mod data_read;
pub mod data_write;
pub mod handshake_read;
pub mod handshake_write;

pub use data_read::{DataReadParser, DataReadState};
pub use data_write::{DataWriteParser, DataWriteState};
pub use handshake_read::{HandshakeReadParser, HandshakeReadState};
pub use handshake_write::{HandshakeWriteParser, HandshakeWriteState};

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
/// Holds all data that must be visible to both sides during the BIP-324 handshake:
/// our secret key, the peer's key once received, the derived cipher session, and a
/// flag that the writer sets when it starts transmitting our key bytes.
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
mod tests {
    use hex_literal::hex;
    use secp256k1::ellswift::ElligatorSwiftParty;

    use super::{DataReadParser, DataWriteParser, HandshakeReadParser, HandshakeWriteParser};
    use crate::cipher::{InboundCipher, OutboundCipher, SessionKeyMaterial};
    use crate::key_from_secret_bytes;
    use crate::protocol::{MAINNET_MAGIC, NUM_LENGTH_BYTES, NUM_TAG_BYTES, Role};
    use crate::state_machine::{StreamReadParser, StreamWriteParser};

    const MAGIC: [u8; 4] = MAINNET_MAGIC;

    // Fixed deterministic keys used across all integration tests.
    const ALICE_SECRET: [u8; 32] =
        hex!("61062ea5071d800bbfd59e2e8b53d47d194b095ae5a4df04936b49772ef0d4d7");
    const BOB_SECRET: [u8; 32] =
        hex!("6f312890ec83bbb26798abaadd574684a53e74ccef7953b790fcc29409080246");

    // Complete a BIP-324 handshake using new_handshake_pair. Returns ciphers for both sides.
    fn complete_handshake() -> (InboundCipher, OutboundCipher, InboundCipher, OutboundCipher) {
        let alice_key = key_from_secret_bytes(ALICE_SECRET).unwrap();
        let bob_key = key_from_secret_bytes(BOB_SECRET).unwrap();

        let bob_wire_key = bob_key.elligator_swift.to_array().to_vec();
        let alice_wire_key = alice_key.elligator_swift.to_array().to_vec();

        let (mut alice_reader, _alice_writer) =
            super::new_handshake_pair(Role::Initiator, MAGIC, alice_key);
        let (mut bob_reader, _bob_writer) =
            super::new_handshake_pair(Role::Responder, MAGIC, bob_key);

        // Exchange public keys
        alice_reader.consume(&mut bob_wire_key.as_slice()).unwrap();
        bob_reader.consume(&mut alice_wire_key.as_slice()).unwrap();

        // Exchange garbage terminators (no garbage content -- empty garbage is valid)
        let alice_outbound_term = alice_reader.outbound_garbage_terminator().unwrap().to_vec();
        let bob_outbound_term = bob_reader.outbound_garbage_terminator().unwrap().to_vec();

        alice_reader
            .consume(&mut bob_outbound_term.as_slice())
            .unwrap();
        bob_reader
            .consume(&mut alice_outbound_term.as_slice())
            .unwrap();

        assert!(alice_reader.is_handshake_done());
        assert!(bob_reader.is_handshake_done());

        let (alice_inbound, alice_outbound) = alice_reader.take_ciphers().unwrap();
        let (bob_inbound, bob_outbound) = bob_reader.take_ciphers().unwrap();

        (alice_inbound, alice_outbound, bob_inbound, bob_outbound)
    }

    // Encrypt one plaintext packet with DataWriteParser and return the ciphertext.
    fn encrypt_packet(parser: &mut DataWriteParser, plaintext: &[u8]) -> Vec<u8> {
        let len_val = plaintext.len() as u32;
        let length_bytes = len_val.to_le_bytes()[..NUM_LENGTH_BYTES].to_vec();
        let mut data_bytes = vec![0x00u8]; // genuine header byte
        data_bytes.extend_from_slice(plaintext);
        let tag_placeholder = vec![0u8; NUM_TAG_BYTES]; // pacing only; parser overwrites with real AEAD tag

        parser.push_length_bytes(&length_bytes);
        parser.push_data_bytes(&data_bytes);
        parser.push_tag_bytes(&tag_placeholder);

        let out_len = NUM_LENGTH_BYTES + data_bytes.len() + NUM_TAG_BYTES;
        let mut out = vec![0u8; out_len];
        parser.produce(&mut out.as_mut_slice()).unwrap();
        out
    }

    // 1. Both sides exchange keys via HandshakeReadParser and independently derive a matching
    //    session ID. Verifies the ECDH is symmetric and the parsers report completion.
    #[test]
    fn test_handshake_roundtrip() {
        let alice_key_for_session = key_from_secret_bytes(ALICE_SECRET).unwrap();
        let bob_key_for_session = key_from_secret_bytes(BOB_SECRET).unwrap();
        let alice_key_for_parser = key_from_secret_bytes(ALICE_SECRET).unwrap();
        let bob_key_for_parser = key_from_secret_bytes(BOB_SECRET).unwrap();

        // Compute session IDs from both sides independently using raw ECDH
        let alice_session = SessionKeyMaterial::from_ecdh(
            alice_key_for_session.elligator_swift,
            bob_key_for_session.elligator_swift,
            alice_key_for_session.secret_key,
            ElligatorSwiftParty::A,
            MAGIC,
        )
        .unwrap();
        let bob_session = SessionKeyMaterial::from_ecdh(
            alice_key_for_session.elligator_swift, // ElligatorSwift is Copy
            bob_key_for_session.elligator_swift,
            bob_key_for_session.secret_key,
            ElligatorSwiftParty::B,
            MAGIC,
        )
        .unwrap();

        assert_eq!(
            alice_session.session_id, bob_session.session_id,
            "Session IDs must match from both sides"
        );

        // Both sides complete the handshake via parsers alone
        let bob_wire_key = bob_key_for_parser.elligator_swift.to_array().to_vec();
        let alice_wire_key = alice_key_for_parser.elligator_swift.to_array().to_vec();

        let (mut alice_parser, _) =
            super::new_handshake_pair(Role::Initiator, MAGIC, alice_key_for_parser);
        let (mut bob_parser, _) =
            super::new_handshake_pair(Role::Responder, MAGIC, bob_key_for_parser);

        alice_parser.consume(&mut bob_wire_key.as_slice()).unwrap();
        bob_parser.consume(&mut alice_wire_key.as_slice()).unwrap();

        let alice_outbound_term = alice_parser.outbound_garbage_terminator().unwrap().to_vec();
        let bob_outbound_term = bob_parser.outbound_garbage_terminator().unwrap().to_vec();

        alice_parser
            .consume(&mut bob_outbound_term.as_slice())
            .unwrap();
        bob_parser
            .consume(&mut alice_outbound_term.as_slice())
            .unwrap();

        assert!(alice_parser.is_handshake_done(), "Alice handshake must complete");
        assert!(bob_parser.is_handshake_done(), "Bob handshake must complete");
    }

    // 2. Complete handshake bidirectionally, then verify a data roundtrip:
    //    Side A encrypts with DataWriteParser → Side B decrypts with DataReadParser → matches plaintext.
    #[test]
    fn test_full_protocol_flow() {
        let (_alice_inbound, alice_outbound, bob_inbound, _bob_outbound) = complete_handshake();

        let plaintext = b"hello from alice to bob";

        let mut encrypt_parser = DataWriteParser::new(alice_outbound);
        let ciphertext = encrypt_packet(&mut encrypt_parser, plaintext);

        let mut decrypt_parser = DataReadParser::new(vec![], bob_inbound);
        decrypt_parser.consume(&mut ciphertext.as_slice()).unwrap();

        let decrypted = decrypt_parser.drain_data_bytes();
        assert_eq!(decrypted[0], 0x00, "Expected genuine header byte");
        assert_eq!(&decrypted[1..], plaintext, "Decrypted payload must match original plaintext");
    }

    // 3. Demonstrate that the protocol parsers work entirely standalone:
    //    no FakePeerRelay, no external wrapper types are involved.
    //    The reader and writer are created as a coupled pair via new_handshake_pair.
    #[test]
    fn test_protocol_parsers_standalone() {
        let alice_key = key_from_secret_bytes(ALICE_SECRET).unwrap();
        let bob_key = key_from_secret_bytes(BOB_SECRET).unwrap();

        let bob_wire_key = bob_key.elligator_swift.to_array().to_vec();
        let alice_wire_key = alice_key.elligator_swift.to_array().to_vec();

        let (mut alice_hs, _alice_w) =
            super::new_handshake_pair(Role::Initiator, MAGIC, alice_key);
        let (mut bob_hs, _bob_w) = super::new_handshake_pair(Role::Responder, MAGIC, bob_key);

        // Key exchange
        alice_hs.consume(&mut bob_wire_key.as_slice()).unwrap();
        bob_hs.consume(&mut alice_wire_key.as_slice()).unwrap();

        // Terminator exchange
        let alice_term = alice_hs.outbound_garbage_terminator().unwrap().to_vec();
        let bob_term = bob_hs.outbound_garbage_terminator().unwrap().to_vec();
        alice_hs.consume(&mut bob_term.as_slice()).unwrap();
        bob_hs.consume(&mut alice_term.as_slice()).unwrap();

        let (_, alice_outbound) = alice_hs.take_ciphers().unwrap();
        let (bob_inbound, _) = bob_hs.take_ciphers().unwrap();

        // Alice → Bob data transfer using only pure parser objects
        let msg = b"standalone parsers work without any external infrastructure";
        let mut write = DataWriteParser::new(alice_outbound);
        let ct = encrypt_packet(&mut write, msg);

        let mut read = DataReadParser::new(vec![], bob_inbound);
        read.consume(&mut ct.as_slice()).unwrap();

        let plain = read.drain_data_bytes();
        assert_eq!(&plain[1..], msg);
    }

    // 4. Multiple consecutive packets through DataWriteParser → DataReadParser.
    //    Verifies that cipher key ratcheting works correctly across packet boundaries.
    #[test]
    fn test_multiple_packets_roundtrip() {
        let (_alice_inbound, alice_outbound, bob_inbound, _bob_outbound) = complete_handshake();

        let messages: &[&[u8]] = &[b"first message", b"second message", b"third message"];

        let mut write_parser = DataWriteParser::new(alice_outbound);
        let ciphertexts: Vec<Vec<u8>> = messages
            .iter()
            .map(|msg| encrypt_packet(&mut write_parser, msg))
            .collect();

        let mut read_parser = DataReadParser::new(vec![], bob_inbound);
        for (i, (ct, expected)) in ciphertexts.iter().zip(messages.iter()).enumerate() {
            read_parser.consume(&mut ct.as_slice()).unwrap();
            let decrypted = read_parser.drain_data_bytes();
            assert_eq!(&decrypted[1..], *expected, "Packet {i} roundtrip failed");
        }
    }

    // 5. set_ecdh_point fails once the writer has started sending key bytes.
    #[test]
    fn test_set_ecdh_point_after_writer_started() {
        use crate::state_machine::StreamWriteParser;

        let alice_key = key_from_secret_bytes(ALICE_SECRET).unwrap();
        let new_key = key_from_secret_bytes(BOB_SECRET).unwrap();

        let (mut reader, mut writer) =
            super::new_handshake_pair(Role::Initiator, MAGIC, alice_key);

        // Start sending key bytes -- this sets writer_started_sending = true
        let mut buf = vec![0u8; 1];
        writer.step(&mut buf.as_mut_slice()).unwrap();

        // Now set_ecdh_point must return an error
        let result = reader.set_ecdh_point(new_key);
        assert!(
            result.is_err(),
            "set_ecdh_point should fail after writer started sending"
        );
    }

    // 6. set_ecdh_point succeeds before the writer has started sending key bytes.
    #[test]
    fn test_set_ecdh_point_before_writer_started() {
        let alice_key = key_from_secret_bytes(ALICE_SECRET).unwrap();
        let new_key = key_from_secret_bytes(BOB_SECRET).unwrap();

        let (mut reader, _writer) = super::new_handshake_pair(Role::Initiator, MAGIC, alice_key);

        let result = reader.set_ecdh_point(new_key);
        assert!(result.is_ok(), "set_ecdh_point should succeed before writer starts sending");
    }

    // 7. Both sides use new_handshake_pair and derive matching cipher sessions.
    #[test]
    fn test_coupled_handshake() {
        let alice_key = key_from_secret_bytes(ALICE_SECRET).unwrap();
        let bob_key = key_from_secret_bytes(BOB_SECRET).unwrap();

        let alice_wire = alice_key.elligator_swift.to_array().to_vec();
        let bob_wire = bob_key.elligator_swift.to_array().to_vec();

        let (mut alice_reader, _alice_writer) =
            super::new_handshake_pair(Role::Initiator, MAGIC, alice_key);
        let (mut bob_reader, _bob_writer) =
            super::new_handshake_pair(Role::Responder, MAGIC, bob_key);

        // Exchange keys
        alice_reader.consume(&mut bob_wire.as_slice()).unwrap();
        bob_reader.consume(&mut alice_wire.as_slice()).unwrap();

        // Exchange terminators
        let alice_term = alice_reader.outbound_garbage_terminator().unwrap().to_vec();
        let bob_term = bob_reader.outbound_garbage_terminator().unwrap().to_vec();
        alice_reader.consume(&mut bob_term.as_slice()).unwrap();
        bob_reader.consume(&mut alice_term.as_slice()).unwrap();

        let (alice_inbound, alice_outbound) = alice_reader.take_ciphers().unwrap();
        let (bob_inbound, bob_outbound) = bob_reader.take_ciphers().unwrap();

        // Alice's outbound keys must match Bob's inbound keys
        assert_eq!(
            alice_outbound.length_cipher.key_bytes,
            bob_inbound.length_cipher.unwrap().key_bytes,
            "alice outbound length key must equal bob inbound length key"
        );
        assert_eq!(
            alice_outbound.packet_cipher.key_bytes,
            bob_inbound.packet_cipher.key_bytes,
            "alice outbound packet key must equal bob inbound packet key"
        );
        // Bob's outbound keys must match Alice's inbound keys
        assert_eq!(
            bob_outbound.length_cipher.key_bytes,
            alice_inbound.length_cipher.unwrap().key_bytes,
            "bob outbound length key must equal alice inbound length key"
        );
        assert_eq!(
            bob_outbound.packet_cipher.key_bytes,
            alice_inbound.packet_cipher.key_bytes,
            "bob outbound packet key must equal alice inbound packet key"
        );
    }

    // 8. The writer produces the correct ellswift bytes without any explicit key injection.
    #[test]
    fn test_writer_reads_key_from_shared_state() {
        use crate::protocol::NUM_ELLIGATOR_SWIFT_BYTES;
        use crate::state_machine::StreamWriteParser;

        let alice_key = key_from_secret_bytes(ALICE_SECRET).unwrap();
        let expected_bytes = alice_key.elligator_swift.to_array();

        let (_reader, mut writer) =
            super::new_handshake_pair(Role::Initiator, MAGIC, alice_key);

        let mut buf = vec![0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        writer.produce(&mut buf.as_mut_slice()).unwrap();

        assert_eq!(buf, expected_bytes, "Writer must produce the key from shared state");
    }

    // Helper, run a full BIP-324 handshake for both sides using new_handshake_pair.
    // Returns (alice_reader, alice_writer, bob_reader, bob_writer), all in HandshakeDone state.
    fn do_full_handshake() -> (
        HandshakeReadParser,
        HandshakeWriteParser,
        HandshakeReadParser,
        HandshakeWriteParser,
    ) {
        use crate::state_machine::StreamWriteParser;

        let alice_key = key_from_secret_bytes(ALICE_SECRET).unwrap();
        let bob_key = key_from_secret_bytes(BOB_SECRET).unwrap();

        let bob_wire_key = bob_key.elligator_swift.to_array().to_vec();
        let alice_wire_key = alice_key.elligator_swift.to_array().to_vec();

        let (mut alice_reader, mut alice_writer) =
            super::new_handshake_pair(Role::Initiator, MAGIC, alice_key);
        let (mut bob_reader, mut bob_writer) =
            super::new_handshake_pair(Role::Responder, MAGIC, bob_key);

        // Exchange public keys (also derives ECDH, making outbound_garbage_terminator available)
        alice_reader.consume(&mut bob_wire_key.as_slice()).unwrap();
        bob_reader.consume(&mut alice_wire_key.as_slice()).unwrap();

        // Exchange garbage terminators (no garbage content)
        let alice_term = alice_reader.outbound_garbage_terminator().unwrap().to_vec();
        let bob_term = bob_reader.outbound_garbage_terminator().unwrap().to_vec();

        alice_reader.consume(&mut bob_term.as_slice()).unwrap();
        bob_reader.consume(&mut alice_term.as_slice()).unwrap();

        assert!(alice_reader.is_handshake_done());
        assert!(bob_reader.is_handshake_done());

        // Drive write parsers to Done: send key bytes + no garbage + garbage terminator.
        // ECDH is complete, so outbound_garbage_terminator is in shared state.
        alice_writer.set_garbage_eof();
        bob_writer.set_garbage_eof();

        let mut discard = vec![0u8; 256];
        alice_writer.produce(&mut discard.as_mut_slice()).unwrap();
        assert!(alice_writer.is_done(), "alice writer must reach Done after produce()");

        let mut discard = vec![0u8; 256];
        bob_writer.produce(&mut discard.as_mut_slice()).unwrap();
        assert!(bob_writer.is_done(), "bob writer must reach Done after produce()");

        (alice_reader, alice_writer, bob_reader, bob_writer)
    }

    // 9. Complete a handshake, call into_data_reader(), feed encrypted data to the resulting
    //    DataReadParser, and verify decryption works.
    #[test]
    fn test_handshake_reader_into_data_reader() {
        let (alice_reader, alice_writer, bob_reader, _bob_writer) = do_full_handshake();

        // Alice transitions to data phase; outbound cipher is deposited into shared state.
        let (_alice_data_reader, _) = alice_reader.into_data_reader();
        let mut alice_data_writer = alice_writer.into_data_writer();

        // Bob's read transition yields the DataReadParser
        let (mut bob_data_reader, _) = bob_reader.into_data_reader();

        // Alice encrypts, bob decrypts
        let plaintext = b"into_data_reader test";
        let ciphertext = encrypt_packet(&mut alice_data_writer, plaintext);

        bob_data_reader.consume(&mut ciphertext.as_slice()).unwrap();
        let decrypted = bob_data_reader.drain_data_bytes();

        assert_eq!(decrypted[0], 0x00, "Expected genuine header byte");
        assert_eq!(&decrypted[1..], plaintext);
    }

    // 10. Complete a handshake, call into_data_writer(), encrypt data, and verify decryption.
    #[test]
    fn test_handshake_writer_into_data_writer() {
        let (alice_reader, alice_writer, bob_reader, _bob_writer) = do_full_handshake();

        // Alice transitions to data phase (reader stores outbound in shared state)
        let (_alice_data_reader, _) = alice_reader.into_data_reader();
        let mut alice_data_writer = alice_writer.into_data_writer();

        // Bob needs inbound cipher: use take_ciphers on a fresh handshake as a cross-check,
        // but since we're testing the writer we get bob's inbound from his reader transition.
        let (mut bob_data_reader, _) = bob_reader.into_data_reader();

        let plaintext = b"into_data_writer test";
        let ciphertext = encrypt_packet(&mut alice_data_writer, plaintext);

        bob_data_reader.consume(&mut ciphertext.as_slice()).unwrap();
        let decrypted = bob_data_reader.drain_data_bytes();

        assert_eq!(decrypted[0], 0x00, "Expected genuine header byte");
        assert_eq!(&decrypted[1..], plaintext);
    }

    // 11. Both sides do handshake → data transition. Side A encrypts, side B decrypts.
    //     This replaces/extends test_full_protocol_flow by using the new transition methods
    //     instead of take_ciphers().
    #[test]
    fn test_full_transition_roundtrip() {
        let (alice_reader, alice_writer, bob_reader, bob_writer) = do_full_handshake();

        // Both sides transition to data phase using the new methods
        let (_alice_data_reader, _) = alice_reader.into_data_reader();
        let mut alice_data_writer = alice_writer.into_data_writer();

        let (mut bob_data_reader, _) = bob_reader.into_data_reader();
        let _bob_data_writer = bob_writer.into_data_writer();

        // Alice encrypts → Bob decrypts
        let plaintext = b"full transition roundtrip";
        let ciphertext = encrypt_packet(&mut alice_data_writer, plaintext);

        bob_data_reader.consume(&mut ciphertext.as_slice()).unwrap();
        let decrypted = bob_data_reader.drain_data_bytes();

        assert_eq!(decrypted[0], 0x00, "Expected genuine header byte");
        assert_eq!(
            &decrypted[1..],
            plaintext,
            "Decrypted payload must match original plaintext"
        );
    }

    // 12. Call into_data_reader() before the handshake completes → should panic.
    #[test]
    #[should_panic(expected = "Handshake must be done before transitioning to data phase")]
    fn test_into_data_reader_panics_if_not_done() {
        let alice_key = key_from_secret_bytes(ALICE_SECRET).unwrap();
        let (alice_reader, _alice_writer) =
            super::new_handshake_pair(Role::Initiator, MAGIC, alice_key);

        // Handshake not done yet -- should panic
        let _ = alice_reader.into_data_reader();
    }
}
