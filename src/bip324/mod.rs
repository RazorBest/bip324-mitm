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

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use secp256k1::ellswift::ElligatorSwiftParty;

    use super::{DataReadParser, DataWriteParser, HandshakeReadParser};
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

    // Complete a BIP-324 handshake using only HandshakeReadParser objects -- no relay or MITM types.
    // Returns (alice_inbound, alice_outbound, bob_inbound, bob_outbound).
    fn complete_handshake() -> (InboundCipher, OutboundCipher, InboundCipher, OutboundCipher) {
        let alice_key = key_from_secret_bytes(ALICE_SECRET).unwrap();
        let bob_key = key_from_secret_bytes(BOB_SECRET).unwrap();

        let bob_wire_key = bob_key.elligator_swift.to_array().to_vec();
        let alice_wire_key = alice_key.elligator_swift.to_array().to_vec();

        let mut alice_parser = HandshakeReadParser::new(Role::Initiator, MAGIC, alice_key);
        let mut bob_parser = HandshakeReadParser::new(Role::Responder, MAGIC, bob_key);

        // Exchange public keys
        alice_parser.consume(&mut bob_wire_key.as_slice()).unwrap();
        bob_parser.consume(&mut alice_wire_key.as_slice()).unwrap();

        // Exchange garbage terminators (no garbage content -- empty garbage is valid)
        let alice_outbound_term = alice_parser.outbound_garbage_terminator().unwrap().to_vec();
        let bob_outbound_term = bob_parser.outbound_garbage_terminator().unwrap().to_vec();

        alice_parser.consume(&mut bob_outbound_term.as_slice()).unwrap();
        bob_parser.consume(&mut alice_outbound_term.as_slice()).unwrap();

        assert!(alice_parser.is_handshake_done());
        assert!(bob_parser.is_handshake_done());

        let (alice_inbound, alice_outbound) = alice_parser.take_ciphers().unwrap();
        let (bob_inbound, bob_outbound) = bob_parser.take_ciphers().unwrap();

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

        let mut alice_parser =
            HandshakeReadParser::new(Role::Initiator, MAGIC, alice_key_for_parser);
        let mut bob_parser = HandshakeReadParser::new(Role::Responder, MAGIC, bob_key_for_parser);

        alice_parser.consume(&mut bob_wire_key.as_slice()).unwrap();
        bob_parser.consume(&mut alice_wire_key.as_slice()).unwrap();

        let alice_outbound_term = alice_parser.outbound_garbage_terminator().unwrap().to_vec();
        let bob_outbound_term = bob_parser.outbound_garbage_terminator().unwrap().to_vec();

        alice_parser.consume(&mut bob_outbound_term.as_slice()).unwrap();
        bob_parser.consume(&mut alice_outbound_term.as_slice()).unwrap();

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
    //    no FakePeerRelay, no Rc<RefCell<>>, and no MitmImpersonatorLeg are involved.
    //    This is the primary proof that the bip324 module separation was successful.
    #[test]
    fn test_protocol_parsers_standalone() {
        // No relay, Rc, or MITM types anywhere in this test.
        let alice_key = key_from_secret_bytes(ALICE_SECRET).unwrap();
        let bob_key = key_from_secret_bytes(BOB_SECRET).unwrap();

        let bob_wire_key = bob_key.elligator_swift.to_array().to_vec();
        let alice_wire_key = alice_key.elligator_swift.to_array().to_vec();

        let mut alice_hs = HandshakeReadParser::new(Role::Initiator, MAGIC, alice_key);
        let mut bob_hs = HandshakeReadParser::new(Role::Responder, MAGIC, bob_key);

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
        let msg = b"standalone parsers work without any MITM infrastructure";
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
}
