use super::*;

use core::str::FromStr;
use hex::prelude::*;
use hex_literal::hex;
use secp256k1::SecretKey;
use secp256k1::ellswift::{ElligatorSwift, ElligatorSwiftParty};
use secp256k1::rand::rngs::mock::StepRng;
use secp256k1::rand::{CryptoRng, RngCore};

use crate::cipher::{CipherSession, InboundCipher, OutboundCipher, SessionKeyMaterial};
use crate::key_from_secret_bytes;
use crate::protocol::{
    MAINNET_MAGIC, NUM_ELLIGATOR_SWIFT_BYTES, NUM_GARBAGE_TERMINATOR_BYTES, NUM_LENGTH_BYTES,
    NUM_TAG_BYTES, PacketType, Role,
};
use crate::state_machine::{StreamReadParser, StreamWriteParser};

const MAGIC: [u8; 4] = MAINNET_MAGIC;

// Returns (alice_outbound [sender], bob_inbound [receiver]) using fixed known keys.
fn make_cipher_pair() -> (OutboundCipher, InboundCipher) {
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
        MAGIC,
    )
    .unwrap();
    let alice_cipher = CipherSession::new(session_keys.clone(), Role::Initiator);
    let bob_cipher = CipherSession::new(session_keys, Role::Responder);
    let (_alice_inbound, alice_outbound) = alice_cipher.into_split();
    let (bob_inbound, _bob_outbound) = bob_cipher.into_split();
    (alice_outbound, bob_inbound)
}

// Mirrors HANDSHAKE_PARAMS1 from lib.rs
#[allow(dead_code)]
struct TestHandshakeParams {
    server_seed: u64,
    server_key: [u8; NUM_ELLIGATOR_SWIFT_BYTES],
    server_garbage_terminator: [u8; NUM_GARBAGE_TERMINATOR_BYTES],
    client_key: [u8; NUM_ELLIGATOR_SWIFT_BYTES],
    client_garbage_terminator: [u8; NUM_GARBAGE_TERMINATOR_BYTES],
    initiator_l: [u8; 32],
    initiator_p: [u8; 32],
    responder_l: [u8; 32],
    responder_p: [u8; 32],
}

const HANDSHAKE_PARAMS1: TestHandshakeParams = TestHandshakeParams {
    server_seed: 32890322278,
    server_key: hex!(
        "6a34b0f8757abbd31934ce6375857b06000d1a4528274eaec46c6e11a243366dcb14d23c315b7305fb4bd7c11ddc515785061f2a9402c867f2550a7e8e5496ca"
    ),
    server_garbage_terminator: hex!("7064cc9fe99282b77afbe58925e2cf2b"),
    client_key: hex!(
        "61a5de62da81aec5967d511fec1f08f98e9c1108bffaaf304b5b31876bec2cbc2d20736f19f93b3f3fd7b9bbf7d1306da07d13218b90fae8c22276846848ad0c"
    ),
    client_garbage_terminator: hex!("e2b91cf5fae994f1e81c361ce00d110d"),
    initiator_l: hex!("ab7e81f5d65d97c015f71bab4506dd93f6dfca7b182f30cd27896afbc4855c3a"),
    initiator_p: hex!("48d22cd6fb02fe202ddc668d2dcade20a9c5500566acb804d18806b5cac44595"),
    responder_l: hex!("42e672f539b95ec5950bb2d97b45a3cb9ac4b58244b05b35fb8ed1315aab8e6d"),
    responder_p: hex!("0c71faf552c2883beebfb82b557593a60caa0f38749bb393dd5bb656ed768a01"),
};

struct TestRng(StepRng);
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

fn insecurerng(seed: u64) -> TestRng {
    TestRng::new(seed, seed / 2 + 1)
}

fn secret_key_bytes_from_rng<Rng: RngCore + CryptoRng>(rng: &mut Rng) -> [u8; 32] {
    let mut buf = [0u8; 32];
    RngCore::fill_bytes(rng, &mut buf);
    buf
}

fn reader_from_rng<Rng: RngCore + CryptoRng>(role: Role, rng: &mut Rng) -> HandshakeReadParser {
    let bytes = secret_key_bytes_from_rng(rng);
    let point = key_from_secret_bytes(bytes).unwrap();
    super::new_handshake_pair(role, MAGIC, point).0
}

fn reader_from_seed(role: Role, seed: u64) -> HandshakeReadParser {
    let mut rng = insecurerng(seed);
    reader_from_rng(role, &mut rng)
}

// 1. Feed 64 key bytes at once. Verify drain_key_bytes() returns all 64.
//    Verify state transitions to ReceivingGarbage.
#[test]
fn test_parse_key_complete() {
    let mut parser = reader_from_seed(Role::Responder, 1111);

    let key_bytes = [0x42u8; NUM_ELLIGATOR_SWIFT_BYTES];
    let mut data = &key_bytes[..];
    parser.consume(&mut data).unwrap();

    let drained = parser.drain_key_bytes();
    assert_eq!(drained.len(), NUM_ELLIGATOR_SWIFT_BYTES);
    assert_eq!(drained, key_bytes);
    assert!(parser.is_key_eof());
}

// 2. Feed 1 byte at a time (64 iterations). After each step(), verify
//    drain_key_bytes() returns 1 byte. After 64, verify state is ReceivingGarbage.
#[test]
fn test_parse_key_byte_by_byte() {
    let mut parser = reader_from_seed(Role::Responder, 2222);

    let key_bytes = [0x7Eu8; NUM_ELLIGATOR_SWIFT_BYTES];
    for i in 0..NUM_ELLIGATOR_SWIFT_BYTES {
        let mut data = &key_bytes[i..i + 1];
        parser.consume(&mut data).unwrap();
        let drained = parser.drain_key_bytes();
        assert_eq!(drained.len(), 1, "Expected 1 byte at step {i}");
        assert_eq!(drained[0], key_bytes[i]);
    }

    assert!(parser.is_key_eof());
}

// 3. Feed 74 bytes. Verify key output is 64 bytes, parser in ReceivingGarbage,
//    extra 10 bytes consumed as potential garbage.
#[test]
fn test_parse_key_overflow() {
    let mut parser = reader_from_seed(Role::Responder, 3333);

    let all_bytes = [0x5Au8; NUM_ELLIGATOR_SWIFT_BYTES + 10];
    let mut data = &all_bytes[..];
    // step() reads exactly remaining (64) bytes from the key phase; then Continue loops.
    // consume() runs until End.
    parser.consume(&mut data).unwrap();

    let drained = parser.drain_key_bytes();
    assert_eq!(drained.len(), NUM_ELLIGATOR_SWIFT_BYTES);
    assert!(parser.is_key_eof());
}

// 4. Feed HANDSHAKE_PARAMS1.client_key as the peer's key. Verify take_inbound_cipher()
//    and take_outbound_cipher() each return Some. Confirm derived key material matches
//    expected vectors.
#[test]
fn test_cipher_session_derivation() {
    let TestHandshakeParams {
        server_seed,
        client_key,
        client_garbage_terminator,
        initiator_l,
        initiator_p,
        responder_l,
        responder_p,
        ..
    } = HANDSHAKE_PARAMS1;

    let mut parser = reader_from_seed(Role::Responder, server_seed);

    let mut data = &client_key[..];
    parser.consume(&mut data).unwrap();

    let inbound = parser
        .take_inbound_cipher()
        .expect("Expected inbound cipher after key phase");
    let outbound = parser
        .take_outbound_cipher()
        .expect("Expected outbound cipher after key phase");

    assert_eq!(
        inbound.length_cipher.unwrap().key_bytes,
        initiator_l,
        "inbound length key mismatch"
    );
    assert_eq!(
        inbound.packet_cipher.key_bytes, initiator_p,
        "inbound packet key mismatch"
    );
    assert_eq!(
        outbound.length_cipher.key_bytes, responder_l,
        "outbound length key mismatch"
    );
    assert_eq!(
        outbound.packet_cipher.key_bytes, responder_p,
        "outbound packet key mismatch"
    );

    // Also verify the inbound garbage terminator equals client's expected value
    let inbound_term = parser
        .inbound_garbage_terminator()
        .expect("Expected ReceivingGarbage state");
    assert_eq!(*inbound_term, client_garbage_terminator);
}

// 5. Feed key + garbage + terminator. Verify drain_garbage_bytes() returns the
//    garbage, is_handshake_done() is true.
#[test]
fn test_garbage_with_terminator() {
    let TestHandshakeParams {
        server_seed,
        client_key,
        client_garbage_terminator,
        ..
    } = HANDSHAKE_PARAMS1;

    let mut parser = reader_from_seed(Role::Responder, server_seed);

    let garbage = [0xAAu8; 20];
    let mut input = Vec::new();
    input.extend_from_slice(&client_key);
    input.extend_from_slice(&garbage);
    input.extend_from_slice(&client_garbage_terminator);

    let mut data = &input[..];
    parser.consume(&mut data).unwrap();

    let drained_garbage = parser.drain_garbage_bytes();
    let drained_term = parser.drain_terminator_bytes();

    assert_eq!(drained_garbage, garbage, "Garbage content mismatch");
    assert_eq!(
        drained_term.len(),
        NUM_GARBAGE_TERMINATOR_BYTES,
        "Terminator length mismatch"
    );
    assert_eq!(
        drained_term, client_garbage_terminator,
        "Terminator mismatch"
    );
    assert!(parser.is_garbage_eof());
    assert!(parser.is_handshake_done());
}

// 6. Feed key + 4112 bytes of garbage. Verify GarbageLimitExceededError.
#[test]
fn test_garbage_limit_exceeded() {
    let TestHandshakeParams {
        server_seed,
        client_key,
        ..
    } = HANDSHAKE_PARAMS1;

    let mut parser = reader_from_seed(Role::Responder, server_seed);

    let mut data = &client_key[..];
    parser.consume(&mut data).unwrap();

    // Feed 4112 bytes of garbage (exceeds 4095 + 16 = 4111 limit)
    let garbage = vec![0xBBu8; 4112];
    let mut gref = &garbage[..];
    let result = parser.consume(&mut gref);

    assert!(
        matches!(result, Err(Bip324Error::GarbageLimitExceededError)),
        "Expected GarbageLimitExceededError"
    );
}

// 7. Set new EcdhPoint after receiving some key bytes (still in ReceivingKey).
//    Verify the new point is used for ECDH.
#[test]
fn test_set_ecdh_point_during_key() {
    let TestHandshakeParams {
        server_seed,
        client_key,
        initiator_l,
        initiator_p,
        responder_l,
        responder_p,
        ..
    } = HANDSHAKE_PARAMS1;

    // Start with an arbitrary initial key
    let mut parser = reader_from_seed(Role::Responder, 7777);

    // Feed a partial key (30 bytes)
    let mut partial = &client_key[..30];
    parser.consume(&mut partial).unwrap();

    // Replace the key with the "real" server key (from server_seed)
    let server_point = {
        let mut rng = insecurerng(server_seed);
        let bytes = secret_key_bytes_from_rng(&mut rng);
        key_from_secret_bytes(bytes).unwrap()
    };
    parser.set_ecdh_point(server_point).unwrap();

    // Feed the remaining 34 bytes
    let mut rest = &client_key[30..];
    parser.consume(&mut rest).unwrap();

    // Now take ciphers, they should be derived from the real server key + client_key
    let inbound = parser.take_inbound_cipher().expect("Expected ciphers");
    let outbound = parser.take_outbound_cipher().expect("Expected ciphers");
    assert_eq!(inbound.length_cipher.unwrap().key_bytes, initiator_l);
    assert_eq!(inbound.packet_cipher.key_bytes, initiator_p);
    assert_eq!(outbound.length_cipher.key_bytes, responder_l);
    assert_eq!(outbound.packet_cipher.key_bytes, responder_p);
}

// 8. Set new EcdhPoint after full key received (in ReceivingGarbage).
//    Verify take_ciphers() returns ciphers derived from the new point.
#[test]
fn test_set_ecdh_point_after_key() {
    let TestHandshakeParams {
        server_seed,
        client_key,
        initiator_l,
        initiator_p,
        responder_l,
        responder_p,
        ..
    } = HANDSHAKE_PARAMS1;

    // Start with an arbitrary initial key
    let mut parser = reader_from_seed(Role::Responder, 8888);

    // Feed full client key, parser moves to ReceivingGarbage with wrong ciphers
    let mut data = &client_key[..];
    parser.consume(&mut data).unwrap();

    // Replace with the correct server key
    let server_point = {
        let mut rng = insecurerng(server_seed);
        let bytes = secret_key_bytes_from_rng(&mut rng);
        key_from_secret_bytes(bytes).unwrap()
    };
    parser.set_ecdh_point(server_point).unwrap();

    // take_ciphers() should now give ciphers from the real server key + client_key
    let inbound = parser.take_inbound_cipher().expect("Expected ciphers");
    let outbound = parser.take_outbound_cipher().expect("Expected ciphers");
    assert_eq!(inbound.length_cipher.unwrap().key_bytes, initiator_l);
    assert_eq!(inbound.packet_cipher.key_bytes, initiator_p);
    assert_eq!(outbound.length_cipher.key_bytes, responder_l);
    assert_eq!(outbound.packet_cipher.key_bytes, responder_p);
}

// 9. Verify is_receiving_key() is true before key bytes are fully received,
//     and is_receiving_garbage() is true after key is complete.
#[test]
fn test_reader_state_transition_into_recv_garbage() {
    let mut parser = reader_from_seed(Role::Responder, 1010);
    assert!(parser.is_receiving_key());
    assert!(!parser.is_receiving_garbage());

    let TestHandshakeParams { client_key, .. } = HANDSHAKE_PARAMS1;
    let mut data = &client_key[..];
    parser.consume(&mut data).unwrap();

    assert!(!parser.is_receiving_key());
    assert!(parser.is_receiving_garbage());
}

// 10. elligator_swift_bytes() returns the parser's own ellswift key.
#[test]
fn test_elligator_swift_bytes() {
    let point = key_from_secret_bytes(ALICE_SECRET).unwrap();
    let expected = point.elligator_swift.to_array();
    let (reader, _) = super::new_handshake_pair(Role::Initiator, MAGIC, point);
    assert_eq!(reader.elligator_swift_bytes(), expected);
}

// 11. After a complete handshake, take_aad() returns the garbage bytes that were received.
#[test]
fn test_take_aad_after_handshake() {
    let TestHandshakeParams {
        server_seed,
        client_key,
        client_garbage_terminator,
        ..
    } = HANDSHAKE_PARAMS1;

    let mut parser = reader_from_seed(Role::Responder, server_seed);

    let garbage = [0xCCu8; 15];
    let mut input = Vec::new();
    input.extend_from_slice(&client_key);
    input.extend_from_slice(&garbage);
    input.extend_from_slice(&client_garbage_terminator);

    let mut data = &input[..];
    parser.consume(&mut data).unwrap();

    assert!(parser.is_handshake_done());
    let aad = parser
        .take_aad()
        .expect("Expected AAD after handshake done");
    assert_eq!(aad, garbage, "AAD must equal the received garbage bytes");
}

// 12. After receiving the peer's full key and completing ECDH,
//     outbound_garbage_terminator() returns Some.
#[test]
fn test_outbound_garbage_terminator_after_ecdh() {
    let TestHandshakeParams {
        server_seed,
        client_key,
        ..
    } = HANDSHAKE_PARAMS1;

    let mut parser = reader_from_seed(Role::Responder, server_seed);
    let mut data = &client_key[..];
    parser.consume(&mut data).unwrap();

    assert!(
        parser.outbound_garbage_terminator().is_some(),
        "outbound_garbage_terminator must be Some after ECDH"
    );
}

const KEY_LEN: usize = NUM_ELLIGATOR_SWIFT_BYTES;
const TERMINATOR_LEN: usize = NUM_GARBAGE_TERMINATOR_BYTES;

// Deterministic secret bytes for handshake write tests.
const SECRET_A: [u8; 32] = [0x01u8; 32];
const SECRET_B: [u8; 32] = [0x02u8; 32];

fn make_writer() -> (HandshakeWriteParser, [u8; KEY_LEN]) {
    let point = key_from_secret_bytes(SECRET_A).unwrap();
    let expected_key = point.elligator_swift.to_array();
    let (_, writer) = super::new_handshake_pair(Role::Initiator, MAINNET_MAGIC, point);
    (writer, expected_key)
}

fn assert_handshake_writer_has_consumed(parser: &mut HandshakeWriteParser) {
    let mut buf = [0u8; 1];
    let mut slice: &mut [u8] = &mut buf;
    parser.produce(&mut slice).unwrap();
    assert_eq!(slice.len(), 1, "writer has unconsumed data");
}

// 1. Create writer. Call produce() with a full KEY_LEN buffer.
//    Verify the output matches the expected ellswift bytes.
#[test]
fn test_write_key_complete() {
    let (mut parser, expected_key) = make_writer();

    let mut buf = vec![0u8; KEY_LEN];
    let mut write_slice = buf.as_mut_slice();
    parser.produce(&mut write_slice).unwrap();

    assert_eq!(buf, expected_key);
    assert_handshake_writer_has_consumed(&mut parser);
}

// 2. Create parser and step() with 10-byte buffer repeatedly. Verify correct chunking.
#[test]
fn test_write_key_chunked() {
    let (mut parser, expected_key) = make_writer();

    let mut all_output = Vec::new();
    let chunk_size = 10;
    let mut remaining = KEY_LEN;
    while remaining > 0 {
        let this_chunk = chunk_size.min(remaining);
        let mut chunk = vec![0u8; this_chunk];
        {
            let mut s = chunk.as_mut_slice();
            parser.produce(&mut s).unwrap();
        }
        all_output.extend_from_slice(&chunk);
        remaining -= this_chunk;
    }

    assert_eq!(all_output, expected_key);
    assert_handshake_writer_has_consumed(&mut parser);
}

// 3. Full handshake: key || garbage || terminator in one produce() call.
//    The outbound terminator is injected via the test helper.
#[test]
fn test_write_full_handshake() {
    let point = key_from_secret_bytes(SECRET_A).unwrap();
    let expected_key = point.elligator_swift.to_array();
    let (_, mut parser) = super::new_handshake_pair(Role::Initiator, MAINNET_MAGIC, point);

    let garbage = vec![0xFFu8; 20];
    let terminator = [0xAAu8; TERMINATOR_LEN];

    parser.push_garbage_bytes(&garbage);
    parser.set_garbage_eof();
    parser.inject_outbound_garbage_terminator_for_test(terminator);

    let mut buf = vec![0u8; KEY_LEN + 20 + TERMINATOR_LEN];
    {
        let mut s = buf.as_mut_slice();
        parser.produce(&mut s).unwrap();
    }

    let mut expected = Vec::new();
    expected.extend_from_slice(&expected_key);
    expected.extend_from_slice(&garbage);
    expected.extend_from_slice(&terminator);

    assert_eq!(buf, expected);
    assert!(parser.is_done());
    assert_handshake_writer_has_consumed(&mut parser);
}

// 4. No garbage: output is key || terminator.
#[test]
fn test_write_no_garbage() {
    let point = key_from_secret_bytes(SECRET_B).unwrap();
    let expected_key = point.elligator_swift.to_array();
    let (_, mut parser) = super::new_handshake_pair(Role::Initiator, MAINNET_MAGIC, point);

    let terminator = [0xBBu8; TERMINATOR_LEN];
    parser.set_garbage_eof();
    parser.inject_outbound_garbage_terminator_for_test(terminator);

    let mut buf = vec![0u8; KEY_LEN + TERMINATOR_LEN];
    {
        let mut s = buf.as_mut_slice();
        parser.produce(&mut s).unwrap();
    }

    let mut expected = Vec::new();
    expected.extend_from_slice(&expected_key);
    expected.extend_from_slice(&terminator);

    assert_eq!(buf, expected);
    assert!(parser.is_done());
    assert_handshake_writer_has_consumed(&mut parser);
}

// 5. writer_started_sending is false before any write, true after.
#[test]
fn test_writer_started_sending_flag() {
    let (mut parser, _) = make_writer();

    assert!(!parser.writer_started_sending());

    let mut buf = vec![0u8; 1];
    parser.produce(&mut buf.as_mut_slice()).unwrap();

    assert!(parser.writer_started_sending());
}

// 6. set_ecdh_point returns Ok when called before the writer has started sending.
#[test]
fn test_set_ecdh_point_ok_before_writer_starts() {
    let alice_key = key_from_secret_bytes(ALICE_SECRET).unwrap();
    let new_key = key_from_secret_bytes(BOB_SECRET).unwrap();
    let (mut reader, _writer) = super::new_handshake_pair(Role::Initiator, MAGIC, alice_key);

    let result = reader.set_ecdh_point(new_key);
    assert!(
        result.is_ok(),
        "set_ecdh_point should succeed before writer starts sending"
    );
}

// 7. set_ecdh_point returns an error once the writer has started sending, even
//    when called after the full peer key has been received (ReceivingGarbage).
//    Mirrors the setup of test_set_ecdh_point_after_key but commits the writer first.
#[test]
fn test_set_ecdh_point_error_after_writer_started() {
    let TestHandshakeParams {
        server_seed,
        client_key,
        ..
    } = HANDSHAKE_PARAMS1;

    let server_point = {
        let mut rng = insecurerng(server_seed);
        let bytes = secret_key_bytes_from_rng(&mut rng);
        key_from_secret_bytes(bytes).unwrap()
    };
    let (mut reader, mut writer) = super::new_handshake_pair(Role::Responder, MAGIC, server_point);

    // Feed full client key so reader moves to ReceivingGarbage (same as test_set_ecdh_point_after_key)
    let mut data = &client_key[..];
    reader.consume(&mut data).unwrap();

    // Commit the writer: once it has sent any byte, key replacement is forbidden
    let mut buf = vec![0u8; 1];
    writer.produce(&mut buf.as_mut_slice()).unwrap();

    // Any replacement point must now be rejected
    let replacement = key_from_secret_bytes(ALICE_SECRET).unwrap();
    let result = reader.set_ecdh_point(replacement);
    assert!(
        result.is_err(),
        "set_ecdh_point must fail after writer has started sending"
    );
}

// 8. Push garbage in small chunks, calling step() after each. Verify output accumulates correctly.
#[test]
fn test_pacing_garbage() {
    let point = key_from_secret_bytes(SECRET_A).unwrap();
    let expected_key = point.elligator_swift.to_array();
    let (_, mut parser) = super::new_handshake_pair(Role::Initiator, MAINNET_MAGIC, point);

    // Consume the key phase first
    let mut key_out = vec![0u8; KEY_LEN];
    {
        let mut s = key_out.as_mut_slice();
        parser.produce(&mut s).unwrap();
    }
    assert_eq!(key_out, expected_key);

    // Push garbage in 3 chunks of 5 bytes and produce after each
    let full_garbage = vec![0x77u8; 15];
    let mut all_garbage_out = Vec::new();

    for chunk in full_garbage.chunks(5) {
        parser.push_garbage_bytes(chunk);
        let mut gbuf = vec![0u8; 5];
        {
            let mut s = gbuf.as_mut_slice();
            parser.produce(&mut s).unwrap();
        }
        all_garbage_out.extend_from_slice(&gbuf);
    }

    assert_eq!(all_garbage_out, full_garbage);
    assert_handshake_writer_has_consumed(&mut parser);
}

// 9. Push garbage without setting EOF. Verify parser stays in SendingGarbage and returns End.
#[test]
fn test_no_output_when_no_garbage_eof() {
    let (mut parser, _) = make_writer();

    // Consume key phase
    let mut key_buf = vec![0u8; KEY_LEN];
    {
        let mut s = key_buf.as_mut_slice();
        parser.produce(&mut s).unwrap();
    }

    // Push garbage but do NOT set EOF
    parser.push_garbage_bytes(&[0xCCu8; 10]);

    // Run produce with a large buffer
    let mut buf = vec![0u8; 100];
    parser.produce(&mut buf.as_mut_slice()).unwrap();

    // Parser should still be in SendingGarbage, not transitioned to terminator
    assert!(parser.is_sending_garbage());
    assert_handshake_writer_has_consumed(&mut parser);
}

// 10. SendingGarbageTerminator waits when outbound_garbage_terminator is not yet ready.
#[test]
fn test_terminator_waits_for_ecdh() {
    let (mut parser, _) = make_writer();

    // Consume the key phase
    let mut key_buf = vec![0u8; KEY_LEN];
    parser.produce(&mut key_buf.as_mut_slice()).unwrap();

    // Skip garbage (set EOF immediately -- no garbage bytes)
    parser.set_garbage_eof();

    // produce() drives through to SendingGarbageTerminator and stops because
    // outbound_garbage_terminator is None (no ECDH has been completed).
    let mut buf = vec![0u8; 200];
    parser.produce(&mut buf.as_mut_slice()).unwrap();

    // Parser is stuck at SendingGarbageTerminator, not Done
    assert!(!parser.is_done());
    assert!(parser.is_sending_terminator());
    assert_eq!(buf, vec![0u8; 200]);
    assert_handshake_writer_has_consumed(&mut parser);
}

// Data read tests

// Encrypt plaintext with OutboundCipher (mocking DataWriteParser, for read-side tests).
fn cipher_encrypt_packet(outbound: &mut OutboundCipher, plaintext: &[u8]) -> Vec<u8> {
    outbound.encrypt_to_vec(plaintext, PacketType::Genuine, None)
}

fn cipher_encrypt_packet_with_aad(
    outbound: &mut OutboundCipher,
    plaintext: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    outbound.encrypt_to_vec(plaintext, PacketType::Genuine, Some(aad))
}

// Drain and check: length_bytes is 3 bytes, data_bytes is 1+plaintext.len(),
// tag_bytes is NUM_TAG_BYTES and matches the last 16 bytes of ciphertext.
fn assert_packet_outputs(parser: &mut DataReadParser, plaintext: &[u8], ciphertext: &[u8]) {
    let length_bytes = parser.drain_length_bytes();
    let data_bytes = parser.drain_data_bytes();
    let tag_bytes = parser.drain_tag_bytes();

    assert_eq!(length_bytes.len(), NUM_LENGTH_BYTES, "length bytes length");
    // data_bytes = header (1 byte) + decrypted plaintext (N bytes)
    assert_eq!(data_bytes.len(), 1 + plaintext.len(), "data bytes length");
    assert_eq!(data_bytes[0], 0x00, "genuine packet header byte");
    assert_eq!(&data_bytes[1..], plaintext, "decrypted plaintext");
    assert_eq!(tag_bytes.len(), NUM_TAG_BYTES, "tag bytes length");
    // tag bytes are the raw network bytes (last 16 bytes of ciphertext)
    assert_eq!(
        tag_bytes,
        &ciphertext[ciphertext.len() - NUM_TAG_BYTES..],
        "tag bytes match ciphertext"
    );
}

// 1. Encrypt a message with OutboundCipher. Feed encrypted bytes to DataReadParser. Drain
//    outputs. Verify length, data, tag match expectations.
#[test]
fn test_decrypt_single_packet() {
    let (mut alice_out, bob_in) = make_cipher_pair();

    let plaintext = b"hello bip324";
    let ciphertext = cipher_encrypt_packet(&mut alice_out, plaintext);

    let mut parser = DataReadParser::new(vec![], bob_in);
    let mut data = &ciphertext[..];
    parser.consume(&mut data).unwrap();

    assert_packet_outputs(&mut parser, plaintext, &ciphertext);
}

// 2. Feed one encrypted byte at a time. Verify incremental output after each step.
#[test]
fn test_decrypt_byte_by_byte() {
    let (mut alice_out, bob_in) = make_cipher_pair();

    let plaintext = b"incremental";
    let ciphertext = cipher_encrypt_packet(&mut alice_out, plaintext);

    let mut parser = DataReadParser::new(vec![], bob_in);

    let mut all_length = vec![];
    let mut all_data = vec![];
    let mut all_tag = vec![];

    for byte in &ciphertext {
        let mut slice = std::slice::from_ref(byte);
        parser.consume(&mut slice).unwrap();
        all_length.extend(parser.drain_length_bytes());
        all_data.extend(parser.drain_data_bytes());
        all_tag.extend(parser.drain_tag_bytes());
    }

    assert_eq!(all_length.len(), NUM_LENGTH_BYTES);
    assert_eq!(all_data.len(), 1 + plaintext.len());
    assert_eq!(all_data[0], 0x00, "genuine packet header byte");
    assert_eq!(&all_data[1..], plaintext.as_slice(), "decrypted plaintext");
    assert_eq!(all_tag.len(), NUM_TAG_BYTES);
    assert_eq!(
        all_tag,
        &ciphertext[ciphertext.len() - NUM_TAG_BYTES..],
        "tag matches ciphertext"
    );
}

// 3. Encrypt two messages. Feed each in a separate consume(). Verify both decrypted correctly.
#[test]
fn test_decrypt_multiple_packets() {
    let (mut alice_out, bob_in) = make_cipher_pair();

    let msg1 = b"first packet";
    let msg2 = b"second packet";
    let ct1 = cipher_encrypt_packet(&mut alice_out, msg1);
    let ct2 = cipher_encrypt_packet(&mut alice_out, msg2);

    let mut parser = DataReadParser::new(vec![], bob_in);

    // Feed first packet
    let mut data = &ct1[..];
    parser.consume(&mut data).unwrap();
    assert_packet_outputs(&mut parser, msg1, &ct1);

    // Feed second packet
    let mut data = &ct2[..];
    parser.consume(&mut data).unwrap();
    assert_packet_outputs(&mut parser, msg2, &ct2);
}

// 4. Create parser with non-empty AAD. Decrypt first packet (encrypted with matching AAD).
//    Verify take_aad() returns the AAD for first packet, None for second.
#[test]
fn test_aad_first_packet() {
    let (mut alice_out, bob_in) = make_cipher_pair();

    let garbage_aad: Vec<u8> = vec![0xAA; 32];
    let mut parser = DataReadParser::new(garbage_aad.clone(), bob_in);

    assert_eq!(parser.take_aad(), None, "No AAD before any packet");

    // First packet: encrypt with the same AAD the parser will use for verification
    let ct1 = cipher_encrypt_packet_with_aad(&mut alice_out, b"version", &garbage_aad);
    let mut data = &ct1[..];
    parser.consume(&mut data).unwrap();

    assert_eq!(
        parser.take_aad(),
        Some(garbage_aad),
        "AAD should be returned after first packet"
    );
    assert_eq!(parser.take_aad(), None, "take_aad() is one-shot");

    // Second packet (no new AAD was set), encrypt with no AAD
    let ct2 = cipher_encrypt_packet(&mut alice_out, b"second");
    let mut data = &ct2[..];
    parser.consume(&mut data).unwrap();

    assert_eq!(
        parser.take_aad(),
        None,
        "No AAD for second packet (none was set)"
    );
}

// 5. Encrypt a packet with AAD_A; create parser with a different AAD_B.
//    Verify consume() panics with "AEAD tag check fail".
#[test]
#[should_panic(expected = "AEAD tag check fail")]
fn test_aad_mismatch_panics() {
    let (mut alice_out, bob_in) = make_cipher_pair();

    let encryption_aad: Vec<u8> = vec![0xAA; 32];
    let reader_aad: Vec<u8> = vec![0xBB; 32];

    // Alice encrypts with encryption_aad; Bob's parser expects reader_aad — mismatch.
    let ct = cipher_encrypt_packet_with_aad(&mut alice_out, b"version", &encryption_aad);
    let mut parser = DataReadParser::new(reader_aad, bob_in);
    let mut data = ct.as_slice();
    parser.consume(&mut data).unwrap();
}

// 6. Feed correct length + content, then corrupt tag bytes. Verify panic.
#[test]
#[should_panic(expected = "AEAD tag check fail")]
fn test_corrupt_tag_panics() {
    let (mut alice_out, bob_in) = make_cipher_pair();

    let plaintext = b"tag corruption test";
    let mut ciphertext = cipher_encrypt_packet(&mut alice_out, plaintext);

    // Corrupt a single tag byte — sufficient to fail the AEAD check.
    let len = ciphertext.len();
    ciphertext[len - 1] ^= 0xFF;

    let mut parser = DataReadParser::new(vec![], bob_in);
    let mut data = ciphertext.as_slice();
    parser.consume(&mut data).unwrap();
}

// 7. Use known session keys. Verify the parser decodes the known ciphertext vector.
//    Matches test_vector_1 in cipher.rs: alice encrypts [0x8e] after one warmup packet,
//    producing ciphertext "7530d2a18720162ac09c25329a60d75adf36eda3c3".
#[test]
fn test_known_vectors() {
    let (mut alice_out, bob_in) = make_cipher_pair();

    // Warmup: encrypt 100 bytes (matches test_vector_1 in cipher.rs which uses
    // gen_garbage(100) before the known second packet)
    let warmup_ct = cipher_encrypt_packet(&mut alice_out, &[0u8; 100]);

    let contents: Vec<u8> = vec![0x8e];
    let ct = cipher_encrypt_packet(&mut alice_out, &contents);
    assert_eq!(
        ct,
        Vec::from_hex("7530d2a18720162ac09c25329a60d75adf36eda3c3").unwrap(),
        "Known vector ciphertext mismatch"
    );

    let mut parser = DataReadParser::new(vec![], bob_in);

    // Consume warmup packet
    let mut data = warmup_ct.as_slice();
    parser.consume(&mut data).unwrap();
    parser.drain_length_bytes();
    parser.drain_data_bytes();
    parser.drain_tag_bytes();

    // Consume known vector packet
    let mut data = ct.as_slice();
    parser.consume(&mut data).unwrap();

    let length_bytes = parser.drain_length_bytes();
    let data_bytes = parser.drain_data_bytes();
    let tag_bytes = parser.drain_tag_bytes();

    assert_eq!(length_bytes.len(), NUM_LENGTH_BYTES);
    // data_bytes[0] = header byte, data_bytes[1..] = decrypted contents = [0x8e]
    assert_eq!(data_bytes.len(), 2, "header + 1 content byte");
    assert_eq!(data_bytes[0], 0x00, "genuine packet header byte");
    assert_eq!(data_bytes[1], 0x8e, "decrypted content byte");
    assert_eq!(tag_bytes.len(), NUM_TAG_BYTES);
    // tag bytes are the raw network bytes (last 16 bytes of known ciphertext)
    assert_eq!(
        tag_bytes,
        &ct[ct.len() - NUM_TAG_BYTES..],
        "tag matches known ciphertext"
    );
}

// 8. Feed ciphertext in two halves without draining between consume() calls.
//    Verifies output buffers accumulate correctly across partial reads.
#[test]
fn test_partial_read_no_intermediate_drain() {
    let (mut alice_out, bob_in) = make_cipher_pair();

    let plaintext = b"partial read test";
    let ciphertext = cipher_encrypt_packet(&mut alice_out, plaintext);

    let mut parser = DataReadParser::new(vec![], bob_in);
    let mid = ciphertext.len() / 2;

    let mut data = &ciphertext[..mid];
    parser.consume(&mut data).unwrap();

    let mut data = &ciphertext[mid..];
    parser.consume(&mut data).unwrap();

    assert_packet_outputs(&mut parser, plaintext, &ciphertext);
}

// 9. Feed exactly the length phase bytes, drain them immediately, then feed the rest.
//    Verifies drain_length_bytes() returns a partial result mid-packet and the
//    subsequent drains complete the packet correctly.
#[test]
fn test_partial_drain_phase_boundary() {
    let (mut alice_out, bob_in) = make_cipher_pair();

    let plaintext = b"phase boundary drain";
    let ciphertext = cipher_encrypt_packet(&mut alice_out, plaintext);

    let mut parser = DataReadParser::new(vec![], bob_in);

    let mut data = &ciphertext[..NUM_LENGTH_BYTES];
    parser.consume(&mut data).unwrap();

    let length_bytes = parser.drain_length_bytes();
    assert_eq!(
        length_bytes.len(),
        NUM_LENGTH_BYTES,
        "length bytes after length phase"
    );
    assert!(parser.drain_data_bytes().is_empty(), "no data bytes yet");
    assert!(parser.drain_tag_bytes().is_empty(), "no tag bytes yet");

    let mut data = &ciphertext[NUM_LENGTH_BYTES..];
    parser.consume(&mut data).unwrap();

    let data_bytes = parser.drain_data_bytes();
    let tag_bytes = parser.drain_tag_bytes();

    assert_eq!(data_bytes.len(), 1 + plaintext.len(), "data bytes length");
    assert_eq!(data_bytes[0], 0x00, "genuine packet header byte");
    assert_eq!(&data_bytes[1..], plaintext, "decrypted plaintext");
    assert_eq!(tag_bytes.len(), NUM_TAG_BYTES, "tag bytes length");
    assert_eq!(
        tag_bytes,
        &ciphertext[ciphertext.len() - NUM_TAG_BYTES..],
        "tag bytes match ciphertext"
    );
}

// Data write tests

// Prepare the three input slices needed by DataWriteParser for one packet.
//
// Returns (length_bytes, data_bytes, tag_placeholder) where:
//   length_bytes: 3-byte little-endian plaintext length (before encryption)
//   data_bytes:   genuine header byte (0x00) + plaintext
//   tag_placeholder: 16 zero bytes used purely for pacing
fn make_packet_input(plaintext: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let len_val = plaintext.len() as u32;
    let length_bytes = len_val.to_le_bytes()[..NUM_LENGTH_BYTES].to_vec();

    let mut data_bytes = vec![0x00u8]; // genuine header
    data_bytes.extend_from_slice(plaintext);

    let tag_placeholder = vec![0u8; NUM_TAG_BYTES];

    (length_bytes, data_bytes, tag_placeholder)
}

// Encrypt one packet with DataWriteParser and return the ciphertext.
fn encrypt_with_parser(
    parser: &mut DataWriteParser,
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> Vec<u8> {
    let (length_bytes, data_bytes, tag_placeholder) = make_packet_input(plaintext);
    parser.push_length_bytes(&length_bytes);
    parser.push_data_bytes(&data_bytes);
    parser.push_tag_bytes(&tag_placeholder);
    if let Some(a) = aad {
        parser.set_aad(a);
    }

    let out_len = NUM_LENGTH_BYTES + data_bytes.len() + NUM_TAG_BYTES;
    let mut out = vec![0u8; out_len];
    parser.produce(&mut out.as_mut_slice()).unwrap();
    out
}

// Assert the writer holds no pending input: produce into a 1-byte buffer and
// verify the slice was not advanced (nothing was written).
fn assert_writer_has_consumed(parser: &mut DataWriteParser) {
    let mut buf = [0u8; 1];
    let mut slice: &mut [u8] = &mut buf;
    parser.produce(&mut slice).unwrap();
    assert_eq!(slice.len(), 1, "writer has unconsumed data");
}

// 1. Push 3 length bytes + header+payload + 16 tag bytes. produce(). Decrypt the output
//    with matching InboundCipher. Verify roundtrip.
#[test]
fn test_encrypt_single_packet() {
    let (alice_out, mut bob_in) = make_cipher_pair();

    let plaintext = b"hello bip324";
    let mut parser = DataWriteParser::new(alice_out);
    let ciphertext = encrypt_with_parser(&mut parser, plaintext, None);

    let packet_len = bob_in.decrypt_packet_len(ciphertext[..NUM_LENGTH_BYTES].try_into().unwrap());
    let mut ct_body = ciphertext[NUM_LENGTH_BYTES..NUM_LENGTH_BYTES + packet_len].to_vec();
    let (_pkt_type, msg) = bob_in.decrypt_in_place(&mut ct_body, None).unwrap();

    // msg[0] is the header byte; msg[1..] is plaintext
    assert_eq!(&msg[1..], plaintext);
    assert_writer_has_consumed(&mut parser);
}

// 2. Push one byte at a time. step() after each. Verify correct encrypted output.
#[test]
fn test_encrypt_byte_by_byte() {
    let (alice_out, mut bob_in) = make_cipher_pair();

    let plaintext = b"incremental";
    let (length_bytes, data_bytes, tag_placeholder) = make_packet_input(plaintext);
    let out_len = NUM_LENGTH_BYTES + data_bytes.len() + NUM_TAG_BYTES;

    let mut parser = DataWriteParser::new(alice_out);
    let mut out = vec![0u8; out_len];
    let mut out_slice = out.as_mut_slice();

    for &byte in &length_bytes {
        parser.push_length_bytes(&[byte]);
        parser.produce(&mut out_slice).unwrap();
    }
    for &byte in &data_bytes {
        parser.push_data_bytes(&[byte]);
        parser.produce(&mut out_slice).unwrap();
    }
    for &byte in &tag_placeholder {
        parser.push_tag_bytes(&[byte]);
        parser.produce(&mut out_slice).unwrap();
    }

    let packet_len = bob_in.decrypt_packet_len(out[..NUM_LENGTH_BYTES].try_into().unwrap());
    let mut ct_body = out[NUM_LENGTH_BYTES..NUM_LENGTH_BYTES + packet_len].to_vec();
    let (_pkt_type, msg) = bob_in.decrypt_in_place(&mut ct_body, None).unwrap();

    assert_eq!(&msg[1..], plaintext);
    assert_writer_has_consumed(&mut parser);
}

// 3. Push two packets' worth of data. Verify both encrypted correctly.
#[test]
fn test_encrypt_multiple_packets() {
    let (alice_out, mut bob_in) = make_cipher_pair();

    let msg1 = b"first packet";
    let msg2 = b"second packet";

    let mut parser = DataWriteParser::new(alice_out);

    let ct1 = encrypt_with_parser(&mut parser, msg1, None);
    let ct2 = encrypt_with_parser(&mut parser, msg2, None);

    // Decrypt first
    let len1 = bob_in.decrypt_packet_len(ct1[..NUM_LENGTH_BYTES].try_into().unwrap());
    let mut body1 = ct1[NUM_LENGTH_BYTES..NUM_LENGTH_BYTES + len1].to_vec();
    let (_pkt, msg) = bob_in.decrypt_in_place(&mut body1, None).unwrap();
    assert_eq!(&msg[1..], msg1.as_slice());

    // Decrypt second
    let len2 = bob_in.decrypt_packet_len(ct2[..NUM_LENGTH_BYTES].try_into().unwrap());
    let mut body2 = ct2[NUM_LENGTH_BYTES..NUM_LENGTH_BYTES + len2].to_vec();
    let (_pkt, msg) = bob_in.decrypt_in_place(&mut body2, None).unwrap();
    assert_eq!(&msg[1..], msg2.as_slice());
    assert_writer_has_consumed(&mut parser);
}

// 4. Set AAD before first packet. Verify encrypted output decrypts correctly with matching AAD.
#[test]
fn test_encrypt_with_aad() {
    let (alice_out, mut bob_in) = make_cipher_pair();

    let garbage_aad: Vec<u8> = vec![0xAA; 32];
    let plaintext = b"aad packet";

    let mut parser = DataWriteParser::new(alice_out);
    let ciphertext = encrypt_with_parser(&mut parser, plaintext, Some(&garbage_aad));

    let packet_len = bob_in.decrypt_packet_len(ciphertext[..NUM_LENGTH_BYTES].try_into().unwrap());
    let mut ct_body = ciphertext[NUM_LENGTH_BYTES..NUM_LENGTH_BYTES + packet_len].to_vec();
    let (_pkt, msg) = bob_in
        .decrypt_in_place(&mut ct_body, Some(&garbage_aad))
        .unwrap();

    assert_eq!(&msg[1..], plaintext);
    assert_writer_has_consumed(&mut parser);
}

// 5. Set AAD before first packet; send a second packet without AAD. Verify first decrypts
//    with matching AAD, and second decrypts with None (AAD is consumed after the first packet).
#[test]
fn test_aad_applies_only_to_first_packet() {
    let (alice_out, mut bob_in) = make_cipher_pair();

    let garbage_aad: Vec<u8> = vec![0xAA; 32];
    let msg1 = b"aad packet";
    let msg2 = b"second packet no aad";

    let mut parser = DataWriteParser::new(alice_out);
    let ct1 = encrypt_with_parser(&mut parser, msg1, Some(&garbage_aad));
    let ct2 = encrypt_with_parser(&mut parser, msg2, None);

    // First packet must decrypt with the matching AAD.
    let len1 = bob_in.decrypt_packet_len(ct1[..NUM_LENGTH_BYTES].try_into().unwrap());
    let mut body1 = ct1[NUM_LENGTH_BYTES..NUM_LENGTH_BYTES + len1].to_vec();
    let (_pkt, dec1) = bob_in
        .decrypt_in_place(&mut body1, Some(&garbage_aad))
        .unwrap();
    assert_eq!(&dec1[1..], msg1.as_slice());

    // Second packet was encrypted without AAD, so None is the correct key.
    // If AAD had leaked into the second packet this would fail.
    let len2 = bob_in.decrypt_packet_len(ct2[..NUM_LENGTH_BYTES].try_into().unwrap());
    let mut body2 = ct2[NUM_LENGTH_BYTES..NUM_LENGTH_BYTES + len2].to_vec();
    let (_pkt, dec2) = bob_in.decrypt_in_place(&mut body2, None).unwrap();
    assert_eq!(&dec2[1..], msg2.as_slice());

    assert_writer_has_consumed(&mut parser);
}

// 6. Push arbitrary tag bytes (not matching computed tag). Verify output uses the parser's
//    computed tag (not the input tag bytes).
#[test]
fn test_tag_replacement() {
    let (alice_out, mut bob_in) = make_cipher_pair();

    let plaintext = b"tag replace";
    let (length_bytes, data_bytes, _) = make_packet_input(plaintext);

    // Push 0xFF bytes as the relay tag -- these should be replaced
    let wrong_tag = vec![0xFFu8; NUM_TAG_BYTES];

    let mut parser = DataWriteParser::new(alice_out);
    parser.push_length_bytes(&length_bytes);
    parser.push_data_bytes(&data_bytes);
    parser.push_tag_bytes(&wrong_tag);

    let out_len = NUM_LENGTH_BYTES + data_bytes.len() + NUM_TAG_BYTES;
    let mut out = vec![0u8; out_len];
    parser.produce(&mut out.as_mut_slice()).unwrap();

    // The last 16 bytes should NOT be 0xFF (they are the real computed tag)
    assert_ne!(
        &out[out_len - NUM_TAG_BYTES..],
        wrong_tag.as_slice(),
        "output tag should be computed AEAD tag, not the pushed bytes"
    );

    // The real AEAD tag allows correct decryption
    let packet_len = bob_in.decrypt_packet_len(out[..NUM_LENGTH_BYTES].try_into().unwrap());
    let mut ct_body = out[NUM_LENGTH_BYTES..NUM_LENGTH_BYTES + packet_len].to_vec();
    let (_pkt, msg) = bob_in.decrypt_in_place(&mut ct_body, None).unwrap();
    assert_eq!(&msg[1..], plaintext);
    assert_writer_has_consumed(&mut parser);
}

// 7. Encrypt with DataWriteParser, decrypt with DataReadParser. Verify plaintext matches.
#[test]
fn test_roundtrip_with_data_read_parser() {
    let (alice_out, bob_in) = make_cipher_pair();

    let plaintext = b"roundtrip test";

    let mut write_parser = DataWriteParser::new(alice_out);
    let ciphertext = encrypt_with_parser(&mut write_parser, plaintext, None);

    let mut read_parser = DataReadParser::new(vec![], bob_in);
    let mut data = ciphertext.as_slice();
    read_parser.consume(&mut data).unwrap();

    let data_bytes = read_parser.drain_data_bytes();
    // data_bytes[0] = header byte, data_bytes[1..] = plaintext
    assert_eq!(data_bytes[0], 0x00, "genuine packet header byte");
    assert_eq!(&data_bytes[1..], plaintext);
    assert_writer_has_consumed(&mut write_parser);
}

// Integration tests

// Fixed deterministic keys used across all integration tests.
const ALICE_SECRET: [u8; 32] =
    hex!("61062ea5071d800bbfd59e2e8b53d47d194b095ae5a4df04936b49772ef0d4d7");
const BOB_SECRET: [u8; 32] =
    hex!("6f312890ec83bbb26798abaadd574684a53e74ccef7953b790fcc29409080246");

// Returns derived ciphers for both sides from a completed BIP-324 handshake using new_handshake_pair.
fn get_derived_ciphers_from_handshake()
-> (InboundCipher, OutboundCipher, InboundCipher, OutboundCipher) {
    let (mut alice_reader, _, mut bob_reader, _) = do_full_handshake();
    let alice_inbound = alice_reader.take_inbound_cipher().unwrap();
    let alice_outbound = alice_reader.take_outbound_cipher().unwrap();
    let bob_inbound = bob_reader.take_inbound_cipher().unwrap();
    let bob_outbound = bob_reader.take_outbound_cipher().unwrap();
    (alice_inbound, alice_outbound, bob_inbound, bob_outbound)
}

// 1. Complete handshake bidirectionally, then verify a data roundtrip:
//    Side A encrypts with DataWriteParser → Side B decrypts with DataReadParser → matches plaintext.
#[test]
fn test_full_protocol_flow() {
    let (_alice_inbound, alice_outbound, bob_inbound, _bob_outbound) =
        get_derived_ciphers_from_handshake();
    let plaintext = b"hello from alice to bob";

    let mut encrypt_parser = DataWriteParser::new(alice_outbound);
    let ciphertext = encrypt_with_parser(&mut encrypt_parser, plaintext, None);

    let mut decrypt_parser = DataReadParser::new(vec![], bob_inbound);
    decrypt_parser.consume(&mut ciphertext.as_slice()).unwrap();

    let decrypted = decrypt_parser.drain_data_bytes();
    assert_eq!(decrypted[0], 0x00, "Expected genuine header byte");
    assert_eq!(
        &decrypted[1..],
        plaintext,
        "Decrypted payload must match original plaintext"
    );
    assert_writer_has_consumed(&mut encrypt_parser);
}

// 2. Verify that data parsers generated from handshake material encrypt and decrypt correctly:
//    DataWriteParser encrypts with alice's outbound cipher; DataReadParser decrypts with bob's inbound cipher.
#[test]
fn test_that_data_parsers_from_handshake_material_are_correct() {
    let (_alice_inbound, alice_outbound, bob_inbound, _bob_outbound) =
        get_derived_ciphers_from_handshake();
    let msg = b"standalone parsers work without any external infrastructure";
    let mut write = DataWriteParser::new(alice_outbound);
    let ct = encrypt_with_parser(&mut write, msg, None);

    let mut read = DataReadParser::new(vec![], bob_inbound);
    read.consume(&mut ct.as_slice()).unwrap();

    let plain = read.drain_data_bytes();
    assert_eq!(&plain[1..], msg);
    assert_writer_has_consumed(&mut write);
}

// 3. Both sides use new_handshake_pair and derive matching cipher sessions.

#[test]
fn test_coupled_handshake() {
    let (mut alice_reader, _, mut bob_reader, _) = do_full_handshake();

    let alice_inbound = alice_reader.take_inbound_cipher().unwrap();
    let alice_outbound = alice_reader.take_outbound_cipher().unwrap();
    let bob_inbound = bob_reader.take_inbound_cipher().unwrap();
    let bob_outbound = bob_reader.take_outbound_cipher().unwrap();
    // Alice's outbound keys must match Bob's inbound keys
    assert_eq!(
        alice_outbound.length_cipher.key_bytes,
        bob_inbound.length_cipher.as_ref().unwrap().key_bytes,
        "alice outbound length key must equal bob inbound length key"
    );
    assert_eq!(
        alice_outbound.packet_cipher.key_bytes, bob_inbound.packet_cipher.key_bytes,
        "alice outbound packet key must equal bob inbound packet key"
    );
    // Bob's outbound keys must match Alice's inbound keys
    assert_eq!(
        bob_outbound.length_cipher.key_bytes,
        alice_inbound.length_cipher.as_ref().unwrap().key_bytes,
        "bob outbound length key must equal alice inbound length key"
    );
    assert_eq!(
        bob_outbound.packet_cipher.key_bytes, alice_inbound.packet_cipher.key_bytes,
        "bob outbound packet key must equal alice inbound packet key"
    );

    // Verify the derived ciphers actually work end-to-end: encrypt with alice's outbound,
    // decrypt with bob's inbound.
    let plaintext = b"coupled handshake roundtrip";
    let mut write_parser = DataWriteParser::new(alice_outbound);
    let ciphertext = encrypt_with_parser(&mut write_parser, plaintext, None);

    let mut read_parser = DataReadParser::new(vec![], bob_inbound);
    read_parser.consume(&mut ciphertext.as_slice()).unwrap();

    let decrypted = read_parser.drain_data_bytes();
    assert_eq!(decrypted[0], 0x00, "Expected genuine header byte");
    assert_eq!(
        &decrypted[1..],
        plaintext,
        "Decrypted payload must match plaintext"
    );
    assert_writer_has_consumed(&mut write_parser);
}

// 4. The writer produces the correct ellswift bytes when constructed via new_handshake_pair.
#[test]
fn test_writer_reads_key_from_handshake_pair() {
    let alice_key = key_from_secret_bytes(ALICE_SECRET).unwrap();
    let expected_bytes = alice_key.elligator_swift.to_array();

    let (_reader, mut writer) = super::new_handshake_pair(Role::Initiator, MAGIC, alice_key);

    let mut buf = vec![0u8; NUM_ELLIGATOR_SWIFT_BYTES];
    writer.produce(&mut buf.as_mut_slice()).unwrap();

    assert_eq!(
        buf, expected_bytes,
        "Writer must produce the key from shared state"
    );
}

// Helper: run a full BIP-324 handshake for both sides using new_handshake_pair.
// Returns (alice_reader, alice_writer, bob_reader, bob_writer), all in HandshakeDone/Done state.
// All bytes flow through produce() → consume(); no internal state is accessed directly.
fn do_full_handshake() -> (
    HandshakeReadParser,
    HandshakeWriteParser,
    HandshakeReadParser,
    HandshakeWriteParser,
) {
    let alice_key = key_from_secret_bytes(ALICE_SECRET).unwrap();
    let bob_key = key_from_secret_bytes(BOB_SECRET).unwrap();

    let (mut alice_reader, mut alice_writer) =
        super::new_handshake_pair(Role::Initiator, MAGIC, alice_key);
    let (mut bob_reader, mut bob_writer) =
        super::new_handshake_pair(Role::Responder, MAGIC, bob_key);

    alice_writer.set_garbage_eof();
    bob_writer.set_garbage_eof();

    // Phase 1: each writer produces its ellswift key bytes
    let mut alice_wire_key = vec![0u8; NUM_ELLIGATOR_SWIFT_BYTES];
    alice_writer
        .produce(&mut alice_wire_key.as_mut_slice())
        .unwrap();
    let mut bob_wire_key = vec![0u8; NUM_ELLIGATOR_SWIFT_BYTES];
    bob_writer
        .produce(&mut bob_wire_key.as_mut_slice())
        .unwrap();

    // Phase 2: readers consume peer key bytes, triggering ECDH on both sides
    alice_reader.consume(&mut bob_wire_key.as_slice()).unwrap();
    bob_reader.consume(&mut alice_wire_key.as_slice()).unwrap();

    // Phase 3: writers produce garbage terminators (ECDH complete, terminator in shared state)
    let mut alice_term = vec![0u8; NUM_GARBAGE_TERMINATOR_BYTES];
    alice_writer
        .produce(&mut alice_term.as_mut_slice())
        .unwrap();
    assert!(
        alice_writer.is_done(),
        "alice writer must reach Done after produce()"
    );
    let mut bob_term = vec![0u8; NUM_GARBAGE_TERMINATOR_BYTES];
    bob_writer.produce(&mut bob_term.as_mut_slice()).unwrap();
    assert!(
        bob_writer.is_done(),
        "bob writer must reach Done after produce()"
    );

    // Phase 4: readers consume peer garbage terminators, completing the handshake
    alice_reader.consume(&mut bob_term.as_slice()).unwrap();
    bob_reader.consume(&mut alice_term.as_slice()).unwrap();

    assert!(alice_reader.is_handshake_done());
    assert!(bob_reader.is_handshake_done());

    (alice_reader, alice_writer, bob_reader, bob_writer)
}

// 5. Complete a handshake, call into_data_reader(), feed encrypted data to the resulting
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
    let ciphertext = encrypt_with_parser(&mut alice_data_writer, plaintext, None);

    bob_data_reader.consume(&mut ciphertext.as_slice()).unwrap();
    let decrypted = bob_data_reader.drain_data_bytes();

    assert_eq!(decrypted[0], 0x00, "Expected genuine header byte");
    assert_eq!(&decrypted[1..], plaintext);
    assert_writer_has_consumed(&mut alice_data_writer);
}

// 6. Complete a handshake, call into_data_writer(), encrypt data, and verify decryption.
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
    let ciphertext = encrypt_with_parser(&mut alice_data_writer, plaintext, None);

    bob_data_reader.consume(&mut ciphertext.as_slice()).unwrap();
    let decrypted = bob_data_reader.drain_data_bytes();

    assert_eq!(decrypted[0], 0x00, "Expected genuine header byte");
    assert_eq!(&decrypted[1..], plaintext);
    assert_writer_has_consumed(&mut alice_data_writer);
}

// 7. Both sides complete a handshake and transition to the data phase. Alice encrypts
//    a message and Bob decrypts it.
#[test]
fn test_data_phase_roundtrip() {
    let (alice_reader, alice_writer, bob_reader, bob_writer) = do_full_handshake();

    let (_alice_data_reader, _) = alice_reader.into_data_reader();
    let mut alice_data_writer = alice_writer.into_data_writer();

    let (mut bob_data_reader, _) = bob_reader.into_data_reader();
    let _bob_data_writer = bob_writer.into_data_writer();

    // Alice encrypts → Bob decrypts
    let plaintext = b"full transition roundtrip";
    let ciphertext = encrypt_with_parser(&mut alice_data_writer, plaintext, None);

    bob_data_reader.consume(&mut ciphertext.as_slice()).unwrap();
    let decrypted = bob_data_reader.drain_data_bytes();

    assert_eq!(decrypted[0], 0x00, "Expected genuine header byte");
    assert_eq!(
        &decrypted[1..],
        plaintext,
        "Decrypted payload must match original plaintext"
    );
    assert_writer_has_consumed(&mut alice_data_writer);
}

// 8. Call into_data_reader() before the handshake completes → should panic.
#[test]
#[should_panic(expected = "Handshake must be done before transitioning to data phase")]
fn test_into_data_reader_panics_if_not_done() {
    let alice_key = key_from_secret_bytes(ALICE_SECRET).unwrap();
    let (alice_reader, _alice_writer) =
        super::new_handshake_pair(Role::Initiator, MAGIC, alice_key);

    // Handshake not done yet -- should panic
    let _ = alice_reader.into_data_reader();
}
