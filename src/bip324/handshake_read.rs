use std::cmp;

use crate::cipher::{CipherSession, InboundCipher, OutboundCipher};
use crate::protocol::{
    AADType, EcdhPoint, GarbageTerminatorType, MagicType, NUM_ELLIGATOR_SWIFT_BYTES,
    NUM_GARBAGE_CONTENT_LIMIT, NUM_GARBAGE_TERMINATOR_BYTES, Role, find_garbage,
};
use crate::state_machine::{BufReader, HasFinal, ProtocolReadParser, ProtocolStatus};
use super::Bip324Error;

#[derive(Debug)]
pub enum HandshakeReadState {
    ReceivingKey(EcdhPoint, usize),          // secret_key, remaining_bytes
    ReceivingGarbage(GarbageTerminatorType), // inbound_garbage_terminator
    HandshakeDone(AADType),                  // garbage content (AAD)
}

impl HasFinal for HandshakeReadState {
    fn is_final(&self) -> bool {
        matches!(self, Self::HandshakeDone(_))
    }
}

pub struct HandshakeReadParser {
    role: Role,
    magic: MagicType,
    state: Option<HandshakeReadState>,
    read_buffer: Vec<u8>,
    other_key: Option<[u8; NUM_ELLIGATOR_SWIFT_BYTES]>,

    // Tracks our own ellswift bytes so the user can read them at any time
    own_ellswift_bytes: [u8; NUM_ELLIGATOR_SWIFT_BYTES],

    // Output buffers -- drained by caller after each step()
    output_key_bytes: Vec<u8>,
    output_garbage_bytes: Vec<u8>,
    output_terminator_bytes: Vec<u8>,
    key_eof: bool,
    garbage_eof: bool,

    // Derived protocol data
    cipher_session: Option<CipherSession>,
    outbound_garbage_terminator: Option<GarbageTerminatorType>,
}

impl HandshakeReadParser {
    pub fn new(role: Role, magic: MagicType, secret_key: EcdhPoint) -> Self {
        let own_ellswift_bytes = secret_key.elligator_swift.to_array();
        Self {
            role,
            magic,
            state: Some(HandshakeReadState::ReceivingKey(
                secret_key,
                NUM_ELLIGATOR_SWIFT_BYTES,
            )),
            read_buffer: vec![],
            other_key: None,
            own_ellswift_bytes,
            output_key_bytes: vec![],
            output_garbage_bytes: vec![],
            output_terminator_bytes: vec![],
            key_eof: false,
            garbage_eof: false,
            cipher_session: None,
            outbound_garbage_terminator: None,
        }
    }

    fn on_share_received(
        &mut self,
        point: EcdhPoint,
    ) -> Result<GarbageTerminatorType, (EcdhPoint, Bip324Error)> {
        let Some(other_key) = &self.other_key else {
            return Err((
                point,
                Bip324Error::IllegalState("on_share_received called with empty other_key".to_string()),
            ));
        };
        let cipher = CipherSession::new_from_shares(self.magic, self.role, point, other_key)
            .map_err(|(point, _)| (point, Bip324Error::KeyGenerationError))?;
        let inbound_garbage_terminator = cipher.inbound_garbage_terminator;
        let outbound_garbage_terminator = cipher.outbound_garbage_terminator;

        self.cipher_session = Some(cipher);
        self.outbound_garbage_terminator = Some(outbound_garbage_terminator);

        Ok(inbound_garbage_terminator)
    }

    pub fn set_ecdh_point(
        &mut self,
        point: EcdhPoint,
    ) -> Result<(), (EcdhPoint, Bip324Error)> {
        use HandshakeReadState::*;

        if self.state.as_ref().is_some_and(|s| s.is_final()) {
            return Err((
                point,
                Bip324Error::IllegalState("Can't change key. Handshake is already done".to_string()),
            ));
        }

        self.own_ellswift_bytes = point.elligator_swift.to_array();

        match self.state.take() {
            Some(ReceivingKey(_old_point, remaining)) => {
                self.state = Some(ReceivingKey(point, remaining));
                Ok(())
            }
            Some(ReceivingGarbage(_old_garbage_terminator)) => {
                let inbound_garbage_terminator = self
                    .on_share_received(point)?;
                self.state = Some(ReceivingGarbage(inbound_garbage_terminator));
                Ok(())
            }
            state => {
                self.state = state;
                Err((
                    point,
                    Bip324Error::IllegalState("Can't change key in this state".to_string()),
                ))
            }
        }
    }

    pub fn drain_key_bytes(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.output_key_bytes)
    }

    pub fn drain_garbage_bytes(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.output_garbage_bytes)
    }

    pub fn drain_terminator_bytes(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.output_terminator_bytes)
    }

    pub fn is_key_eof(&self) -> bool {
        self.key_eof
    }

    pub fn is_garbage_eof(&self) -> bool {
        self.garbage_eof
    }

    pub fn take_ciphers(&mut self) -> Option<(InboundCipher, OutboundCipher)> {
        self.cipher_session.take().map(|c| c.into_split())
    }

    pub fn outbound_garbage_terminator(&self) -> Option<&GarbageTerminatorType> {
        self.outbound_garbage_terminator.as_ref()
    }

    pub fn elligator_swift_bytes(&self) -> [u8; NUM_ELLIGATOR_SWIFT_BYTES] {
        self.own_ellswift_bytes
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
            ReceivingKey(point, mut remaining) => {
                let mut key_buf = vec![0u8; remaining];
                let size = match data.read(&mut key_buf) {
                    Ok(size) => size,
                    Err(err) => {
                        return (
                            ReceivingKey(point, remaining),
                            Err(Bip324Error::ReadError(err)),
                        );
                    }
                };
                remaining -= size;

                self.read_buffer.extend_from_slice(&key_buf[..size]);
                self.output_key_bytes.extend_from_slice(&key_buf[..size]);

                if remaining == 0 {
                    self.key_eof = true;

                    let mut other_key = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
                    other_key.copy_from_slice(&std::mem::take(&mut self.read_buffer));
                    self.other_key = Some(other_key);

                    let inbound_garbage_terminator = match self.on_share_received(point) {
                        Ok(ret) => ret,
                        Err((point, err)) => {
                            return (ReceivingKey(point, remaining), Err(err));
                        }
                    };

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
                    self.output_garbage_bytes.extend_from_slice(&garbage_chunk);
                    self.garbage_eof = true;

                    let term_chunk = self.read_buffer[garbage_len..].to_vec();
                    self.output_terminator_bytes.extend_from_slice(&term_chunk);

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
                    self.output_garbage_bytes.extend_from_slice(&garbage_chunk);

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

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use secp256k1::rand::{CryptoRng, RngCore};
    use secp256k1::rand::rngs::mock::StepRng;

    use crate::protocol::NUM_GARBAGE_TERMINATOR_BYTES;
    use crate::state_machine::StreamReadParser;

    const DEFAULT_MAGIC: MagicType = [0xF9, 0xBE, 0xB4, 0xD9];

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

    fn parser_from_rng<Rng: RngCore + CryptoRng>(
        role: Role,
        rng: &mut Rng,
    ) -> HandshakeReadParser {
        let bytes = secret_key_bytes_from_rng(rng);
        let point = crate::key_from_secret_bytes(bytes).unwrap();
        HandshakeReadParser::new(role, DEFAULT_MAGIC, point)
    }

    fn parser_from_seed(role: Role, seed: u64) -> HandshakeReadParser {
        let mut rng = insecurerng(seed);
        parser_from_rng(role, &mut rng)
    }

    // 1. Feed 64 key bytes at once. Verify drain_key_bytes() returns all 64.
    //    Verify state transitions to ReceivingGarbage.
    #[test]
    fn test_parse_key_complete() {
        let mut parser = parser_from_seed(Role::Responder, 1111);

        let key_bytes = [0x42u8; NUM_ELLIGATOR_SWIFT_BYTES];
        let mut data = &key_bytes[..];
        parser.step(&mut data).unwrap();

        let drained = parser.drain_key_bytes();
        assert_eq!(drained.len(), NUM_ELLIGATOR_SWIFT_BYTES);
        assert_eq!(drained, key_bytes);
        assert!(parser.is_key_eof());
        assert!(matches!(
            parser.state,
            Some(HandshakeReadState::ReceivingGarbage(_))
        ));
    }

    // 2. Feed 1 byte at a time (64 iterations). After each step(), verify
    //    drain_key_bytes() returns 1 byte. After 64, verify state is ReceivingGarbage.
    #[test]
    fn test_parse_key_byte_by_byte() {
        let mut parser = parser_from_seed(Role::Responder, 2222);

        let key_bytes = [0x7Eu8; NUM_ELLIGATOR_SWIFT_BYTES];
        for i in 0..NUM_ELLIGATOR_SWIFT_BYTES {
            let mut data = &key_bytes[i..i + 1];
            parser.step(&mut data).unwrap();
            let drained = parser.drain_key_bytes();
            assert_eq!(drained.len(), 1, "Expected 1 byte at step {i}");
            assert_eq!(drained[0], key_bytes[i]);
        }

        assert!(parser.is_key_eof());
        assert!(matches!(
            parser.state,
            Some(HandshakeReadState::ReceivingGarbage(_))
        ));
    }

    // 3. Feed 74 bytes. Verify key output is 64 bytes, parser in ReceivingGarbage,
    //    extra 10 bytes consumed as potential garbage.
    #[test]
    fn test_parse_key_overflow() {
        let mut parser = parser_from_seed(Role::Responder, 3333);

        let all_bytes = [0x5Au8; NUM_ELLIGATOR_SWIFT_BYTES + 10];
        let mut data = &all_bytes[..];
        // step() reads exactly remaining (64) bytes from the key phase; then Continue loops.
        // consume() runs until End.
        parser.consume(&mut data).unwrap();

        let drained = parser.drain_key_bytes();
        assert_eq!(drained.len(), NUM_ELLIGATOR_SWIFT_BYTES);
        assert!(parser.is_key_eof());
        assert!(matches!(
            parser.state,
            Some(HandshakeReadState::ReceivingGarbage(_))
        ));
    }

    // 4. Feed HANDSHAKE_PARAMS1.client_key as the peer's key. Verify take_ciphers()
    //    returns Some((inbound, outbound)). Confirm derived key material matches
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

        let mut parser = parser_from_seed(Role::Responder, server_seed);

        let mut data = &client_key[..];
        parser.consume(&mut data).unwrap();

        let (inbound, outbound) = parser.take_ciphers().expect("Expected ciphers after key phase");

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
        let Some(HandshakeReadState::ReceivingGarbage(inbound_term)) = parser.state.as_ref()
        else {
            panic!("Expected ReceivingGarbage state");
        };
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

        let mut parser = parser_from_seed(Role::Responder, server_seed);

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
        assert_eq!(drained_term, client_garbage_terminator, "Terminator mismatch");
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

        let mut parser = parser_from_seed(Role::Responder, server_seed);

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
        let mut parser = parser_from_seed(Role::Responder, 7777);

        // Feed a partial key (30 bytes)
        let mut partial = &client_key[..30];
        parser.step(&mut partial).unwrap();
        assert!(matches!(
            parser.state,
            Some(HandshakeReadState::ReceivingKey(..))
        ));

        // Replace the key with the "real" server key (from server_seed)
        let server_point = {
            let mut rng = insecurerng(server_seed);
            let bytes = secret_key_bytes_from_rng(&mut rng);
            crate::key_from_secret_bytes(bytes).unwrap()
        };
        parser.set_ecdh_point(server_point).unwrap();

        // Feed the remaining 34 bytes
        let mut rest = &client_key[30..];
        parser.consume(&mut rest).unwrap();

        // Now take ciphers — they should be derived from the real server key + client_key
        let (inbound, outbound) = parser.take_ciphers().expect("Expected ciphers");
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
        let mut parser = parser_from_seed(Role::Responder, 8888);

        // Feed full client key — parser moves to ReceivingGarbage with wrong ciphers
        let mut data = &client_key[..];
        parser.consume(&mut data).unwrap();
        assert!(matches!(
            parser.state,
            Some(HandshakeReadState::ReceivingGarbage(_))
        ));

        // Replace with the correct server key
        let server_point = {
            let mut rng = insecurerng(server_seed);
            let bytes = secret_key_bytes_from_rng(&mut rng);
            crate::key_from_secret_bytes(bytes).unwrap()
        };
        parser.set_ecdh_point(server_point).unwrap();

        // take_ciphers() should now give ciphers from the real server key + client_key
        let (inbound, outbound) = parser.take_ciphers().expect("Expected ciphers");
        assert_eq!(inbound.length_cipher.unwrap().key_bytes, initiator_l);
        assert_eq!(inbound.packet_cipher.key_bytes, initiator_p);
        assert_eq!(outbound.length_cipher.key_bytes, responder_l);
        assert_eq!(outbound.packet_cipher.key_bytes, responder_p);
    }
}
