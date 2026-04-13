use std::cmp;
use std::collections::VecDeque;

use crate::cipher::OutboundCipher;
use crate::protocol::{NUM_ELLIGATOR_SWIFT_BYTES, NUM_GARBAGE_TERMINATOR_BYTES};
use crate::state_machine::{BufWriter, HasFinal, ProtocolStatus, ProtocolWriteParser};
use super::SharedHandshakeState;

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
        self.outbound_cipher.is_some()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_from_secret_bytes;
    use crate::protocol::{MAINNET_MAGIC, Role};
    use crate::state_machine::{ProtocolStatus, StreamWriteParser};

    const KEY_LEN: usize = NUM_ELLIGATOR_SWIFT_BYTES;
    const TERMINATOR_LEN: usize = NUM_GARBAGE_TERMINATOR_BYTES;

    // Deterministic secret bytes for tests.
    const SECRET_A: [u8; 32] = [0x01u8; 32];
    const SECRET_B: [u8; 32] = [0x02u8; 32];

    fn make_writer() -> (HandshakeWriteParser, [u8; KEY_LEN]) {
        let point = key_from_secret_bytes(SECRET_A).unwrap();
        let expected_key = point.elligator_swift.to_array();
        let (_, writer) = super::super::new_handshake_pair(Role::Initiator, MAINNET_MAGIC, point);
        (writer, expected_key)
    }

    // 1. Create parser with key from shared state. produce() with 64-byte buffer.
    //    Verify all key bytes written match the ellswift bytes.
    #[test]
    fn test_write_key_complete() {
        let (mut parser, expected_key) = make_writer();

        let mut buf = vec![0u8; KEY_LEN];
        let mut write_slice = buf.as_mut_slice();
        parser.step(&mut write_slice).unwrap();

        assert_eq!(buf, expected_key);
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
                parser.step(&mut s).unwrap();
            }
            all_output.extend_from_slice(&chunk);
            remaining -= this_chunk;
        }

        assert_eq!(all_output, expected_key);
    }

    // 3. Full handshake: key || garbage || terminator in one produce() call.
    //    The outbound terminator is injected via the test helper.
    #[test]
    fn test_write_full_handshake() {
        let point = key_from_secret_bytes(SECRET_A).unwrap();
        let expected_key = point.elligator_swift.to_array();
        let (_, mut parser) =
            super::super::new_handshake_pair(Role::Initiator, MAINNET_MAGIC, point);

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
    }

    // 4. No garbage: output is key || terminator.
    #[test]
    fn test_write_no_garbage() {
        let point = key_from_secret_bytes(SECRET_B).unwrap();
        let expected_key = point.elligator_swift.to_array();
        let (_, mut parser) =
            super::super::new_handshake_pair(Role::Initiator, MAINNET_MAGIC, point);

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
    }

    // 5. writer_started_sending is false before any write, true after.
    #[test]
    fn test_writer_started_sending_flag() {
        let (mut parser, _) = make_writer();

        assert!(!parser.shared.borrow().writer_started_sending);

        let mut buf = vec![0u8; 1];
        parser.step(&mut buf.as_mut_slice()).unwrap();

        assert!(parser.shared.borrow().writer_started_sending);
    }

    // 6. Push garbage in small chunks, calling step() after each. Verify output accumulates correctly.
    #[test]
    fn test_pacing_garbage() {
        let point = key_from_secret_bytes(SECRET_A).unwrap();
        let expected_key = point.elligator_swift.to_array();
        let (_, mut parser) =
            super::super::new_handshake_pair(Role::Initiator, MAINNET_MAGIC, point);

        // Consume the key phase first
        let mut key_out = vec![0u8; KEY_LEN];
        {
            let mut s = key_out.as_mut_slice();
            let result = parser.step(&mut s).unwrap();
            assert!(matches!(result, ProtocolStatus::Continue));
        }
        assert_eq!(key_out, expected_key);
        assert!(matches!(
            parser.state,
            Some(HandshakeWriteState::SendingGarbage)
        ));

        // Push garbage in 3 chunks of 5 bytes and step after each
        let full_garbage = vec![0x77u8; 15];
        let mut all_garbage_out = Vec::new();

        for chunk in full_garbage.chunks(5) {
            parser.push_garbage_bytes(chunk);
            let mut gbuf = vec![0u8; 5];
            {
                let mut s = gbuf.as_mut_slice();
                parser.step(&mut s).unwrap();
            }
            all_garbage_out.extend_from_slice(&gbuf);
        }

        assert_eq!(all_garbage_out, full_garbage);
        assert!(matches!(
            parser.state,
            Some(HandshakeWriteState::SendingGarbage)
        ));
    }

    // 7. Push garbage without setting EOF. Verify parser stays in SendingGarbage and returns End.
    #[test]
    fn test_no_output_when_no_garbage_eof() {
        let (mut parser, _) = make_writer();

        // Consume key phase
        let mut key_buf = vec![0u8; KEY_LEN];
        {
            let mut s = key_buf.as_mut_slice();
            parser.step(&mut s).unwrap();
        }

        // Push garbage but do NOT set EOF
        parser.push_garbage_bytes(&[0xCCu8; 10]);

        // Run step with a large buffer
        let mut buf = vec![0u8; 100];
        let result = {
            let mut s = buf.as_mut_slice();
            parser.step(&mut s).unwrap()
        };

        // Should return End (no transition to SendingGarbageTerminator)
        assert!(matches!(result, ProtocolStatus::End));
        // Parser should still be in SendingGarbage
        assert!(matches!(
            parser.state,
            Some(HandshakeWriteState::SendingGarbage)
        ));
    }

    // 8. SendingGarbageTerminator waits when outbound_garbage_terminator is not yet ready.
    #[test]
    fn test_terminator_waits_for_ecdh() {
        let (mut parser, _) = make_writer();

        // Consume the key phase
        let mut key_buf = vec![0u8; KEY_LEN];
        parser.step(&mut key_buf.as_mut_slice()).unwrap();

        // Skip garbage (set EOF immediately -- no garbage bytes)
        parser.set_garbage_eof();

        // produce() drives through to SendingGarbageTerminator and stops because
        // outbound_garbage_terminator is None (no ECDH has been completed).
        let mut buf = vec![0u8; 200];
        parser.produce(&mut buf.as_mut_slice()).unwrap();

        // Parser is stuck at SendingGarbageTerminator, not Done
        assert!(!parser.is_done());
        assert!(parser.is_sending_terminator());
    }
}
