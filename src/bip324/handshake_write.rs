use std::cmp;

use crate::cipher::OutboundCipher;
use crate::state_machine::{BufWriter, HasFinal, ProtocolStatus, ProtocolWriteParser};

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
    key_bytes: Vec<u8>,
    garbage_bytes: Vec<u8>,
    garbage_eof: bool,
    terminator_bytes: Vec<u8>,
    outbound_cipher: Option<OutboundCipher>,
}

impl HandshakeWriteParser {
    pub fn new(key_bytes: Vec<u8>) -> Self {
        Self {
            state: Some(HandshakeWriteState::SendingKey),
            key_bytes,
            garbage_bytes: vec![],
            garbage_eof: false,
            terminator_bytes: vec![],
            outbound_cipher: None,
        }
    }

    pub fn set_key_bytes(&mut self, key: Vec<u8>) {
        self.key_bytes = key;
    }

    pub fn push_garbage_bytes(&mut self, bytes: &[u8]) {
        self.garbage_bytes.extend_from_slice(bytes);
    }

    pub fn set_garbage_eof(&mut self) {
        self.garbage_eof = true;
    }

    pub fn set_terminator(&mut self, terminator: &[u8]) {
        self.terminator_bytes = terminator.to_vec();
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
                let size = cmp::min(data.remaining(), self.key_bytes.len());
                data.write_all(&self.key_bytes[..size]).unwrap();
                self.key_bytes.splice(..size, []);

                if self.key_bytes.is_empty() {
                    (SendingGarbage, Ok(ProtocolStatus::Continue))
                } else {
                    (state, Ok(ProtocolStatus::End))
                }
            }
            state @ SendingGarbage => {
                let size = cmp::min(data.remaining(), self.garbage_bytes.len());
                data.write_all(&self.garbage_bytes[..size]).unwrap();
                self.garbage_bytes.splice(..size, []);

                if self.garbage_bytes.is_empty() && self.garbage_eof {
                    (SendingGarbageTerminator, Ok(ProtocolStatus::Continue))
                } else {
                    (state, Ok(ProtocolStatus::End))
                }
            }
            state @ SendingGarbageTerminator => {
                let size = cmp::min(data.remaining(), self.terminator_bytes.len());
                data.write_all(&self.terminator_bytes[..size]).unwrap();
                self.terminator_bytes.splice(..size, []);

                if self.terminator_bytes.is_empty() {
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
    use crate::protocol::NUM_ELLIGATOR_SWIFT_BYTES;
    use crate::state_machine::{ProtocolStatus, StreamWriteParser};

    const KEY_LEN: usize = NUM_ELLIGATOR_SWIFT_BYTES;
    const TERMINATOR_LEN: usize = 16;

    // 1. Create parser with 64 key bytes. produce() with 64-byte buffer. Verify all key bytes written.
    #[test]
    fn test_write_key_complete() {
        let expected_key = vec![0xABu8; KEY_LEN];
        let mut parser = HandshakeWriteParser::new(expected_key.clone());

        let mut buf = vec![0u8; KEY_LEN];
        let mut write_slice = buf.as_mut_slice();
        parser.step(&mut write_slice).unwrap();

        assert_eq!(buf, expected_key);
    }

    // 2. Create parser with 64 key bytes. step() with 10-byte buffer repeatedly. Verify correct chunking.
    #[test]
    fn test_write_key_chunked() {
        let expected_key: Vec<u8> = (0u8..KEY_LEN as u8).collect();
        let mut parser = HandshakeWriteParser::new(expected_key.clone());

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
    #[test]
    fn test_write_full_handshake() {
        let key = vec![0x01u8; KEY_LEN];
        let garbage = vec![0xFFu8; 20];
        let terminator = vec![0xAAu8; TERMINATOR_LEN];

        let mut parser = HandshakeWriteParser::new(key.clone());
        parser.push_garbage_bytes(&garbage);
        parser.set_garbage_eof();
        parser.set_terminator(&terminator);

        let mut buf = vec![0u8; KEY_LEN + 20 + TERMINATOR_LEN];
        {
            let mut s = buf.as_mut_slice();
            parser.produce(&mut s).unwrap();
        }

        let mut expected = Vec::new();
        expected.extend_from_slice(&key);
        expected.extend_from_slice(&garbage);
        expected.extend_from_slice(&terminator);

        assert_eq!(buf, expected);
        assert!(parser.is_done());
    }

    // 4. No garbage: output is key || terminator.
    #[test]
    fn test_write_no_garbage() {
        let key = vec![0x02u8; KEY_LEN];
        let terminator = vec![0xBBu8; TERMINATOR_LEN];

        let mut parser = HandshakeWriteParser::new(key.clone());
        parser.set_garbage_eof();
        parser.set_terminator(&terminator);

        let mut buf = vec![0u8; KEY_LEN + TERMINATOR_LEN];
        {
            let mut s = buf.as_mut_slice();
            parser.produce(&mut s).unwrap();
        }

        let mut expected = Vec::new();
        expected.extend_from_slice(&key);
        expected.extend_from_slice(&terminator);

        assert_eq!(buf, expected);
        assert!(parser.is_done());
    }

    // 5. Change key bytes before any writing. Verify new key is written.
    #[test]
    fn test_set_key_bytes() {
        let original_key = vec![0x01u8; KEY_LEN];
        let new_key = vec![0x02u8; KEY_LEN];

        let mut parser = HandshakeWriteParser::new(original_key);
        parser.set_key_bytes(new_key.clone());

        let mut buf = vec![0u8; KEY_LEN];
        {
            let mut s = buf.as_mut_slice();
            parser.step(&mut s).unwrap();
        }

        assert_eq!(buf, new_key);
    }

    // 6. Push garbage in small chunks, calling step() after each. Verify output accumulates correctly.
    #[test]
    fn test_pacing_garbage() {
        let key = vec![0x03u8; KEY_LEN];
        let mut parser = HandshakeWriteParser::new(key.clone());

        // Consume the key phase first
        let mut key_out = vec![0u8; KEY_LEN];
        {
            let mut s = key_out.as_mut_slice();
            let result = parser.step(&mut s).unwrap();
            assert!(matches!(result, ProtocolStatus::Continue));
        }
        assert_eq!(key_out, key);
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
        let key = vec![0x04u8; KEY_LEN];
        let mut parser = HandshakeWriteParser::new(key);

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
}
