use crate::cipher::OutboundCipher;
use crate::external::chacha20_poly1305::ChaCha20Poly1305Stream;
use crate::protocol::NUM_LENGTH_BYTES;
use crate::state_machine::{BufWriter, HasFinal, ProtocolStatus, ProtocolWriteParser};

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
    input_length_bytes: Vec<u8>,
    input_data_bytes: Vec<u8>,
    input_tag_bytes: Vec<u8>,
    input_aad: Option<Vec<u8>>,
}

impl DataWriteParser {
    pub fn new(outbound_cipher: OutboundCipher) -> Self {
        Self {
            state: Some(DataWriteState::SendingLength(NUM_LENGTH_BYTES, vec![])),
            outbound_cipher,
            input_length_bytes: vec![],
            input_data_bytes: vec![],
            input_tag_bytes: vec![],
            input_aad: None,
        }
    }

    pub fn push_length_bytes(&mut self, bytes: &[u8]) {
        self.input_length_bytes.extend_from_slice(bytes);
    }

    pub fn push_data_bytes(&mut self, bytes: &[u8]) {
        self.input_data_bytes.extend_from_slice(bytes);
    }

    pub fn push_tag_bytes(&mut self, bytes: &[u8]) {
        self.input_tag_bytes.extend_from_slice(bytes);
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
                let new_written = [&written[..], &self.input_length_bytes[..size]].concat();
                buf.copy_from_slice(&self.input_length_bytes[..size]);
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

                buf.copy_from_slice(&self.input_data_bytes[..size]);
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

#[cfg(test)]
mod tests {
    use super::*;
    use core::str::FromStr;
    use secp256k1::SecretKey;
    use secp256k1::ellswift::{ElligatorSwift, ElligatorSwiftParty};

    use crate::bip324::data_read::DataReadParser;
    use crate::cipher::{CipherSession, InboundCipher, OutboundCipher, SessionKeyMaterial};
    use crate::protocol::{NUM_TAG_BYTES, Role};
    use crate::state_machine::{StreamReadParser, StreamWriteParser};

    const MAGIC: [u8; 4] = [0xF9, 0xBE, 0xB4, 0xD9];

    // Returns (alice_outbound [sender], bob_inbound [receiver]) using fixed known keys.
    fn make_cipher_pair() -> (OutboundCipher, InboundCipher) {
        let alice = SecretKey::from_str(
            "61062ea5071d800bbfd59e2e8b53d47d194b095ae5a4df04936b49772ef0d4d7",
        )
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
            parser.step(&mut out_slice).unwrap();
        }
        for &byte in &data_bytes {
            parser.push_data_bytes(&[byte]);
            parser.step(&mut out_slice).unwrap();
        }
        for &byte in &tag_placeholder {
            parser.push_tag_bytes(&[byte]);
            parser.step(&mut out_slice).unwrap();
        }

        let packet_len = bob_in.decrypt_packet_len(out[..NUM_LENGTH_BYTES].try_into().unwrap());
        let mut ct_body = out[NUM_LENGTH_BYTES..NUM_LENGTH_BYTES + packet_len].to_vec();
        let (_pkt_type, msg) = bob_in.decrypt_in_place(&mut ct_body, None).unwrap();

        assert_eq!(&msg[1..], plaintext);
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
        let (_pkt, msg) = bob_in.decrypt_in_place(&mut ct_body, Some(&garbage_aad)).unwrap();

        assert_eq!(&msg[1..], plaintext);
    }

    // 5. Push arbitrary tag bytes (not matching computed tag). Verify output uses the parser's
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
    }

    // 6. Encrypt with DataWriteParser, decrypt with DataReadParser. Verify plaintext matches.
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
    }
}
