use std::cmp;

use crate::cipher::{InboundCipher, LengthDecryptor};
use crate::external::chacha20_poly1305::ChaCha20Poly1305Stream;
use crate::protocol::{AADType, NUM_LENGTH_BYTES, NUM_TAG_BYTES, TagType};
use crate::state_machine::{BufReader, HasFinal, ProtocolReadParser, ProtocolStatus};

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
    /// Always returns false -- packet reading loops forever
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
    output_length_bytes: Vec<u8>,
    output_data_bytes: Vec<u8>,
    output_tag_bytes: Vec<u8>,
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
            output_length_bytes: vec![],
            output_data_bytes: vec![],
            output_tag_bytes: vec![],
            output_aad: None,
        }
    }

    pub fn drain_length_bytes(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.output_length_bytes)
    }

    pub fn drain_data_bytes(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.output_data_bytes)
    }

    pub fn drain_tag_bytes(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.output_tag_bytes)
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

                self.output_length_bytes.extend_from_slice(&data_to_process);

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
                self.output_data_bytes.extend_from_slice(&data_to_process);

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

                self.output_tag_bytes.extend_from_slice(&data_to_process);

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

#[cfg(test)]
mod tests {
    use super::*;
    use core::str::FromStr;
    use secp256k1::SecretKey;
    use secp256k1::ellswift::{ElligatorSwift, ElligatorSwiftParty};

    use crate::cipher::{CipherSession, OutboundCipher, SessionKeyMaterial};
    use crate::protocol::{PacketType, NUM_LENGTH_BYTES, NUM_TAG_BYTES, Role};
    use crate::state_machine::StreamReadParser;

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

    fn encrypt_packet(outbound: &mut OutboundCipher, plaintext: &[u8]) -> Vec<u8> {
        outbound.encrypt_to_vec(plaintext, PacketType::Genuine, None)
    }

    fn encrypt_packet_with_aad(outbound: &mut OutboundCipher, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        outbound.encrypt_to_vec(plaintext, PacketType::Genuine, Some(aad))
    }

    // Drain and check: length_bytes is 3 bytes, data_bytes is 1+plaintext.len(),
    // tag_bytes is NUM_TAG_BYTES and matches the last 16 bytes of ciphertext.
    fn assert_packet_outputs(
        parser: &mut DataReadParser,
        plaintext: &[u8],
        ciphertext: &[u8],
    ) {
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
        let ciphertext = encrypt_packet(&mut alice_out, plaintext);

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
        let ciphertext = encrypt_packet(&mut alice_out, plaintext);

        let mut parser = DataReadParser::new(vec![], bob_in);

        let mut all_length = vec![];
        let mut all_data = vec![];
        let mut all_tag = vec![];

        for byte in &ciphertext {
            let mut slice = std::slice::from_ref(byte);
            parser.step(&mut slice).unwrap();
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
        let ct1 = encrypt_packet(&mut alice_out, msg1);
        let ct2 = encrypt_packet(&mut alice_out, msg2);

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
        let ct1 = encrypt_packet_with_aad(&mut alice_out, b"version", &garbage_aad);
        let mut data = &ct1[..];
        parser.consume(&mut data).unwrap();

        assert_eq!(
            parser.take_aad(),
            Some(garbage_aad),
            "AAD should be returned after first packet"
        );
        assert_eq!(parser.take_aad(), None, "take_aad() is one-shot");

        // Second packet (no new AAD was set), encrypt with no AAD
        let ct2 = encrypt_packet(&mut alice_out, b"second");
        let mut data = &ct2[..];
        parser.consume(&mut data).unwrap();

        assert_eq!(
            parser.take_aad(),
            None,
            "No AAD for second packet (none was set)"
        );
    }

    // 5. Feed correct length + content, then corrupt tag bytes. Verify panic.
    #[test]
    #[should_panic(expected = "AEAD tag check fail")]
    fn test_corrupt_tag_panics() {
        let (mut alice_out, bob_in) = make_cipher_pair();

        let plaintext = b"tag corruption test";
        let mut ciphertext = encrypt_packet(&mut alice_out, plaintext);

        // Corrupt all 16 tag bytes at the end
        let len = ciphertext.len();
        for byte in &mut ciphertext[len - NUM_TAG_BYTES..] {
            *byte ^= 0xFF;
        }

        let mut parser = DataReadParser::new(vec![], bob_in);
        let mut data = &ciphertext[..];
        parser.consume(&mut data).unwrap();
    }

    // 6. Use known session keys. Verify the parser decodes the known ciphertext vector.
    //    Matches test_vector_1 in cipher.rs: alice encrypts [0x8e] after one warmup packet,
    //    producing ciphertext "7530d2a18720162ac09c25329a60d75adf36eda3c3".
    #[test]
    fn test_known_vectors() {
        use hex::prelude::*;

        let (mut alice_out, bob_in) = make_cipher_pair();

        // Warmup: encrypt 100 bytes (matches test_vector_1 in cipher.rs which uses
        // gen_garbage(100) before the known second packet)
        let warmup_ct = encrypt_packet(&mut alice_out, &[0u8; 100]);

        let contents: Vec<u8> = vec![0x8e];
        let ct = encrypt_packet(&mut alice_out, &contents);
        assert_eq!(
            ct,
            Vec::from_hex("7530d2a18720162ac09c25329a60d75adf36eda3c3").unwrap(),
            "Known vector ciphertext mismatch"
        );

        let mut parser = DataReadParser::new(vec![], bob_in);

        // Consume warmup packet
        let mut data = &warmup_ct[..];
        parser.consume(&mut data).unwrap();
        parser.drain_length_bytes();
        parser.drain_data_bytes();
        parser.drain_tag_bytes();

        // Consume known vector packet
        let mut data = &ct[..];
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
}
