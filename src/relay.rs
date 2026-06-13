use std::collections::VecDeque;
use std::error::Error;
use std::io::{Read, Write};

use crate::protocol::{
    NUM_ELLIGATOR_SWIFT_BYTES, NUM_GARBAGE_TERMINATOR_BYTES, NUM_LENGTH_BYTES, NUM_TAG_BYTES,
    PartialPacket, ProtocolBuffer,
};

pub trait FakePeerRelayReader {
    fn read_key(&mut self, data: &mut [u8]) -> std::io::Result<usize>;
    fn is_eof_key(&self) -> bool;
    fn peek_len_key(&self) -> usize;

    fn read_garbage(&mut self, data: &mut [u8]) -> std::io::Result<usize>;
    fn is_eof_garbage(&self) -> bool;
    fn peek_len_garbage(&self) -> usize;

    fn read_terminator(&mut self, data: &mut [u8]) -> std::io::Result<usize>;
    fn is_eof_terminator(&self) -> bool;
    fn peek_len_terminator(&self) -> usize;

    fn read_length_bytes(&mut self, data: &mut [u8]) -> usize;
    fn peek_length_bytes(&self) -> usize;
    fn read_data_bytes(&mut self, buf: &mut [u8]) -> usize;
    fn peek_data_bytes(&self) -> usize;
    fn read_tag_bytes(&mut self, buf: &mut [u8]) -> usize;
    fn peek_tag_bytes(&self) -> usize;
    fn read_aad(&mut self) -> Option<Vec<u8>>;
    fn peek_aad_bytes(&self) -> usize;
}

pub trait FakePeerRelayWriter {
    fn write_key(&mut self, data: &[u8]) -> std::io::Result<usize>;
    fn set_eof_key(&mut self);

    fn write_garbage(&mut self, data: &[u8]) -> std::io::Result<usize>;
    fn set_eof_garbage(&mut self);

    fn write_terminator(&mut self, data: &[u8]) -> std::io::Result<usize>;
    fn set_eof_terminator(&mut self);

    /// Writes the length section of a packet. BIP-324 decodes it as a 3 byte little-endian integer.
    fn write_length_bytes(&mut self, data: &[u8]);
    /// Writes the payload section of a packet
    fn write_data_bytes(&mut self, data: &[u8]);
    fn write_tag_bytes(&mut self, data: &[u8]);
    fn set_aad(&mut self, data: &[u8]);
}

#[derive(Default)]
pub struct FakePeerRelay {
    key: ProtocolBuffer,
    garbage: ProtocolBuffer,
    terminator: ProtocolBuffer,
    packets: Vec<PartialPacket>,
}

impl FakePeerRelay {
    pub fn remove_first_packet_if_empty(&mut self) {
        if self.packets.is_empty() {
            return;
        }

        if self.packets[0].is_empty() {
            self.packets.splice(..1, []);
        }
    }

    pub fn remove_first_packet(&mut self) {
        if self.packets.is_empty() {
            return;
        }
        self.packets.splice(..1, []);
    }
}

impl FakePeerRelayReader for FakePeerRelay {
    fn read_key(&mut self, data: &mut [u8]) -> std::io::Result<usize> {
        self.key.read(data)
    }

    fn is_eof_key(&self) -> bool {
        self.key.is_eof()
    }

    fn peek_len_key(&self) -> usize {
        self.key.peek_len()
    }

    fn read_garbage(&mut self, data: &mut [u8]) -> std::io::Result<usize> {
        self.garbage.read(data)
    }

    fn is_eof_garbage(&self) -> bool {
        self.garbage.is_eof()
    }

    fn peek_len_garbage(&self) -> usize {
        self.garbage.peek_len()
    }

    fn read_terminator(&mut self, data: &mut [u8]) -> std::io::Result<usize> {
        self.terminator.read(data)
    }

    fn is_eof_terminator(&self) -> bool {
        self.terminator.is_eof()
    }

    fn peek_len_terminator(&self) -> usize {
        self.terminator.peek_len()
    }

    fn read_length_bytes(&mut self, data: &mut [u8]) -> usize {
        if self.packets.is_empty() {
            return 0;
        }

        let packet = &mut self.packets[0];
        let size = packet.read_length_bytes(data);

        self.remove_first_packet_if_empty();

        size
    }

    fn peek_length_bytes(&self) -> usize {
        if self.packets.is_empty() {
            return 0;
        }

        self.packets[0].peek_length_bytes()
    }

    fn read_data_bytes(&mut self, data: &mut [u8]) -> usize {
        if self.packets.is_empty() {
            return 0;
        }

        let packet = &mut self.packets[0];
        let size = packet.read_data_bytes(data);

        self.remove_first_packet_if_empty();

        size
    }

    fn peek_data_bytes(&self) -> usize {
        if self.packets.is_empty() {
            return 0;
        }

        self.packets[0].peek_data_bytes()
    }

    fn read_tag_bytes(&mut self, data: &mut [u8]) -> usize {
        if self.packets.is_empty() {
            return 0;
        }

        let packet = &mut self.packets[0];
        let size = packet.read_tag_bytes(data);

        self.remove_first_packet_if_empty();

        size
    }

    fn peek_tag_bytes(&self) -> usize {
        if self.packets.is_empty() {
            return 0;
        }

        self.packets[0].peek_tag_bytes()
    }

    fn read_aad(&mut self) -> Option<Vec<u8>> {
        if self.packets.is_empty() {
            return None;
        }

        let packet = &mut self.packets[0];
        let aad = packet.read_aad();

        self.remove_first_packet_if_empty();

        aad
    }

    fn peek_aad_bytes(&self) -> usize {
        if self.packets.is_empty() {
            return 0;
        }

        self.packets[0].peek_aad()
    }
}

impl FakePeerRelayWriter for FakePeerRelay {
    fn write_key(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.key.write(data)
    }

    fn set_eof_key(&mut self) {
        self.key.set_eof();
    }

    fn write_garbage(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.garbage.write(data)
    }

    fn set_eof_garbage(&mut self) {
        self.garbage.set_eof();
    }

    fn write_terminator(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.terminator.write(data)
    }

    fn set_eof_terminator(&mut self) {
        self.terminator.set_eof();
    }

    fn write_length_bytes(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        if self.packets.is_empty()
            || self.packets[self.packets.len() - 1].data.is_some()
            || self.packets[self.packets.len() - 1].tag.is_some()
        {
            self.packets.push(PartialPacket::new());
        }

        let packets_len = self.packets.len();
        let last_packet = &mut self.packets[packets_len - 1];

        if last_packet.length_bytes.is_none() {
            last_packet.length_bytes = Some(VecDeque::new());
        }

        let length_bytes = &mut last_packet.length_bytes.as_mut().unwrap();
        length_bytes.extend(data);
    }

    fn write_data_bytes(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        if self.packets.is_empty() || self.packets[self.packets.len() - 1].tag.is_some() {
            self.packets.push(PartialPacket::new());
        }

        let packets_len = self.packets.len();
        let last_packet = &mut self.packets[packets_len - 1];

        if last_packet.data.is_none() {
            last_packet.data = Some(VecDeque::new());
        }

        let packet_data = &mut last_packet.data.as_mut().unwrap();
        packet_data.extend(data);
    }

    fn write_tag_bytes(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        if self.packets.is_empty() {
            self.packets.push(PartialPacket::new());
        }

        let packets_len = self.packets.len();
        let last_packet = &mut self.packets[packets_len - 1];

        if last_packet.tag.is_none() {
            last_packet.tag = Some(VecDeque::new());
        }

        let packet_tag = &mut last_packet.tag.as_mut().unwrap();
        packet_tag.extend(data);
    }

    fn set_aad(&mut self, aad: &[u8]) {
        if self.packets.is_empty() {
            self.packets.push(PartialPacket::new());
        }

        let packets_len = self.packets.len();
        let last_packet = &mut self.packets[packets_len - 1];

        last_packet.set_aad(aad);
    }
}

#[derive(Debug, PartialEq)]
pub struct HandshakeKey {
    pub data: Box<[u8; NUM_ELLIGATOR_SWIFT_BYTES]>,
}

#[derive(Debug, PartialEq)]
pub struct HandshakeGarbage {
    pub data: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct HandshakeTerminator {
    pub data: Box<[u8; NUM_GARBAGE_TERMINATOR_BYTES]>,
}

#[derive(Debug, PartialEq)]
pub enum ProtocolHandshakePacket {
    Key(HandshakeKey),
    Garbage(HandshakeGarbage),
    Terminator(HandshakeTerminator),
}

#[derive(Debug, PartialEq)]
pub struct ProtocolDataPacket {
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub enum ProtocolPacket {
    Handshake(ProtocolHandshakePacket),
    Data(ProtocolDataPacket),
    Err(Box<dyn Error>),
}

impl PartialEq for ProtocolPacket {
    fn eq(&self, other: &Self) -> bool {
        use ProtocolPacket::*;
        match (self, other) {
            (Handshake(v1), Handshake(v2)) => v1 == v2,
            (Data(v1), Data(v2)) => v1 == v2,
            (Err(..), Err(..)) => false,
            _ => false,
        }
    }
}

#[derive(Default)]
pub struct UserPacketRelay {
    pub stream_relay: FakePeerRelay,
    pub queue: VecDeque<ProtocolPacket>,
}

impl FakePeerRelayWriter for UserPacketRelay {
    fn write_key(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.stream_relay.write_key(data)
    }

    fn set_eof_key(&mut self) {
        if self.stream_relay.is_eof_key() {
            return;
        }
        self.stream_relay.set_eof_key();

        let mut data = [0u8; NUM_ELLIGATOR_SWIFT_BYTES];
        let packet = match self.stream_relay.read_key(&mut data) {
            Ok(read_cnt) => {
                if read_cnt != data.len() {
                    let err = format!(
                        "User relay can't read the entire key. Expected: {}. Read: {}.",
                        data.len(),
                        read_cnt
                    );
                    ProtocolPacket::Err(err.into())
                } else {
                    ProtocolPacket::Handshake(ProtocolHandshakePacket::Key(HandshakeKey {
                        data: data.into(),
                    }))
                }
            }
            Err(err) => ProtocolPacket::Err(err.into()),
        };

        self.queue.push_front(packet);
    }

    fn write_garbage(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.stream_relay.write_garbage(data)
    }

    fn set_eof_garbage(&mut self) {
        if self.stream_relay.is_eof_garbage() {
            return;
        }
        self.stream_relay.set_eof_garbage();

        let mut data = vec![0u8; self.stream_relay.peek_len_garbage()];
        let packet = match self.stream_relay.read_garbage(&mut data) {
            Ok(read_cnt) => {
                if read_cnt != data.len() {
                    let err = format!(
                        "User relay can't read the entire garbage. Expected: {}. Read: {}.",
                        data.len(),
                        read_cnt
                    );
                    ProtocolPacket::Err(err.into())
                } else {
                    ProtocolPacket::Handshake(ProtocolHandshakePacket::Garbage(HandshakeGarbage {
                        data,
                    }))
                }
            }
            Err(err) => ProtocolPacket::Err(err.into()),
        };

        self.queue.push_front(packet);
    }

    fn write_terminator(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.stream_relay.write_terminator(data)
    }

    fn set_eof_terminator(&mut self) {
        if self.stream_relay.is_eof_terminator() {
            return;
        }
        self.stream_relay.set_eof_terminator();

        let mut data = [0u8; NUM_GARBAGE_TERMINATOR_BYTES];
        let packet = match self.stream_relay.read_terminator(&mut data) {
            Ok(read_cnt) => {
                if read_cnt != data.len() {
                    let err = format!(
                        "User relay can't read the entire terminator. Expected: {}. Read: {}.",
                        data.len(),
                        read_cnt
                    );
                    ProtocolPacket::Err(err.into())
                } else {
                    ProtocolPacket::Handshake(ProtocolHandshakePacket::Terminator(
                        HandshakeTerminator { data: data.into() },
                    ))
                }
            }
            Err(err) => ProtocolPacket::Err(err.into()),
        };

        self.queue.push_front(packet);
    }

    fn write_length_bytes(&mut self, data: &[u8]) {
        self.stream_relay.write_length_bytes(data);

        if self.stream_relay.peek_length_bytes() < NUM_LENGTH_BYTES {
            return;
        }

        let mut buf = [0u8; NUM_LENGTH_BYTES];
        self.stream_relay.read_length_bytes(&mut buf);
    }

    fn write_data_bytes(&mut self, data: &[u8]) {
        self.stream_relay.write_data_bytes(data);
    }

    fn write_tag_bytes(&mut self, data: &[u8]) {
        self.stream_relay.write_tag_bytes(data);
        if self.stream_relay.peek_tag_bytes() < NUM_TAG_BYTES {
            return;
        }

        let payload_len = self.stream_relay.peek_data_bytes();
        let mut buf = vec![0u8; payload_len];
        self.stream_relay.read_data_bytes(&mut buf);
        self.queue
            .push_front(ProtocolPacket::Data(ProtocolDataPacket { data: buf }));
        // Since we only read the data, and we don't need something else, we can
        // remove the packet even if it's not empty
        self.stream_relay.remove_first_packet();
    }

    fn set_aad(&mut self, _aad: &[u8]) {
        // The user packet relay doesn't expose the aad
    }
}

impl UserPacketRelay {
    pub fn next_protocol_packet(&mut self) -> Option<ProtocolPacket> {
        self.queue.pop_back()
    }
}
