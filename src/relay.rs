use std::collections::VecDeque;
use std::io::{Read, Write};

use crate::protocol::{PartialPacket, ProtocolBuffer};

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
    pub fn remove_first_packet_if_consumed(&mut self) {
        if self.packets.is_empty() {
            return;
        }
        let packet = &self.packets[0];
        let packet_is_empty = packet.is_empty();
        let is_consumed = packet_is_empty && self.packets.len() > 1;

        if is_consumed {
            self.packets.splice(..1, []);
        }
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

        self.remove_first_packet_if_consumed();

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

        self.remove_first_packet_if_consumed();

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

        self.remove_first_packet_if_consumed();

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

        let packet_is_empty = packet.is_empty();
        let is_consumed = packet_is_empty && self.packets.len() > 1;

        if is_consumed {
            self.packets.splice(..1, []);
        }

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
