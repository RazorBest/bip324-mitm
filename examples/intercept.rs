use std::collections::{HashMap, VecDeque};
use std::error::Error;

use bip324_mitm::MitmBIP324;
use etherparse::{InternetSlice::Ipv4, SlicedPacket, TcpSlice, TransportSlice::Tcp};
use secp256k1::rand;

const TCP_SEQ_OFFSET: usize = 4;
const TCP_DATA_OFFSET: usize = 12;
const TCP_CHECKSUM_OFFSET: usize = 16;
const TCP_CHECKSUM_LEN: usize = 2;

// The maximum expected size of the tcp buffer of the client or server
const MAX_WINDOW_SIZE: i64 = 4194304;

const MAINNET_MAGIC: [u8; 4] = [0xf9u8, 0xbeu8, 0xb4u8, 0xd9u8];

struct BufferedPacket {
    seq: u32,
    payload: Vec<u8>,
}

impl BufferedPacket {
    fn new(tcp_segment: &[u8]) -> Self {
        let p = tcp_segment;
        let seq = u32::from_be_bytes([
            p[TCP_SEQ_OFFSET],
            p[TCP_SEQ_OFFSET + 1],
            p[TCP_SEQ_OFFSET + 2],
            p[TCP_SEQ_OFFSET + 3],
        ]);
        let data_offset = (p[TCP_DATA_OFFSET] >> 4) as usize;
        let header_len = data_offset * 4;

        Self {
            seq,
            payload: p[header_len..].to_vec(),
        }
    }

    fn merge_into_vec(buf_vec: &Vec<&BufferedPacket>) -> Vec<u8> {
        buf_vec.iter().fold(vec![], |mut acc, packet| {
            acc.extend_from_slice(&packet.payload);
            acc
        })
    }
}

struct TcpPeerTracker {
    first_seq: bool,
    seq: u32,
    fin: bool,
    prev_len: u32,
    // Assumption: the packets in the queue are ordered
    buffers: VecDeque<BufferedPacket>,
    seq_before_wrap: Option<u32>,
}

impl TcpPeerTracker {
    fn new() -> Self {
        Self {
            first_seq: false,
            seq: 0,
            fin: false,
            prev_len: 0,
            buffers: VecDeque::new(),
            seq_before_wrap: None,
        }
    }

    fn update(
        &mut self,
        syn: bool,
        fin: bool,
        new_seq: u32,
        new_len: u32,
    ) -> Result<(bool, bool), String> {
        let mut retransmission = false;
        let mut future = false;
        if syn && !self.first_seq {
            self.seq = new_seq.wrapping_add(1);
            self.prev_len = new_len;
            self.first_seq = true;
            return Ok((retransmission, future));
        }

        if fin {
            self.seq = new_seq.wrapping_add(1);
            self.prev_len = new_len;
            self.fin = true;
            return Ok((retransmission, future));
        }

        let new_seq = new_seq as i64;
        let self_seq = self.seq as i64;
        let prev_len = self.prev_len as i64;

        if (1..=MAX_WINDOW_SIZE).contains(&(self_seq + prev_len - new_seq + (u32::MAX as i64)))
            || (1..=MAX_WINDOW_SIZE).contains(&(self_seq + prev_len - new_seq))
        {
            retransmission = true;
            return Ok((retransmission, future));
        }

        // If the seq is ahead (but not too much), it might mean that this is a reordered packet
        if (1..=MAX_WINDOW_SIZE).contains(&((new_seq + u32::MAX as i64) - (self_seq + prev_len)))
            || (1..=MAX_WINDOW_SIZE).contains(&(new_seq - (self_seq + prev_len)))
        {
            future = true;
            return Ok((retransmission, future));
        }

        if (self_seq as u32).wrapping_add(prev_len as u32) != (new_seq as u32) {
            return Err("Seq doesn't match the expected value".to_string());
        }

        self.seq = new_seq as u32;
        self.prev_len = new_len;

        Ok((retransmission, future))
    }

    fn add_sent_packet(&mut self, tcp_segment: &[u8]) {
        let packet = BufferedPacket::new(tcp_segment);
        // If a wrap-around is triggered
        if !self.buffers.is_empty() && self.buffers[self.buffers.len() - 1].seq > packet.seq {
            self.seq_before_wrap = Some(self.buffers[self.buffers.len() - 1].seq);
        }
        self.buffers.push_back(packet);
    }

    fn clear_old_packets_from_buffers(&mut self) {
        if self.buffers.is_empty() {
            return;
        }
        let last_seq = if let Some(seq_before_wrap) = self.seq_before_wrap {
            seq_before_wrap as i64 + self.buffers[self.buffers.len() - 1].seq as i64
        } else {
            self.buffers[self.buffers.len() - 1].seq as i64
        };

        let cutoff = self
            .buffers
            .iter()
            .position(|packet| last_seq - (packet.seq as i64) > MAX_WINDOW_SIZE)
            .unwrap_or(0);
        self.buffers.drain(..cutoff);
    }

    fn search_packets_in_bufs<'a>(
        &'a self,
        mut seq: u32,
        mut payload_len: usize,
    ) -> Option<Vec<&'a BufferedPacket>> {
        let mut found_packets: Vec<&'a BufferedPacket> = vec![];
        for packet in self.buffers.iter() {
            let packet_seq = packet.seq;
            if packet_seq == seq {
                found_packets.push(packet);
                payload_len -= packet.payload.len();
                seq = seq.wrapping_add(packet.payload.len() as u32);
            }

            if payload_len == 0 {
                break;
            }
        }

        if payload_len != 0 {
            return None;
        }

        Some(found_packets)
    }
}

struct TcpSession<T>
where
    T: Default,
{
    src_ip: [u8; 4],
    src_port: u16,
    src_tracker: TcpPeerTracker,
    dst_tracker: TcpPeerTracker,
    src_init: bool,
    state: T,
}

impl<T: Default> Default for TcpSession<T> {
    fn default() -> Self {
        Self {
            src_ip: [0u8; 4],
            src_port: 0,
            src_tracker: TcpPeerTracker::new(),
            dst_tracker: TcpPeerTracker::new(),
            src_init: false,
            state: T::default(),
        }
    }
}

impl<T: Default> TcpSession<T> {
    fn read_tcp_packet<'a>(
        &mut self,
        src_ip: [u8; 4],
        src_port: u16,
        tcp: &etherparse::TcpSlice<'a>,
    ) -> Result<(bool, Option<Vec<u8>>, bool), String> {
        if !self.src_init {
            self.src_ip = src_ip;
            self.src_port = src_port;
            self.src_init = true;
        }

        let seq = tcp.sequence_number();
        let syn = tcp.syn();
        let fin = tcp.fin();
        let payload_len = tcp.payload().len() as u32;

        let is_client;
        let retransmission: bool;
        let future: bool;

        if self.src_ip == src_ip && self.src_port == src_port {
            is_client = true;
            (retransmission, future) = self.src_tracker.update(syn, fin, seq, payload_len)?;
        } else {
            is_client = false;
            (retransmission, future) = self.dst_tracker.update(syn, fin, seq, payload_len)?;
        }

        if payload_len == 0 || !retransmission || future {
            return Ok((is_client, None, future));
        }

        let buf_vec = if is_client {
            self.src_tracker
                .search_packets_in_bufs(seq, tcp.payload().len())
        } else {
            self.dst_tracker
                .search_packets_in_bufs(seq, tcp.payload().len())
        }
        .expect("The stored packet was not found");
        let reconstructed_payload = BufferedPacket::merge_into_vec(&buf_vec);

        Ok((is_client, Some(reconstructed_payload), future))
    }

    fn add_sent_packet(&mut self, src_ip: &[u8; 4], src_port: u16, tcp_segment: &[u8]) {
        if *src_ip == self.src_ip && src_port == self.src_port {
            self.src_tracker.add_sent_packet(tcp_segment);
        } else {
            self.dst_tracker.add_sent_packet(tcp_segment);
        }

        self.clear_old_packets_from_buffers();
    }

    fn clear_old_packets_from_buffers(&mut self) {
        self.src_tracker.clear_old_packets_from_buffers();
        self.dst_tracker.clear_old_packets_from_buffers();
    }
}

struct BIP324State {
    is_bip324: bool,
    bip324: Option<MitmBIP324>,
}

impl Default for BIP324State {
    fn default() -> Self {
        Self {
            is_bip324: true,
            bip324: None,
        }
    }
}

impl BIP324State {
    fn replace_payload(&mut self, is_client: bool, payload: &mut [u8]) -> Option<usize> {
        if !self.is_bip324 {
            return None;
        }

        let bip324 = self.bip324.get_or_insert_with(|| {
            let mut rng = rand::thread_rng();
            let mut bip324 = MitmBIP324::new(&mut rng).unwrap();
            bip324.ensure_terminator_not_split(true).unwrap();
            bip324.enable_user_relay();

            bip324
        });

        let read = if is_client {
            // client --> mitm --> server
            bip324.client_write(payload).unwrap();
            bip324.server_read(payload).unwrap()
        } else {
            // server --> mitm --> client
            bip324.server_write(payload).unwrap();
            bip324.client_read(payload).unwrap()
        };

        if read != payload.len() {
            panic!("bip324 didn't fill the entire buffer");
        }

        Some(read)
    }
}

type TcpAddrPair = ([u8; 4], u16, [u8; 4], u16);

pub enum InterceptVerdict {
    Accept,
    Drop,
}

pub struct Interceptor {
    queue: nfq::Queue,
    sessions: HashMap<TcpAddrPair, TcpSession<BIP324State>>,
}

impl Interceptor {
    fn new(queue_num: u16) -> Result<Self, Box<dyn Error>> {
        let mut queue = nfq::Queue::open()?;
        queue.bind(queue_num)?;

        Ok(Self {
            queue,
            sessions: HashMap::new(),
        })
    }

    fn get_next_msg(&mut self) -> Result<nfq::Message, Box<dyn Error>> {
        Ok(self.queue.recv()?)
    }

    fn verdict(&mut self, msg: nfq::Message) -> Result<(), Box<dyn Error>> {
        Ok(self.queue.verdict(msg)?)
    }

    fn live_intercept(&mut self) -> Result<(), Box<dyn Error>> {
        println!("Interception started");
        loop {
            let mut msg = self.get_next_msg()?;

            {
                let payload_len = msg.get_payload().len();
                let original_len = msg.get_original_len();
                if payload_len != original_len {
                    println!("len / original: {} / {}", payload_len, original_len);
                    panic!("Packet was truncated");
                }
            }

            let ip_payload = msg.get_payload_mut();

            let verdict: InterceptVerdict = self.on_packet(ip_payload);
            match verdict {
                InterceptVerdict::Accept => {
                    msg.set_verdict(nfq::Verdict::Accept);
                }
                InterceptVerdict::Drop => {
                    msg.set_verdict(nfq::Verdict::Drop);
                }
            }

            self.verdict(msg).unwrap();
        }
    }

    fn on_packet(&mut self, ip_payload: &mut [u8]) -> InterceptVerdict {
        let Ok(parsed) = SlicedPacket::from_ip(ip_payload) else {
            panic!("Can't parse IP packet: {ip_payload:?}");
        };

        let (src_ip, dst_ip, ip_header_size) = match &parsed.net {
            Some(Ipv4(ip)) => (
                ip.header().source(),
                ip.header().destination(),
                (ip.header().ihl() * 4) as usize,
            ),
            _ => {
                panic!("Unhandled link packet");
            }
        };

        drop(parsed);
        let verdict = self.on_tcp_packet(src_ip, dst_ip, &mut ip_payload[ip_header_size..]);

        let Ok(parsed) = SlicedPacket::from_ip(ip_payload) else {
            panic!("Can't parse IP packet");
        };
        let Some(Tcp(tcp)) = &parsed.transport else {
            panic!("Can't parse TCP packet");
        };

        let new_checksum = tcp.calc_checksum_ipv4(src_ip, dst_ip).unwrap();

        drop(parsed);
        ip_payload[ip_header_size + TCP_CHECKSUM_OFFSET
            ..ip_header_size + TCP_CHECKSUM_OFFSET + TCP_CHECKSUM_LEN]
            .copy_from_slice(&new_checksum.to_be_bytes());

        verdict
    }

    fn on_tcp_packet(
        &mut self,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        tcp_payload: &mut [u8],
    ) -> InterceptVerdict {
        let Ok(tcp) = TcpSlice::from_slice(tcp_payload) else {
            panic!("Can't parse TCP packet");
        };

        let src_port = tcp.source_port();
        let dst_port = tcp.destination_port();
        let header_len = tcp.header_len();
        let payload_len = tcp.payload().len();

        if self.sessions.len() > 200 {
            panic!("Too many sessions");
        }

        let session = self.get_session(src_ip, src_port, dst_ip, dst_port);

        if !session.state.is_bip324
            || tcp.payload().len() >= 4 && tcp.payload()[..4] == MAINNET_MAGIC
        {
            session.state.is_bip324 = false;
            return InterceptVerdict::Drop;
        }

        let (is_client, buffered_payload, future) =
            session.read_tcp_packet(src_ip, src_port, &tcp).unwrap();

        // Only accept ordered packets
        if future {
            return InterceptVerdict::Drop;
        }

        let payload = &mut tcp_payload[header_len..];
        if let Some(buffered_payload) = buffered_payload.as_ref() {
            payload.copy_from_slice(buffered_payload);
        } else if payload_len > 0 {
            let _read = session.state.replace_payload(is_client, payload);
        }

        if buffered_payload.is_none() {
            session.add_sent_packet(&src_ip, src_port, tcp_payload);
        }

        session.state.bip324.as_mut().and_then(|bip324| {
            while let Some(prot_pkt) = bip324.next_client_protocol_packet().unwrap() {
                if let bip324_mitm::relay::ProtocolPacket::Data(pdata) = prot_pkt {
                    println!("[client] -> [server]");
                    if pdata.data[0] == 0u8 {
                        println!("Data: {:?}", pdata);
                    } else {
                        println!("(Decoy)");
                    }
                }
            }

            while let Some(prot_pkt) = bip324.next_server_protocol_packet().unwrap() {
                if let bip324_mitm::relay::ProtocolPacket::Data(pdata) = prot_pkt {
                    println!("[server] -> [client]");
                    if pdata.data[0] == 0u8 {
                        println!("Data: {:?}", pdata);
                    } else {
                        println!("(Decoy)");
                    }
                }
            }

            None::<()>
        });

        InterceptVerdict::Accept
    }

    fn get_session(
        &mut self,
        src_ip: [u8; 4],
        src_port: u16,
        dst_ip: [u8; 4],
        dst_port: u16,
    ) -> &mut TcpSession<BIP324State> {
        // Sort them
        let key = if src_ip < dst_ip || (src_ip == dst_ip && src_port < dst_port) {
            (src_ip, src_port, dst_ip, dst_port)
        } else {
            (dst_ip, dst_port, src_ip, src_port)
        };

        self.sessions.entry(key).or_default()
    }
}

fn main() {
    // NFQUEUE needs to be configured in iptables. Check the README

    // The user must create a queue filter for this id
    let queue_num = 0u16;

    let mut interceptor = Interceptor::new(queue_num).unwrap();
    println!("Interceptor initialized");
    interceptor.live_intercept().unwrap();
}
