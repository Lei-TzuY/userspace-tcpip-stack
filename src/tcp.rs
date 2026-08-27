//! Layer 4: Transmission Control Protocol (TCP - RFC 793, RFC 9293).
//!
//! Connection-oriented, reliable transport protocol with TCP Option parsing,
//! out-of-order segment reassembly, Congestion Control (RFC 5681), adaptive RTT / RTO (RFC 6298),
//! Karn's algorithm, Fast Retransmit, sliding window flow control, and full finite-state machine.

use crate::checksum::{compute_ipv4_transport_checksum, verify_ipv4_transport_checksum};
use crate::congestion::{CongestionControl, RttEstimator};
use crate::ipv4::Ipv4Address;
use crate::tcp_seq::{seq_diff, seq_ge, seq_gt, seq_le, seq_lt};
use std::collections::{BTreeMap, HashMap};
use std::fmt;

pub const TCP_MIN_HEADER_LEN: usize = 20;

/// Maximum retransmission attempts for a single segment before the connection is aborted.
/// Prevents unbounded retransmission loops when a peer disappears.
pub const MAX_RETRANSMITS: u32 = 12;

/// Upper bound on bytes held in the out-of-order reassembly queue. Segments beyond this
/// are dropped (the peer will retransmit), bounding memory under adversarial reordering.
pub const MAX_OOO_BYTES: usize = 262_144;

/// TIME_WAIT duration (2 * MSL) in simulated milliseconds.
pub const TIME_WAIT_MS: u64 = 2_000;

/// Interval between zero-window probes while the peer advertises a zero receive window.
pub const PERSIST_INTERVAL_MS: u64 = 500;

/// Send-buffer capacity in bytes. `write` accepts at most this much unsent data and
/// reports a short write beyond it, so an application cannot grow the buffer without bound.
pub const SND_BUFFER_CAPACITY: usize = 262_144;

// Flag bitmasks
pub const TCP_FLAG_FIN: u8 = 0x01;
pub const TCP_FLAG_SYN: u8 = 0x02;
pub const TCP_FLAG_RST: u8 = 0x04;
pub const TCP_FLAG_PSH: u8 = 0x08;
pub const TCP_FLAG_ACK: u8 = 0x10;
pub const TCP_FLAG_URG: u8 = 0x20;

// TCP Option Kinds (RFC 793, RFC 7323)
pub const TCP_OPT_EOL: u8 = 0;
pub const TCP_OPT_NOP: u8 = 1;
pub const TCP_OPT_MSS: u8 = 2;
pub const TCP_OPT_WSCALE: u8 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpOption {
    EndOfOptions,
    Nop,
    Mss(u16),
    WindowScale(u8),
    Unknown { kind: u8, data: Vec<u8> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
}

impl TcpFlags {
    pub fn from_u8(val: u8) -> Self {
        TcpFlags {
            fin: (val & TCP_FLAG_FIN) != 0,
            syn: (val & TCP_FLAG_SYN) != 0,
            rst: (val & TCP_FLAG_RST) != 0,
            psh: (val & TCP_FLAG_PSH) != 0,
            ack: (val & TCP_FLAG_ACK) != 0,
            urg: (val & TCP_FLAG_URG) != 0,
        }
    }

    pub fn to_u8(&self) -> u8 {
        let mut val = 0u8;
        if self.fin {
            val |= TCP_FLAG_FIN;
        }
        if self.syn {
            val |= TCP_FLAG_SYN;
        }
        if self.rst {
            val |= TCP_FLAG_RST;
        }
        if self.psh {
            val |= TCP_FLAG_PSH;
        }
        if self.ack {
            val |= TCP_FLAG_ACK;
        }
        if self.urg {
            val |= TCP_FLAG_URG;
        }
        val
    }

    pub fn syn_ack() -> Self {
        TcpFlags {
            syn: true,
            ack: true,
            ..Default::default()
        }
    }

    pub fn ack() -> Self {
        TcpFlags {
            ack: true,
            ..Default::default()
        }
    }

    pub fn syn() -> Self {
        TcpFlags {
            syn: true,
            ..Default::default()
        }
    }

    pub fn fin_ack() -> Self {
        TcpFlags {
            fin: true,
            ack: true,
            ..Default::default()
        }
    }

    pub fn rst() -> Self {
        TcpFlags {
            rst: true,
            ..Default::default()
        }
    }
}

impl fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut flags = Vec::new();
        if self.syn {
            flags.push("SYN");
        }
        if self.ack {
            flags.push("ACK");
        }
        if self.fin {
            flags.push("FIN");
        }
        if self.rst {
            flags.push("RST");
        }
        if self.psh {
            flags.push("PSH");
        }
        if self.urg {
            flags.push("URG");
        }
        if flags.is_empty() {
            write!(f, "[NONE]")
        } else {
            write!(f, "[{}]", flags.join("|"))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpSegment<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset: u8, // in 32-bit words (min 5 = 20 bytes)
    pub flags: TcpFlags,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
    pub options: Vec<TcpOption>,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpError {
    SegmentTooShort(usize),
    InvalidDataOffset(u8),
    DataOffsetExceedsLength {
        offset_bytes: usize,
        available: usize,
    },
    TruncatedOption {
        offset: usize,
        kind: u8,
    },
    InvalidOptionLength {
        offset: usize,
        kind: u8,
        length: u8,
    },
    OptionLengthExceedsHeader {
        offset: usize,
        kind: u8,
        length: u8,
        remaining: usize,
    },
    InvalidChecksum {
        found: u16,
    },
}

impl fmt::Display for TcpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TcpError::SegmentTooShort(len) => {
                write!(f, "TCP segment too short ({} bytes, min 20)", len)
            }
            TcpError::InvalidDataOffset(d) => write!(f, "Invalid TCP data offset: {} (min 5)", d),
            TcpError::DataOffsetExceedsLength {
                offset_bytes,
                available,
            } => {
                write!(
                    f,
                    "TCP header offset {} exceeds segment length {}",
                    offset_bytes, available
                )
            }
            TcpError::TruncatedOption { offset, kind } => write!(
                f,
                "TCP option kind {} at byte {} is missing its length byte",
                kind, offset
            ),
            TcpError::InvalidOptionLength {
                offset,
                kind,
                length,
            } => write!(
                f,
                "TCP option kind {} at byte {} has invalid length {}",
                kind, offset, length
            ),
            TcpError::OptionLengthExceedsHeader {
                offset,
                kind,
                length,
                remaining,
            } => write!(
                f,
                "TCP option kind {} at byte {} declares length {} with only {} header bytes remaining",
                kind, offset, length, remaining
            ),
            TcpError::InvalidChecksum { found } => {
                write!(
                    f,
                    "TCP checksum mismatch with checksum field 0x{:04x}",
                    found
                )
            }
        }
    }
}

impl std::error::Error for TcpError {}

impl<'a> TcpSegment<'a> {
    pub fn parse(
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        data: &'a [u8],
        check_checksum: bool,
    ) -> Result<Self, TcpError> {
        if data.len() < TCP_MIN_HEADER_LEN {
            return Err(TcpError::SegmentTooShort(data.len()));
        }

        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let seq_num = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ack_num = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

        let data_offset = data[12] >> 4;
        if data_offset < 5 {
            return Err(TcpError::InvalidDataOffset(data_offset));
        }

        let offset_bytes = (data_offset as usize) * 4;
        if offset_bytes > data.len() {
            return Err(TcpError::DataOffsetExceedsLength {
                offset_bytes,
                available: data.len(),
            });
        }

        let flags_raw = data[13];
        let flags = TcpFlags::from_u8(flags_raw);
        let window_size = u16::from_be_bytes([data[14], data[15]]);
        let checksum = u16::from_be_bytes([data[16], data[17]]);
        let urgent_ptr = u16::from_be_bytes([data[18], data[19]]);

        if check_checksum && !verify_ipv4_transport_checksum(src_ip.0, dst_ip.0, 6, data) {
            return Err(TcpError::InvalidChecksum { found: checksum });
        }

        // Parse TCP Options (between byte 20 and offset_bytes)
        let mut options = Vec::new();
        let mut opt_offset = TCP_MIN_HEADER_LEN;
        while opt_offset < offset_bytes {
            let kind = data[opt_offset];
            if kind == TCP_OPT_EOL {
                options.push(TcpOption::EndOfOptions);
                break;
            }
            if kind == TCP_OPT_NOP {
                options.push(TcpOption::Nop);
                opt_offset += 1;
                continue;
            }

            if opt_offset + 1 >= offset_bytes {
                return Err(TcpError::TruncatedOption {
                    offset: opt_offset,
                    kind,
                });
            }
            let length = data[opt_offset + 1];
            let len = usize::from(length);
            if len < 2 {
                return Err(TcpError::InvalidOptionLength {
                    offset: opt_offset,
                    kind,
                    length,
                });
            }
            let remaining = offset_bytes - opt_offset;
            if len > remaining {
                return Err(TcpError::OptionLengthExceedsHeader {
                    offset: opt_offset,
                    kind,
                    length,
                    remaining,
                });
            }

            match kind {
                TCP_OPT_MSS => {
                    if len != 4 {
                        return Err(TcpError::InvalidOptionLength {
                            offset: opt_offset,
                            kind,
                            length,
                        });
                    }
                    let mss = u16::from_be_bytes([data[opt_offset + 2], data[opt_offset + 3]]);
                    options.push(TcpOption::Mss(mss));
                }
                TCP_OPT_WSCALE => {
                    if len != 3 {
                        return Err(TcpError::InvalidOptionLength {
                            offset: opt_offset,
                            kind,
                            length,
                        });
                    }
                    options.push(TcpOption::WindowScale(data[opt_offset + 2]));
                }
                other => {
                    let opt_data = data[opt_offset + 2..opt_offset + len].to_vec();
                    options.push(TcpOption::Unknown {
                        kind: other,
                        data: opt_data,
                    });
                }
            }
            opt_offset += len;
        }

        let payload = &data[offset_bytes..];

        Ok(TcpSegment {
            src_port,
            dst_port,
            seq_num,
            ack_num,
            data_offset,
            flags,
            window_size,
            checksum,
            urgent_ptr,
            options,
            payload,
        })
    }

    pub fn serialize(
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        src_port: u16,
        dst_port: u16,
        seq_num: u32,
        ack_num: u32,
        flags: TcpFlags,
        window_size: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        Self::serialize_with_options(
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            seq_num,
            ack_num,
            flags,
            window_size,
            &[],
            payload,
        )
    }

    pub fn serialize_with_options(
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        src_port: u16,
        dst_port: u16,
        seq_num: u32,
        ack_num: u32,
        flags: TcpFlags,
        window_size: u16,
        options: &[TcpOption],
        payload: &[u8],
    ) -> Vec<u8> {
        let mut opt_bytes = Vec::new();
        for opt in options {
            match opt {
                TcpOption::EndOfOptions => opt_bytes.push(TCP_OPT_EOL),
                TcpOption::Nop => opt_bytes.push(TCP_OPT_NOP),
                TcpOption::Mss(mss) => {
                    opt_bytes.push(TCP_OPT_MSS);
                    opt_bytes.push(4);
                    opt_bytes.extend_from_slice(&mss.to_be_bytes());
                }
                TcpOption::WindowScale(scale) => {
                    opt_bytes.push(TCP_OPT_WSCALE);
                    opt_bytes.push(3);
                    opt_bytes.push(*scale);
                }
                TcpOption::Unknown { kind, data } => {
                    opt_bytes.push(*kind);
                    opt_bytes.push((data.len() + 2) as u8);
                    opt_bytes.extend_from_slice(data);
                }
            }
        }

        // Pad options to multiple of 4 bytes
        while opt_bytes.len() % 4 != 0 {
            opt_bytes.push(TCP_OPT_NOP);
        }

        let header_len = TCP_MIN_HEADER_LEN + opt_bytes.len();
        let data_offset = (header_len / 4) as u8;
        let total_len = header_len + payload.len();
        let mut buf = Vec::with_capacity(total_len);

        buf.extend_from_slice(&src_port.to_be_bytes());
        buf.extend_from_slice(&dst_port.to_be_bytes());
        buf.extend_from_slice(&seq_num.to_be_bytes());
        buf.extend_from_slice(&ack_num.to_be_bytes());
        buf.push((data_offset << 4) & 0xF0);
        buf.push(flags.to_u8());
        buf.extend_from_slice(&window_size.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x00]); // Checksum placeholder
        buf.extend_from_slice(&0u16.to_be_bytes()); // Urgent pointer
        buf.extend_from_slice(&opt_bytes);
        buf.extend_from_slice(payload);

        let csum = compute_ipv4_transport_checksum(src_ip.0, dst_ip.0, 6, &buf);
        buf[16..18].copy_from_slice(&csum.to_be_bytes());

        buf
    }
}

/// TCP Connection States (RFC 793)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

impl fmt::Display for TcpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TcpState::Closed => write!(f, "CLOSED"),
            TcpState::Listen => write!(f, "LISTEN"),
            TcpState::SynSent => write!(f, "SYN_SENT"),
            TcpState::SynReceived => write!(f, "SYN_RECEIVED"),
            TcpState::Established => write!(f, "ESTABLISHED"),
            TcpState::FinWait1 => write!(f, "FIN_WAIT_1"),
            TcpState::FinWait2 => write!(f, "FIN_WAIT_2"),
            TcpState::CloseWait => write!(f, "CLOSE_WAIT"),
            TcpState::Closing => write!(f, "CLOSING"),
            TcpState::LastAck => write!(f, "LAST_ACK"),
            TcpState::TimeWait => write!(f, "TIME_WAIT"),
        }
    }
}

/// 4-tuple Socket Key: (Local IP, Local Port, Remote IP, Remote Port)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SocketAddrV4 {
    pub ip: Ipv4Address,
    pub port: u16,
}

impl fmt::Display for SocketAddrV4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.ip, self.port)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpConnectionKey {
    pub local: SocketAddrV4,
    pub remote: SocketAddrV4,
}

/// Lightweight runtime metrics and telemetry for a TCP socket.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TcpStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub segments_sent: u64,
    pub segments_received: u64,
    pub retransmissions: u64,
    pub duplicate_acks: u64,
    pub fast_retransmits: u64,
    pub timeouts: u64,
    /// Segments rejected as unacceptable (bad ACK, off-window RST, failed checksum).
    pub invalid_segments: u64,
    /// Window probes emitted while the peer advertised a zero receive window.
    pub zero_window_probes: u64,
}

/// An unacknowledged segment tracked in flight for retransmission.
#[derive(Debug, Clone)]
pub struct RetransmitSegment {
    pub seq_num: u32,
    pub end_seq: u32, // seq_num + bytes (including +1 for SYN or FIN)
    pub flags: TcpFlags,
    pub payload: Vec<u8>,
    pub first_sent_ms: u64,
    pub last_sent_ms: u64,
    pub retransmits: u32,
}

/// Manages a single TCP connection state machine, out-of-order reassembly queue,
/// congestion control, adaptive RTO retransmission, and flow control.
#[derive(Debug, Clone)]
pub struct TcpConnection {
    pub local: SocketAddrV4,
    pub remote: SocketAddrV4,
    pub state: TcpState,
    pub snd_una: u32,
    pub snd_nxt: u32,
    pub snd_wnd: u16,
    pub rcv_nxt: u32,
    pub rcv_wnd: u16,
    pub rcv_capacity: usize,
    pub peer_mss: u16,
    pub local_mss: u16,
    pub rx_buffer: Vec<u8>,
    pub tx_buffer: Vec<u8>,
    pub ooo_queue: BTreeMap<u32, Vec<u8>>, // Legacy mirror of the reassembly queue (read-only view)
    pub ooo_segments: Vec<(u32, Vec<u8>)>, // Wraparound-safe out-of-order reassembly buffer
    pub retransmit_queue: Vec<RetransmitSegment>,
    pub congestion: CongestionControl,
    pub rtt: RttEstimator,
    pub stats: TcpStats,
    pub current_time_ms: u64,
    pub time_wait_entered_ms: Option<u64>,
    pub fin_sent: bool,
    /// True once the peer's FIN has been received and accounted for in `rcv_nxt`.
    pub fin_received: bool,
    /// Set when the application requested close but a FIN could not be emitted yet.
    pub close_requested: bool,
    /// Set after `MAX_RETRANSMITS` unsuccessful retries of the same segment.
    pub aborted: bool,
    /// Deadline for the next zero-window probe while the peer advertises a zero window.
    pub persist_deadline_ms: Option<u64>,
    /// Receive window most recently advertised to the peer, used to detect when the
    /// window reopens so an unsolicited window update can be sent.
    pub last_advertised_wnd: u16,
}

impl TcpConnection {
    pub fn new_server(local: SocketAddrV4, remote: SocketAddrV4, isn: u32) -> Self {
        let mss = 1460;
        TcpConnection {
            local,
            remote,
            state: TcpState::Listen,
            snd_una: isn,
            snd_nxt: isn,
            snd_wnd: 65535,
            rcv_nxt: 0,
            rcv_wnd: 65535,
            rcv_capacity: 65535,
            peer_mss: mss,
            local_mss: mss,
            rx_buffer: Vec::new(),
            tx_buffer: Vec::new(),
            ooo_queue: BTreeMap::new(),
            ooo_segments: Vec::new(),
            retransmit_queue: Vec::new(),
            congestion: CongestionControl::new(mss as u32),
            rtt: RttEstimator::new(),
            stats: TcpStats::default(),
            current_time_ms: 0,
            time_wait_entered_ms: None,
            fin_sent: false,
            fin_received: false,
            close_requested: false,
            aborted: false,
            persist_deadline_ms: None,
            last_advertised_wnd: 65535,
        }
    }

    pub fn new_client(local: SocketAddrV4, remote: SocketAddrV4, isn: u32) -> Self {
        let mss = 1460;
        TcpConnection {
            local,
            remote,
            state: TcpState::Closed,
            snd_una: isn,
            snd_nxt: isn,
            snd_wnd: 65535,
            rcv_nxt: 0,
            rcv_wnd: 65535,
            rcv_capacity: 65535,
            peer_mss: mss,
            local_mss: mss,
            rx_buffer: Vec::new(),
            tx_buffer: Vec::new(),
            ooo_queue: BTreeMap::new(),
            ooo_segments: Vec::new(),
            retransmit_queue: Vec::new(),
            congestion: CongestionControl::new(mss as u32),
            rtt: RttEstimator::new(),
            stats: TcpStats::default(),
            current_time_ms: 0,
            time_wait_entered_ms: None,
            fin_sent: false,
            fin_received: false,
            close_requested: false,
            aborted: false,
            persist_deadline_ms: None,
            last_advertised_wnd: 65535,
        }
    }

    /// Total bytes currently parked in the out-of-order reassembly queue.
    pub fn ooo_bytes(&self) -> usize {
        self.ooo_segments.iter().map(|(_, p)| p.len()).sum()
    }

    /// Keeps the legacy `ooo_queue` view in sync with the authoritative `ooo_segments` buffer.
    fn sync_legacy_ooo_view(&mut self) {
        self.ooo_queue.clear();
        for (seq, payload) in &self.ooo_segments {
            self.ooo_queue.insert(*seq, payload.clone());
        }
    }

    /// Accepts a data segment into the receive stream, performing wraparound-safe trimming,
    /// out-of-order buffering, and in-order reassembly. Duplicate or already-delivered bytes
    /// are discarded so the application never observes them twice.
    fn accept_data(&mut self, seq: u32, payload: &[u8]) {
        if payload.is_empty() {
            return;
        }

        let window = self.current_rcv_wnd() as u32;
        let seg_end = seq.wrapping_add(payload.len() as u32);

        // Entirely in the past: every byte was already delivered.
        if seq_le(seg_end, self.rcv_nxt) {
            return;
        }

        // Trim bytes to the left of rcv_nxt (partial retransmission overlap).
        let (seq, payload) = if seq_lt(seq, self.rcv_nxt) {
            let offset = seq_diff(self.rcv_nxt, seq) as usize;
            if offset >= payload.len() {
                return;
            }
            (self.rcv_nxt, &payload[offset..])
        } else {
            (seq, payload)
        };

        // Enforce the advertised receive window: refuse anything that would overflow it.
        if window == 0 {
            return;
        }
        let offset_in_window = seq_diff(seq, self.rcv_nxt);
        if offset_in_window >= window {
            return;
        }
        let allowed = (window - offset_in_window) as usize;
        let payload = if payload.len() > allowed {
            &payload[..allowed]
        } else {
            payload
        };
        if payload.is_empty() {
            return;
        }

        if seq == self.rcv_nxt {
            self.rx_buffer.extend_from_slice(payload);
            self.rcv_nxt = self.rcv_nxt.wrapping_add(payload.len() as u32);
            self.stats.bytes_received += payload.len() as u64;
            self.drain_ooo();
        } else {
            self.buffer_ooo(seq, payload);
        }
        self.sync_legacy_ooo_view();
    }

    /// Parks an out-of-order segment, de-duplicating against what is already buffered and
    /// bounding the total queued bytes so adversarial reordering cannot exhaust memory.
    fn buffer_ooo(&mut self, seq: u32, payload: &[u8]) {
        let seg_end = seq.wrapping_add(payload.len() as u32);

        // Already fully covered by a queued segment.
        if self.ooo_segments.iter().any(|(s, p)| {
            let e = s.wrapping_add(p.len() as u32);
            seq_le(*s, seq) && seq_le(seg_end, e)
        }) {
            return;
        }

        // Replace any queued segment that this one fully covers.
        self.ooo_segments.retain(|(s, p)| {
            let e = s.wrapping_add(p.len() as u32);
            !(seq_le(seq, *s) && seq_le(e, seg_end))
        });

        if self.ooo_bytes() + payload.len() > MAX_OOO_BYTES {
            // Bounded queue: drop and let the peer retransmit rather than grow without limit.
            return;
        }

        self.ooo_segments.push((seq, payload.to_vec()));
        self.ooo_segments.sort_by(|a, b| {
            if seq_lt(a.0, b.0) {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            }
        });
    }

    /// Moves every out-of-order segment that has become contiguous into the receive buffer.
    fn drain_ooo(&mut self) {
        loop {
            let mut advanced = false;
            let mut i = 0;
            while i < self.ooo_segments.len() {
                let seq = self.ooo_segments[i].0;
                let end = seq.wrapping_add(self.ooo_segments[i].1.len() as u32);

                if seq_le(end, self.rcv_nxt) {
                    // Superseded by data already delivered.
                    self.ooo_segments.remove(i);
                    advanced = true;
                    continue;
                }
                if seq_le(seq, self.rcv_nxt) {
                    let offset = seq_diff(self.rcv_nxt, seq) as usize;
                    let (_, payload) = self.ooo_segments.remove(i);
                    let fresh = &payload[offset..];
                    self.rx_buffer.extend_from_slice(fresh);
                    self.rcv_nxt = self.rcv_nxt.wrapping_add(fresh.len() as u32);
                    self.stats.bytes_received += fresh.len() as u64;
                    advanced = true;
                    continue;
                }
                i += 1;
            }
            if !advanced {
                break;
            }
        }
    }

    /// Builds a bare ACK carrying the current cumulative acknowledgement and receive window.
    fn build_ack(&mut self) -> Vec<u8> {
        self.stats.segments_sent += 1;
        let wnd = self.current_rcv_wnd();
        self.last_advertised_wnd = wnd;
        TcpSegment::serialize(
            self.local.ip,
            self.remote.ip,
            self.local.port,
            self.remote.port,
            self.snd_nxt,
            self.rcv_nxt,
            TcpFlags::ack(),
            wnd,
            &[],
        )
    }

    /// True when an inbound RST may tear down the connection. RFC 5961 requires the reset
    /// to fall inside the current receive window, so off-window resets are ignored.
    fn rst_acceptable(&self, seg: &TcpSegment<'_>) -> bool {
        match self.state {
            TcpState::SynSent => seg.flags.ack && seg.ack_num == self.snd_nxt,
            TcpState::Listen | TcpState::Closed => false,
            _ => {
                let window = (self.current_rcv_wnd() as u32).max(1);
                seq_ge(seg.seq_num, self.rcv_nxt)
                    && seq_lt(seg.seq_num, self.rcv_nxt.wrapping_add(window))
            }
        }
    }

    /// Records a sequence-space-consuming transmission in the retransmission queue and
    /// charges its length against the congestion window.
    fn track_for_retransmit(
        &mut self,
        seq: u32,
        len: u32,
        flags: TcpFlags,
        payload: Vec<u8>,
        now_ms: u64,
    ) {
        self.retransmit_queue.push(RetransmitSegment {
            seq_num: seq,
            end_seq: seq.wrapping_add(len),
            flags,
            payload,
            first_sent_ms: now_ms,
            last_sent_ms: now_ms,
            retransmits: 0,
        });
        self.congestion.record_sent(len);
    }

    /// Retires every retransmission-queue entry fully covered by `ack_num` and feeds
    /// unambiguous round-trip samples to the RTT estimator (Karn's algorithm).
    fn retire_acked(&mut self, ack_num: u32, now_ms: u64) {
        let mut remaining = Vec::with_capacity(self.retransmit_queue.len());
        for entry in std::mem::take(&mut self.retransmit_queue) {
            if seq_le(entry.end_seq, ack_num) {
                // Karn's algorithm: a retransmitted segment yields an ambiguous sample.
                if entry.retransmits == 0 {
                    let sample = now_ms.saturating_sub(entry.first_sent_ms) as f64;
                    self.rtt.update_sample(sample.max(1.0));
                }
            } else {
                remaining.push(entry);
            }
        }
        self.retransmit_queue = remaining;
    }

    /// Dynamic receive window calculation based on buffer capacity.
    pub fn current_rcv_wnd(&self) -> u16 {
        let avail = self.rcv_capacity.saturating_sub(self.rx_buffer.len());
        avail.min(65535) as u16
    }

    /// Application write interface. Enqueues as much as the send buffer can hold and
    /// returns how many bytes were accepted, which may be fewer than requested. Bounding
    /// the buffer keeps a fast writer from growing memory without limit while the network
    /// drains at its own pace.
    pub fn write(&mut self, data: &[u8]) -> usize {
        let room = SND_BUFFER_CAPACITY.saturating_sub(self.tx_buffer.len());
        let accepted = room.min(data.len());
        self.tx_buffer.extend_from_slice(&data[..accepted]);
        accepted
    }

    /// Unused send-buffer capacity in bytes.
    pub fn send_buffer_available(&self) -> usize {
        SND_BUFFER_CAPACITY.saturating_sub(self.tx_buffer.len())
    }

    /// Application read interface: drains available bytes from rx_buffer.
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        if self.rx_buffer.is_empty() {
            return 0;
        }
        let to_read = buf.len().min(self.rx_buffer.len());
        buf[..to_read].copy_from_slice(&self.rx_buffer[..to_read]);
        self.rx_buffer.drain(..to_read);
        self.rcv_wnd = self.current_rcv_wnd();
        to_read
    }

    /// Client initiates active connection opening (sends SYN).
    pub fn initiate_syn(&mut self) -> Vec<u8> {
        self.initiate_syn_at(self.current_time_ms)
    }

    pub fn initiate_syn_at(&mut self, now_ms: u64) -> Vec<u8> {
        self.current_time_ms = now_ms;
        self.state = TcpState::SynSent;
        let syn_seq = self.snd_nxt;
        self.snd_nxt = self.snd_nxt.wrapping_add(1);

        let options = vec![TcpOption::Mss(self.local_mss)];
        let packet = TcpSegment::serialize_with_options(
            self.local.ip,
            self.remote.ip,
            self.local.port,
            self.remote.port,
            syn_seq,
            0,
            TcpFlags::syn(),
            self.current_rcv_wnd(),
            &options,
            &[],
        );

        self.track_for_retransmit(syn_seq, 1, TcpFlags::syn(), Vec::new(), now_ms);
        self.stats.segments_sent += 1;

        packet
    }

    /// Client or Server sends application data.
    pub fn send_data(&mut self, payload: &[u8]) -> Option<Vec<u8>> {
        self.send_data_at(payload, self.current_time_ms)
    }

    pub fn send_data_at(&mut self, payload: &[u8], now_ms: u64) -> Option<Vec<u8>> {
        self.current_time_ms = now_ms;
        if self.state != TcpState::Established {
            return None;
        }
        self.write(payload);
        let mut segments = self.poll_output(now_ms);
        segments.pop()
    }

    /// Initiates active connection teardown (sends FIN).
    pub fn initiate_close(&mut self) -> Option<Vec<u8>> {
        self.initiate_close_at(self.current_time_ms)
    }

    ///
    /// A close requested while application data is still queued is deferred: the FIN is
    /// emitted by `poll_output` only after the last byte of `tx_buffer` has been sent, so
    /// no application data is ever discarded by a close.
    pub fn initiate_close_at(&mut self, now_ms: u64) -> Option<Vec<u8>> {
        self.current_time_ms = now_ms;
        match self.state {
            TcpState::Established | TcpState::CloseWait => {
                self.close_requested = true;
                if self.tx_buffer.is_empty() {
                    self.emit_fin(now_ms)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Emits the FIN for a pending close and advances the state machine.
    fn emit_fin(&mut self, now_ms: u64) -> Option<Vec<u8>> {
        if self.fin_sent {
            return None;
        }
        self.state = match self.state {
            TcpState::Established => TcpState::FinWait1,
            TcpState::CloseWait => TcpState::LastAck,
            _ => return None,
        };

        let fin_seq = self.snd_nxt;
        self.snd_nxt = self.snd_nxt.wrapping_add(1);
        self.fin_sent = true;

        let packet = TcpSegment::serialize(
            self.local.ip,
            self.remote.ip,
            self.local.port,
            self.remote.port,
            fin_seq,
            self.rcv_nxt,
            TcpFlags::fin_ack(),
            self.current_rcv_wnd(),
            &[],
        );

        self.track_for_retransmit(fin_seq, 1, TcpFlags::fin_ack(), Vec::new(), now_ms);
        self.stats.segments_sent += 1;

        Some(packet)
    }

    /// Handles an incoming TCP segment.
    pub fn handle_segment(&mut self, seg: &TcpSegment<'_>) -> Option<Vec<u8>> {
        self.handle_segment_at(seg, self.current_time_ms)
    }

    /// Handles an incoming TCP segment with an explicit simulation timestamp.
    pub fn handle_segment_at(&mut self, seg: &TcpSegment<'_>, now_ms: u64) -> Option<Vec<u8>> {
        self.current_time_ms = now_ms;
        self.stats.segments_received += 1;

        // Inspect options for MSS
        for opt in &seg.options {
            if let TcpOption::Mss(m) = opt {
                self.peer_mss = *m;
                self.congestion.mss = *m as u32;
            }
        }

        if seg.flags.rst {
            // RFC 5961: only an in-window reset may tear the connection down. Blind
            // off-window resets are counted and discarded.
            if self.rst_acceptable(seg) {
                self.state = TcpState::Closed;
                self.retransmit_queue.clear();
                self.tx_buffer.clear();
                self.ooo_segments.clear();
                self.ooo_queue.clear();
            } else {
                self.stats.invalid_segments += 1;
            }
            return None;
        }

        match self.state {
            TcpState::Listen => {
                if seg.flags.syn {
                    self.rcv_nxt = seg.seq_num.wrapping_add(1);
                    self.snd_wnd = seg.window_size;
                    let my_syn_seq = self.snd_nxt;
                    self.snd_nxt = self.snd_nxt.wrapping_add(1);
                    self.state = TcpState::SynReceived;

                    // Send SYN-ACK with our MSS option
                    let options = vec![TcpOption::Mss(self.local_mss)];
                    let syn_ack = TcpSegment::serialize_with_options(
                        self.local.ip,
                        self.remote.ip,
                        self.local.port,
                        self.remote.port,
                        my_syn_seq,
                        self.rcv_nxt,
                        TcpFlags::syn_ack(),
                        self.current_rcv_wnd(),
                        &options,
                        &[],
                    );

                    self.track_for_retransmit(
                        my_syn_seq,
                        1,
                        TcpFlags::syn_ack(),
                        Vec::new(),
                        now_ms,
                    );
                    self.stats.segments_sent += 1;

                    Some(syn_ack)
                } else {
                    None
                }
            }

            TcpState::SynSent => {
                if seg.flags.syn && seg.flags.ack {
                    if seg.ack_num == self.snd_nxt {
                        self.rcv_nxt = seg.seq_num.wrapping_add(1);
                        self.snd_wnd = seg.window_size;
                        self.state = TcpState::Established;

                        // The SYN consumed one byte of sequence space and was charged
                        // against the congestion window; acknowledging it must release
                        // that byte, or bytes_in_flight stays permanently inflated and
                        // eventually wedges the sender.
                        let acked = seq_diff(seg.ack_num, self.snd_una);
                        self.snd_una = seg.ack_num;
                        self.congestion.on_ack(acked);
                        // Retires the SYN and takes an RTT sample (Karn's algorithm).
                        self.retire_acked(seg.ack_num, now_ms);

                        // Send ACK to complete 3-way handshake
                        let ack = TcpSegment::serialize(
                            self.local.ip,
                            self.remote.ip,
                            self.local.port,
                            self.remote.port,
                            self.snd_nxt,
                            self.rcv_nxt,
                            TcpFlags::ack(),
                            self.current_rcv_wnd(),
                            &[],
                        );
                        self.stats.segments_sent += 1;
                        Some(ack)
                    } else {
                        None
                    }
                } else if seg.flags.syn {
                    // Simultaneous open
                    self.rcv_nxt = seg.seq_num.wrapping_add(1);
                    self.state = TcpState::SynReceived;
                    let syn_ack = TcpSegment::serialize(
                        self.local.ip,
                        self.remote.ip,
                        self.local.port,
                        self.remote.port,
                        self.snd_nxt,
                        self.rcv_nxt,
                        TcpFlags::syn_ack(),
                        self.current_rcv_wnd(),
                        &[],
                    );
                    self.stats.segments_sent += 1;
                    Some(syn_ack)
                } else {
                    None
                }
            }

            TcpState::SynReceived => {
                if seg.flags.ack && seg.ack_num == self.snd_nxt {
                    self.snd_wnd = seg.window_size;
                    self.state = TcpState::Established;

                    // Release the sequence byte the SYN-ACK consumed (see the SynSent arm).
                    let acked = seq_diff(seg.ack_num, self.snd_una);
                    self.snd_una = seg.ack_num;
                    self.congestion.on_ack(acked);
                    self.retire_acked(seg.ack_num, now_ms);

                    // The final handshake ACK may piggyback data. Route it through the same
                    // reassembly path as every other segment so sequence validation, window
                    // enforcement, and duplicate suppression all still apply.
                    if !seg.payload.is_empty() {
                        self.accept_data(seg.seq_num, seg.payload);
                        return Some(self.build_ack());
                    }
                    None
                } else {
                    None
                }
            }

            TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2 => {
                let mut resp_segment = None;

                // 1. Process the acknowledgement field and slide the send window.
                if seg.flags.ack {
                    if seq_gt(seg.ack_num, self.snd_una) && seq_le(seg.ack_num, self.snd_nxt) {
                        let bytes_acked = seq_diff(seg.ack_num, self.snd_una);
                        self.snd_una = seg.ack_num;
                        self.snd_wnd = seg.window_size;
                        self.congestion.on_ack(bytes_acked);
                        self.retire_acked(seg.ack_num, now_ms);
                    } else if seq_gt(seg.ack_num, self.snd_nxt) {
                        // ACK of data we never sent: unacceptable. Re-advertise our state
                        // (RFC 9293 3.10.7.4) and drop the segment.
                        self.stats.invalid_segments += 1;
                        return Some(self.build_ack());
                    } else if seg.ack_num == self.snd_una
                        && seg.payload.is_empty()
                        && !seg.flags.syn
                        && !seg.flags.fin
                        && !self.retransmit_queue.is_empty()
                    {
                        // A pure duplicate ACK only counts while data is genuinely outstanding.
                        self.snd_wnd = seg.window_size;
                        self.stats.duplicate_acks += 1;
                        if self.congestion.on_dup_ack()
                            && let Some(pkt) = self.retransmit_oldest(now_ms, true)
                        {
                            resp_segment = Some(pkt);
                        }
                    } else {
                        // Stale or pure window update.
                        self.snd_wnd = seg.window_size;
                    }
                }

                // 2. Reassemble inbound payload (in-order, out-of-order, or overlapping).
                //    Data refused because it fell outside the receive window still draws an
                //    ACK below, which is what answers a peer's zero-window probe.
                let had_payload = !seg.payload.is_empty();
                if had_payload {
                    self.accept_data(seg.seq_num, seg.payload);
                }

                // 3. Process an inbound FIN. Its sequence number sits immediately after any
                //    payload the same segment carried, so data+FIN segments close correctly.
                let fin_seq = seg
                    .seq_num
                    .wrapping_add(if seg.flags.syn { 1 } else { 0 })
                    .wrapping_add(seg.payload.len() as u32);
                let mut fin_consumed = false;
                if seg.flags.fin && fin_seq == self.rcv_nxt && !self.fin_received {
                    self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                    self.fin_received = true;
                    fin_consumed = true;

                    self.state = match self.state {
                        // Passive close: the application may still send, so park in
                        // CLOSE_WAIT until it calls close().
                        TcpState::Established => TcpState::CloseWait,
                        // Our FIN is still unacknowledged: simultaneous close.
                        TcpState::FinWait1 => TcpState::Closing,
                        TcpState::FinWait2 => {
                            self.time_wait_entered_ms = Some(now_ms);
                            TcpState::TimeWait
                        }
                        other => other,
                    };
                }

                // 4. Acknowledge anything that consumed sequence space.
                if (had_payload || fin_consumed) && resp_segment.is_none() {
                    resp_segment = Some(self.build_ack());
                }

                // 5. A FIN_WAIT_1 whose FIN has now been acknowledged moves on.
                if self.state == TcpState::FinWait1
                    && self.fin_sent
                    && seq_ge(self.snd_una, self.snd_nxt)
                {
                    self.state = TcpState::FinWait2;
                } else if self.state == TcpState::Closing
                    && self.fin_sent
                    && seq_ge(self.snd_una, self.snd_nxt)
                {
                    self.state = TcpState::TimeWait;
                    self.time_wait_entered_ms = Some(now_ms);
                }

                resp_segment
            }

            TcpState::CloseWait => {
                if seg.flags.ack
                    && seq_gt(seg.ack_num, self.snd_una)
                    && seq_le(seg.ack_num, self.snd_nxt)
                {
                    let bytes_acked = seq_diff(seg.ack_num, self.snd_una);
                    self.snd_una = seg.ack_num;
                    self.snd_wnd = seg.window_size;
                    self.congestion.on_ack(bytes_acked);
                    self.retire_acked(seg.ack_num, now_ms);
                }
                // A retransmitted FIN must be re-acknowledged so the peer can leave FIN_WAIT.
                if seg.flags.fin {
                    return Some(self.build_ack());
                }
                None
            }

            TcpState::Closing => {
                if seg.flags.ack && seq_ge(seg.ack_num, self.snd_nxt) {
                    let acked = seq_diff(seg.ack_num, self.snd_una);
                    self.snd_una = seg.ack_num;
                    self.congestion.on_ack(acked);
                    self.retire_acked(seg.ack_num, now_ms);
                    self.state = TcpState::TimeWait;
                    self.time_wait_entered_ms = Some(now_ms);
                }
                None
            }

            TcpState::LastAck => {
                if seg.flags.ack && seq_ge(seg.ack_num, self.snd_nxt) {
                    let acked = seq_diff(seg.ack_num, self.snd_una);
                    self.snd_una = seg.ack_num;
                    self.congestion.on_ack(acked);
                    self.retire_acked(seg.ack_num, now_ms);
                    self.state = TcpState::Closed;
                }
                None
            }

            TcpState::TimeWait => {
                if seg.flags.fin {
                    // Re-acknowledge duplicate FIN in TIME_WAIT
                    let ack = TcpSegment::serialize(
                        self.local.ip,
                        self.remote.ip,
                        self.local.port,
                        self.remote.port,
                        self.snd_nxt,
                        self.rcv_nxt,
                        TcpFlags::ack(),
                        self.current_rcv_wnd(),
                        &[],
                    );
                    self.stats.segments_sent += 1;
                    return Some(ack);
                }
                None
            }

            TcpState::Closed => None,
        }
    }

    /// Re-sends the oldest unacknowledged segment. `fast` marks a fast retransmit
    /// (duplicate-ACK triggered) rather than an RTO expiry.
    fn retransmit_oldest(&mut self, now_ms: u64, fast: bool) -> Option<Vec<u8>> {
        let rcv_nxt = self.rcv_nxt;
        let rcv_wnd = self.current_rcv_wnd();
        let local_mss = self.local_mss;

        let oldest = self.retransmit_queue.first_mut()?;
        if oldest.retransmits >= MAX_RETRANSMITS {
            return None;
        }
        oldest.last_sent_ms = now_ms;
        oldest.retransmits += 1;

        let seq = oldest.seq_num;
        let flags = oldest.flags;
        let payload = oldest.payload.clone();
        let is_syn = flags.syn;

        self.stats.retransmissions += 1;
        self.stats.segments_sent += 1;
        if fast {
            self.stats.fast_retransmits += 1;
        }

        // A SYN or SYN-ACK must carry the MSS option again; it is not remembered by the peer
        // from a segment it never received.
        let packet = if is_syn {
            let options = vec![TcpOption::Mss(local_mss)];
            TcpSegment::serialize_with_options(
                self.local.ip,
                self.remote.ip,
                self.local.port,
                self.remote.port,
                seq,
                rcv_nxt,
                flags,
                rcv_wnd,
                &options,
                &payload,
            )
        } else {
            TcpSegment::serialize(
                self.local.ip,
                self.remote.ip,
                self.local.port,
                self.remote.port,
                seq,
                rcv_nxt,
                flags,
                rcv_wnd,
                &payload,
            )
        };
        Some(packet)
    }

    /// True when the connection has finished and its resources may be reclaimed.
    pub fn is_reapable(&self, now_ms: u64) -> bool {
        if self.aborted {
            return true;
        }
        match self.state {
            TcpState::Closed => true,
            TcpState::TimeWait => self
                .time_wait_entered_ms
                .is_some_and(|t| now_ms.saturating_sub(t) >= TIME_WAIT_MS),
            _ => false,
        }
    }

    /// Bytes handed to the network but not yet acknowledged.
    pub fn bytes_in_flight(&self) -> u32 {
        self.congestion.in_flight
    }

    /// Periodic pump. Segments queued application data according to the negotiated MSS and
    /// the smaller of the congestion and receive windows, retransmits on RTO expiry, emits
    /// a deferred FIN once the send buffer drains, probes a zero window, and expires
    /// TIME_WAIT. Driven entirely by the caller-supplied simulated clock.
    pub fn poll_output(&mut self, now_ms: u64) -> Vec<Vec<u8>> {
        self.current_time_ms = now_ms;
        let mut packets = Vec::new();

        if self.aborted || self.state == TcpState::Closed {
            return packets;
        }

        // 1. Segment and transmit queued application data.
        //    bytes_in_flight is held at or below min(cwnd, rwnd) by send_window_available().
        let sending = matches!(self.state, TcpState::Established | TcpState::CloseWait);
        if sending && !self.tx_buffer.is_empty() {
            loop {
                let avail = self.congestion.send_window_available(self.snd_wnd);
                if avail == 0 {
                    break;
                }
                let chunk_size = (avail as usize)
                    .min(self.peer_mss as usize)
                    .min(self.tx_buffer.len());
                if chunk_size == 0 {
                    break;
                }

                let chunk: Vec<u8> = self.tx_buffer.drain(..chunk_size).collect();
                let seq = self.snd_nxt;
                self.snd_nxt = self.snd_nxt.wrapping_add(chunk.len() as u32);

                let mut flags = TcpFlags::ack();
                flags.psh = true;

                let wnd = self.current_rcv_wnd();
                self.last_advertised_wnd = wnd;
                let segment = TcpSegment::serialize(
                    self.local.ip,
                    self.remote.ip,
                    self.local.port,
                    self.remote.port,
                    seq,
                    self.rcv_nxt,
                    flags,
                    wnd,
                    &chunk,
                );

                self.stats.bytes_sent += chunk.len() as u64;
                self.stats.segments_sent += 1;
                self.track_for_retransmit(seq, chunk.len() as u32, flags, chunk, now_ms);
                packets.push(segment);

                if self.tx_buffer.is_empty() {
                    break;
                }
            }
        }

        // 2. A close deferred behind queued data fires once the send buffer has drained.
        if self.close_requested
            && !self.fin_sent
            && self.tx_buffer.is_empty()
            && matches!(self.state, TcpState::Established | TcpState::CloseWait)
            && let Some(fin) = self.emit_fin(now_ms)
        {
            packets.push(fin);
        }

        // 3. Retransmission timeout on the oldest unacknowledged segment.
        let rto = self.rtt.rto as u64;
        let expired = self
            .retransmit_queue
            .first()
            .map(|e| now_ms.saturating_sub(e.last_sent_ms) >= rto)
            .unwrap_or(false);
        if expired {
            let exhausted = self
                .retransmit_queue
                .first()
                .map(|e| e.retransmits >= MAX_RETRANSMITS)
                .unwrap_or(false);
            if exhausted {
                // The peer is unreachable. Abort rather than retransmit forever.
                self.aborted = true;
                self.state = TcpState::Closed;
                self.retransmit_queue.clear();
                self.tx_buffer.clear();
                return packets;
            }

            self.congestion.on_timeout();
            self.rtt.backoff();
            self.stats.timeouts += 1;
            if let Some(pkt) = self.retransmit_oldest(now_ms, false) {
                packets.push(pkt);
            }
        }

        // 4. Unsolicited window update. Once the application drains the receive buffer the
        //    peer must be told the window reopened, otherwise a sender that stalled on a
        //    zero window would wait forever for an ACK that has nothing left to acknowledge.
        //    A window is "effectively closed" whenever it is too small to carry a full
        //    segment, not only when it is exactly zero: a peer that advertised 1 byte
        //    stalls just as completely as one that advertised none.
        let wnd_now = self.current_rcv_wnd();
        if self.last_advertised_wnd < self.local_mss
            && wnd_now >= self.local_mss
            && !matches!(self.state, TcpState::Closed | TcpState::TimeWait)
        {
            packets.push(self.build_ack());
        }

        // 5. Zero-window probe (persist timer). The probe carries one byte of real data so
        //    the receiver is obliged to answer: it either accepts the byte or discards it
        //    as out of window, and either way it returns an ACK carrying the live window.
        let stalled = self.congestion.send_window_available(self.snd_wnd) == 0
            && self.retransmit_queue.is_empty();
        if sending && !self.tx_buffer.is_empty() && stalled {
            match self.persist_deadline_ms {
                None => self.persist_deadline_ms = Some(now_ms + PERSIST_INTERVAL_MS),
                Some(due) if now_ms >= due => {
                    self.persist_deadline_ms = Some(now_ms + PERSIST_INTERVAL_MS);
                    self.stats.zero_window_probes += 1;
                    self.stats.segments_sent += 1;

                    let chunk: Vec<u8> = self.tx_buffer.drain(..1).collect();
                    let seq = self.snd_nxt;
                    self.snd_nxt = self.snd_nxt.wrapping_add(1);
                    let flags = TcpFlags::ack();
                    let wnd = self.current_rcv_wnd();
                    self.last_advertised_wnd = wnd;

                    let probe = TcpSegment::serialize(
                        self.local.ip,
                        self.remote.ip,
                        self.local.port,
                        self.remote.port,
                        seq,
                        self.rcv_nxt,
                        flags,
                        wnd,
                        &chunk,
                    );
                    self.stats.bytes_sent += 1;
                    self.track_for_retransmit(seq, 1, flags, chunk, now_ms);
                    packets.push(probe);
                }
                Some(_) => {}
            }
        } else {
            self.persist_deadline_ms = None;
        }

        // 6. TIME_WAIT expiry after 2 * MSL.
        if self.state == TcpState::TimeWait
            && let Some(entered) = self.time_wait_entered_ms
            && now_ms.saturating_sub(entered) >= TIME_WAIT_MS
        {
            self.state = TcpState::Closed;
        }

        packets
    }
}

/// TCP Connection Manager
#[derive(Default)]
pub struct TcpManager {
    pub listeners: HashMap<u16, u32>, // port -> next ISN
    pub connections: HashMap<TcpConnectionKey, TcpConnection>,
    pub current_time_ms: u64,
}

impl TcpManager {
    pub fn new() -> Self {
        TcpManager {
            listeners: HashMap::new(),
            connections: HashMap::new(),
            current_time_ms: 0,
        }
    }

    pub fn listen(&mut self, port: u16) {
        self.listeners.insert(port, 1000);
    }

    pub fn connect(&mut self, local: SocketAddrV4, remote: SocketAddrV4, isn: u32) -> Vec<u8> {
        let key = TcpConnectionKey { local, remote };
        let mut conn = TcpConnection::new_client(local, remote, isn);
        let syn_packet = conn.initiate_syn_at(self.current_time_ms);
        self.connections.insert(key, conn);
        syn_packet
    }

    pub fn send_data(
        &mut self,
        local: SocketAddrV4,
        remote: SocketAddrV4,
        data: &[u8],
    ) -> Option<Vec<u8>> {
        let key = TcpConnectionKey { local, remote };
        if let Some(conn) = self.connections.get_mut(&key) {
            conn.send_data_at(data, self.current_time_ms)
        } else {
            None
        }
    }

    pub fn close(&mut self, local: SocketAddrV4, remote: SocketAddrV4) -> Option<Vec<u8>> {
        let key = TcpConnectionKey { local, remote };
        if let Some(conn) = self.connections.get_mut(&key) {
            conn.initiate_close_at(self.current_time_ms)
        } else {
            None
        }
    }

    pub fn get_connection(
        &self,
        local: SocketAddrV4,
        remote: SocketAddrV4,
    ) -> Option<&TcpConnection> {
        let key = TcpConnectionKey { local, remote };
        self.connections.get(&key)
    }

    pub fn get_connection_mut(
        &mut self,
        local: SocketAddrV4,
        remote: SocketAddrV4,
    ) -> Option<&mut TcpConnection> {
        let key = TcpConnectionKey { local, remote };
        self.connections.get_mut(&key)
    }

    pub fn has_endpoint(
        &self,
        local_ip: Ipv4Address,
        local_port: u16,
        remote_ip: Ipv4Address,
        remote_port: u16,
    ) -> bool {
        let key = TcpConnectionKey {
            local: SocketAddrV4 {
                ip: local_ip,
                port: local_port,
            },
            remote: SocketAddrV4 {
                ip: remote_ip,
                port: remote_port,
            },
        };
        self.connections.contains_key(&key) || self.listeners.contains_key(&local_port)
    }

    pub fn process_segment(
        &mut self,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        seg: &TcpSegment<'_>,
    ) -> Option<Vec<u8>> {
        self.process_segment_at(src_ip, dst_ip, seg, self.current_time_ms)
    }

    pub fn process_segment_at(
        &mut self,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        seg: &TcpSegment<'_>,
        now_ms: u64,
    ) -> Option<Vec<u8>> {
        self.current_time_ms = now_ms;
        let key = TcpConnectionKey {
            local: SocketAddrV4 {
                ip: dst_ip,
                port: seg.dst_port,
            },
            remote: SocketAddrV4 {
                ip: src_ip,
                port: seg.src_port,
            },
        };

        if let Some(conn) = self.connections.get_mut(&key) {
            return conn.handle_segment_at(seg, now_ms);
        }

        // Check if port is listening
        if let Some(isn) = self.listeners.get_mut(&seg.dst_port)
            && seg.flags.syn
        {
            let mut conn = TcpConnection::new_server(key.local, key.remote, *isn);
            *isn = isn.wrapping_add(1000);
            let resp = conn.handle_segment_at(seg, now_ms);
            self.connections.insert(key, conn);
            return resp;
        }

        // Port closed -> send RST
        if !seg.flags.rst {
            let rst_seq = if seg.flags.ack { seg.ack_num } else { 0 };
            let rst_ack = seg.seq_num.wrapping_add(if seg.flags.syn || seg.flags.fin {
                1
            } else {
                seg.payload.len() as u32
            });
            let mut flags = TcpFlags::rst();
            if !seg.flags.ack {
                flags.ack = true;
            }
            return Some(TcpSegment::serialize(
                dst_ip,
                src_ip,
                seg.dst_port,
                seg.src_port,
                rst_seq,
                rst_ack,
                flags,
                0,
                &[],
            ));
        }

        None
    }

    /// Advances simulated time and generates any pending or retransmitted TCP segments.
    pub fn step_timers(&mut self, now_ms: u64) -> Vec<(SocketAddrV4, SocketAddrV4, Vec<u8>)> {
        self.current_time_ms = now_ms;
        let mut outgoing = Vec::new();
        for (key, conn) in self.connections.iter_mut() {
            let packets = conn.poll_output(now_ms);
            for p in packets {
                outgoing.push((key.local, key.remote, p));
            }
        }
        outgoing
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_options_mss_parsing() {
        let src_ip = Ipv4Address::new(10, 0, 0, 1);
        let dst_ip = Ipv4Address::new(10, 0, 0, 2);
        let options = vec![TcpOption::Mss(1400), TcpOption::WindowScale(7)];

        let raw = TcpSegment::serialize_with_options(
            src_ip,
            dst_ip,
            12345,
            80,
            100,
            0,
            TcpFlags::syn(),
            65535,
            &options,
            &[],
        );

        let parsed = TcpSegment::parse(src_ip, dst_ip, &raw, true).unwrap();
        assert_eq!(parsed.options.len(), 3);
        assert_eq!(parsed.options[0], TcpOption::Mss(1400));
        assert_eq!(parsed.options[1], TcpOption::WindowScale(7));
        assert_eq!(parsed.options[2], TcpOption::Nop);
    }

    #[test]
    fn test_tcp_rejects_malformed_option_tails() {
        let src_ip = Ipv4Address::new(10, 0, 0, 1);
        let dst_ip = Ipv4Address::new(10, 0, 0, 2);
        let base = TcpSegment::serialize_with_options(
            src_ip,
            dst_ip,
            12345,
            80,
            100,
            0,
            TcpFlags::syn(),
            65535,
            &[
                TcpOption::Nop,
                TcpOption::Nop,
                TcpOption::Nop,
                TcpOption::Nop,
            ],
            &[],
        );
        assert_eq!(base.len(), 24);

        let mut missing_length = base.clone();
        missing_length[20..24].copy_from_slice(&[
            TCP_OPT_NOP,
            TCP_OPT_NOP,
            TCP_OPT_NOP,
            TCP_OPT_MSS,
        ]);
        assert_eq!(
            TcpSegment::parse(src_ip, dst_ip, &missing_length, false).unwrap_err(),
            TcpError::TruncatedOption {
                offset: 23,
                kind: TCP_OPT_MSS,
            }
        );

        let mut too_short = base.clone();
        too_short[20..24].copy_from_slice(&[TCP_OPT_MSS, 1, 0, 0]);
        assert_eq!(
            TcpSegment::parse(src_ip, dst_ip, &too_short, false).unwrap_err(),
            TcpError::InvalidOptionLength {
                offset: 20,
                kind: TCP_OPT_MSS,
                length: 1,
            }
        );

        let mut overruns_header = base;
        overruns_header[20..24].copy_from_slice(&[TCP_OPT_MSS, 5, 0, 0]);
        assert_eq!(
            TcpSegment::parse(src_ip, dst_ip, &overruns_header, false).unwrap_err(),
            TcpError::OptionLengthExceedsHeader {
                offset: 20,
                kind: TCP_OPT_MSS,
                length: 5,
                remaining: 4,
            }
        );
    }

    #[test]
    fn test_tcp_terminal_single_byte_options_remain_valid() {
        let src_ip = Ipv4Address::new(10, 0, 0, 1);
        let dst_ip = Ipv4Address::new(10, 0, 0, 2);
        let base = TcpSegment::serialize_with_options(
            src_ip,
            dst_ip,
            12345,
            80,
            100,
            0,
            TcpFlags::syn(),
            65535,
            &[
                TcpOption::Nop,
                TcpOption::Nop,
                TcpOption::Nop,
                TcpOption::Nop,
            ],
            &[],
        );

        let parsed_nop = TcpSegment::parse(src_ip, dst_ip, &base, false).unwrap();
        assert_eq!(parsed_nop.options, vec![TcpOption::Nop; 4]);

        let mut terminal_eol = base;
        terminal_eol[23] = TCP_OPT_EOL;
        let parsed_eol = TcpSegment::parse(src_ip, dst_ip, &terminal_eol, false).unwrap();
        assert_eq!(
            parsed_eol.options,
            vec![
                TcpOption::Nop,
                TcpOption::Nop,
                TcpOption::Nop,
                TcpOption::EndOfOptions,
            ]
        );
    }

    #[test]
    fn test_tcp_out_of_order_reassembly() {
        let mut conn = TcpConnection::new_server(
            SocketAddrV4 {
                ip: Ipv4Address::new(10, 0, 0, 1),
                port: 80,
            },
            SocketAddrV4 {
                ip: Ipv4Address::new(10, 0, 0, 2),
                port: 50000,
            },
            1000,
        );
        conn.state = TcpState::Established;
        conn.rcv_nxt = 100;

        // 1. Receive segment B (Seq 105..110) out of order
        let seg_b = TcpSegment {
            src_port: 50000,
            dst_port: 80,
            seq_num: 105,
            ack_num: 1000,
            data_offset: 5,
            flags: TcpFlags::ack(),
            window_size: 65535,
            checksum: 0,
            urgent_ptr: 0,
            options: vec![],
            payload: b"WORLD",
        };
        conn.handle_segment(&seg_b);
        assert_eq!(conn.rcv_nxt, 100); // Still waiting for seq 100
        assert_eq!(conn.rx_buffer.len(), 0);

        // 2. Receive segment A (Seq 100..105) in order
        let seg_a = TcpSegment {
            src_port: 50000,
            dst_port: 80,
            seq_num: 100,
            ack_num: 1000,
            data_offset: 5,
            flags: TcpFlags::ack(),
            window_size: 65535,
            checksum: 0,
            urgent_ptr: 0,
            options: vec![],
            payload: b"HELLO",
        };
        conn.handle_segment(&seg_a);

        // Both segment A and buffered segment B should now be assembled
        assert_eq!(conn.rcv_nxt, 100 + 5 + 5);
        assert_eq!(conn.rx_buffer, b"HELLOWORLD");
    }

    #[test]
    fn test_tcp_client_server_full_lifecycle() {
        let client_ip = Ipv4Address::new(192, 168, 1, 10);
        let server_ip = Ipv4Address::new(192, 168, 1, 20);
        let client_port = 45000;
        let server_port = 80;

        let mut client_mgr = TcpManager::new();
        let mut server_mgr = TcpManager::new();
        server_mgr.listen(server_port);

        let client_sock = SocketAddrV4 {
            ip: client_ip,
            port: client_port,
        };
        let server_sock = SocketAddrV4 {
            ip: server_ip,
            port: server_port,
        };

        // 1. Client sends SYN
        let syn_bytes = client_mgr.connect(client_sock, server_sock, 1000);
        let syn_seg = TcpSegment::parse(client_ip, server_ip, &syn_bytes, true).unwrap();
        assert_eq!(syn_seg.flags, TcpFlags::syn());
        assert_eq!(
            client_mgr
                .get_connection(client_sock, server_sock)
                .unwrap()
                .state,
            TcpState::SynSent
        );

        // 2. Server processes SYN, sends SYN-ACK
        let syn_ack_bytes = server_mgr
            .process_segment(client_ip, server_ip, &syn_seg)
            .unwrap();
        let syn_ack_seg = TcpSegment::parse(server_ip, client_ip, &syn_ack_bytes, true).unwrap();
        assert_eq!(syn_ack_seg.flags, TcpFlags::syn_ack());
        assert_eq!(
            server_mgr
                .get_connection(server_sock, client_sock)
                .unwrap()
                .state,
            TcpState::SynReceived
        );

        // 3. Client processes SYN-ACK, sends ACK -> ESTABLISHED
        let ack_bytes = client_mgr
            .process_segment(server_ip, client_ip, &syn_ack_seg)
            .unwrap();
        let ack_seg = TcpSegment::parse(client_ip, server_ip, &ack_bytes, true).unwrap();
        assert_eq!(ack_seg.flags, TcpFlags::ack());
        assert_eq!(
            client_mgr
                .get_connection(client_sock, server_sock)
                .unwrap()
                .state,
            TcpState::Established
        );

        // 4. Server processes ACK -> ESTABLISHED
        let server_resp = server_mgr.process_segment(client_ip, server_ip, &ack_seg);
        assert!(server_resp.is_none());
        assert_eq!(
            server_mgr
                .get_connection(server_sock, client_sock)
                .unwrap()
                .state,
            TcpState::Established
        );

        // 5. Client sends Data ("HTTP GET")
        let data_bytes = client_mgr
            .send_data(client_sock, server_sock, b"GET / HTTP/1.1\r\n\r\n")
            .unwrap();
        let data_seg = TcpSegment::parse(client_ip, server_ip, &data_bytes, true).unwrap();
        assert_eq!(data_seg.payload, b"GET / HTTP/1.1\r\n\r\n");

        // 6. Server receives data and sends ACK
        let data_ack_bytes = server_mgr
            .process_segment(client_ip, server_ip, &data_seg)
            .unwrap();
        let data_ack_seg = TcpSegment::parse(server_ip, client_ip, &data_ack_bytes, true).unwrap();
        assert_eq!(data_ack_seg.flags, TcpFlags::ack());
        assert_eq!(
            server_mgr
                .get_connection(server_sock, client_sock)
                .unwrap()
                .rx_buffer,
            b"GET / HTTP/1.1\r\n\r\n"
        );

        // 7. Client processes data ACK
        let _ = client_mgr.process_segment(server_ip, client_ip, &data_ack_seg);

        // 8. Client closes connection (FIN-ACK)
        let fin_bytes = client_mgr.close(client_sock, server_sock).unwrap();
        let fin_seg = TcpSegment::parse(client_ip, server_ip, &fin_bytes, true).unwrap();
        assert_eq!(fin_seg.flags, TcpFlags::fin_ack());
        assert_eq!(
            client_mgr
                .get_connection(client_sock, server_sock)
                .unwrap()
                .state,
            TcpState::FinWait1
        );

        // 9. Server receives FIN and acknowledges it, entering CLOSE_WAIT. It does not
        //    send its own FIN yet: the receiving application may still have data to send,
        //    and a passive close must not discard it (RFC 9293 3.6).
        let fin_ack_bytes = server_mgr
            .process_segment(client_ip, server_ip, &fin_seg)
            .unwrap();
        let close_wait_ack = TcpSegment::parse(server_ip, client_ip, &fin_ack_bytes, true).unwrap();
        assert_eq!(close_wait_ack.flags, TcpFlags::ack());
        assert_eq!(
            server_mgr
                .get_connection(server_sock, client_sock)
                .unwrap()
                .state,
            TcpState::CloseWait
        );

        // 9b. The client's FIN is acknowledged, moving it to FIN_WAIT_2.
        let _ = client_mgr.process_segment(server_ip, client_ip, &close_wait_ack);
        assert_eq!(
            client_mgr
                .get_connection(client_sock, server_sock)
                .unwrap()
                .state,
            TcpState::FinWait2
        );

        // 9c. The server application closes, which is what emits the server's FIN.
        let fin_ack_bytes = server_mgr.close(server_sock, client_sock).unwrap();
        let fin_ack_seg = TcpSegment::parse(server_ip, client_ip, &fin_ack_bytes, true).unwrap();
        assert_eq!(fin_ack_seg.flags, TcpFlags::fin_ack());
        assert_eq!(
            server_mgr
                .get_connection(server_sock, client_sock)
                .unwrap()
                .state,
            TcpState::LastAck
        );

        // 10. Client receives FIN-ACK, sends ACK -> TIME_WAIT
        let final_ack_bytes = client_mgr
            .process_segment(server_ip, client_ip, &fin_ack_seg)
            .unwrap();
        let final_ack_seg =
            TcpSegment::parse(client_ip, server_ip, &final_ack_bytes, true).unwrap();
        assert_eq!(final_ack_seg.flags, TcpFlags::ack());
        assert_eq!(
            client_mgr
                .get_connection(client_sock, server_sock)
                .unwrap()
                .state,
            TcpState::TimeWait
        );

        // 11. Server receives final ACK -> CLOSED
        let server_closed_resp = server_mgr.process_segment(client_ip, server_ip, &final_ack_seg);
        assert!(server_closed_resp.is_none());
        assert_eq!(
            server_mgr
                .get_connection(server_sock, client_sock)
                .unwrap()
                .state,
            TcpState::Closed
        );
    }
}
