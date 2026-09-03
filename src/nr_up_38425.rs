//! 3GPP TS 38.425 NR User Plane Protocol (F1-U & Xn-U) and Radio Flow Control Engine.
//!
//! Provides PDU Type 0 (DL USER DATA) encapsulation with 24-bit sequence numbers,
//! PDU Type 1 (DL DATA DELIVERY STATUS) flow control reporting, and a credit-based
//! sliding window transmitter (`NrUpFlowController`) with selective fast retransmission.

use std::collections::VecDeque;
use std::fmt;

/// Maximum 24-bit NR-U sequence number (2^24 - 1).
pub const NR_U_MAX_SN: u32 = 0x00FF_FFFF;

/// PDU Type per 3GPP TS 38.425 Section 5.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NrUpPduType {
    DlUserData = 0,
    DlDataDeliveryStatus = 1,
}

impl NrUpPduType {
    pub fn from_u8(val: u8) -> Result<Self, NrUpError> {
        match val & 0x0F {
            0 => Ok(NrUpPduType::DlUserData),
            1 => Ok(NrUpPduType::DlDataDeliveryStatus),
            other => Err(NrUpError::UnsupportedPduType(other)),
        }
    }
}

/// Error type for 3GPP TS 38.425 operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NrUpError {
    HeaderTooShort { need: usize, got: usize },
    UnsupportedPduType(u8),
    BufferOverflow { in_flight: usize, credit: u32 },
    SequenceNumberOverflow(u32),
    MalformedPacket(&'static str),
}

impl fmt::Display for NrUpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NrUpError::HeaderTooShort { need, got } => {
                write!(
                    f,
                    "NR-UP header too short: need {} bytes, got {}",
                    need, got
                )
            }
            NrUpError::UnsupportedPduType(t) => {
                write!(f, "Unsupported 3GPP TS 38.425 PDU Type: {}", t)
            }
            NrUpError::BufferOverflow { in_flight, credit } => {
                write!(
                    f,
                    "DU buffer credit exceeded: in-flight {} bytes > credit {} bytes",
                    in_flight, credit
                )
            }
            NrUpError::SequenceNumberOverflow(sn) => {
                write!(f, "NR-U sequence number {} exceeds 24-bit limit", sn)
            }
            NrUpError::MalformedPacket(msg) => write!(f, "Malformed NR-UP packet: {}", msg),
        }
    }
}

impl std::error::Error for NrUpError {}

/// Block of discarded NR-U sequence numbers (O-RAN/3GPP RLC buffer purge).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscardedSnBlock {
    pub start_nr_u_sn: u32,
    pub count: u8,
}

/// PDU Type 0: DL USER DATA (3GPP TS 38.425 Section 5.5.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NrUpDlUserData {
    pub nr_u_sn: u32,
    pub report_polling: bool,
    pub dl_flush: bool,
    pub user_data_exist: bool,
    pub assistance_info_present: bool,
    pub discarded_blocks: Vec<DiscardedSnBlock>,
    pub payload: Vec<u8>,
}

impl NrUpDlUserData {
    pub fn new(nr_u_sn: u32, payload: Vec<u8>) -> Result<Self, NrUpError> {
        if nr_u_sn > NR_U_MAX_SN {
            return Err(NrUpError::SequenceNumberOverflow(nr_u_sn));
        }
        Ok(Self {
            nr_u_sn,
            report_polling: false,
            dl_flush: false,
            user_data_exist: !payload.is_empty(),
            assistance_info_present: false,
            discarded_blocks: Vec::new(),
            payload,
        })
    }

    /// Serializes DL USER DATA into wire format.
    pub fn serialize(&self) -> Vec<u8> {
        let has_discard = !self.discarded_blocks.is_empty();
        let mut out = Vec::with_capacity(8 + self.payload.len());

        // Octet 1: Spare (bits 7-4) | PDU Type = 0 (bits 3-0)
        out.push(0x00);

        // Octet 2: Flags
        let mut flags = 0u8;
        if self.assistance_info_present {
            flags |= 0x10;
        }
        if self.user_data_exist {
            flags |= 0x08;
        }
        if self.report_polling {
            flags |= 0x04;
        }
        if self.dl_flush {
            flags |= 0x02;
        }
        if has_discard {
            flags |= 0x01;
        }
        out.push(flags);

        // Octets 3-5: NR-U Sequence Number (24-bit big-endian)
        out.push(((self.nr_u_sn >> 16) & 0xFF) as u8);
        out.push(((self.nr_u_sn >> 8) & 0xFF) as u8);
        out.push((self.nr_u_sn & 0xFF) as u8);

        // Optional Discard Blocks
        if has_discard {
            out.push(self.discarded_blocks.len().min(255) as u8);
            for b in self.discarded_blocks.iter().take(255) {
                out.push(((b.start_nr_u_sn >> 16) & 0xFF) as u8);
                out.push(((b.start_nr_u_sn >> 8) & 0xFF) as u8);
                out.push((b.start_nr_u_sn & 0xFF) as u8);
                out.push(b.count);
            }
        }

        // Payload (PDCP PDU)
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parses DL USER DATA from wire format.
    pub fn parse(data: &[u8]) -> Result<Self, NrUpError> {
        if data.len() < 5 {
            return Err(NrUpError::HeaderTooShort {
                need: 5,
                got: data.len(),
            });
        }

        let pdu_type = NrUpPduType::from_u8(data[0])?;
        if pdu_type != NrUpPduType::DlUserData {
            return Err(NrUpError::UnsupportedPduType(data[0] & 0x0F));
        }

        let flags = data[1];
        let assistance_info_present = (flags & 0x10) != 0;
        let user_data_exist = (flags & 0x08) != 0;
        let report_polling = (flags & 0x04) != 0;
        let dl_flush = (flags & 0x02) != 0;
        let has_discard = (flags & 0x01) != 0;

        let nr_u_sn = ((data[2] as u32) << 16) | ((data[3] as u32) << 8) | (data[4] as u32);
        let mut offset = 5;

        let mut discarded_blocks = Vec::new();
        if has_discard {
            if data.len() < offset + 1 {
                return Err(NrUpError::HeaderTooShort {
                    need: offset + 1,
                    got: data.len(),
                });
            }
            let num_blocks = data[offset] as usize;
            offset += 1;
            if data.len() < offset + num_blocks * 4 {
                return Err(NrUpError::HeaderTooShort {
                    need: offset + num_blocks * 4,
                    got: data.len(),
                });
            }
            for _ in 0..num_blocks {
                let start_sn = ((data[offset] as u32) << 16)
                    | ((data[offset + 1] as u32) << 8)
                    | (data[offset + 2] as u32);
                let count = data[offset + 3];
                discarded_blocks.push(DiscardedSnBlock {
                    start_nr_u_sn: start_sn,
                    count,
                });
                offset += 4;
            }
        }

        let payload = if offset < data.len() {
            data[offset..].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            nr_u_sn,
            report_polling,
            dl_flush,
            user_data_exist,
            assistance_info_present,
            discarded_blocks,
            payload,
        })
    }
}

/// Lost sequence number range reported by DU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LostSnRange {
    pub start_sn: u32,
    pub end_sn: u32,
}

/// Cause value for DDDS feedback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DddsCause {
    Unknown = 0,
    RadioLinkOutage = 1,
    SuccessfulHandover = 2,
    HandoverCancellation = 3,
}

impl DddsCause {
    pub fn from_u8(val: u8) -> Self {
        match val {
            1 => DddsCause::RadioLinkOutage,
            2 => DddsCause::SuccessfulHandover,
            3 => DddsCause::HandoverCancellation,
            _ => DddsCause::Unknown,
        }
    }
}

/// PDU Type 1: DL DATA DELIVERY STATUS (DDDS) (3GPP TS 38.425 Section 5.5.2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NrUpDlDataDeliveryStatus {
    pub desired_buffer_size: u32,
    pub highest_delivered_nr_u_sn: Option<u32>,
    pub highest_transmitted_nr_u_sn: Option<u32>,
    pub cause: Option<DddsCause>,
    pub lost_sn_ranges: Vec<LostSnRange>,
    pub final_frame: bool,
}

impl NrUpDlDataDeliveryStatus {
    pub fn new(desired_buffer_size: u32) -> Self {
        Self {
            desired_buffer_size,
            highest_delivered_nr_u_sn: None,
            highest_transmitted_nr_u_sn: None,
            cause: None,
            lost_sn_ranges: Vec::new(),
            final_frame: false,
        }
    }

    /// Serializes DDDS into wire format.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16);

        // Octet 1: Spare (bits 7-4) | PDU Type = 1 (bits 3-0)
        out.push(0x01);

        // Octet 2: Flags
        let mut f1 = 0u8;
        if !self.lost_sn_ranges.is_empty() {
            f1 |= 0x10; // Lost NR-U SN present
        }
        if self.highest_delivered_nr_u_sn.is_some() {
            f1 |= 0x04; // Highest Delivered NR-U SN present
        }
        if self.final_frame {
            f1 |= 0x02; // Final Frame Indication
        }
        out.push(f1);

        // Octet 3: Secondary flags
        let mut f2 = 0u8;
        if self.cause.is_some() {
            f2 |= 0x01; // Cause value present
        }
        out.push(f2);

        // Octets 4-7: Desired Buffer Size (32-bit big-endian)
        out.extend_from_slice(&self.desired_buffer_size.to_be_bytes());

        // Highest Delivered NR-U SN (3 octets, 24-bit)
        if let Some(h_deliv) = self.highest_delivered_nr_u_sn {
            out.push(((h_deliv >> 16) & 0xFF) as u8);
            out.push(((h_deliv >> 8) & 0xFF) as u8);
            out.push((h_deliv & 0xFF) as u8);
        }

        // Highest Transmitted NR-U SN (3 octets, 24-bit) if present
        if let Some(h_tx) = self.highest_transmitted_nr_u_sn {
            out.push(((h_tx >> 16) & 0xFF) as u8);
            out.push(((h_tx >> 8) & 0xFF) as u8);
            out.push((h_tx & 0xFF) as u8);
        }

        // Cause Value
        if let Some(c) = self.cause {
            out.push(c as u8);
        }

        // Lost NR-U SN Ranges
        if !self.lost_sn_ranges.is_empty() {
            out.push(self.lost_sn_ranges.len().min(255) as u8);
            for r in self.lost_sn_ranges.iter().take(255) {
                out.push(((r.start_sn >> 16) & 0xFF) as u8);
                out.push(((r.start_sn >> 8) & 0xFF) as u8);
                out.push((r.start_sn & 0xFF) as u8);
                out.push(((r.end_sn >> 16) & 0xFF) as u8);
                out.push(((r.end_sn >> 8) & 0xFF) as u8);
                out.push((r.end_sn & 0xFF) as u8);
            }
        }

        out
    }

    /// Parses DDDS from wire format.
    pub fn parse(data: &[u8]) -> Result<Self, NrUpError> {
        if data.len() < 7 {
            return Err(NrUpError::HeaderTooShort {
                need: 7,
                got: data.len(),
            });
        }

        let pdu_type = NrUpPduType::from_u8(data[0])?;
        if pdu_type != NrUpPduType::DlDataDeliveryStatus {
            return Err(NrUpError::UnsupportedPduType(data[0] & 0x0F));
        }

        let f1 = data[1];
        let lost_sn_present = (f1 & 0x10) != 0;
        let highest_deliv_present = (f1 & 0x04) != 0;
        let final_frame = (f1 & 0x02) != 0;

        let f2 = data[2];
        let cause_present = (f2 & 0x01) != 0;

        let desired_buffer_size = u32::from_be_bytes([data[3], data[4], data[5], data[6]]);
        let mut offset = 7;

        let highest_delivered_nr_u_sn = if highest_deliv_present {
            if data.len() < offset + 3 {
                return Err(NrUpError::HeaderTooShort {
                    need: offset + 3,
                    got: data.len(),
                });
            }
            let sn = ((data[offset] as u32) << 16)
                | ((data[offset + 1] as u32) << 8)
                | (data[offset + 2] as u32);
            offset += 3;
            Some(sn)
        } else {
            None
        };

        let cause = if cause_present {
            if data.len() < offset + 1 {
                return Err(NrUpError::HeaderTooShort {
                    need: offset + 1,
                    got: data.len(),
                });
            }
            let c = DddsCause::from_u8(data[offset]);
            offset += 1;
            Some(c)
        } else {
            None
        };

        let mut lost_sn_ranges = Vec::new();
        if lost_sn_present && offset < data.len() {
            let num_ranges = data[offset] as usize;
            offset += 1;
            if data.len() < offset + num_ranges * 6 {
                return Err(NrUpError::HeaderTooShort {
                    need: offset + num_ranges * 6,
                    got: data.len(),
                });
            }
            for _ in 0..num_ranges {
                let start_sn = ((data[offset] as u32) << 16)
                    | ((data[offset + 1] as u32) << 8)
                    | (data[offset + 2] as u32);
                let end_sn = ((data[offset + 3] as u32) << 16)
                    | ((data[offset + 4] as u32) << 8)
                    | (data[offset + 5] as u32);
                lost_sn_ranges.push(LostSnRange { start_sn, end_sn });
                offset += 6;
            }
        }

        Ok(Self {
            desired_buffer_size,
            highest_delivered_nr_u_sn,
            highest_transmitted_nr_u_sn: None,
            cause,
            lost_sn_ranges,
            final_frame,
        })
    }
}

/// F1-U Sliding Window Credit Flow Controller (gNB-CU-UP transmitter).
#[derive(Debug, Clone)]
pub struct NrUpFlowController {
    pub desired_buffer_size: u32,
    pub in_flight_bytes: usize,
    pub next_nr_u_sn: u32,
    pub highest_delivered_sn: Option<u32>,
    pub unacked_packets: VecDeque<(u32, Vec<u8>)>,
    pub total_sent_packets: u64,
    pub total_retransmitted_packets: u64,
    pub total_delivered_packets: u64,
}

impl NrUpFlowController {
    pub fn new(initial_buffer_size: u32) -> Self {
        Self {
            desired_buffer_size: initial_buffer_size,
            in_flight_bytes: 0,
            next_nr_u_sn: 0,
            highest_delivered_sn: None,
            unacked_packets: VecDeque::new(),
            total_sent_packets: 0,
            total_retransmitted_packets: 0,
            total_delivered_packets: 0,
        }
    }

    /// Checks if transmitter has sufficient DU buffer credit to transmit `payload_len` bytes.
    pub fn can_send(&self, payload_len: usize) -> bool {
        self.in_flight_bytes + payload_len <= (self.desired_buffer_size as usize)
    }

    /// Encapsulates and sends a new downlink PDCP PDU if credit allows.
    pub fn send_packet(
        &mut self,
        payload: Vec<u8>,
        report_polling: bool,
    ) -> Result<NrUpDlUserData, NrUpError> {
        let p_len = payload.len();
        if !self.can_send(p_len) {
            return Err(NrUpError::BufferOverflow {
                in_flight: self.in_flight_bytes + p_len,
                credit: self.desired_buffer_size,
            });
        }

        let sn = self.next_nr_u_sn;
        self.next_nr_u_sn = (self.next_nr_u_sn + 1) & NR_U_MAX_SN;

        let mut pdu = NrUpDlUserData::new(sn, payload.clone())?;
        pdu.report_polling = report_polling;

        self.in_flight_bytes += p_len;
        self.total_sent_packets += 1;
        self.unacked_packets.push_back((sn, payload));

        Ok(pdu)
    }

    /// Ingests DDDS feedback from DU, prunes acknowledged packets, and retransmits lost ranges.
    pub fn process_delivery_status(
        &mut self,
        ddds: &NrUpDlDataDeliveryStatus,
    ) -> Vec<NrUpDlUserData> {
        self.desired_buffer_size = ddds.desired_buffer_size;

        // Prune packets up to highest_delivered_nr_u_sn
        if let Some(h_deliv) = ddds.highest_delivered_nr_u_sn {
            self.highest_delivered_sn = Some(h_deliv);
            while let Some((sn, pld)) = self.unacked_packets.front() {
                // Check if sn <= h_deliv (handling 24-bit circular sequence space)
                let diff = h_deliv.wrapping_sub(*sn) & NR_U_MAX_SN;
                if diff < (NR_U_MAX_SN / 2) {
                    self.in_flight_bytes = self.in_flight_bytes.saturating_sub(pld.len());
                    self.total_delivered_packets += 1;
                    self.unacked_packets.pop_front();
                } else {
                    break;
                }
            }
        }

        // Fast retransmit missing SNs reported in lost ranges
        let mut retransmissions = Vec::new();
        for range in &ddds.lost_sn_ranges {
            for (sn, pld) in &self.unacked_packets {
                let s_diff = sn.wrapping_sub(range.start_sn) & NR_U_MAX_SN;
                let e_diff = range.end_sn.wrapping_sub(*sn) & NR_U_MAX_SN;
                let span = range.end_sn.wrapping_sub(range.start_sn) & NR_U_MAX_SN;

                if s_diff + e_diff == span {
                    if let Ok(mut retx_pdu) = NrUpDlUserData::new(*sn, pld.clone()) {
                        retx_pdu.report_polling = true;
                        self.total_retransmitted_packets += 1;
                        retransmissions.push(retx_pdu);
                    }
                }
            }
        }

        retransmissions
    }
}
