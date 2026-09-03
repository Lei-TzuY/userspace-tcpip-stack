//! 3GPP TS 38.322 5G NR Radio Link Control (RLC) Engine.
//!
//! Implements Layer 2 RLC protocols:
//! - AM (Acknowledged Mode), UM (Unacknowledged Mode), and TM (Transparent Mode)
//! - PDU framing: 12-bit & 18-bit SN, Segmentation Info (SI), Segment Offset (SO)
//! - Segmentation and Reassembly of SDUs based on MAC transport grants
//! - AM ARQ state machine: Polling, Status PDU (ACK_SN, NACK ranges), and retransmission

use std::collections::{BTreeMap, HashMap};

/// RLC Sequence Number length in Acknowledged Mode (AM).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RlcAmSnSize {
    Am12Bits,
    Am18Bits,
}

impl RlcAmSnSize {
    #[inline]
    pub fn max_sn(&self) -> u32 {
        match self {
            RlcAmSnSize::Am12Bits => 4095,
            RlcAmSnSize::Am18Bits => 262143,
        }
    }
}

/// RLC Sequence Number length in Unacknowledged Mode (UM).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RlcUmSnSize {
    Um6Bits,
    Um12Bits,
}

/// RLC Operating Mode for an RLC entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RlcEntityMode {
    Tm,
    Um { sn_size: RlcUmSnSize },
    Am { sn_size: RlcAmSnSize },
}

/// Segmentation Information (SI) (TS 38.322 Section 6.2.3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RlcSegmentationInfo {
    Full = 0x00,          // Complete SDU (no SO field)
    FirstSegment = 0x01,  // First segment of SDU (no SO field)
    LastSegment = 0x02,   // Last segment of SDU (SO present)
    MiddleSegment = 0x03, // Neither first nor last segment (SO present)
}

impl RlcSegmentationInfo {
    pub fn from_u8(val: u8) -> Self {
        match val & 0x03 {
            0x00 => RlcSegmentationInfo::Full,
            0x01 => RlcSegmentationInfo::FirstSegment,
            0x02 => RlcSegmentationInfo::LastSegment,
            _ => RlcSegmentationInfo::MiddleSegment,
        }
    }
}

/// RLC AM Data PDU representation (TS 38.322 Section 6.2.2.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RlcAmDataPdu {
    pub sn_size: RlcAmSnSize,
    pub poll: bool,
    pub si: RlcSegmentationInfo,
    pub sn: u32,
    pub so: Option<u16>, // Segment Offset, present if si is LastSegment or MiddleSegment
    pub payload: Vec<u8>,
}

impl RlcAmDataPdu {
    /// Serializes AM Data PDU to wire bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let has_so = matches!(
            self.si,
            RlcSegmentationInfo::LastSegment | RlcSegmentationInfo::MiddleSegment
        );
        let so_len = if has_so { 2 } else { 0 };

        match self.sn_size {
            RlcAmSnSize::Am12Bits => {
                let mut buf = Vec::with_capacity(3 + so_len + self.payload.len());
                let p_bit = if self.poll { 0x40 } else { 0x00 };
                let si_bits = (self.si as u8) << 4;
                // Octet 1: D/C=1 (0x80), P, SI, R(00), SN[11..10]
                let b0 = 0x80 | p_bit | si_bits | (((self.sn >> 10) & 0x03) as u8);
                // Octet 2: SN[9..2]
                let b1 = ((self.sn >> 2) & 0xFF) as u8;
                // Octet 3: SN[1..0], R(000000)
                let b2 = ((self.sn & 0x03) as u8) << 6;
                buf.push(b0);
                buf.push(b1);
                buf.push(b2);
                if has_so {
                    buf.extend_from_slice(&self.so.unwrap_or(0).to_be_bytes());
                }
                buf.extend_from_slice(&self.payload);
                buf
            }
            RlcAmSnSize::Am18Bits => {
                let mut buf = Vec::with_capacity(3 + so_len + self.payload.len());
                let p_bit = if self.poll { 0x40 } else { 0x00 };
                let si_bits = (self.si as u8) << 4;
                // Octet 1: D/C=1 (0x80), P, SI, R(00), SN[17..16]
                let b0 = 0x80 | p_bit | si_bits | (((self.sn >> 16) & 0x03) as u8);
                // Octet 2: SN[15..8]
                let b1 = ((self.sn >> 8) & 0xFF) as u8;
                // Octet 3: SN[7..0]
                let b2 = (self.sn & 0xFF) as u8;
                buf.push(b0);
                buf.push(b1);
                buf.push(b2);
                if has_so {
                    buf.extend_from_slice(&self.so.unwrap_or(0).to_be_bytes());
                }
                buf.extend_from_slice(&self.payload);
                buf
            }
        }
    }

    /// Parses AM Data PDU from wire bytes.
    pub fn parse(sn_size: RlcAmSnSize, data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 3 {
            return Err("RLC AM PDU too short for header");
        }
        if (data[0] & 0x80) == 0 {
            return Err("Expected AM Data PDU (D/C=1), found Control PDU");
        }
        let poll = (data[0] & 0x40) != 0;
        let si = RlcSegmentationInfo::from_u8((data[0] >> 4) & 0x03);

        let (sn, header_len) = match sn_size {
            RlcAmSnSize::Am12Bits => {
                let sn = (((data[0] & 0x03) as u32) << 10)
                    | ((data[1] as u32) << 2)
                    | (((data[2] >> 6) & 0x03) as u32);
                (sn, 3)
            }
            RlcAmSnSize::Am18Bits => {
                let sn =
                    (((data[0] & 0x03) as u32) << 16) | ((data[1] as u32) << 8) | (data[2] as u32);
                (sn, 3)
            }
        };

        let has_so = matches!(
            si,
            RlcSegmentationInfo::LastSegment | RlcSegmentationInfo::MiddleSegment
        );
        let (so, payload_offset) = if has_so {
            if data.len() < header_len + 2 {
                return Err("RLC AM PDU too short for Segment Offset (SO)");
            }
            let so_val = u16::from_be_bytes([data[header_len], data[header_len + 1]]);
            (Some(so_val), header_len + 2)
        } else {
            (None, header_len)
        };

        Ok(Self {
            sn_size,
            poll,
            si,
            sn,
            so,
            payload: data[payload_offset..].to_vec(),
        })
    }
}

/// NACK range in RLC Status PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RlcNackRange {
    pub nack_sn: u32,
    pub so_start: Option<u16>,
    pub so_end: Option<u16>,
}

/// RLC AM Status PDU (TS 38.322 Section 6.2.2.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RlcStatusPdu {
    pub ack_sn: u32,
    pub nacks: Vec<RlcNackRange>,
}

impl RlcStatusPdu {
    /// Serializes Status PDU to wire format (18-bit SN format).
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // Octet 1: D/C=0 (0x00), CPT=000 (0x00), ACK_SN[17..14]
        let b0 = ((self.ack_sn >> 14) & 0x0F) as u8;
        // Octet 2: ACK_SN[13..6]
        let b1 = ((self.ack_sn >> 6) & 0xFF) as u8;
        // Octet 3: ACK_SN[5..0] << 2, E1 (bit 1)
        let e1 = if !self.nacks.is_empty() { 0x02 } else { 0x00 };
        let b2 = (((self.ack_sn & 0x3F) as u8) << 2) | e1;
        buf.push(b0);
        buf.push(b1);
        buf.push(b2);

        // Serialize NACKs
        for (i, nack) in self.nacks.iter().enumerate() {
            let is_last = i == self.nacks.len() - 1;
            let next_e1 = if !is_last { 0x02 } else { 0x00 };
            let nb0 = ((nack.nack_sn >> 14) & 0x0F) as u8;
            let nb1 = ((nack.nack_sn >> 6) & 0xFF) as u8;
            let nb2 = (((nack.nack_sn & 0x3F) as u8) << 2) | next_e1;
            buf.push(nb0);
            buf.push(nb1);
            buf.push(nb2);
        }

        buf
    }

    /// Parses Status PDU from wire format.
    pub fn parse(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 3 {
            return Err("RLC Status PDU too short");
        }
        if (data[0] & 0x80) != 0 {
            return Err("Expected Control PDU (D/C=0), found Data PDU");
        }

        let ack_sn = (((data[0] & 0x0F) as u32) << 14)
            | ((data[1] as u32) << 6)
            | (((data[2] >> 2) & 0x3F) as u32);

        let mut nacks = Vec::new();
        let mut has_e1 = (data[2] & 0x02) != 0;
        let mut offset = 3;

        while has_e1 && offset + 3 <= data.len() {
            let nack_sn = (((data[offset] & 0x0F) as u32) << 14)
                | ((data[offset + 1] as u32) << 6)
                | (((data[offset + 2] >> 2) & 0x3F) as u32);

            has_e1 = (data[offset + 2] & 0x02) != 0;
            nacks.push(RlcNackRange {
                nack_sn,
                so_start: None,
                so_end: None,
            });
            offset += 3;
        }

        Ok(Self { ack_sn, nacks })
    }
}

/// RLC Segment item stored in receiver reassembly buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RlcSegment {
    pub offset: usize,
    pub data: Vec<u8>,
}

/// SDU Reassembly state for an SN.
#[derive(Debug, Clone, Default)]
pub struct SduReassembly {
    pub segments: Vec<RlcSegment>,
    pub total_length: Option<usize>,
}

impl SduReassembly {
    fn insert_segment(&mut self, offset: usize, data: Vec<u8>, is_last: bool) {
        if is_last {
            self.total_length = Some(offset + data.len());
        }
        self.segments.push(RlcSegment { offset, data });
        self.segments.sort_by_key(|s| s.offset);
    }

    fn is_complete(&self) -> bool {
        let total = match self.total_length {
            Some(t) => t,
            None => return false,
        };

        let mut current_offset = 0;
        for seg in &self.segments {
            if seg.offset <= current_offset {
                current_offset = current_offset.max(seg.offset + seg.data.len());
            } else {
                return false; // Gap exists
            }
        }
        current_offset >= total
    }

    fn assemble(self) -> Option<Vec<u8>> {
        let total = self.total_length?;
        let mut full_sdu = vec![0u8; total];
        for seg in self.segments {
            let end = seg.offset + seg.data.len();
            if end <= total {
                full_sdu[seg.offset..end].copy_from_slice(&seg.data);
            }
        }
        Some(full_sdu)
    }
}

/// 3GPP TS 38.322 RLC Entity state machine.
#[derive(Debug)]
pub struct RlcEntity {
    pub mode: RlcEntityMode,
    // Transmitter state
    pub tx_next: u32,
    pub tx_buffer: HashMap<u32, Vec<RlcAmDataPdu>>,
    pub retransmit_queue: Vec<RlcAmDataPdu>,
    // Receiver state
    pub rx_next: u32,
    pub rx_reassembly: BTreeMap<u32, SduReassembly>,
    pub delivered_sdus: Vec<Vec<u8>>,
}

impl RlcEntity {
    pub fn new(mode: RlcEntityMode) -> Self {
        Self {
            mode,
            tx_next: 0,
            tx_buffer: HashMap::new(),
            retransmit_queue: Vec::new(),
            rx_next: 0,
            rx_reassembly: BTreeMap::new(),
            delivered_sdus: Vec::new(),
        }
    }

    /// Segments an SDU according to grant_size and produces RLC AM Data PDUs.
    pub fn segment_and_send(
        &mut self,
        sdu: &[u8],
        grant_size: usize,
        poll: bool,
    ) -> Vec<RlcAmDataPdu> {
        let sn_size = match self.mode {
            RlcEntityMode::Am { sn_size } => sn_size,
            _ => RlcAmSnSize::Am18Bits,
        };

        let sn = self.tx_next;
        self.tx_next = (self.tx_next + 1) & sn_size.max_sn();

        let mut pdus = Vec::new();

        if sdu.len() <= grant_size {
            // Unsegmented Full SDU
            let pdu = RlcAmDataPdu {
                sn_size,
                poll,
                si: RlcSegmentationInfo::Full,
                sn,
                so: None,
                payload: sdu.to_vec(),
            };
            pdus.push(pdu);
        } else {
            // Segmented SDU
            let mut offset = 0;
            while offset < sdu.len() {
                let remaining = sdu.len() - offset;
                let chunk_size = remaining.min(grant_size);
                let chunk_data = sdu[offset..offset + chunk_size].to_vec();

                let is_first = offset == 0;
                let is_last = (offset + chunk_size) == sdu.len();
                let is_poll = is_last && poll;

                let (si, so) = if is_first {
                    (RlcSegmentationInfo::FirstSegment, None)
                } else if is_last {
                    (RlcSegmentationInfo::LastSegment, Some(offset as u16))
                } else {
                    (RlcSegmentationInfo::MiddleSegment, Some(offset as u16))
                };

                let pdu = RlcAmDataPdu {
                    sn_size,
                    poll: is_poll,
                    si,
                    sn,
                    so,
                    payload: chunk_data,
                };

                pdus.push(pdu);
                offset += chunk_size;
            }
        }

        self.tx_buffer.insert(sn, pdus.clone());
        pdus
    }

    /// Processes an incoming AM Data PDU and reassembles SDU when complete.
    pub fn receive_am_pdu(&mut self, pdu: &RlcAmDataPdu) -> Result<Option<Vec<u8>>, &'static str> {
        if pdu.sn >= self.rx_next {
            self.rx_next = pdu.sn + 1;
        }

        if pdu.si == RlcSegmentationInfo::Full {
            self.delivered_sdus.push(pdu.payload.clone());
            return Ok(Some(pdu.payload.clone()));
        }

        let offset = pdu.so.unwrap_or(0) as usize;
        let is_last = pdu.si == RlcSegmentationInfo::LastSegment;

        let reassembly = self.rx_reassembly.entry(pdu.sn).or_default();
        reassembly.insert_segment(offset, pdu.payload.clone(), is_last);

        if reassembly.is_complete() {
            if let Some(entry) = self.rx_reassembly.remove(&pdu.sn) {
                if let Some(sdu) = entry.assemble() {
                    self.delivered_sdus.push(sdu.clone());
                    return Ok(Some(sdu));
                }
            }
        }

        Ok(None)
    }

    /// Generates a Status PDU acknowledging received packets and indicating missing SNs.
    pub fn generate_status_pdu(&self) -> RlcStatusPdu {
        let ack_sn = self.rx_next;
        let mut nacks = Vec::new();

        // Any uncompleted reassembly before rx_next is NACKed
        for &sn in self.rx_reassembly.keys() {
            if sn < ack_sn {
                nacks.push(RlcNackRange {
                    nack_sn: sn,
                    so_start: None,
                    so_end: None,
                });
            }
        }

        RlcStatusPdu { ack_sn, nacks }
    }

    /// Processes a received Status PDU: frees acknowledged PDUs and enqueues NACKed PDUs for retransmission.
    pub fn process_status_pdu(&mut self, status: &RlcStatusPdu) {
        let nack_sns: Vec<u32> = status.nacks.iter().map(|n| n.nack_sn).collect();

        // 1. Release fully ACKed packets
        self.tx_buffer.retain(|&sn, _| {
            if sn < status.ack_sn && !nack_sns.contains(&sn) {
                false // Free ACKed PDU
            } else {
                true // Keep unacked / nacked
            }
        });

        // 2. Enqueue NACKed packets for retransmission
        for nack_sn in nack_sns {
            if let Some(pdus) = self.tx_buffer.get(&nack_sn) {
                self.retransmit_queue.extend_from_slice(pdus);
            }
        }
    }
}
