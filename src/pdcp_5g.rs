//! 3GPP TS 38.323 5G NR Packet Data Convergence Protocol (PDCP) Engine.
//!
//! Implements Layer 2 PDCP convergence protocols for 5G NR:
//! - 12-bit & 18-bit Sequence Number framing and parsing
//! - 32-bit COUNT derivation and Hyper Frame Number (HFN) circular rollover
//! - In-order delivery sliding window with reordering buffer and deduplication
//! - Control PDU generation (PDCP Status Report with FMC and lost packet bitmap)

use std::collections::BTreeMap;

/// PDCP Sequence Number length configuration (TS 38.323 Section 6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdcpSnSize {
    Sn12Bits, // 12-bit SN: max 4095, window 2048 (SRB and voice DRB)
    Sn18Bits, // 18-bit SN: max 262143, window 131072 (High throughput eMBB DRB)
}

impl PdcpSnSize {
    #[inline]
    pub fn num_bits(&self) -> u32 {
        match self {
            PdcpSnSize::Sn12Bits => 12,
            PdcpSnSize::Sn18Bits => 18,
        }
    }

    #[inline]
    pub fn max_sn(&self) -> u32 {
        (1 << self.num_bits()) - 1
    }

    #[inline]
    pub fn window_size(&self) -> u32 {
        1 << (self.num_bits() - 1)
    }
}

/// Bearer type for PDCP entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdcpBearerType {
    Srb, // Signaling Radio Bearer
    Drb, // Data Radio Bearer
}

/// PDCP Data PDU representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdcpDataPdu {
    pub sn_size: PdcpSnSize,
    pub sn: u32,
    pub payload: Vec<u8>,
}

impl PdcpDataPdu {
    /// Serializes Data PDU into wire format.
    pub fn serialize(&self) -> Vec<u8> {
        match self.sn_size {
            PdcpSnSize::Sn12Bits => {
                let mut buf = Vec::with_capacity(2 + self.payload.len());
                // Octet 1: D/C=1 (1 bit), R=000 (3 bits), SN[11..8] (4 bits)
                let b0 = 0x80 | (((self.sn >> 8) & 0x0F) as u8);
                // Octet 2: SN[7..0]
                let b1 = (self.sn & 0xFF) as u8;
                buf.push(b0);
                buf.push(b1);
                buf.extend_from_slice(&self.payload);
                buf
            }
            PdcpSnSize::Sn18Bits => {
                let mut buf = Vec::with_capacity(3 + self.payload.len());
                // Octet 1: D/C=1 (1 bit), R=00000 (5 bits), SN[17..16] (2 bits)
                let b0 = 0x80 | (((self.sn >> 16) & 0x03) as u8);
                // Octet 2: SN[15..8]
                let b1 = ((self.sn >> 8) & 0xFF) as u8;
                // Octet 3: SN[7..0]
                let b2 = (self.sn & 0xFF) as u8;
                buf.push(b0);
                buf.push(b1);
                buf.push(b2);
                buf.extend_from_slice(&self.payload);
                buf
            }
        }
    }

    /// Parses Data PDU from wire format.
    pub fn parse(sn_size: PdcpSnSize, data: &[u8]) -> Result<Self, &'static str> {
        match sn_size {
            PdcpSnSize::Sn12Bits => {
                if data.len() < 2 {
                    return Err("PDCP 12-bit Data PDU too short");
                }
                // Verify D/C bit = 1
                if (data[0] & 0x80) == 0 {
                    return Err("Expected Data PDU, found Control PDU (D/C=0)");
                }
                let sn = (((data[0] & 0x0F) as u32) << 8) | (data[1] as u32);
                Ok(Self {
                    sn_size,
                    sn,
                    payload: data[2..].to_vec(),
                })
            }
            PdcpSnSize::Sn18Bits => {
                if data.len() < 3 {
                    return Err("PDCP 18-bit Data PDU too short");
                }
                // Verify D/C bit = 1
                if (data[0] & 0x80) == 0 {
                    return Err("Expected Data PDU, found Control PDU (D/C=0)");
                }
                let sn =
                    (((data[0] & 0x03) as u32) << 16) | ((data[1] as u32) << 8) | (data[2] as u32);
                Ok(Self {
                    sn_size,
                    sn,
                    payload: data[3..].to_vec(),
                })
            }
        }
    }
}

/// PDCP Control PDU (TS 38.323 Section 6.2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PdcpControlPdu {
    StatusReport {
        fmc: u32,        // First Missing COUNT (32-bit)
        bitmap: Vec<u8>, // Variable length bitmap
    },
}

impl PdcpControlPdu {
    /// Serializes Control PDU into wire format.
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            PdcpControlPdu::StatusReport { fmc, bitmap } => {
                let mut buf = Vec::with_capacity(5 + bitmap.len());
                // Octet 1: D/C=0 (1 bit), PDU Type=000 (3 bits), R=0000 (4 bits)
                buf.push(0x00);
                // Octet 2..5: FMC (32-bit big endian)
                buf.extend_from_slice(&fmc.to_be_bytes());
                // Bitmap
                buf.extend_from_slice(bitmap);
                buf
            }
        }
    }

    /// Parses Control PDU from wire format.
    pub fn parse(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 5 {
            return Err("PDCP Control PDU too short");
        }
        // Verify D/C bit = 0
        if (data[0] & 0x80) != 0 {
            return Err("Expected Control PDU, found Data PDU (D/C=1)");
        }
        let pdu_type = (data[0] >> 4) & 0x07;
        if pdu_type != 0 {
            return Err("Unsupported PDCP Control PDU type");
        }
        let fmc = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        let bitmap = data[5..].to_vec();
        Ok(PdcpControlPdu::StatusReport { fmc, bitmap })
    }
}

/// 3GPP TS 38.323 PDCP Entity state machine.
#[derive(Debug, Clone)]
pub struct PdcpEntity {
    pub bearer_type: PdcpBearerType,
    pub sn_size: PdcpSnSize,
    // Transmitter state variables
    pub tx_next: u32,
    // Receiver state variables
    pub rx_next: u32,
    pub rx_deliv: u32,
    pub rx_reord: u32,
    // Reordering buffer: COUNT -> SDU payload
    pub reordering_buffer: BTreeMap<u32, Vec<u8>>,
    // In-order delivered SDUs to upper layer
    pub delivered_sdus: Vec<Vec<u8>>,
    // Statistics
    pub transmitted_pdus: u64,
    pub received_pdus: u64,
    pub duplicate_pdus: u64,
}

impl PdcpEntity {
    pub fn new(bearer_type: PdcpBearerType, sn_size: PdcpSnSize) -> Self {
        Self {
            bearer_type,
            sn_size,
            tx_next: 0,
            rx_next: 0,
            rx_deliv: 0,
            rx_reord: 0,
            reordering_buffer: BTreeMap::new(),
            delivered_sdus: Vec::new(),
            transmitted_pdus: 0,
            received_pdus: 0,
            duplicate_pdus: 0,
        }
    }

    /// Transmits an SDU: assigns COUNT and produces a Data PDU.
    pub fn transmit_sdu(&mut self, sdu: Vec<u8>) -> PdcpDataPdu {
        let count = self.tx_next;
        let sn = count & self.sn_size.max_sn();

        self.tx_next = self.tx_next.wrapping_add(1);
        self.transmitted_pdus += 1;

        PdcpDataPdu {
            sn_size: self.sn_size,
            sn,
            payload: sdu,
        }
    }

    /// Derives 32-bit COUNT from received SN per TS 38.323 Section 5.2.2.1.
    pub fn derive_rx_count(&self, sn: u32) -> u32 {
        let sn_bits = self.sn_size.num_bits();
        let max_sn = self.sn_size.max_sn();
        let window = self.sn_size.window_size();

        let hfn = self.rx_next >> sn_bits;
        let next_sn = self.rx_next & max_sn;

        let derived_hfn = if sn + window < next_sn {
            hfn + 1
        } else if sn >= next_sn + window {
            if hfn > 0 { hfn - 1 } else { 0 }
        } else {
            hfn
        };

        (derived_hfn << sn_bits) | sn
    }

    /// Processes an incoming Data PDU: handles reordering, deduplication, and in-order delivery.
    pub fn receive_pdu(&mut self, pdu: &PdcpDataPdu) -> Result<(), &'static str> {
        let count = self.derive_rx_count(pdu.sn);
        self.received_pdus += 1;

        // Discard duplicates
        if count < self.rx_deliv || self.reordering_buffer.contains_key(&count) {
            self.duplicate_pdus += 1;
            return Ok(());
        }

        // Store SDU in reordering buffer
        self.reordering_buffer.insert(count, pdu.payload.clone());

        // Update RX_NEXT
        if count >= self.rx_next {
            self.rx_next = count + 1;
        }

        // Deliver consecutive in-order SDUs
        while let Some(sdu) = self.reordering_buffer.remove(&self.rx_deliv) {
            self.delivered_sdus.push(sdu);
            self.rx_deliv += 1;
        }

        // Advance RX_REORD if needed
        if self.rx_reord <= self.rx_deliv && self.rx_deliv < self.rx_next {
            self.rx_reord = self.rx_next;
        }

        Ok(())
    }

    /// Handles t-Reordering timer expiration: flushes reordering buffer up to rx_reord.
    pub fn handle_t_reordering_expiry(&mut self) {
        // Deliver all stored SDUs with COUNT < rx_reord
        let to_deliver: Vec<u32> = self
            .reordering_buffer
            .keys()
            .copied()
            .filter(|&c| c < self.rx_reord)
            .collect();

        for c in to_deliver {
            if let Some(sdu) = self.reordering_buffer.remove(&c) {
                self.delivered_sdus.push(sdu);
            }
        }

        self.rx_deliv = self.rx_reord;
        if self.rx_deliv < self.rx_next {
            self.rx_reord = self.rx_next;
        }
    }

    /// Generates a PDCP Status Report indicating missing gaps.
    pub fn generate_status_report(&self) -> Option<PdcpControlPdu> {
        if self.rx_deliv >= self.rx_next {
            return None; // No gaps to report
        }

        let fmc = self.rx_deliv;
        let total_bits = (self.rx_next - fmc - 1) as usize;
        let num_bytes = (total_bits + 7) / 8;
        let mut bitmap = vec![0u8; num_bytes];

        for i in 0..total_bits {
            let target_count = fmc + 1 + (i as u32);
            if self.reordering_buffer.contains_key(&target_count) {
                let byte_idx = i / 8;
                let bit_idx = 7 - (i % 8);
                bitmap[byte_idx] |= 1 << bit_idx;
            }
        }

        Some(PdcpControlPdu::StatusReport { fmc, bitmap })
    }
}
