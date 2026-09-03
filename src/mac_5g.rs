//! 3GPP TS 38.321 5G NR Medium Access Control (MAC) Engine.
//!
//! Implements the 5G NR Layer 2 MAC sublayer responsible for:
//! - MAC PDU framing with subheaders (R/F/LCID/L variable-length encoding)
//! - Logical Channel multiplexing (LCID 0..63) into Transport Blocks
//! - MAC Control Elements (CEs): BSR, C-RNTI, Timing Advance, PHR, Padding
//! - HARQ entity with configurable number of processes
//! - Uplink grant-based PDU assembly and downlink PDU demultiplexing

// ---------------------------------------------------------------------------
// Constants (TS 38.321 Table 6.2.1-1, 6.2.1-2)
// ---------------------------------------------------------------------------

/// Reserved LCID for Padding in DL-SCH.
pub const MAC_LCID_PADDING: u8 = 63;

/// LCID for C-RNTI MAC CE (UL-SCH, Table 6.2.1-2).
pub const MAC_LCID_CRNTI: u8 = 58;

/// LCID for Short BSR (Buffer Status Report) MAC CE (UL-SCH).
pub const MAC_LCID_SHORT_BSR: u8 = 59;

/// LCID for Long BSR MAC CE (UL-SCH).
pub const MAC_LCID_LONG_BSR: u8 = 60;

/// LCID for Short Truncated BSR MAC CE (UL-SCH).
pub const MAC_LCID_SHORT_TRUNC_BSR: u8 = 61;

/// LCID for Long Truncated BSR MAC CE (UL-SCH).
pub const MAC_LCID_LONG_TRUNC_BSR: u8 = 62;

/// LCID for Timing Advance Command MAC CE (DL-SCH, Table 6.2.1-1).
pub const MAC_LCID_TA_CMD: u8 = 61;

/// LCID for DRX Command MAC CE (DL-SCH).
pub const MAC_LCID_DRX_CMD: u8 = 60;

/// LCID for UE Contention Resolution Identity (DL-SCH).
pub const MAC_LCID_CONTENTION_RESOLUTION: u8 = 59;

/// LCID for Single Entry PHR MAC CE (UL-SCH).
pub const MAC_LCID_SINGLE_ENTRY_PHR: u8 = 57;

/// Maximum number of HARQ processes in 5G NR (TS 38.321 Section 5.4).
pub const MAC_MAX_HARQ_PROCESSES: usize = 16;

/// Maximum number of logical channels (LCID 0..32 for DTCH/DCCH).
pub const MAC_MAX_LOGICAL_CHANNELS: usize = 33;

// ---------------------------------------------------------------------------
// MAC Subheader (TS 38.321 Section 6.1.2)
// ---------------------------------------------------------------------------

/// MAC Subheader framing format.
///
/// Fixed-size subheader (1 byte, no L field): used for MAC CEs with known
/// fixed sizes and for padding.
///
/// Variable-size subheader (2 or 3 bytes): R/F/LCID/L where:
/// - R: Reserved (1 bit, always 0)
/// - F: Format (1 bit): 0 = 8-bit L field, 1 = 16-bit L field
/// - LCID: Logical Channel ID (6 bits)
/// - L: Length of MAC SDU or MAC CE payload
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacSubheader {
    /// Logical Channel ID (6 bits: 0..63).
    pub lcid: u8,
    /// Length of the associated MAC SDU or MAC CE payload.
    /// `None` for fixed-size MAC CEs (padding, DRX, etc.) where L is implicit.
    pub length: Option<u16>,
}

impl MacSubheader {
    /// Encode this subheader to wire bytes.
    ///
    /// Returns 1, 2, or 3 bytes depending on the presence and size of L.
    pub fn to_bytes(&self) -> Vec<u8> {
        let lcid_bits = self.lcid & 0x3F;
        match self.length {
            None => {
                // Fixed-size: 1 byte = R(0) | F(0) | LCID
                vec![lcid_bits]
            }
            Some(len) if len <= 255 => {
                // 8-bit L: R(0) | F(0) | LCID, then L (1 byte)
                vec![lcid_bits, len as u8]
            }
            Some(len) => {
                // 16-bit L: R(0) | F(1) | LCID, then L (2 bytes, big-endian)
                let first = 0x40 | lcid_bits; // F=1
                vec![first, (len >> 8) as u8, (len & 0xFF) as u8]
            }
        }
    }

    /// Decode a MAC subheader from a byte slice starting at `offset`.
    ///
    /// Returns `(subheader, bytes_consumed)` or `None` if parsing fails.
    pub fn from_bytes(data: &[u8], offset: usize) -> Option<(Self, usize)> {
        if offset >= data.len() {
            return None;
        }
        let first = data[offset];
        let f_bit = (first & 0x40) != 0;
        let lcid = first & 0x3F;

        // Check if this is a fixed-size subheader (padding, certain CEs)
        if lcid == MAC_LCID_PADDING || lcid == MAC_LCID_DRX_CMD {
            return Some((MacSubheader { lcid, length: None }, 1));
        }

        if f_bit {
            // 16-bit L field
            if offset + 3 > data.len() {
                return None;
            }
            let len = ((data[offset + 1] as u16) << 8) | (data[offset + 2] as u16);
            Some((
                MacSubheader {
                    lcid,
                    length: Some(len),
                },
                3,
            ))
        } else {
            // 8-bit L field
            if offset + 2 > data.len() {
                return None;
            }
            let len = data[offset + 1] as u16;
            Some((
                MacSubheader {
                    lcid,
                    length: Some(len),
                },
                2,
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// MAC SDU and MAC CE types
// ---------------------------------------------------------------------------

/// A single element within a MAC PDU: either an SDU (RLC payload on a
/// logical channel) or a MAC Control Element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacPduElement {
    /// MAC SDU: payload from RLC on a given logical channel.
    Sdu { lcid: u8, payload: Vec<u8> },
    /// Short BSR (Buffer Status Report): 1 byte = LCG ID (2 bits) + Buffer Size (6 bits).
    ShortBsr { lcg_id: u8, buffer_size_index: u8 },
    /// Long BSR: reports buffer status for all 8 Logical Channel Groups.
    /// Each entry is a 6-bit buffer size index (0..63).
    LongBsr { buffer_sizes: [u8; 8] },
    /// C-RNTI MAC CE: carries the UE's C-RNTI (2 bytes).
    CRnti { c_rnti: u16 },
    /// Timing Advance Command MAC CE (DL): TAG ID (2 bits) + TA Command (6 bits).
    TimingAdvanceCommand { tag_id: u8, ta_command: u8 },
    /// Single Entry PHR (Power Headroom Report): PH (6 bits) + PCmax,f,c (6 bits).
    SingleEntryPhr { power_headroom: u8, pcmax: u8 },
    /// Padding bytes.
    Padding { length: usize },
}

impl MacPduElement {
    /// Get the LCID for this element.
    pub fn lcid(&self) -> u8 {
        match self {
            MacPduElement::Sdu { lcid, .. } => *lcid,
            MacPduElement::ShortBsr { .. } => MAC_LCID_SHORT_BSR,
            MacPduElement::LongBsr { .. } => MAC_LCID_LONG_BSR,
            MacPduElement::CRnti { .. } => MAC_LCID_CRNTI,
            MacPduElement::TimingAdvanceCommand { .. } => MAC_LCID_TA_CMD,
            MacPduElement::SingleEntryPhr { .. } => MAC_LCID_SINGLE_ENTRY_PHR,
            MacPduElement::Padding { .. } => MAC_LCID_PADDING,
        }
    }

    /// Encode just the payload (CE body or SDU bytes) — not including subheader.
    pub fn payload_bytes(&self) -> Vec<u8> {
        match self {
            MacPduElement::Sdu { payload, .. } => payload.clone(),
            MacPduElement::ShortBsr {
                lcg_id,
                buffer_size_index,
            } => {
                // 1 byte: LCG ID (bits 7-6) | Buffer Size Index (bits 5-0)
                vec![((lcg_id & 0x03) << 6) | (buffer_size_index & 0x3F)]
            }
            MacPduElement::LongBsr { buffer_sizes } => {
                // LCG bitmap (1 byte) + buffer size entries
                // Encode all 8 LCGs as present (bitmap = 0xFF) for simplicity
                let mut buf = vec![0xFF_u8]; // all 8 LCGs present
                // Pack 6-bit values: for simplicity, encode each as 1 byte (truncated)
                for &bs in buffer_sizes.iter() {
                    buf.push(bs & 0x3F);
                }
                buf
            }
            MacPduElement::CRnti { c_rnti } => {
                vec![(*c_rnti >> 8) as u8, (*c_rnti & 0xFF) as u8]
            }
            MacPduElement::TimingAdvanceCommand { tag_id, ta_command } => {
                // 1 byte: TAG ID (bits 7-6) | TA Command (bits 5-0)
                vec![((tag_id & 0x03) << 6) | (ta_command & 0x3F)]
            }
            MacPduElement::SingleEntryPhr {
                power_headroom,
                pcmax,
            } => {
                // 2 bytes: R(2) + PH(6), R(2) + PCmax(6)
                vec![power_headroom & 0x3F, pcmax & 0x3F]
            }
            MacPduElement::Padding { length } => {
                vec![0x00; *length]
            }
        }
    }
}

// ---------------------------------------------------------------------------
// MAC PDU (Transport Block) (TS 38.321 Section 6.1.2)
// ---------------------------------------------------------------------------

/// A MAC PDU (Transport Block) consisting of one or more MAC subPDUs.
///
/// Each subPDU = MAC subheader + MAC SDU or MAC CE.
/// The last subPDU in a MAC PDU may be padding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacPdu {
    pub elements: Vec<MacPduElement>,
}

impl MacPdu {
    /// Create an empty MAC PDU.
    pub fn new() -> Self {
        MacPdu {
            elements: Vec::new(),
        }
    }

    /// Add an element (SDU or CE) to the MAC PDU.
    pub fn add_element(&mut self, element: MacPduElement) {
        self.elements.push(element);
    }

    /// Serialize the complete MAC PDU to wire bytes (Transport Block).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for elem in &self.elements {
            let payload = elem.payload_bytes();
            let subhdr = MacSubheader {
                lcid: elem.lcid(),
                length: match elem {
                    MacPduElement::Padding { .. } => None,
                    _ => Some(payload.len() as u16),
                },
            };
            buf.extend_from_slice(&subhdr.to_bytes());
            buf.extend_from_slice(&payload);
        }
        buf
    }

    /// Parse a MAC PDU from a Transport Block byte slice.
    ///
    /// Returns the parsed MAC PDU or `None` if framing is invalid.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let mut pdu = MacPdu::new();
        let mut offset = 0;

        while offset < data.len() {
            let (subhdr, hdr_len) = MacSubheader::from_bytes(data, offset)?;
            offset += hdr_len;

            if subhdr.lcid == MAC_LCID_PADDING {
                // Remaining bytes are padding
                let pad_len = data.len() - offset;
                pdu.add_element(MacPduElement::Padding { length: pad_len });
                break;
            }

            let payload_len = subhdr.length? as usize;
            if offset + payload_len > data.len() {
                return None; // truncated
            }
            let payload = data[offset..offset + payload_len].to_vec();
            offset += payload_len;

            let element = match subhdr.lcid {
                MAC_LCID_SHORT_BSR => {
                    if payload.len() < 1 {
                        return None;
                    }
                    MacPduElement::ShortBsr {
                        lcg_id: (payload[0] >> 6) & 0x03,
                        buffer_size_index: payload[0] & 0x3F,
                    }
                }
                MAC_LCID_CRNTI => {
                    if payload.len() < 2 {
                        return None;
                    }
                    MacPduElement::CRnti {
                        c_rnti: ((payload[0] as u16) << 8) | (payload[1] as u16),
                    }
                }
                MAC_LCID_TA_CMD => {
                    if payload.len() < 1 {
                        return None;
                    }
                    MacPduElement::TimingAdvanceCommand {
                        tag_id: (payload[0] >> 6) & 0x03,
                        ta_command: payload[0] & 0x3F,
                    }
                }
                MAC_LCID_SINGLE_ENTRY_PHR => {
                    if payload.len() < 2 {
                        return None;
                    }
                    MacPduElement::SingleEntryPhr {
                        power_headroom: payload[0] & 0x3F,
                        pcmax: payload[1] & 0x3F,
                    }
                }
                lcid if lcid <= 32 => {
                    // Logical channel SDU (LCID 0..32)
                    MacPduElement::Sdu { lcid, payload }
                }
                _ => {
                    // Unknown LCID — treat as SDU for forward compatibility
                    MacPduElement::Sdu {
                        lcid: subhdr.lcid,
                        payload,
                    }
                }
            };
            pdu.add_element(element);
        }
        Some(pdu)
    }
}

impl Default for MacPdu {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Buffer Status Report Table (TS 38.321 Table 6.1.3.1-1)
// ---------------------------------------------------------------------------

/// Convert a buffer size in bytes to a BSR index (0..63).
/// Uses a simplified logarithmic mapping per TS 38.321 Table 6.1.3.1-1.
pub fn bytes_to_bsr_index(bytes: u32) -> u8 {
    if bytes == 0 {
        return 0;
    }
    // Simplified: map logarithmically into 6-bit range
    // Real table has 64 entries; we use a logarithmic approximation
    let log_val = (bytes as f64).log2();
    let index = ((log_val / 20.0) * 63.0) as u8;
    if index > 63 { 63 } else { index }
}

// ---------------------------------------------------------------------------
// Logical Channel Prioritization (LCP) (TS 38.321 Section 5.4.3.1)
// ---------------------------------------------------------------------------

/// Logical Channel priority configuration for UL scheduling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogicalChannelConfig {
    /// LCID (0..32).
    pub lcid: u8,
    /// Priority (1 = highest, 16 = lowest).
    pub priority: u8,
    /// Prioritized Bit Rate (PBR) in bytes per TTI.
    /// 0 means no guaranteed rate.
    pub pbr_bytes_per_tti: u32,
    /// Bucket Size Duration in TTIs.
    pub bucket_size_duration: u32,
}

/// State of a logical channel's token bucket for LCP.
#[derive(Debug, Clone)]
pub struct LogicalChannelState {
    pub config: LogicalChannelConfig,
    /// Current bucket level (in bytes). Replenished by PBR each TTI.
    pub bucket_bytes: i64,
    /// Pending data (bytes) queued from RLC for this channel.
    pub pending_data: u32,
}

impl LogicalChannelState {
    /// Create a new logical channel state.
    pub fn new(config: LogicalChannelConfig) -> Self {
        let initial_bucket = (config.pbr_bytes_per_tti * config.bucket_size_duration) as i64;
        LogicalChannelState {
            config,
            bucket_bytes: initial_bucket,
            pending_data: 0,
        }
    }

    /// Replenish the token bucket by one TTI's worth of PBR.
    pub fn replenish(&mut self) {
        let max_bucket = (self.config.pbr_bytes_per_tti * self.config.bucket_size_duration) as i64;
        self.bucket_bytes += self.config.pbr_bytes_per_tti as i64;
        if self.bucket_bytes > max_bucket {
            self.bucket_bytes = max_bucket;
        }
    }
}

// ---------------------------------------------------------------------------
// HARQ Process (TS 38.321 Section 5.4.1)
// ---------------------------------------------------------------------------

/// State of a HARQ process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HarqState {
    /// Idle: available for new transmission.
    Idle,
    /// Awaiting ACK/NACK from peer.
    WaitingForFeedback,
    /// NACK received, pending retransmission.
    PendingRetransmission,
}

/// A single HARQ process.
#[derive(Debug, Clone)]
pub struct HarqProcess {
    /// Process ID (0..15).
    pub process_id: u8,
    /// Current state.
    pub state: HarqState,
    /// Number of transmissions so far (initial TX = 1).
    pub tx_count: u8,
    /// Maximum retransmissions before declaring failure.
    pub max_retx: u8,
    /// New Data Indicator (NDI) — toggles on each new transport block.
    pub ndi: bool,
    /// Redundancy version for current transmission.
    pub redundancy_version: u8,
    /// Buffered transport block data (for retransmission).
    pub tb_data: Option<Vec<u8>>,
}

impl HarqProcess {
    /// Create a new idle HARQ process.
    pub fn new(process_id: u8, max_retx: u8) -> Self {
        HarqProcess {
            process_id,
            state: HarqState::Idle,
            tx_count: 0,
            max_retx,
            ndi: false,
            redundancy_version: 0,
            tb_data: None,
        }
    }

    /// Submit a new transport block for initial transmission.
    pub fn new_transmission(&mut self, tb: Vec<u8>) {
        self.ndi = !self.ndi; // Toggle NDI for new data
        self.tx_count = 1;
        self.redundancy_version = 0;
        self.tb_data = Some(tb);
        self.state = HarqState::WaitingForFeedback;
    }

    /// Process ACK feedback — release the HARQ buffer.
    pub fn receive_ack(&mut self) {
        self.state = HarqState::Idle;
        self.tb_data = None;
        self.tx_count = 0;
    }

    /// Process NACK feedback — schedule retransmission.
    /// Returns `true` if retransmission is possible, `false` if max retx exceeded.
    pub fn receive_nack(&mut self) -> bool {
        if self.tx_count >= self.max_retx {
            // Max retransmissions exceeded → declare failure, reset
            self.state = HarqState::Idle;
            self.tb_data = None;
            self.tx_count = 0;
            return false;
        }
        self.state = HarqState::PendingRetransmission;
        true
    }

    /// Perform retransmission — increment RV and tx count.
    /// Returns the transport block data for retransmission, or `None` if not pending.
    pub fn retransmit(&mut self) -> Option<Vec<u8>> {
        if self.state != HarqState::PendingRetransmission {
            return None;
        }
        self.tx_count += 1;
        // RV cycling: 0 → 2 → 3 → 1 → 0 (TS 38.214)
        self.redundancy_version = match self.redundancy_version {
            0 => 2,
            2 => 3,
            3 => 1,
            _ => 0,
        };
        self.state = HarqState::WaitingForFeedback;
        self.tb_data.clone()
    }
}

// ---------------------------------------------------------------------------
// MAC Entity (TS 38.321 Section 5)
// ---------------------------------------------------------------------------

/// The main MAC entity for a UE or gNB cell.
///
/// Manages logical channel multiplexing, HARQ processes, and MAC PDU
/// assembly/disassembly.
pub struct MacEntity {
    /// HARQ processes (up to 16).
    pub harq_processes: Vec<HarqProcess>,
    /// Logical channel configurations and states, indexed by LCID.
    pub logical_channels: Vec<Option<LogicalChannelState>>,
    /// Received MAC SDUs per logical channel: `(lcid, payload)`.
    pub received_sdus: Vec<(u8, Vec<u8>)>,
    /// Received MAC CEs for inspection/testing.
    pub received_ces: Vec<MacPduElement>,
}

impl MacEntity {
    /// Create a new MAC entity with the specified number of HARQ processes.
    pub fn new(num_harq_processes: usize, max_retx: u8) -> Self {
        let n = num_harq_processes.min(MAC_MAX_HARQ_PROCESSES);
        let harq_processes = (0..n)
            .map(|i| HarqProcess::new(i as u8, max_retx))
            .collect();
        let mut logical_channels = Vec::with_capacity(MAC_MAX_LOGICAL_CHANNELS);
        for _ in 0..MAC_MAX_LOGICAL_CHANNELS {
            logical_channels.push(None);
        }
        MacEntity {
            harq_processes,
            logical_channels,
            received_sdus: Vec::new(),
            received_ces: Vec::new(),
        }
    }

    /// Configure a logical channel.
    pub fn configure_logical_channel(&mut self, config: LogicalChannelConfig) {
        let lcid = config.lcid as usize;
        if lcid < MAC_MAX_LOGICAL_CHANNELS {
            self.logical_channels[lcid] = Some(LogicalChannelState::new(config));
        }
    }

    /// Enqueue data for a logical channel (from RLC).
    pub fn enqueue_data(&mut self, lcid: u8, data_bytes: u32) {
        let idx = lcid as usize;
        if idx < MAC_MAX_LOGICAL_CHANNELS {
            if let Some(ref mut lc) = self.logical_channels[idx] {
                lc.pending_data += data_bytes;
            }
        }
    }

    // -----------------------------------------------------------------------
    // Uplink: Logical Channel Prioritization + PDU Assembly
    // -----------------------------------------------------------------------

    /// Assemble an uplink MAC PDU from pending data using Logical Channel
    /// Prioritization (LCP) per TS 38.321 Section 5.4.3.1.
    ///
    /// `grant_bytes`: Total UL grant size in bytes (transport block size).
    ///
    /// Returns the assembled MAC PDU and the HARQ process ID used.
    /// Returns `None` if no HARQ process is available.
    pub fn assemble_ul_pdu(&mut self, grant_bytes: usize) -> Option<(u8, MacPdu)> {
        // Find an idle HARQ process
        let harq_idx = self
            .harq_processes
            .iter()
            .position(|h| h.state == HarqState::Idle)?;

        let mut pdu = MacPdu::new();
        let mut remaining = grant_bytes;

        // Collect active logical channels sorted by priority (ascending = higher prio)
        let mut active_lcids: Vec<u8> = Vec::new();
        for i in 0..MAC_MAX_LOGICAL_CHANNELS {
            if let Some(ref lc) = self.logical_channels[i] {
                if lc.pending_data > 0 {
                    active_lcids.push(i as u8);
                }
            }
        }
        active_lcids.sort_by_key(|&lcid| {
            self.logical_channels[lcid as usize]
                .as_ref()
                .map(|lc| lc.config.priority)
                .unwrap_or(255)
        });

        // Phase 1: Allocate up to PBR for each channel in priority order
        for &lcid in &active_lcids {
            let idx = lcid as usize;
            if remaining < 3 {
                break; // Need at least subheader (2 bytes) + 1 byte payload
            }
            if let Some(ref mut lc) = self.logical_channels[idx] {
                if lc.pending_data == 0 {
                    continue;
                }
                let pbr_allow = if lc.bucket_bytes > 0 {
                    lc.bucket_bytes as u32
                } else {
                    0
                };
                if pbr_allow == 0 {
                    continue;
                }
                let subhdr_overhead = if lc.pending_data.min(pbr_allow) <= 255 {
                    2
                } else {
                    3
                };
                let max_payload = remaining.saturating_sub(subhdr_overhead);
                if max_payload == 0 {
                    continue;
                }
                let serve = lc.pending_data.min(pbr_allow).min(max_payload as u32);
                if serve == 0 {
                    continue;
                }
                // Create dummy SDU payload (in real system, dequeue from RLC)
                let payload = vec![0xAA; serve as usize];
                let elem = MacPduElement::Sdu {
                    lcid,
                    payload: payload.clone(),
                };
                let actual_subhdr_len = if serve <= 255 { 2 } else { 3 };
                remaining -= actual_subhdr_len + serve as usize;
                lc.pending_data -= serve;
                lc.bucket_bytes -= serve as i64;
                pdu.add_element(elem);
            }
        }

        // Phase 2: Distribute remaining grant to channels with leftover data
        for &lcid in &active_lcids {
            let idx = lcid as usize;
            if remaining < 3 {
                break;
            }
            if let Some(ref mut lc) = self.logical_channels[idx] {
                if lc.pending_data == 0 {
                    continue;
                }
                let subhdr_overhead = if lc.pending_data <= 255 { 2 } else { 3 };
                let max_payload = remaining.saturating_sub(subhdr_overhead);
                if max_payload == 0 {
                    continue;
                }
                let serve = lc.pending_data.min(max_payload as u32);
                if serve == 0 {
                    continue;
                }
                let payload = vec![0xBB; serve as usize];
                let elem = MacPduElement::Sdu { lcid, payload };
                let actual_subhdr_len = if serve <= 255 { 2 } else { 3 };
                remaining -= actual_subhdr_len + serve as usize;
                lc.pending_data -= serve;
                pdu.add_element(elem);
            }
        }

        // Add padding if remaining space > 0
        if remaining > 0 {
            // Padding subheader = 1 byte, rest is zero-fill
            if remaining > 1 {
                pdu.add_element(MacPduElement::Padding {
                    length: remaining - 1,
                });
            } else {
                pdu.add_element(MacPduElement::Padding { length: 0 });
            }
        }

        // Serialize and submit to HARQ
        let tb = pdu.to_bytes();
        self.harq_processes[harq_idx].new_transmission(tb);

        Some((harq_idx as u8, pdu))
    }

    // -----------------------------------------------------------------------
    // Downlink: PDU Demultiplexing
    // -----------------------------------------------------------------------

    /// Demultiplex a received downlink MAC PDU (Transport Block).
    ///
    /// Parses all subPDUs and dispatches SDUs to the appropriate logical
    /// channels and processes MAC CEs.
    pub fn receive_dl_pdu(&mut self, tb: &[u8]) -> Option<MacPdu> {
        let pdu = MacPdu::from_bytes(tb)?;

        for elem in &pdu.elements {
            match elem {
                MacPduElement::Sdu { lcid, payload } => {
                    self.received_sdus.push((*lcid, payload.clone()));
                }
                MacPduElement::Padding { .. } => {
                    // Ignore padding
                }
                ce => {
                    self.received_ces.push(ce.clone());
                }
            }
        }
        Some(pdu)
    }

    /// Find the next HARQ process that needs retransmission.
    pub fn next_retransmission(&mut self) -> Option<(u8, Vec<u8>)> {
        for process in &mut self.harq_processes {
            if process.state == HarqState::PendingRetransmission {
                if let Some(tb) = process.retransmit() {
                    return Some((process.process_id, tb));
                }
            }
        }
        None
    }

    /// Replenish all logical channel token buckets (call once per TTI).
    pub fn tti_tick(&mut self) {
        for lc_opt in &mut self.logical_channels {
            if let Some(lc) = lc_opt {
                lc.replenish();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_subheader_8bit_length_roundtrip() {
        let subhdr = MacSubheader {
            lcid: 4,
            length: Some(100),
        };
        let wire = subhdr.to_bytes();
        assert_eq!(wire.len(), 2);
        assert_eq!(wire[0], 4); // R=0, F=0, LCID=4
        assert_eq!(wire[1], 100);

        let (parsed, consumed) = MacSubheader::from_bytes(&wire, 0).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(parsed, subhdr);
    }

    #[test]
    fn test_mac_subheader_16bit_length() {
        let subhdr = MacSubheader {
            lcid: 1,
            length: Some(1000),
        };
        let wire = subhdr.to_bytes();
        assert_eq!(wire.len(), 3);
        assert_eq!(wire[0], 0x40 | 1); // R=0, F=1, LCID=1
        assert_eq!(wire[1], (1000 >> 8) as u8);
        assert_eq!(wire[2], (1000 & 0xFF) as u8);

        let (parsed, consumed) = MacSubheader::from_bytes(&wire, 0).unwrap();
        assert_eq!(consumed, 3);
        assert_eq!(parsed, subhdr);
    }

    #[test]
    fn test_mac_subheader_padding_fixed() {
        let subhdr = MacSubheader {
            lcid: MAC_LCID_PADDING,
            length: None,
        };
        let wire = subhdr.to_bytes();
        assert_eq!(wire.len(), 1);
        assert_eq!(wire[0], 63);

        let (parsed, consumed) = MacSubheader::from_bytes(&wire, 0).unwrap();
        assert_eq!(consumed, 1);
        assert_eq!(parsed, subhdr);
    }
}
