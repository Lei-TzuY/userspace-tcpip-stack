//! 3GPP Release 18/19 5G-Advanced Paging Occasion (PO/PF) Calculation, DCI Format 1_0 Short Message & Subgrouping Engine.
//!
//! Standards Reference:
//! - 3GPP TS 38.304 Rel-18 §7.1: Discontinuous Reception (DRX) for paging, Paging Frame (PF), and Paging Occasion (PO) formulas.
//! - 3GPP TS 38.304 Rel-18 §7.4: Rel-17/18 Paging Subgrouping and Early Indication (PEI) support.
//! - 3GPP TS 38.212 Rel-18 §7.3.1.2.1: DCI Format 1_0 with P-RNTI (`0xFFFE`) and Short Message multiplexing.
//! - 3GPP TS 38.213 Rel-18 §4.1: PDCCH monitoring occasions for paging.
//! - 3GPP TS 38.331 Rel-18 §6.2.2: RRC Paging message with 5G-S-TMSI and Full I-RNTI records.
//!
//! Features:
//! 1. Full DRX paging configuration ($T \in \{32, 64, 128, 256\}$ frames) and parameter scaling.
//! 2. Exact Paging Frame (PF) validation: $(SFN + \text{PF\_offset}) \bmod T = (T / N) \cdot (UE\_ID \bmod N)$.
//! 3. Paging Occasion (PO) index determination: $i_s = \lfloor UE\_ID / N \rfloor \bmod N_s$.
//! 4. Next PF/PO prediction engine handling 1024-frame SFN wrap-around.
//! 5. Rel-18 Paging Subgrouping: $\text{subgroupId} = \lfloor UE\_ID / (N \cdot N_s) \rfloor \bmod N_{\text{subgroups}}$.
//! 6. DCI Format 1_0 Short Message encoder/decoder (P-RNTI `0xFFFE`, SI Modification, ETWS/CMAS, StopPagingMonitoring).
//! 7. RRC PagingRecord processing and UE identity matching (5G-S-TMSI / Full I-RNTI).
//! 8. Binary wire framing (`PagingWirePdu`) with magic `0x50414745` ("PAGE") and CRC-16 CCITT validation.

use std::fmt;

// ---------------------------------------------------------------------------
// Constants & Error Definitions
// ---------------------------------------------------------------------------

/// Magic bytes for Paging Wire PDU: "PAGE" (0x50414745).
pub const PAGE_WIRE_MAGIC: u32 = 0x50414745;

/// Standard CRC-16 CCITT polynomial.
pub const CRC16_CCITT_POLY: u16 = 0x1021;

/// Standard P-RNTI value (0xFFFE).
pub const P_RNTI: u16 = 0xFFFE;

/// Maximum 5G System Frame Number (1024 frames: 0..1023).
pub const MAX_SFN: u16 = 1024;

/// Short Message bit flags (TS 38.212 §7.3.1.2.1).
pub const SHORT_MSG_SYS_INFO_MOD: u8 = 0x01;
pub const SHORT_MSG_ETWS_CMAS_IND: u8 = 0x02;
pub const SHORT_MSG_STOP_PAGING_MON: u8 = 0x04;

/// Errors encountered in Paging processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PagingError {
    InvalidDrxCycle(u16),
    InvalidNParameter { n: u16, t: u16 },
    InvalidNsParameter(u8),
    InvalidPfOffset { offset: u16, t: u16 },
    InvalidSfn(u16),
    InvalidSubgroupCount(u8),
    InvalidWireMagic(u32),
    WirePayloadTooShort { needed: usize, found: usize },
    WireCrcMismatch { expected: u16, computed: u16 },
}

impl fmt::Display for PagingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDrxCycle(t) => write!(f, "Invalid DRX cycle T: {} frames (must be 32, 64, 128, or 256)", t),
            Self::InvalidNParameter { n, t } => {
                write!(f, "Invalid N: {} for DRX cycle T: {} (must divide T evenly)", n, t)
            }
            Self::InvalidNsParameter(ns) => write!(f, "Invalid Ns: {} (must be 1, 2, or 4)", ns),
            Self::InvalidPfOffset { offset, t } => {
                write!(f, "Invalid PF offset: {} (must be < T: {})", offset, t)
            }
            Self::InvalidSfn(sfn) => write!(f, "Invalid SFN: {} (must be < 1024)", sfn),
            Self::InvalidSubgroupCount(c) => write!(f, "Invalid subgroup count: {} (must be 1, 2, 4, or 8)", c),
            Self::InvalidWireMagic(m) => write!(f, "Invalid wire magic: 0x{:08X}", m),
            Self::WirePayloadTooShort { needed, found } => {
                write!(f, "Wire payload too short: needed {} bytes, found {}", needed, found)
            }
            Self::WireCrcMismatch { expected, computed } => {
                write!(f, "Wire CRC-16 mismatch: expected 0x{:04X}, computed 0x{:04X}", expected, computed)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Paging DRX & Cell/UE Configuration (TS 38.304 §7.1)
// ---------------------------------------------------------------------------

/// Paging DRX Cycle in radio frames ($T \in \{32, 64, 128, 256\}$).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PagingDrxCycle {
    Rf32 = 32,
    Rf64 = 64,
    Rf128 = 128,
    Rf256 = 256,
}

impl PagingDrxCycle {
    #[inline]
    pub fn frames(self) -> u16 {
        self as u16
    }
}

/// Number of Paging Occasions per Paging Frame ($N_s \in \{1, 2, 4\}$).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumberOfPagingOccasions {
    One = 1,
    Two = 2,
    Four = 4,
}

/// Paging Configuration broadcast in SIB1 (`PagingCycle`, `nAndPagingFrameOffset`, `ns`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PagingConfig {
    /// DRX cycle $T$ in frames.
    pub drx_cycle: PagingDrxCycle,
    /// $N$: Number of total paging frames in cycle $T$. Must divide $T$.
    pub n: u16,
    /// Number of paging occasions in a PF ($N_s \in \{1, 2, 4\}$).
    pub ns: NumberOfPagingOccasions,
    /// Paging Frame offset $\in [0, T-1]$ (introduced for load balancing).
    pub pf_offset: u16,
}

impl PagingConfig {
    pub fn new(
        drx_cycle: PagingDrxCycle,
        n: u16,
        ns: NumberOfPagingOccasions,
        pf_offset: u16,
    ) -> Result<Self, PagingError> {
        let t = drx_cycle.frames();
        if n == 0 || t % n != 0 || n > t {
            return Err(PagingError::InvalidNParameter { n, t });
        }
        if pf_offset >= t {
            return Err(PagingError::InvalidPfOffset { offset: pf_offset, t });
        }
        Ok(Self {
            drx_cycle,
            n,
            ns,
            pf_offset,
        })
    }
}

// ---------------------------------------------------------------------------
// UE Paging Identity & Formulas (TS 38.304 §7.1)
// ---------------------------------------------------------------------------

/// 5G UE Paging Identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UePagingIdentity {
    /// 48-bit 5G-S-TMSI (AMF Set ID: 10 bits, AMF Pointer: 6 bits, 5G-TMSI: 32 bits).
    Ng5gSTmsi(u64),
    /// 40-bit Full I-RNTI (for RRC_INACTIVE state).
    FullIRnti(u64),
}

impl UePagingIdentity {
    /// Computes $UE\_ID = 5G\text{-S-TMSI} \bmod 1024$ (or $\text{Full I-RNTI} \bmod 1024$).
    #[inline]
    pub fn ue_id(&self) -> u16 {
        match self {
            Self::Ng5gSTmsi(val) => (val % 1024) as u16,
            Self::FullIRnti(val) => (val % 1024) as u16,
        }
    }
}

/// Evaluates whether the given `sfn` is a Paging Frame (PF) for the UE:
/// $(SFN + \text{PF\_offset}) \bmod T = (T / N) \cdot (UE\_ID \bmod N)$.
pub fn is_paging_frame(sfn: u16, config: &PagingConfig, ue_id: u16) -> bool {
    let t = config.drx_cycle.frames();
    let n = config.n;
    let lhs = (sfn + config.pf_offset) % t;
    let rhs = (t / n) * (ue_id % n);
    lhs == rhs
}

/// Computes Paging Occasion (PO) index $i_s \in \{0, \dots, N_s - 1\}$:
/// $i_s = \lfloor UE\_ID / N \rfloor \bmod N_s$.
pub fn compute_po_index(config: &PagingConfig, ue_id: u16) -> u8 {
    let n = config.n;
    let ns = config.ns as u16;
    ((ue_id / n) % ns) as u8
}

/// Finds the next Paging Frame SFN $\ge \text{current\_sfn}$ (handling 1024-frame wrap-around):
/// Returns `(next_pf_sfn, po_index)`.
pub fn next_paging_frame(
    current_sfn: u16,
    config: &PagingConfig,
    ue_id: u16,
) -> (u16, u8) {
    let t = config.drx_cycle.frames();
    let n = config.n;
    let target_mod = ((t / n) * (ue_id % n)) % t;
    let po_index = compute_po_index(config, ue_id);

    for delta in 0..MAX_SFN {
        let candidate_sfn = (current_sfn + delta) % MAX_SFN;
        let sfn_mod = (candidate_sfn + config.pf_offset) % t;
        if sfn_mod == target_mod {
            return (candidate_sfn, po_index);
        }
    }

    // Default fallback
    (current_sfn, po_index)
}

// ---------------------------------------------------------------------------
// Rel-18 Paging Subgrouping (TS 38.304 §7.4)
// ---------------------------------------------------------------------------

/// Computes UE Subgroup ID to avoid unnecessary wake-ups:
/// $\text{subgroupId} = \lfloor UE\_ID / (N \cdot N_s) \rfloor \bmod N_{\text{subgroups}}$.
pub fn compute_paging_subgroup_id(
    config: &PagingConfig,
    ue_id: u16,
    n_subgroups: u8,
) -> Result<u8, PagingError> {
    if n_subgroups == 0 || (n_subgroups & (n_subgroups - 1)) != 0 || n_subgroups > 8 {
        return Err(PagingError::InvalidSubgroupCount(n_subgroups));
    }
    let denominator = config.n * (config.ns as u16);
    let subgroup_id = ((ue_id / denominator) % (n_subgroups as u16)) as u8;
    Ok(subgroup_id)
}

// ---------------------------------------------------------------------------
// DCI Format 1_0 with P-RNTI & Short Message (TS 38.212 §7.3.1.2.1)
// ---------------------------------------------------------------------------

/// Short Message Indicator (2 bits) in DCI Format 1_0 with P-RNTI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShortMessageIndicator {
    SchedulingOnly = 1,
    ShortMessageOnly = 2,
    BothSchedulingAndShortMessage = 3,
}

/// DCI Format 1_0 Short Message Payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShortMessage {
    /// Bit 1: System Information modification.
    pub system_info_modification: bool,
    /// Bit 2: ETWS and CMAS notification.
    pub etws_cmas_indication: bool,
    /// Bit 3: Stop paging monitoring (for eDRX / RedCap power saving).
    pub stop_paging_monitoring: bool,
}

impl ShortMessage {
    pub fn to_byte(self) -> u8 {
        let mut byte = 0u8;
        if self.system_info_modification {
            byte |= SHORT_MSG_SYS_INFO_MOD;
        }
        if self.etws_cmas_indication {
            byte |= SHORT_MSG_ETWS_CMAS_IND;
        }
        if self.stop_paging_monitoring {
            byte |= SHORT_MSG_STOP_PAGING_MON;
        }
        byte
    }

    pub fn from_byte(byte: u8) -> Self {
        Self {
            system_info_modification: (byte & SHORT_MSG_SYS_INFO_MOD) != 0,
            etws_cmas_indication: (byte & SHORT_MSG_ETWS_CMAS_IND) != 0,
            stop_paging_monitoring: (byte & SHORT_MSG_STOP_PAGING_MON) != 0,
        }
    }
}

// ---------------------------------------------------------------------------
// RRC Paging Record & Filtering (TS 38.331 §6.2.2)
// ---------------------------------------------------------------------------

/// Paging Cause indicated in RRC Paging Record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PagingCause {
    Voice,
    Data,
    Signaling,
    Emergency,
}

/// RRC Paging Record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PagingRecord {
    pub ue_identity: UePagingIdentity,
    pub paging_cause: PagingCause,
}

/// Checks if a list of PagingRecords contains a page for the UE.
pub fn check_paging_records(records: &[PagingRecord], my_identity: UePagingIdentity) -> Option<PagingCause> {
    for rec in records {
        if rec.ue_identity == my_identity {
            return Some(rec.paging_cause);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// CRC-16 CCITT for Wire Framing
// ---------------------------------------------------------------------------

pub fn compute_crc16(data: &[u8]) -> u16 {
    let mut crc = 0xFFFFu16;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            if (crc & 0x8000) != 0 {
                crc = (crc << 1) ^ CRC16_CCITT_POLY;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

// ---------------------------------------------------------------------------
// Binary Wire Framing (`PagingWirePdu`)
// ---------------------------------------------------------------------------

/// Wire PDU transporting paging frame allocation and DCI short message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PagingWirePdu {
    pub sfn: u16,
    pub po_index: u8,
    pub ue_identity_raw: u64,
    pub short_message: u8,
    pub subgroup_id: u8,
}

impl PagingWirePdu {
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(18);
        buf.extend_from_slice(&PAGE_WIRE_MAGIC.to_be_bytes());
        buf.extend_from_slice(&self.sfn.to_be_bytes());
        buf.push(self.po_index);
        buf.extend_from_slice(&self.ue_identity_raw.to_be_bytes());
        buf.push(self.short_message);
        buf.push(self.subgroup_id);

        let crc = compute_crc16(&buf);
        buf.extend_from_slice(&crc.to_be_bytes());
        buf
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, PagingError> {
        if bytes.len() < 19 {
            return Err(PagingError::WirePayloadTooShort {
                needed: 19,
                found: bytes.len(),
            });
        }
        let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != PAGE_WIRE_MAGIC {
            return Err(PagingError::InvalidWireMagic(magic));
        }

        let body_len = bytes.len() - 2;
        let expected_crc = u16::from_be_bytes([bytes[body_len], bytes[body_len + 1]]);
        let computed_crc = compute_crc16(&bytes[..body_len]);
        if expected_crc != computed_crc {
            return Err(PagingError::WireCrcMismatch {
                expected: expected_crc,
                computed: computed_crc,
            });
        }

        let sfn = u16::from_be_bytes([bytes[4], bytes[5]]);
        let po_index = bytes[6];
        let ue_identity_raw = u64::from_be_bytes([
            bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14],
        ]);
        let short_message = bytes[15];
        let subgroup_id = bytes[16];

        Ok(Self {
            sfn,
            po_index,
            ue_identity_raw,
            short_message,
            subgroup_id,
        })
    }
}
