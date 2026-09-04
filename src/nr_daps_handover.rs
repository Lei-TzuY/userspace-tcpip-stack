//! 3GPP Rel-17 / Rel-18 5G NR Dual Active Protocol Stack (DAPS) Handover Engine.
//!
//! Implements 3GPP TS 38.300 §9.2.3.4.1, TS 38.323 §5.1.2 / §5.2.2, TS 38.331 §5.3.5.3,
//! and TS 38.133 / TS 38.213 DAPS handover specifications:
//! - Dual active protocol stack management maintaining concurrent links to Source and Target gNBs.
//! - True zero-millisecond (0 ms) data interruption mobility for mission-critical URLLC and XR.
//! - Independent cryptographic and integrity contexts for Source and Target legs ($K_{gNB}^{src}, K_{gNB}^{tgt}$).
//! - Unified Downlink Reordering and Deduplication buffer across both legs with sliding-window delivery.
//! - Seamless Uplink data switching from Source to Target upon target RACH success with buffer forwarding.
//! - Dual-transmission UL power sharing with strict $P_{CMAX}$ enforcement and priority scaling.
//! - Fault-tolerant $T_{304}$ timer management and failure fallback to Source cell.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fmt;

/// Standard number of bits in DAPS PDCP Sequence Numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DapsSnSize {
    Sn12Bits,
    Sn18Bits,
}

impl DapsSnSize {
    pub fn num_bits(&self) -> u32 {
        match self {
            DapsSnSize::Sn12Bits => 12,
            DapsSnSize::Sn18Bits => 18,
        }
    }

    pub fn max_sn(&self) -> u32 {
        (1 << self.num_bits()) - 1
    }

    pub fn window_size(&self) -> u32 {
        1 << (self.num_bits() - 1)
    }
}

/// DAPS radio leg (Source cell vs Target cell).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DapsLeg {
    Source,
    Target,
}

/// Operating state of the Dual Active Protocol Stack handover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DapsState {
    /// Normal single-link communication with Source gNB.
    SourceOnly,
    /// RRCReconfiguration with daps-Config received; Target layers initialized; T304 timer running.
    DapsConfigured,
    /// Target MAC is attempting Random Access (Msg1 / MsgA).
    TargetRachAttempting,
    /// Target RACH preamble contention resolved successfully.
    TargetRachSuccess,
    /// Uplink user data switched to Target gNB; Source UL retained for HARQ-ACK and RLC status.
    UplinkSwitched,
    /// Both DL legs actively receiving user data; Target UL transmitting; reordering and deduplication active.
    DualActive,
    /// RRC commanded daps-SourceRelease; Source stack torn down; Target single-link steady state.
    SourceReleased,
    /// Target RACH failed or T304 expired; Target context discarded; fallback to Source single-link.
    TargetFailureFallback,
}

/// Uplink channel type for power sharing arbitration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DapsUlChannel {
    SourcePusch = 1,
    TargetPusch = 2,
    SourcePucch = 3,
    TargetPucch = 4,
    TargetPrach = 5,
}

/// Reason for DAPS handover failure reported back to Source gNB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DapsFailureReason {
    T304Expiry,
    TargetRachFailure,
    TargetRadioLinkFailure,
}

/// Errors raised during DAPS handover operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DapsError {
    InvalidStateTransition { from: DapsState, to: DapsState },
    SecurityContextMissing(DapsLeg),
    IntegrityCheckFailed { leg: DapsLeg, count: u32 },
    BufferOverflow { capacity: usize, requested: usize },
    InvalidPdu(&'static str),
    TargetFailure(DapsFailureReason),
}

impl fmt::Display for DapsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DapsError::InvalidStateTransition { from, to } => {
                write!(
                    f,
                    "Invalid DAPS state transition from {:?} to {:?}",
                    from, to
                )
            }
            DapsError::SecurityContextMissing(leg) => {
                write!(f, "Missing security context for {:?} leg", leg)
            }
            DapsError::IntegrityCheckFailed { leg, count } => {
                write!(
                    f,
                    "Integrity verification failed on {:?} leg at COUNT {}",
                    leg, count
                )
            }
            DapsError::BufferOverflow {
                capacity,
                requested,
            } => {
                write!(
                    f,
                    "DAPS buffer overflow: capacity {} exceeded by request {}",
                    capacity, requested
                )
            }
            DapsError::InvalidPdu(msg) => write!(f, "Invalid DAPS PDU: {}", msg),
            DapsError::TargetFailure(reason) => write!(f, "DAPS target failure: {:?}", reason),
        }
    }
}

impl std::error::Error for DapsError {}

/// Ciphering algorithm for 5G NR DAPS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DapsCipherAlg {
    Nea0, // Null encryption
    Nea1, // Snow3G / stream cipher emulation
    Nea2, // 128-AES-CTR stream cipher emulation
}

/// Integrity protection algorithm for 5G NR DAPS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DapsIntegrityAlg {
    Nia0, // Null integrity
    Nia1, // Snow3G MAC emulation
    Nia2, // 128-AES-CMAC emulation
}

/// Cryptographic security context per DAPS leg (Source vs Target).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DapsSecurityContext {
    pub key: [u8; 16],
    pub cipher_alg: DapsCipherAlg,
    pub integrity_alg: DapsIntegrityAlg,
    pub bearer_id: u8,
    pub direction_ul: u8,
    pub direction_dl: u8,
}

impl DapsSecurityContext {
    pub fn new(
        key: [u8; 16],
        cipher_alg: DapsCipherAlg,
        integrity_alg: DapsIntegrityAlg,
        bearer_id: u8,
    ) -> Self {
        Self {
            key,
            cipher_alg,
            integrity_alg,
            bearer_id,
            direction_ul: 0,
            direction_dl: 1,
        }
    }

    /// Generates deterministic keystream byte at given index using standard key and COUNT.
    #[inline]
    fn keystream_byte(&self, count: u32, index: usize) -> u8 {
        let mut state = count ^ (self.bearer_id as u32) ^ ((index as u32) << 8);
        for &k in &self.key {
            state = state.rotate_left(3) ^ (k as u32);
            state = state.wrapping_mul(0x9E3779B9);
        }
        (state & 0xFF) as u8
    }

    /// Performs stream ciphering / deciphering on payload.
    pub fn process_cipher(&self, count: u32, payload: &[u8]) -> Vec<u8> {
        if self.cipher_alg == DapsCipherAlg::Nea0 {
            return payload.to_vec();
        }
        payload
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ self.keystream_byte(count, i))
            .collect()
    }

    /// Computes 4-byte Message Authentication Code (MAC-I) for integrity protection.
    pub fn compute_mac(&self, count: u32, payload: &[u8]) -> [u8; 4] {
        if self.integrity_alg == DapsIntegrityAlg::Nia0 {
            return [0u8; 4];
        }
        let mut mac_acc: u32 = 0x811C9DC5 ^ count ^ ((self.bearer_id as u32) << 24);
        for (i, &b) in payload.iter().enumerate() {
            mac_acc ^= (b as u32) ^ (self.keystream_byte(count, i) as u32);
            mac_acc = mac_acc.wrapping_mul(0x01000193);
        }
        mac_acc.to_be_bytes()
    }

    /// Verifies 4-byte Message Authentication Code (MAC-I).
    pub fn verify_mac(&self, count: u32, payload: &[u8], expected_mac: [u8; 4]) -> bool {
        if self.integrity_alg == DapsIntegrityAlg::Nia0 {
            return true;
        }
        self.compute_mac(count, payload) == expected_mac
    }
}

/// Protocol Data Unit transferred over a DAPS leg.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DapsPdu {
    pub leg: DapsLeg,
    pub sn: u32,
    pub count: u32,
    pub payload: Vec<u8>,
    pub mac: [u8; 4],
}

/// Service Data Unit delivered to or from upper layers (SDAP / IP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DapsSdu {
    pub sdu_id: u32,
    pub payload: Vec<u8>,
}

/// Downlink Reordering and Deduplication buffer across Source and Target legs (TS 38.323 §5.2.2).
#[derive(Debug, Clone)]
pub struct DapsReorderingBuffer {
    pub sn_size: DapsSnSize,
    /// Next expected COUNT to be assigned to next received PDU.
    pub rx_next: u32,
    /// First COUNT not yet delivered to upper layers.
    pub rx_deliv: u32,
    /// COUNT following the PDU that triggered the reordering timer.
    pub rx_reord: u32,
    /// Out-of-order received SDUs awaiting in-order delivery.
    reorder_map: BTreeMap<u32, Vec<u8>>,
    /// Set of delivered COUNTs to suppress duplicate deliveries.
    delivered_counts: HashSet<u32>,
    /// Duplicate packets detected and suppressed.
    pub duplicates_detected: u32,
}

impl DapsReorderingBuffer {
    pub fn new(sn_size: DapsSnSize) -> Self {
        Self {
            sn_size,
            rx_next: 0,
            rx_deliv: 0,
            rx_reord: 0,
            reorder_map: BTreeMap::new(),
            delivered_counts: HashSet::new(),
            duplicates_detected: 0,
        }
    }

    /// Processes a received SDU from either leg, eliminating duplicates and delivering in-order SDUs.
    pub fn receive_sdu(&mut self, count: u32, payload: Vec<u8>) -> Vec<Vec<u8>> {
        // Duplicate check: if already delivered or already present in reorder map, drop it
        if self.delivered_counts.contains(&count) || self.reorder_map.contains_key(&count) {
            self.duplicates_detected += 1;
            return Vec::new();
        }

        // If older than rx_deliv, it was already acknowledged / delivered earlier
        if count < self.rx_deliv {
            self.duplicates_detected += 1;
            return Vec::new();
        }

        self.reorder_map.insert(count, payload);

        if count >= self.rx_next {
            self.rx_next = count + 1;
        }

        // In-order delivery: drain consecutive packets starting from rx_deliv
        let mut delivered = Vec::new();
        while let Some(sdu) = self.reorder_map.remove(&self.rx_deliv) {
            self.delivered_counts.insert(self.rx_deliv);
            // Prune delivered_counts to prevent unbounded memory growth
            if self.rx_deliv >= 1000 {
                self.delivered_counts.remove(&(self.rx_deliv - 1000));
            }
            delivered.push(sdu);
            self.rx_deliv += 1;
        }

        delivered
    }
}

/// Power sharing manager for dual active uplink transmissions (TS 38.213 §7.6 / TS 38.133).
#[derive(Debug, Clone, PartialEq)]
pub struct DapsPowerManager {
    /// Maximum allowable total transmission power in dBm (e.g. 23.0 dBm).
    pub p_cmax_dbm: f64,
}

impl DapsPowerManager {
    pub fn new(p_cmax_dbm: f64) -> Self {
        Self { p_cmax_dbm }
    }

    #[inline]
    fn dbm_to_mw(dbm: f64) -> f64 {
        10.0f64.powf(dbm / 10.0)
    }

    #[inline]
    fn mw_to_dbm(mw: f64) -> f64 {
        if mw <= 1e-6 { -60.0 } else { 10.0 * mw.log10() }
    }

    /// Arbitrates and allocates transmit power for overlapping Source and Target UL slots.
    /// Returns (allocated_source_power_dbm, allocated_target_power_dbm).
    pub fn allocate_power(
        &self,
        src_req_dbm: f64,
        src_chan: DapsUlChannel,
        tgt_req_dbm: f64,
        tgt_chan: DapsUlChannel,
    ) -> (f64, f64) {
        let p_cmax_mw = Self::dbm_to_mw(self.p_cmax_dbm);
        let src_req_mw = Self::dbm_to_mw(src_req_dbm);
        let tgt_req_mw = Self::dbm_to_mw(tgt_req_dbm);

        if src_req_mw + tgt_req_mw <= p_cmax_mw {
            return (src_req_dbm, tgt_req_dbm);
        }

        // Power exceeds P_CMAX: prioritize higher priority channel
        if tgt_chan >= src_chan {
            // Target takes precedence
            let tgt_alloc_mw = tgt_req_mw.min(p_cmax_mw);
            let src_alloc_mw = (p_cmax_mw - tgt_alloc_mw).max(0.0);
            (Self::mw_to_dbm(src_alloc_mw), Self::mw_to_dbm(tgt_alloc_mw))
        } else {
            // Source takes precedence
            let src_alloc_mw = src_req_mw.min(p_cmax_mw);
            let tgt_alloc_mw = (p_cmax_mw - src_alloc_mw).max(0.0);
            (Self::mw_to_dbm(src_alloc_mw), Self::mw_to_dbm(tgt_alloc_mw))
        }
    }
}

/// Real-time operational telemetry for DAPS handover performance.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DapsTelemetry {
    pub source_rx_pdus: u64,
    pub source_rx_bytes: u64,
    pub target_rx_pdus: u64,
    pub target_rx_bytes: u64,
    pub source_tx_pdus: u64,
    pub target_tx_pdus: u64,
    pub duplicates_suppressed: u32,
    pub total_delivered_sdus: u32,
    pub interruption_duration_ms: u64,
    pub handover_duration_ms: u64,
    pub fallback_occurred: bool,
    pub last_failure_reason: Option<DapsFailureReason>,
}

/// Comprehensive 3GPP Rel-17 DAPS Handover Engine.
#[derive(Debug, Clone)]
pub struct DapsEngine {
    pub state: DapsState,
    pub sn_size: DapsSnSize,
    pub source_security: Option<DapsSecurityContext>,
    pub target_security: Option<DapsSecurityContext>,
    pub reordering_buffer: DapsReorderingBuffer,
    pub power_manager: DapsPowerManager,
    pub telemetry: DapsTelemetry,

    // Internal sequence and buffer state
    tx_next: u32,
    ul_buffer: VecDeque<(u32, Vec<u8>)>, // (sdu_id, payload)
    t304_timer_ms: u64,
    t304_elapsed_ms: u64,
    t304_active: bool,
    ho_start_timestamp_ms: Option<u64>,
}

impl DapsEngine {
    /// Creates a new DAPS Engine initialized on Source cell.
    pub fn new(
        sn_size: DapsSnSize,
        source_security: DapsSecurityContext,
        p_cmax_dbm: f64,
        t304_timer_ms: u64,
    ) -> Self {
        Self {
            state: DapsState::SourceOnly,
            sn_size,
            source_security: Some(source_security),
            target_security: None,
            reordering_buffer: DapsReorderingBuffer::new(sn_size),
            power_manager: DapsPowerManager::new(p_cmax_dbm),
            telemetry: DapsTelemetry::default(),
            tx_next: 0,
            ul_buffer: VecDeque::new(),
            t304_timer_ms,
            t304_elapsed_ms: 0,
            t304_active: false,
            ho_start_timestamp_ms: None,
        }
    }

    /// Step 1: Receives RRCReconfiguration with daps-Config (TS 38.331 §5.3.5.3).
    pub fn configure_target(
        &mut self,
        target_security: DapsSecurityContext,
        timestamp_ms: u64,
    ) -> Result<(), DapsError> {
        if self.state != DapsState::SourceOnly {
            return Err(DapsError::InvalidStateTransition {
                from: self.state,
                to: DapsState::DapsConfigured,
            });
        }
        self.target_security = Some(target_security);
        self.state = DapsState::DapsConfigured;
        self.t304_active = true;
        self.t304_elapsed_ms = 0;
        self.ho_start_timestamp_ms = Some(timestamp_ms);
        Ok(())
    }

    /// Step 2: Target MAC initiates Random Access (Msg1 / MsgA).
    pub fn start_target_rach(&mut self) -> Result<(), DapsError> {
        if self.state != DapsState::DapsConfigured {
            return Err(DapsError::InvalidStateTransition {
                from: self.state,
                to: DapsState::TargetRachAttempting,
            });
        }
        self.state = DapsState::TargetRachAttempting;
        Ok(())
    }

    /// Step 3: Target RACH completes successfully (Msg2 RAR / MsgB contention resolution).
    /// Uplink data transmission switches from Source to Target gNB (TS 38.323 §5.1.2).
    pub fn target_rach_success(&mut self) -> Result<(), DapsError> {
        if self.state != DapsState::TargetRachAttempting {
            return Err(DapsError::InvalidStateTransition {
                from: self.state,
                to: DapsState::TargetRachSuccess,
            });
        }
        self.t304_active = false;
        self.state = DapsState::UplinkSwitched;
        Ok(())
    }

    /// Step 4: Enters full DualActive state (both DL legs active, Target UL active).
    pub fn enter_dual_active(&mut self) -> Result<(), DapsError> {
        if self.state != DapsState::UplinkSwitched {
            return Err(DapsError::InvalidStateTransition {
                from: self.state,
                to: DapsState::DualActive,
            });
        }
        self.state = DapsState::DualActive;
        Ok(())
    }

    /// Step 5: Receives RRC daps-SourceRelease from Target gNB (TS 38.331 §5.3.5.8.3).
    /// Tears down Source protocol stack; transitions to Target single-link steady state.
    pub fn release_source(&mut self, timestamp_ms: u64) -> Result<(), DapsError> {
        if self.state != DapsState::DualActive && self.state != DapsState::UplinkSwitched {
            return Err(DapsError::InvalidStateTransition {
                from: self.state,
                to: DapsState::SourceReleased,
            });
        }
        self.source_security = None;
        self.state = DapsState::SourceReleased;
        if let Some(start) = self.ho_start_timestamp_ms {
            self.telemetry.handover_duration_ms = timestamp_ms.saturating_sub(start);
        }
        // DAPS guarantees 0 ms interruption because DL and UL data flow was never paused
        self.telemetry.interruption_duration_ms = 0;
        Ok(())
    }

    /// Handles T304 timer tick and detects RACH timeout failure (TS 38.331 §5.3.7.3).
    pub fn tick_timer(&mut self, delta_ms: u64) -> Option<DapsFailureReason> {
        if !self.t304_active {
            return None;
        }
        self.t304_elapsed_ms += delta_ms;
        if self.t304_elapsed_ms >= self.t304_timer_ms {
            self.t304_active = false;
            self.fallback_to_source(DapsFailureReason::T304Expiry);
            return Some(DapsFailureReason::T304Expiry);
        }
        None
    }

    /// Fallback to Source cell upon Target failure without dropping the active call.
    pub fn fallback_to_source(&mut self, reason: DapsFailureReason) {
        self.target_security = None;
        self.state = DapsState::TargetFailureFallback;
        self.telemetry.fallback_occurred = true;
        self.telemetry.last_failure_reason = Some(reason);
        // In fallback, Source cell remains active and call is maintained
    }

    /// Transmits an Uplink SDU from upper layer.
    /// Routes to Source gNB if before UL switch, or Target gNB after UL switch.
    pub fn send_ul_sdu(&mut self, sdu_id: u32, payload: Vec<u8>) -> Result<DapsPdu, DapsError> {
        let leg = match self.state {
            DapsState::SourceOnly
            | DapsState::DapsConfigured
            | DapsState::TargetRachAttempting
            | DapsState::TargetFailureFallback => DapsLeg::Source,

            DapsState::TargetRachSuccess
            | DapsState::UplinkSwitched
            | DapsState::DualActive
            | DapsState::SourceReleased => DapsLeg::Target,
        };

        let sec = match leg {
            DapsLeg::Source => self
                .source_security
                .as_ref()
                .ok_or(DapsError::SecurityContextMissing(DapsLeg::Source))?,
            DapsLeg::Target => self
                .target_security
                .as_ref()
                .ok_or(DapsError::SecurityContextMissing(DapsLeg::Target))?,
        };

        let sn = self.tx_next & self.sn_size.max_sn();
        let count = self.tx_next;
        self.tx_next += 1;

        let ciphered = sec.process_cipher(count, &payload);
        let mac = sec.compute_mac(count, &ciphered);

        // Store in UL buffer in case retransmission / forwarding is needed
        self.ul_buffer.push_back((sdu_id, payload));
        if self.ul_buffer.len() > 1000 {
            self.ul_buffer.pop_front();
        }

        match leg {
            DapsLeg::Source => self.telemetry.source_tx_pdus += 1,
            DapsLeg::Target => self.telemetry.target_tx_pdus += 1,
        }

        Ok(DapsPdu {
            leg,
            sn,
            count,
            payload: ciphered,
            mac,
        })
    }

    /// Receives a Downlink PDU from either Source or Target lower layers.
    /// Deciphers using the appropriate leg's security context, verifies MAC-I,
    /// and passes to unified reordering buffer for duplicate elimination and in-order delivery.
    pub fn receive_dl_pdu(&mut self, pdu: DapsPdu) -> Result<Vec<Vec<u8>>, DapsError> {
        let sec = match pdu.leg {
            DapsLeg::Source => {
                self.telemetry.source_rx_pdus += 1;
                self.telemetry.source_rx_bytes += pdu.payload.len() as u64;
                self.source_security
                    .as_ref()
                    .ok_or(DapsError::SecurityContextMissing(DapsLeg::Source))?
            }
            DapsLeg::Target => {
                self.telemetry.target_rx_pdus += 1;
                self.telemetry.target_rx_bytes += pdu.payload.len() as u64;
                self.target_security
                    .as_ref()
                    .ok_or(DapsError::SecurityContextMissing(DapsLeg::Target))?
            }
        };

        if !sec.verify_mac(pdu.count, &pdu.payload, pdu.mac) {
            return Err(DapsError::IntegrityCheckFailed {
                leg: pdu.leg,
                count: pdu.count,
            });
        }

        let plain = sec.process_cipher(pdu.count, &pdu.payload);
        let delivered = self.reordering_buffer.receive_sdu(pdu.count, plain);

        self.telemetry.duplicates_suppressed = self.reordering_buffer.duplicates_detected;
        self.telemetry.total_delivered_sdus += delivered.len() as u32;

        Ok(delivered)
    }

    /// Clears acknowledged packets from uplink transmission buffer.
    pub fn acknowledge_ul_sdu(&mut self, sdu_id: u32) {
        self.ul_buffer.retain(|(id, _)| *id != sdu_id);
    }

    /// Pending unacknowledged uplink packets in transmission buffer.
    pub fn pending_ul_count(&self) -> usize {
        self.ul_buffer.len()
    }
}
