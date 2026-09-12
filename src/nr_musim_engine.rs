//! 3GPP Rel-18 5G-Advanced Multi-SIM (MUSIM) & Dual-Stack Coordination Engine.
//!
//! Compliant with:
//! - 3GPP TS 38.300 §16.16 Rel-18 ("Multi-SIM operation in NR")
//! - 3GPP TS 38.331 Rel-18 (`MUSIM-AssistanceInformation`, `MUSIM-GapConfig`, `PagingValid-Time`)
//! - 3GPP TS 38.321 §5.x Rel-18 (MAC CE for Temporary Leave and Return)
//! - 3GPP TS 38.304 §7 Rel-18 (Paging Frame & Paging Occasion calculation)
//! - 3GPP TR 38.855 Rel-18 (Study on Multi-SIM Device Architectures)
//! - 3GPP TS 38.101-1 / TS 38.213 (Dual-SIM Dual-Active UL Transmit Power Constraints)
//!
//! Key Capabilities:
//! 1. Multi-SIM device capability handling: Single-Rx/Single-Tx (SS), Dual-Rx/Single-Tx (DSDS),
//!    and Dual-Rx/Dual-Tx (DSDA).
//! 2. Paging Collision Avoidance & Paging Occasion ($PF / PO$) Overlap Analysis.
//! 3. Autonomous Generation of 3GPP `MUSIM-AssistanceInformation` proposing DRX offsets and paging subgrouping.
//! 4. MUSIM Gap Scheduling (`MUSIM-GapConfig`) for non-colliding inter-network tuning.
//! 5. Temporary Leave & Resume State Machine with RRC Release Request / MAC CE generation.
//! 6. DSDA Dynamic Total Transmit Power Sharing Servo enforcing $P_A + P_B \le P_{\text{CMAX}}$ with
//!    QoS/Service priority waterfilling.
//! 7. Binary serialization and decoding of MUSIM Control Elements.
//!
//! Pure Rust standard library implementation with zero external dependencies.

// ---------------------------------------------------------------------------
// Constants (3GPP TS 38.300 / TS 38.331 / TS 38.101)
// ---------------------------------------------------------------------------

/// Maximum nominal UE total transmit power $P_{\text{CMAX}}$ in milliwatts (23 dBm = ~200 mW).
pub const DEFAULT_PCMAX_MW: f64 = 199.526_231_496_888; // 10^(2.3) ~ 199.53 mW

/// Default minimum viable transmit power floor in milliwatts (-30 dBm = 0.001 mW).
pub const MIN_TRANSMIT_POWER_MW: f64 = 0.001;

/// Maximum number of System Frame Number (SFN) frames in a hyperframe cycle (0..1023).
pub const MAX_SFN_FRAMES: u32 = 1024;

/// Default temporary leave duration in milliseconds (5.0 seconds).
pub const DEFAULT_TEMPORARY_LEAVE_DURATION_MS: u32 = 5000;

/// Default MUSIM Gap length in milliseconds for paging reception.
pub const DEFAULT_MUSIM_GAP_LENGTH_MS: u16 = 10;

/// Default MUSIM Gap periodicity in milliseconds.
pub const DEFAULT_MUSIM_GAP_PERIODICITY_MS: u16 = 640;

// ---------------------------------------------------------------------------
// Enumerations & Error Types
// ---------------------------------------------------------------------------

/// Identifier for SIM cards in a multi-SIM terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SimId {
    SimA,
    SimB,
}

impl SimId {
    pub fn peer(&self) -> Self {
        match self {
            Self::SimA => Self::SimB,
            Self::SimB => Self::SimA,
        }
    }
}

/// Multi-SIM terminal RF hardware architecture capability (TR 38.855 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MusimDeviceCapability {
    /// Single-Rx / Single-Tx (SS): Only one network active at any millisecond. Requires gaps & leave.
    SingleRxSingleTx,
    /// Dual-Rx / Single-Tx (DSDS): Can listen to paging on both networks; only one can transmit.
    DualRxSingleTx,
    /// Dual-Rx / Dual-Tx (DSDA): Simultaneous reception & transmission. Requires power sharing servo.
    DualRxDualTx,
}

/// 3GPP RRC protocol connection state for a SIM stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MusimRrcState {
    RrcIdle,
    RrcInactive,
    RrcConnected,
}

/// Traffic and service priority hierarchy for multi-SIM arbitration (TS 38.300 §16.16).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MusimServicePriority {
    /// Emergency call or regulatory emergency alert (Highest: 0).
    Emergency = 0,
    /// Real-time Voice over NR (VoNR) / conversational voice.
    VoiceOverNr = 1,
    /// Critical RRC / NAS signaling (e.g. Handover, Authentication).
    RrcSignaling = 2,
    /// Ultra-Reliable Low Latency Communications (URLLC).
    UrllcData = 3,
    /// Best-Effort mobile broadband data (e.g. background sync, streaming).
    BestEffortData = 4,
    /// Idle mode paging and sync monitoring.
    PagingMonitoring = 5,
}

/// Cause triggering a Temporary Leave on the active network (TS 38.331).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MusimLeaveCause {
    /// Incoming paging response on the peer SIM.
    PagingResponse,
    /// User initiated or received a VoNR voice call on the peer SIM.
    VoiceCall,
    /// User initiated an emergency service on the peer SIM.
    EmergencyCall,
    /// High-priority mobility or location registration signaling on the peer SIM.
    SignalingTransaction,
    /// User or policy defined temporary leave.
    Other,
}

/// Action commanded by the MUSIM engine when a leave is requested.
#[derive(Debug, Clone, PartialEq)]
pub enum MusimLeaveAction {
    /// Transmit RRCReleaseRequest / UEAssistanceInformation with leave cause and duration.
    SendRrcLeaveRequest {
        cause: MusimLeaveCause,
        expected_duration_ms: u32,
    },
    /// Transmit MAC CE for fast temporary leave (TS 38.321).
    SendMacCeTemporaryLeave {
        cause: MusimLeaveCause,
        expected_duration_ms: u32,
    },
    /// Reject leave because current SIM service has higher priority (e.g. emergency).
    RejectLeaveConflict {
        active_priority: MusimServicePriority,
        requested_priority: MusimServicePriority,
    },
}

/// Errors occurring in multi-SIM coordination and parsing.
#[derive(Debug, Clone, PartialEq)]
pub enum MusimError {
    SimNotFound(SimId),
    InvalidConfiguration(String),
    BufferTooShort { expected: usize, actual: usize },
    InvalidBitfield,
    PowerConstraintViolation { total_power_mw: f64, pcmax_mw: f64 },
}

impl std::fmt::Display for MusimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SimNotFound(id) => write!(f, "SIM slot {:?} not configured", id),
            Self::InvalidConfiguration(msg) => write!(f, "Invalid MUSIM configuration: {}", msg),
            Self::BufferTooShort { expected, actual } => {
                write!(
                    f,
                    "Buffer too short: expected {} bytes, got {}",
                    expected, actual
                )
            }
            Self::InvalidBitfield => write!(f, "Corrupted MUSIM binary bitfield"),
            Self::PowerConstraintViolation {
                total_power_mw,
                pcmax_mw,
            } => {
                write!(
                    f,
                    "Total transmit power {:.2} mW exceeds PCMAX {:.2} mW",
                    total_power_mw, pcmax_mw
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SIM Profile & Paging Occasion Computation (TS 38.304 §7)
// ---------------------------------------------------------------------------

/// Configuration and state profile for an individual SIM card.
#[derive(Debug, Clone, PartialEq)]
pub struct SimProfile {
    pub sim_id: SimId,
    pub plmn_id: [u8; 3],
    pub rrc_state: MusimRrcState,
    pub active_service: MusimServicePriority,
    /// 5G-S-TMSI or hashed IMSI value used in Paging Occasion determination.
    pub ue_id: u64,
    /// Discontinuous Reception (DRX) cycle $T$ in radio frames (e.g., 32, 64, 128, 256).
    pub drx_cycle_frames: u32,
    /// Number of paging frames $N$ in DRX cycle ($N \le T$).
    pub paging_frames_n: u32,
    /// Number of paging occasions $N_s$ within a paging frame (1, 2, or 4).
    pub paging_occasions_ns: u32,
    /// Current radio frame offset applied to this SIM.
    pub frame_offset: u32,
}

impl SimProfile {
    pub fn new(sim_id: SimId, plmn_id: [u8; 3], ue_id: u64, drx_cycle_frames: u32) -> Self {
        Self {
            sim_id,
            plmn_id,
            rrc_state: MusimRrcState::RrcIdle,
            active_service: MusimServicePriority::PagingMonitoring,
            ue_id,
            drx_cycle_frames: drx_cycle_frames.max(1),
            paging_frames_n: drx_cycle_frames.max(1),
            paging_occasions_ns: 1,
            frame_offset: 0,
        }
    }

    /// Calculate Paging Frame (PF) SFN according to 3GPP TS 38.304 §7.1:
    /// $\text{SFN} \pmod T = (T / N) \cdot (\text{UE\_ID} \pmod N) + \text{offset} \pmod T$
    pub fn calculate_paging_frame(&self) -> u32 {
        let t = self.drx_cycle_frames.max(1);
        let n = self.paging_frames_n.max(1).min(t);
        let step = t / n;
        let ue_mod_n = (self.ue_id % (n as u64)) as u32;
        ((step * ue_mod_n) + self.frame_offset) % t
    }

    /// Calculate Paging Occasion index $i_s$ in subframe according to TS 38.304:
    /// $i_s = \lfloor \text{UE\_ID} / N \rfloor \pmod{N_s}$
    pub fn calculate_paging_occasion_subframe(&self) -> u8 {
        let n = self.paging_frames_n.max(1) as u64;
        let ns = self.paging_occasions_ns.max(1) as u64;
        let i_s = ((self.ue_id / n) % ns) as u8;

        // Subframe mapping for FDD (TS 38.304 Table 7.1-1):
        // Ns=1 -> subframe 9; Ns=2 -> subframe 4, 9; Ns=4 -> 0, 4, 5, 9
        match (self.paging_occasions_ns, i_s) {
            (1, _) => 9,
            (2, 0) => 4,
            (2, 1) => 9,
            (4, 0) => 0,
            (4, 1) => 4,
            (4, 2) => 5,
            (4, 3) => 9,
            _ => 9,
        }
    }
}

// ---------------------------------------------------------------------------
// Paging Collision Detection & Assistance Information (TS 38.331)
// ---------------------------------------------------------------------------

/// Paging collision event where peer SIM paging overlaps with active SIM transmission/reception.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PagingCollisionEvent {
    pub sfn: u32,
    pub subframe: u8,
    pub busy_sim: SimId,
    pub paged_sim: SimId,
}

/// 3GPP Rel-18 `MUSIM-AssistanceInformation` message payload.
#[derive(Debug, Clone, PartialEq)]
pub struct MusimAssistanceInfo {
    /// Suggested DRX offset to shift Paging Frame away from collision (in frames 0..15).
    pub preferred_drx_offset_frames: u8,
    /// Whether Paging Subgrouping (TS 38.304 §7.4) is requested.
    pub paging_subgrouping_requested: bool,
    /// Recommended MUSIM gap periodicity in ms.
    pub recommended_gap_periodicity_ms: u16,
    /// Recommended MUSIM gap duration in ms.
    pub recommended_gap_length_ms: u16,
}

impl MusimAssistanceInfo {
    /// Serialize `MUSIM-AssistanceInformation` into compact 4-byte network binary frame.
    /// Bitfield:
    /// [0]: preferred_drx_offset (4 bits) | paging_subgrouping (1 bit) | reserved (3 bits)
    /// [1..2]: recommended_gap_periodicity_ms (u16 BE)
    /// [3]: recommended_gap_length_ms (u8)
    pub fn to_bytes(&self) -> [u8; 4] {
        let mut buf = [0u8; 4];
        let b0 = ((self.preferred_drx_offset_frames & 0x0F) << 4)
            | (if self.paging_subgrouping_requested {
                0x08
            } else {
                0x00
            });
        buf[0] = b0;
        let per_bytes = self.recommended_gap_periodicity_ms.to_be_bytes();
        buf[1] = per_bytes[0];
        buf[2] = per_bytes[1];
        buf[3] = (self.recommended_gap_length_ms.min(255)) as u8;
        buf
    }

    /// Deserialize binary frame back to `MusimAssistanceInfo`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MusimError> {
        if bytes.len() < 4 {
            return Err(MusimError::BufferTooShort {
                expected: 4,
                actual: bytes.len(),
            });
        }
        let b0 = bytes[0];
        let preferred_drx_offset_frames = (b0 >> 4) & 0x0F;
        let paging_subgrouping_requested = (b0 & 0x08) != 0;
        let recommended_gap_periodicity_ms = u16::from_be_bytes([bytes[1], bytes[2]]);
        let recommended_gap_length_ms = bytes[3] as u16;

        Ok(Self {
            preferred_drx_offset_frames,
            paging_subgrouping_requested,
            recommended_gap_periodicity_ms,
            recommended_gap_length_ms,
        })
    }
}

// ---------------------------------------------------------------------------
// MUSIM Gap Scheduler (TS 38.331 `MUSIM-GapConfig`)
// ---------------------------------------------------------------------------

/// Configuration for periodic/aperiodic gaps allocated to tune to peer SIM.
#[derive(Debug, Clone, PartialEq)]
pub struct MusimGapConfig {
    pub gap_id: u8,
    pub gap_length_ms: u16,
    pub gap_periodicity_ms: u16,
    pub gap_offset_ms: u16,
    pub enabled: bool,
}

impl MusimGapConfig {
    pub fn new(
        gap_id: u8,
        gap_length_ms: u16,
        gap_periodicity_ms: u16,
        gap_offset_ms: u16,
    ) -> Self {
        Self {
            gap_id,
            gap_length_ms,
            gap_periodicity_ms: gap_periodicity_ms.max(10),
            gap_offset_ms,
            enabled: true,
        }
    }

    /// Check if a gap is currently active at timestamp `time_ms`.
    pub fn is_gap_active(&self, time_ms: u64) -> bool {
        if !self.enabled {
            return false;
        }
        let per = self.gap_periodicity_ms as u64;
        let off = self.gap_offset_ms as u64;
        let cycle_pos = (time_ms + per - (off % per)) % per;
        cycle_pos < (self.gap_length_ms as u64)
    }
}

// ---------------------------------------------------------------------------
// DSDA Dynamic Transmit Power Sharing Servo (TS 38.213 / TS 38.101)
// ---------------------------------------------------------------------------

/// Transmit power allocation result for Dual-SIM Dual-Active operation.
#[derive(Debug, Clone, PartialEq)]
pub struct PowerSharingAllocation {
    pub sim_a_power_mw: f64,
    pub sim_b_power_mw: f64,
    pub sim_a_power_dbm: f64,
    pub sim_b_power_dbm: f64,
    pub total_power_mw: f64,
    pub was_throttled: bool,
}

/// Dynamic power sharing servo enforcing $P_{\text{alloc}, A} + P_{\text{alloc}, B} \le P_{\text{CMAX}}$.
#[derive(Debug, Clone, PartialEq)]
pub struct MusimPowerSharingServo {
    pub pcmax_mw: f64,
}

impl MusimPowerSharingServo {
    pub fn new(pcmax_mw: f64) -> Result<Self, MusimError> {
        if pcmax_mw <= 0.0 {
            return Err(MusimError::InvalidConfiguration(
                "PCMAX must be strictly positive".to_string(),
            ));
        }
        Ok(Self { pcmax_mw })
    }

    pub fn default_ue() -> Self {
        Self {
            pcmax_mw: DEFAULT_PCMAX_MW,
        }
    }

    /// Convert milliwatts to decibel-milliwatts (dBm).
    pub fn mw_to_dbm(mw: f64) -> f64 {
        if mw <= 1e-12 {
            -120.0
        } else {
            10.0 * mw.log10()
        }
    }

    /// Convert decibel-milliwatts (dBm) to milliwatts.
    pub fn dbm_to_mw(dbm: f64) -> f64 {
        10.0_f64.powf(dbm / 10.0)
    }

    /// Compute power allocation satisfying total budget constraint using QoS waterfilling.
    pub fn allocate_power(
        &self,
        sim_a_req_mw: f64,
        sim_a_prio: MusimServicePriority,
        sim_b_req_mw: f64,
        sim_b_prio: MusimServicePriority,
    ) -> PowerSharingAllocation {
        let req_a = sim_a_req_mw.max(0.0);
        let req_b = sim_b_req_mw.max(0.0);
        let total_req = req_a + req_b;

        // Case 1: Within PCMAX budget -> grant full requested powers
        if total_req <= self.pcmax_mw {
            return PowerSharingAllocation {
                sim_a_power_mw: req_a,
                sim_b_power_mw: req_b,
                sim_a_power_dbm: Self::mw_to_dbm(req_a),
                sim_b_power_dbm: Self::mw_to_dbm(req_b),
                total_power_mw: total_req,
                was_throttled: false,
            };
        }

        // Case 2: Exceeds PCMAX -> priority-based waterfilling
        let (alloc_a, alloc_b) = if sim_a_prio < sim_b_prio {
            // SIM A has higher priority (smaller numeric value)
            let p_a = req_a.min(self.pcmax_mw);
            let p_b = (self.pcmax_mw - p_a).max(0.0);
            (p_a, p_b)
        } else if sim_b_prio < sim_a_prio {
            // SIM B has higher priority
            let p_b = req_b.min(self.pcmax_mw);
            let p_a = (self.pcmax_mw - p_b).max(0.0);
            (p_a, p_b)
        } else {
            // Equal priority: proportional scaling
            let scale = self.pcmax_mw / total_req;
            (req_a * scale, req_b * scale)
        };

        PowerSharingAllocation {
            sim_a_power_mw: alloc_a,
            sim_b_power_mw: alloc_b,
            sim_a_power_dbm: Self::mw_to_dbm(alloc_a),
            sim_b_power_dbm: Self::mw_to_dbm(alloc_b),
            total_power_mw: alloc_a + alloc_b,
            was_throttled: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Temporary Leave & Return State Machine
// ---------------------------------------------------------------------------

/// State of a SIM stack's temporary leave.
#[derive(Debug, Clone, PartialEq)]
pub enum TemporaryLeaveState {
    Active,
    LeaveInProgress {
        cause: MusimLeaveCause,
        leave_start_ms: u64,
        duration_ms: u32,
    },
}

// ---------------------------------------------------------------------------
// Multi-SIM Coordination Engine
// ---------------------------------------------------------------------------

/// Complete 3GPP Rel-18 Multi-SIM (MUSIM) & Dual-Stack Coordination Engine.
#[derive(Debug, PartialEq)]
pub struct MusimEngine {
    pub capability: MusimDeviceCapability,
    pub sim_a: SimProfile,
    pub sim_b: SimProfile,
    pub gap_config: Option<MusimGapConfig>,
    pub power_servo: MusimPowerSharingServo,
    pub leave_state_a: TemporaryLeaveState,
    pub leave_state_b: TemporaryLeaveState,
    /// Statistics: Total detected paging collisions.
    pub stats_paging_collisions: u64,
    /// Statistics: Total temporary leave requests initiated.
    pub stats_leave_requests: u64,
    /// Statistics: Total power throttle interventions.
    pub stats_power_throttles: u64,
}

impl MusimEngine {
    pub fn new(capability: MusimDeviceCapability, sim_a: SimProfile, sim_b: SimProfile) -> Self {
        Self {
            capability,
            sim_a,
            sim_b,
            gap_config: None,
            power_servo: MusimPowerSharingServo::default_ue(),
            leave_state_a: TemporaryLeaveState::Active,
            leave_state_b: TemporaryLeaveState::Active,
            stats_paging_collisions: 0,
            stats_leave_requests: 0,
            stats_power_throttles: 0,
        }
    }

    /// Configure MUSIM Gap for periodic inter-network monitoring.
    pub fn configure_gap(&mut self, gap: MusimGapConfig) {
        self.gap_config = Some(gap);
    }

    /// Update RRC state and active service for a designated SIM.
    pub fn update_sim_state(
        &mut self,
        sim_id: SimId,
        rrc_state: MusimRrcState,
        service: MusimServicePriority,
    ) -> Result<(), MusimError> {
        match sim_id {
            SimId::SimA => {
                self.sim_a.rrc_state = rrc_state;
                self.sim_a.active_service = service;
            }
            SimId::SimB => {
                self.sim_b.rrc_state = rrc_state;
                self.sim_b.active_service = service;
            }
        }
        Ok(())
    }

    /// Detect paging collision events within a lookahead horizon of radio frames.
    pub fn detect_paging_collisions(
        &mut self,
        current_sfn: u32,
        lookahead_frames: u32,
    ) -> Vec<PagingCollisionEvent> {
        let mut collisions = Vec::new();

        let sim_a_pf = self.sim_a.calculate_paging_frame();
        let sim_a_po_subframe = self.sim_a.calculate_paging_occasion_subframe();

        let sim_b_pf = self.sim_b.calculate_paging_frame();
        let sim_b_po_subframe = self.sim_b.calculate_paging_occasion_subframe();

        for i in 0..lookahead_frames {
            let sfn = (current_sfn + i) % MAX_SFN_FRAMES;

            // Check if SIM B has a Paging Occasion at this SFN and SIM A is RRC_CONNECTED
            if self.sim_a.rrc_state == MusimRrcState::RrcConnected {
                let sim_b_cycle_pos = sfn % self.sim_b.drx_cycle_frames;
                if sim_b_cycle_pos == sim_b_pf {
                    collisions.push(PagingCollisionEvent {
                        sfn,
                        subframe: sim_b_po_subframe,
                        busy_sim: SimId::SimA,
                        paged_sim: SimId::SimB,
                    });
                }
            }

            // Check if SIM A has a Paging Occasion at this SFN and SIM B is RRC_CONNECTED
            if self.sim_b.rrc_state == MusimRrcState::RrcConnected {
                let sim_a_cycle_pos = sfn % self.sim_a.drx_cycle_frames;
                if sim_a_cycle_pos == sim_a_pf {
                    collisions.push(PagingCollisionEvent {
                        sfn,
                        subframe: sim_a_po_subframe,
                        busy_sim: SimId::SimB,
                        paged_sim: SimId::SimA,
                    });
                }
            }
        }

        self.stats_paging_collisions += collisions.len() as u64;
        collisions
    }

    /// Generate 3GPP `MUSIM-AssistanceInformation` to resolve paging collisions.
    pub fn generate_assistance_info(&self, paged_sim: SimId) -> MusimAssistanceInfo {
        let preferred_offset = match paged_sim {
            SimId::SimA => 2, // Shift PF by 2 radio frames
            SimId::SimB => 4, // Shift PF by 4 radio frames
        };

        MusimAssistanceInfo {
            preferred_drx_offset_frames: preferred_offset,
            paging_subgrouping_requested: true,
            recommended_gap_periodicity_ms: DEFAULT_MUSIM_GAP_PERIODICITY_MS,
            recommended_gap_length_ms: DEFAULT_MUSIM_GAP_LENGTH_MS,
        }
    }

    /// Request a Temporary Leave from active network on `from_sim` to serve `peer_sim`.
    pub fn request_temporary_leave(
        &mut self,
        from_sim: SimId,
        cause: MusimLeaveCause,
        duration_ms: u32,
        now_ms: u64,
    ) -> Result<MusimLeaveAction, MusimError> {
        self.stats_leave_requests += 1;

        let (from_prio, peer_prio) = match from_sim {
            SimId::SimA => (self.sim_a.active_service, self.sim_b.active_service),
            SimId::SimB => (self.sim_b.active_service, self.sim_a.active_service),
        };

        // If from_sim has strictly higher priority (e.g. active Emergency), reject leave
        if from_prio == MusimServicePriority::Emergency && cause != MusimLeaveCause::EmergencyCall {
            return Ok(MusimLeaveAction::RejectLeaveConflict {
                active_priority: from_prio,
                requested_priority: peer_prio,
            });
        }

        // Set state to LeaveInProgress
        match from_sim {
            SimId::SimA => {
                self.leave_state_a = TemporaryLeaveState::LeaveInProgress {
                    cause,
                    leave_start_ms: now_ms,
                    duration_ms,
                };
            }
            SimId::SimB => {
                self.leave_state_b = TemporaryLeaveState::LeaveInProgress {
                    cause,
                    leave_start_ms: now_ms,
                    duration_ms,
                };
            }
        }

        // For high-priority voice/emergency use fast MAC CE, otherwise RRCReleaseRequest
        let action =
            if cause == MusimLeaveCause::EmergencyCall || cause == MusimLeaveCause::VoiceCall {
                MusimLeaveAction::SendMacCeTemporaryLeave {
                    cause,
                    expected_duration_ms: duration_ms,
                }
            } else {
                MusimLeaveAction::SendRrcLeaveRequest {
                    cause,
                    expected_duration_ms: duration_ms,
                }
            };

        Ok(action)
    }

    /// Return from Temporary Leave back to active communication.
    pub fn resume_from_leave(&mut self, sim_id: SimId) -> Result<(), MusimError> {
        match sim_id {
            SimId::SimA => self.leave_state_a = TemporaryLeaveState::Active,
            SimId::SimB => self.leave_state_b = TemporaryLeaveState::Active,
        }
        Ok(())
    }

    /// Perform DSDA simultaneous transmit power allocation.
    pub fn arbitrate_transmit_power(
        &mut self,
        sim_a_mw: f64,
        sim_b_mw: f64,
    ) -> Result<PowerSharingAllocation, MusimError> {
        let alloc = self.power_servo.allocate_power(
            sim_a_mw,
            self.sim_a.active_service,
            sim_b_mw,
            self.sim_b.active_service,
        );

        if alloc.was_throttled {
            self.stats_power_throttles += 1;
        }

        Ok(alloc)
    }
}

// ---------------------------------------------------------------------------
// Unit Tests (Internal Module)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_paging_frame_calculation() {
        let sim = SimProfile::new(SimId::SimA, [4, 6, 0], 100, 64);
        let pf = sim.calculate_paging_frame();
        assert_eq!(pf, 36);
        assert_eq!(sim.calculate_paging_occasion_subframe(), 9);
    }

    #[test]
    fn test_musim_assistance_info_serialization() {
        let info = MusimAssistanceInfo {
            preferred_drx_offset_frames: 7,
            paging_subgrouping_requested: true,
            recommended_gap_periodicity_ms: 320,
            recommended_gap_length_ms: 20,
        };

        let bytes = info.to_bytes();
        let decoded = MusimAssistanceInfo::from_bytes(&bytes).expect("Decodes cleanly");
        assert_eq!(info, decoded);
    }

    #[test]
    fn test_power_sharing_waterfilling_emergency_priority() {
        let servo = MusimPowerSharingServo::default_ue();

        let alloc = servo.allocate_power(
            150.0,
            MusimServicePriority::BestEffortData,
            150.0,
            MusimServicePriority::Emergency,
        );

        assert!(alloc.was_throttled);
        assert!((alloc.sim_b_power_mw - 150.0).abs() < 1e-4);
        assert!((alloc.sim_a_power_mw - (servo.pcmax_mw - 150.0)).abs() < 1e-4);
        assert!((alloc.total_power_mw - servo.pcmax_mw).abs() < 1e-4);
    }
}
