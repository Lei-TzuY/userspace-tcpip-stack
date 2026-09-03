//! PTP Telecom Profile Path Trace & Announce Fault TLV Propagation (IEEE 1588-2019 / ITU-T G.8275.1).
//!
//! Extends the PTP Telecom Profile with:
//! - **PATH_TRACE TLV (Type 0x0008)**: Appended to Announce messages by each Boundary Clock (T-BC)
//!   to record the chain of Clock Identities from Grandmaster to leaf, enabling loop detection
//!   and path visualization.
//! - **Announce Fault Propagation**: When a T-BC loses its upstream reference, it degrades its
//!   clockClass to Holdover (class 7/140/150) and propagates this via modified Announce messages.
//!   Downstream T-BCs detect the holdover cascade and may switchover to alternate masters.
//! - **Path Trace Engine**: Validates incoming path traces for loops, maintains path depth limits,
//!   and computes effective path metrics.

use std::collections::HashSet;

/// PTP TLV Type for PATH_TRACE (IEEE 1588-2019 Section 16.2.7).
pub const PTP_TLV_TYPE_PATH_TRACE: u16 = 0x0008;

/// Maximum path depth before declaring excessive hops.
pub const MAX_PATH_TRACE_DEPTH: usize = 64;

/// PTP Clock Classes used in Telecom Profile fault propagation.
pub const CLOCK_CLASS_LOCKED: u8 = 6;
pub const CLOCK_CLASS_HOLDOVER_IN_SPEC: u8 = 7;
pub const CLOCK_CLASS_HOLDOVER_OUT_OF_SPEC: u8 = 140;
pub const CLOCK_CLASS_FREERUN: u8 = 248;
pub const CLOCK_CLASS_SLAVE_ONLY: u8 = 255;

/// Holdover Degradation Thresholds (ITU-T G.8275.1 Section 6.7.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HoldoverTimingBudget {
    /// Maximum time in holdover-in-spec before degrading to out-of-spec (seconds).
    pub holdover_in_spec_timeout_sec: u32,
    /// Clock accuracy that degrades as holdover time increases.
    pub initial_accuracy: u8,
    pub degraded_accuracy: u8,
}

impl Default for HoldoverTimingBudget {
    fn default() -> Self {
        HoldoverTimingBudget {
            holdover_in_spec_timeout_sec: 1000, // ~17 minutes G.8273.2 Class C
            initial_accuracy: 0x21,             // Within 100ns
            degraded_accuracy: 0x25,            // Within 1µs
        }
    }
}

/// A single entry in the PTP PATH_TRACE TLV.
pub type ClockIdentity = [u8; 8];

/// PATH_TRACE TLV (IEEE 1588-2019 Section 16.2.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathTraceTlv {
    pub path: Vec<ClockIdentity>,
}

impl PathTraceTlv {
    pub fn new() -> Self {
        PathTraceTlv { path: Vec::new() }
    }

    /// Appends a clock identity to the path trace.
    /// Returns false if maximum depth would be exceeded (excessive hops).
    pub fn append(&mut self, clock_id: ClockIdentity) -> bool {
        if self.path.len() >= MAX_PATH_TRACE_DEPTH {
            return false;
        }
        self.path.push(clock_id);
        true
    }

    /// Checks whether appending this clock_id would create a loop.
    pub fn would_create_loop(&self, clock_id: &ClockIdentity) -> bool {
        self.path.iter().any(|id| id == clock_id)
    }

    /// Path depth (number of boundary clocks traversed).
    pub fn depth(&self) -> usize {
        self.path.len()
    }

    /// Serializes the PATH_TRACE TLV to bytes (TLV header + 8 bytes per entry).
    pub fn serialize(&self) -> Vec<u8> {
        let data_len = self.path.len() * 8;
        let mut buf = Vec::with_capacity(4 + data_len);

        // TLV Type (2 bytes) + Length (2 bytes)
        buf.extend_from_slice(&PTP_TLV_TYPE_PATH_TRACE.to_be_bytes());
        buf.extend_from_slice(&(data_len as u16).to_be_bytes());

        for clock_id in &self.path {
            buf.extend_from_slice(clock_id);
        }
        buf
    }

    /// Parses a PATH_TRACE TLV from bytes.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let tlv_type = u16::from_be_bytes([data[0], data[1]]);
        if tlv_type != PTP_TLV_TYPE_PATH_TRACE {
            return None;
        }
        let tlv_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if tlv_len % 8 != 0 || data.len() < 4 + tlv_len {
            return None;
        }

        let entry_count = tlv_len / 8;
        let mut path = Vec::with_capacity(entry_count);

        for i in 0..entry_count {
            let offset = 4 + i * 8;
            let mut clock_id = [0u8; 8];
            clock_id.copy_from_slice(&data[offset..offset + 8]);
            path.push(clock_id);
        }

        Some(PathTraceTlv { path })
    }
}

impl Default for PathTraceTlv {
    fn default() -> Self {
        Self::new()
    }
}

/// Announce message representation with path trace and fault state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelecomAnnounce {
    pub source_clock_identity: ClockIdentity,
    pub grandmaster_identity: ClockIdentity,
    pub clock_class: u8,
    pub clock_accuracy: u8,
    pub offset_scaled_log_variance: u16,
    pub priority1: u8,
    pub priority2: u8,
    pub local_priority: u8,
    pub steps_removed: u16,
    pub path_trace: PathTraceTlv,
}

impl TelecomAnnounce {
    /// Constructs a new Announce from a T-GM (grandmaster at step 0).
    pub fn from_grandmaster(gm_clock_id: ClockIdentity) -> Self {
        let mut pt = PathTraceTlv::new();
        pt.append(gm_clock_id);

        TelecomAnnounce {
            source_clock_identity: gm_clock_id,
            grandmaster_identity: gm_clock_id,
            clock_class: CLOCK_CLASS_LOCKED,
            clock_accuracy: 0x20,
            offset_scaled_log_variance: 0x4000,
            priority1: 128,
            priority2: 128,
            local_priority: 128,
            steps_removed: 0,
            path_trace: pt,
        }
    }
}

/// Upstream reference state at a Boundary Clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamRefState {
    /// Locked to upstream GM reference.
    Locked,
    /// In holdover — upstream lost, using local oscillator.
    HoldoverInSpec { elapsed_sec: u32 },
    /// Holdover exceeded timing budget — out of spec.
    HoldoverOutOfSpec,
    /// Free-running — no reference ever acquired.
    FreeRun,
}

/// PTP Telecom Path Trace & Fault Propagation Engine.
///
/// Each T-BC instance maintains:
/// - Its own clock identity and local priority
/// - The best upstream Announce (from its selected master port)
/// - Holdover state tracking with timing budget
/// - Path trace loop detection
#[derive(Debug, Clone)]
pub struct PtpPathTraceEngine {
    pub clock_identity: ClockIdentity,
    pub local_priority: u8,
    pub upstream_state: UpstreamRefState,
    pub holdover_budget: HoldoverTimingBudget,
    pub current_best_announce: Option<TelecomAnnounce>,
    pub loop_detections: usize,
    pub holdover_transitions: usize,
    pub announces_forwarded: usize,
    pub announces_suppressed: usize,
}

impl PtpPathTraceEngine {
    pub fn new(clock_identity: ClockIdentity, local_priority: u8) -> Self {
        PtpPathTraceEngine {
            clock_identity,
            local_priority,
            upstream_state: UpstreamRefState::FreeRun,
            holdover_budget: HoldoverTimingBudget::default(),
            current_best_announce: None,
            loop_detections: 0,
            holdover_transitions: 0,
            announces_forwarded: 0,
            announces_suppressed: 0,
        }
    }

    /// Processes an incoming Announce message on a slave port.
    ///
    /// Returns `Ok(())` if accepted, or `Err(reason)` if rejected.
    pub fn process_incoming_announce(
        &mut self,
        announce: &TelecomAnnounce,
    ) -> Result<(), PathTraceRejectReason> {
        // 1. Loop detection: check if our own clock_identity is already in the path trace
        if announce.path_trace.would_create_loop(&self.clock_identity) {
            self.loop_detections += 1;
            return Err(PathTraceRejectReason::LoopDetected);
        }

        // 2. Excessive path depth check
        if announce.path_trace.depth() >= MAX_PATH_TRACE_DEPTH {
            return Err(PathTraceRejectReason::ExcessiveDepth);
        }

        // 3. Holdover clock class check: if GM is in holdover, note degradation
        let _is_holdover = matches!(
            announce.clock_class,
            CLOCK_CLASS_HOLDOVER_IN_SPEC | CLOCK_CLASS_HOLDOVER_OUT_OF_SPEC
        );

        // 4. Accept as current best (simplified — full BMCA comparison omitted, covered by ptp_telecom.rs)
        let should_accept = match &self.current_best_announce {
            None => true,
            Some(current) => {
                // Lower clockClass wins; on tie, fewer hops wins; on tie, lower clock_identity wins
                if announce.clock_class < current.clock_class {
                    true
                } else if announce.clock_class == current.clock_class {
                    if announce.steps_removed < current.steps_removed {
                        true
                    } else if announce.steps_removed == current.steps_removed {
                        announce.grandmaster_identity < current.grandmaster_identity
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
        };

        if should_accept {
            self.current_best_announce = Some(announce.clone());
            self.upstream_state = UpstreamRefState::Locked;
        }

        Ok(())
    }

    /// Generates an Announce message for downstream ports.
    ///
    /// Appends this T-BC's clock identity to the path trace and increments stepsRemoved.
    /// If in holdover, degrades the clockClass accordingly.
    pub fn generate_downstream_announce(&mut self) -> Option<TelecomAnnounce> {
        let base = self.current_best_announce.as_ref()?;

        let mut downstream = base.clone();
        downstream.source_clock_identity = self.clock_identity;
        downstream.steps_removed = base.steps_removed + 1;
        downstream.local_priority = self.local_priority;

        // Append our clock identity to the path trace
        if !downstream.path_trace.append(self.clock_identity) {
            self.announces_suppressed += 1;
            return None; // Path too deep
        }

        // Apply holdover degradation if upstream is lost
        match self.upstream_state {
            UpstreamRefState::Locked => {
                // clockClass remains as received from upstream
            }
            UpstreamRefState::HoldoverInSpec { elapsed_sec } => {
                downstream.clock_class = CLOCK_CLASS_HOLDOVER_IN_SPEC;
                if elapsed_sec > self.holdover_budget.holdover_in_spec_timeout_sec / 2 {
                    downstream.clock_accuracy = self.holdover_budget.degraded_accuracy;
                }
            }
            UpstreamRefState::HoldoverOutOfSpec => {
                downstream.clock_class = CLOCK_CLASS_HOLDOVER_OUT_OF_SPEC;
                downstream.clock_accuracy = self.holdover_budget.degraded_accuracy;
            }
            UpstreamRefState::FreeRun => {
                downstream.clock_class = CLOCK_CLASS_FREERUN;
                downstream.clock_accuracy = 0xFE; // Unknown
            }
        }

        self.announces_forwarded += 1;
        Some(downstream)
    }

    /// Signals that the upstream reference has been lost, transitioning to holdover.
    pub fn signal_upstream_loss(&mut self) {
        if self.upstream_state == UpstreamRefState::Locked {
            self.upstream_state = UpstreamRefState::HoldoverInSpec { elapsed_sec: 0 };
            self.holdover_transitions += 1;
        }
    }

    /// Advances the holdover timer by the given number of seconds.
    /// Automatically degrades from HoldoverInSpec → HoldoverOutOfSpec when budget expires.
    pub fn advance_holdover_timer(&mut self, elapsed_sec: u32) {
        if let UpstreamRefState::HoldoverInSpec {
            elapsed_sec: ref mut current,
        } = self.upstream_state
        {
            *current += elapsed_sec;
            if *current >= self.holdover_budget.holdover_in_spec_timeout_sec {
                self.upstream_state = UpstreamRefState::HoldoverOutOfSpec;
            }
        }
    }

    /// Signals that the upstream reference has been restored.
    pub fn signal_upstream_restore(&mut self) {
        self.upstream_state = UpstreamRefState::Locked;
    }

    /// Validates a complete path trace for loops (used at any node receiving an Announce).
    pub fn validate_path_trace(path_trace: &PathTraceTlv) -> PathTraceValidation {
        let mut seen: HashSet<ClockIdentity> = HashSet::new();
        for (idx, clock_id) in path_trace.path.iter().enumerate() {
            if !seen.insert(*clock_id) {
                return PathTraceValidation::LoopAt {
                    position: idx,
                    clock_id: *clock_id,
                };
            }
        }

        if path_trace.depth() > MAX_PATH_TRACE_DEPTH {
            PathTraceValidation::ExcessiveDepth {
                depth: path_trace.depth(),
            }
        } else {
            PathTraceValidation::Valid {
                depth: path_trace.depth(),
            }
        }
    }
}

/// Reason an incoming Announce with path trace was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathTraceRejectReason {
    LoopDetected,
    ExcessiveDepth,
}

/// Result of path trace validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathTraceValidation {
    Valid {
        depth: usize,
    },
    LoopAt {
        position: usize,
        clock_id: ClockIdentity,
    },
    ExcessiveDepth {
        depth: usize,
    },
}
