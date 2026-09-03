//! IEEE 802.1Qch CQF Hot-Standby Dual-Plane Redundancy & Active-Passive Gate Coordination Engine.
//!
//! Provides ultra-reliable deterministic cyclic queue coordination across dual independent
//! transmission planes (Plane A & Plane B) for mission-critical industrial automation and
//! aerospace avionics networks. Supports hitless active-standby switchover and dual-active
//! frame replication with dynamic health monitoring.

use std::fmt;

/// Identifies the cyclic transmission plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TsnPlane {
    PlaneA,
    PlaneB,
}

impl fmt::Display for TsnPlane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TsnPlane::PlaneA => write!(f, "Plane-A"),
            TsnPlane::PlaneB => write!(f, "Plane-B"),
        }
    }
}

/// Operational state of a cyclic transmission plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaneState {
    Active,
    Standby,
    Degraded,
    Failed,
}

/// Redundancy operational mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DualPlaneMode {
    /// Primary plane forwards traffic; secondary plane is hot-standby with live cycle synchronization.
    ActiveStandby,
    /// Both planes forward in parallel for dual-path replication.
    DualActiveReplication,
}

/// Health and telemetry metrics for a transmission plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaneMetrics {
    pub tx_frames: u64,
    pub tx_bytes: u64,
    pub cycle_overruns: u64,
    pub consecutive_drops: u32,
    pub health_score: u8, // 0..100
}

impl Default for PlaneMetrics {
    fn default() -> Self {
        Self {
            tx_frames: 0,
            tx_bytes: 0,
            cycle_overruns: 0,
            consecutive_drops: 0,
            health_score: 100,
        }
    }
}

/// Verdict returned when dispatching a time-critical cyclic frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DualPlaneDispatchVerdict {
    ForwardSinglePlane {
        plane: TsnPlane,
        target_cycle: u64,
        frame_bytes: usize,
    },
    ForwardReplicatedBothPlanes {
        cycle_a: u64,
        cycle_b: u64,
        frame_bytes: usize,
    },
    FailoverTriggeredAndForwarded {
        from_plane: TsnPlane,
        to_plane: TsnPlane,
        reason: String,
        target_cycle: u64,
        frame_bytes: usize,
    },
    AllPlanesFailedDrop {
        stream_id: u32,
        frame_bytes: usize,
    },
}

/// IEEE 802.1Qch CQF Dual-Plane Redundancy & Coordination Engine.
#[derive(Debug, Clone)]
pub struct TsnCqfDualPlaneEngine {
    pub cycle_duration_ns: u64,
    pub mode: DualPlaneMode,
    pub active_plane: TsnPlane,
    pub plane_a_state: PlaneState,
    pub plane_b_state: PlaneState,
    pub plane_a_metrics: PlaneMetrics,
    pub plane_b_metrics: PlaneMetrics,
    pub failover_threshold_score: u8,
    pub total_failovers: u64,
    pub total_dispatches: u64,
    pub total_drops: u64,
}

impl TsnCqfDualPlaneEngine {
    /// Creates a new Dual-Plane CQF Engine with default active Plane A.
    pub fn new(cycle_duration_ns: u64) -> Self {
        Self {
            cycle_duration_ns,
            mode: DualPlaneMode::ActiveStandby,
            active_plane: TsnPlane::PlaneA,
            plane_a_state: PlaneState::Active,
            plane_b_state: PlaneState::Standby,
            plane_a_metrics: PlaneMetrics::default(),
            plane_b_metrics: PlaneMetrics::default(),
            failover_threshold_score: 50,
            total_failovers: 0,
            total_dispatches: 0,
            total_drops: 0,
        }
    }

    /// Sets the redundancy mode.
    pub fn set_mode(&mut self, mode: DualPlaneMode) {
        self.mode = mode;
        match mode {
            DualPlaneMode::ActiveStandby => {
                if self.active_plane == TsnPlane::PlaneA {
                    if self.plane_a_state != PlaneState::Failed {
                        self.plane_a_state = PlaneState::Active;
                    }
                    if self.plane_b_state != PlaneState::Failed {
                        self.plane_b_state = PlaneState::Standby;
                    }
                } else {
                    if self.plane_b_state != PlaneState::Failed {
                        self.plane_b_state = PlaneState::Active;
                    }
                    if self.plane_a_state != PlaneState::Failed {
                        self.plane_a_state = PlaneState::Standby;
                    }
                }
            }
            DualPlaneMode::DualActiveReplication => {
                if self.plane_a_state != PlaneState::Failed {
                    self.plane_a_state = PlaneState::Active;
                }
                if self.plane_b_state != PlaneState::Failed {
                    self.plane_b_state = PlaneState::Active;
                }
            }
        }
    }

    /// Updates health metrics for a given plane.
    pub fn update_plane_telemetry(
        &mut self,
        plane: TsnPlane,
        cycle_overruns: u64,
        consecutive_drops: u32,
        health_score: u8,
    ) {
        let (metrics, state) = match plane {
            TsnPlane::PlaneA => (&mut self.plane_a_metrics, &mut self.plane_a_state),
            TsnPlane::PlaneB => (&mut self.plane_b_metrics, &mut self.plane_b_state),
        };

        metrics.cycle_overruns = cycle_overruns;
        metrics.consecutive_drops = consecutive_drops;
        metrics.health_score = health_score.min(100);

        if health_score == 0 || consecutive_drops >= 5 {
            *state = PlaneState::Failed;
        } else if health_score < self.failover_threshold_score {
            *state = PlaneState::Degraded;
        } else if self.mode == DualPlaneMode::DualActiveReplication
            || (*state == PlaneState::Active || *state == PlaneState::Standby)
        {
            if self.mode == DualPlaneMode::ActiveStandby {
                if self.active_plane == plane {
                    *state = PlaneState::Active;
                } else {
                    *state = PlaneState::Standby;
                }
            } else {
                *state = PlaneState::Active;
            }
        }
    }

    /// Dispatches a cyclic frame across the dual planes according to policy and health status.
    pub fn dispatch_frame(
        &mut self,
        stream_id: u32,
        frame_bytes: usize,
        time_ns: u64,
    ) -> DualPlaneDispatchVerdict {
        self.total_dispatches += 1;
        let target_cycle = (time_ns / self.cycle_duration_ns) + 1;

        match self.mode {
            DualPlaneMode::DualActiveReplication => {
                let a_ok = self.plane_a_state != PlaneState::Failed;
                let b_ok = self.plane_b_state != PlaneState::Failed;

                if a_ok && b_ok {
                    self.plane_a_metrics.tx_frames += 1;
                    self.plane_a_metrics.tx_bytes += frame_bytes as u64;
                    self.plane_b_metrics.tx_frames += 1;
                    self.plane_b_metrics.tx_bytes += frame_bytes as u64;

                    DualPlaneDispatchVerdict::ForwardReplicatedBothPlanes {
                        cycle_a: target_cycle,
                        cycle_b: target_cycle,
                        frame_bytes,
                    }
                } else if a_ok {
                    self.plane_a_metrics.tx_frames += 1;
                    self.plane_a_metrics.tx_bytes += frame_bytes as u64;
                    DualPlaneDispatchVerdict::ForwardSinglePlane {
                        plane: TsnPlane::PlaneA,
                        target_cycle,
                        frame_bytes,
                    }
                } else if b_ok {
                    self.plane_b_metrics.tx_frames += 1;
                    self.plane_b_metrics.tx_bytes += frame_bytes as u64;
                    DualPlaneDispatchVerdict::ForwardSinglePlane {
                        plane: TsnPlane::PlaneB,
                        target_cycle,
                        frame_bytes,
                    }
                } else {
                    self.total_drops += 1;
                    DualPlaneDispatchVerdict::AllPlanesFailedDrop {
                        stream_id,
                        frame_bytes,
                    }
                }
            }
            DualPlaneMode::ActiveStandby => {
                let (active_state, standby_plane, standby_state) = match self.active_plane {
                    TsnPlane::PlaneA => (self.plane_a_state, TsnPlane::PlaneB, self.plane_b_state),
                    TsnPlane::PlaneB => (self.plane_b_state, TsnPlane::PlaneA, self.plane_a_state),
                };

                // Check if active plane requires failover
                if active_state == PlaneState::Failed || active_state == PlaneState::Degraded {
                    if standby_state == PlaneState::Standby || standby_state == PlaneState::Active {
                        // Execute failover
                        let old_plane = self.active_plane;
                        self.active_plane = standby_plane;
                        self.total_failovers += 1;

                        match self.active_plane {
                            TsnPlane::PlaneA => {
                                self.plane_a_state = PlaneState::Active;
                                self.plane_a_metrics.tx_frames += 1;
                                self.plane_a_metrics.tx_bytes += frame_bytes as u64;
                            }
                            TsnPlane::PlaneB => {
                                self.plane_b_state = PlaneState::Active;
                                self.plane_b_metrics.tx_frames += 1;
                                self.plane_b_metrics.tx_bytes += frame_bytes as u64;
                            }
                        }

                        let reason = if active_state == PlaneState::Failed {
                            format!("Primary {} completely failed (Health 0)", old_plane)
                        } else {
                            format!(
                                "Primary {} degraded below threshold (Score {})",
                                old_plane,
                                if old_plane == TsnPlane::PlaneA {
                                    self.plane_a_metrics.health_score
                                } else {
                                    self.plane_b_metrics.health_score
                                }
                            )
                        };

                        return DualPlaneDispatchVerdict::FailoverTriggeredAndForwarded {
                            from_plane: old_plane,
                            to_plane: self.active_plane,
                            reason,
                            target_cycle,
                            frame_bytes,
                        };
                    }
                }

                // If active plane is still usable
                if active_state != PlaneState::Failed {
                    match self.active_plane {
                        TsnPlane::PlaneA => {
                            self.plane_a_metrics.tx_frames += 1;
                            self.plane_a_metrics.tx_bytes += frame_bytes as u64;
                        }
                        TsnPlane::PlaneB => {
                            self.plane_b_metrics.tx_frames += 1;
                            self.plane_b_metrics.tx_bytes += frame_bytes as u64;
                        }
                    }

                    DualPlaneDispatchVerdict::ForwardSinglePlane {
                        plane: self.active_plane,
                        target_cycle,
                        frame_bytes,
                    }
                } else if standby_state != PlaneState::Failed {
                    // Active failed and standby degraded but alive
                    let old_plane = self.active_plane;
                    self.active_plane = standby_plane;
                    self.total_failovers += 1;
                    match self.active_plane {
                        TsnPlane::PlaneA => {
                            self.plane_a_state = PlaneState::Active;
                            self.plane_a_metrics.tx_frames += 1;
                            self.plane_a_metrics.tx_bytes += frame_bytes as u64;
                        }
                        TsnPlane::PlaneB => {
                            self.plane_b_state = PlaneState::Active;
                            self.plane_b_metrics.tx_bytes += frame_bytes as u64;
                        }
                    }
                    DualPlaneDispatchVerdict::FailoverTriggeredAndForwarded {
                        from_plane: old_plane,
                        to_plane: self.active_plane,
                        reason: "Active failed, switched to degraded standby".to_string(),
                        target_cycle,
                        frame_bytes,
                    }
                } else {
                    self.total_drops += 1;
                    DualPlaneDispatchVerdict::AllPlanesFailedDrop {
                        stream_id,
                        frame_bytes,
                    }
                }
            }
        }
    }

    /// Resets the dual-plane engine to default state.
    pub fn reset(&mut self) {
        self.active_plane = TsnPlane::PlaneA;
        self.plane_a_state = PlaneState::Active;
        self.plane_b_state = PlaneState::Standby;
        self.plane_a_metrics = PlaneMetrics::default();
        self.plane_b_metrics = PlaneMetrics::default();
        self.total_failovers = 0;
        self.total_dispatches = 0;
        self.total_drops = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tsn_cqf_dual_plane_lifecycle() {
        let mut engine = TsnCqfDualPlaneEngine::new(100_000);

        // 1. Initial dispatch on active Plane A
        let v1 = engine.dispatch_frame(1, 1500, 25_000);
        assert_eq!(
            v1,
            DualPlaneDispatchVerdict::ForwardSinglePlane {
                plane: TsnPlane::PlaneA,
                target_cycle: 1,
                frame_bytes: 1500,
            }
        );
        assert_eq!(engine.plane_a_metrics.tx_frames, 1);

        // 2. Degrade Plane A -> triggers failover to Plane B
        engine.update_plane_telemetry(TsnPlane::PlaneA, 5, 2, 40);
        assert_eq!(engine.plane_a_state, PlaneState::Degraded);

        let v2 = engine.dispatch_frame(1, 1200, 125_000);
        match v2 {
            DualPlaneDispatchVerdict::FailoverTriggeredAndForwarded {
                from_plane,
                to_plane,
                target_cycle,
                frame_bytes,
                ..
            } => {
                assert_eq!(from_plane, TsnPlane::PlaneA);
                assert_eq!(to_plane, TsnPlane::PlaneB);
                assert_eq!(target_cycle, 2);
                assert_eq!(frame_bytes, 1200);
            }
            _ => panic!("Expected failover verdict"),
        }
        assert_eq!(engine.active_plane, TsnPlane::PlaneB);
        assert_eq!(engine.total_failovers, 1);

        // 3. Switch to DualActiveReplication mode
        engine.set_mode(DualPlaneMode::DualActiveReplication);
        engine.update_plane_telemetry(TsnPlane::PlaneA, 0, 0, 100);
        let v3 = engine.dispatch_frame(2, 800, 205_000);
        assert_eq!(
            v3,
            DualPlaneDispatchVerdict::ForwardReplicatedBothPlanes {
                cycle_a: 3,
                cycle_b: 3,
                frame_bytes: 800,
            }
        );

        // 4. Fail both planes -> drop
        engine.update_plane_telemetry(TsnPlane::PlaneA, 10, 6, 0);
        engine.update_plane_telemetry(TsnPlane::PlaneB, 10, 6, 0);
        let v4 = engine.dispatch_frame(3, 500, 305_000);
        assert_eq!(
            v4,
            DualPlaneDispatchVerdict::AllPlanesFailedDrop {
                stream_id: 3,
                frame_bytes: 500,
            }
        );
        assert_eq!(engine.total_drops, 1);
    }
}
