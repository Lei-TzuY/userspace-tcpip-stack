// =============================================================================
// IEEE 802.1Qch CQF Stream Priority Promotion & Preemption Fallback Engine
// =============================================================================
//
// In deterministic TSN CQF systems, transient buffering or transmission delays
// may cause frames to lag behind their scheduled forwarding cycle.
//
// The Priority Promotion Engine monitors frame residency age:
//   1. Normal Phase: Frame forwarded with base PCP (e.g. PCP 4).
//   2. Promotion Phase: If frame age exceeds `promote_threshold_ns`, priority is
//      dynamically elevated to `promoted_pcp` (e.g. PCP 7) to guarantee immediate
//      egress before deadline expiry.
//   3. Deadline Expiry: If frame age exceeds `drop_deadline_ns`, frame is dropped.
//   4. Fallback Demotion: If expedited queue is saturated, frame falls back to
//      preemption-capable best-effort queue.
//
// Pure safe Rust, zero external crates.

/// Priority promotion decision verdict for a metered frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PriorityPromoteVerdict {
    /// Forwarded with original base priority.
    Normal { pcp: u8, age_ns: u64 },
    /// Elevated to higher priority due to nearing deadline.
    Promoted {
        original_pcp: u8,
        promoted_pcp: u8,
        age_ns: u64,
    },
    /// Demoted to best-effort preemption queue due to high-priority buffer full.
    PreemptionFallback { fallback_pcp: u8 },
    /// Dropped because deadline has expired.
    DeadlineMissDrop { age_ns: u64, max_allowed_ns: u64 },
}

/// Profile for priority-promotable TSN stream.
#[derive(Debug, Clone)]
pub struct PrioPromoteProfile {
    pub stream_id: u32,
    pub name: String,
    pub base_pcp: u8,
    pub promoted_pcp: u8,
    pub fallback_pcp: u8,
    pub promote_threshold_ns: u64,
    pub drop_deadline_ns: u64,
    pub total_normal: u64,
    pub total_promoted: u64,
    pub total_fallbacks: u64,
    pub total_deadline_misses: u64,
}

impl PrioPromoteProfile {
    pub fn new(
        stream_id: u32,
        name: &str,
        base_pcp: u8,
        promoted_pcp: u8,
        fallback_pcp: u8,
        promote_threshold_ns: u64,
        drop_deadline_ns: u64,
    ) -> Self {
        Self {
            stream_id,
            name: name.to_string(),
            base_pcp: base_pcp.min(7),
            promoted_pcp: promoted_pcp.min(7),
            fallback_pcp: fallback_pcp.min(7),
            promote_threshold_ns,
            drop_deadline_ns,
            total_normal: 0,
            total_promoted: 0,
            total_fallbacks: 0,
            total_deadline_misses: 0,
        }
    }
}

/// TSN CQF Priority Promotion & Preemption Fallback Engine.
pub struct TsnCqfPrioPromoteEngine {
    pub high_prio_capacity: usize,
    pub high_prio_current_count: usize,
    pub streams: Vec<PrioPromoteProfile>,
}

impl TsnCqfPrioPromoteEngine {
    pub fn new(high_prio_capacity: usize) -> Self {
        Self {
            high_prio_capacity,
            high_prio_current_count: 0,
            streams: Vec::new(),
        }
    }

    /// Register or update a stream profile.
    pub fn register_stream(&mut self, profile: PrioPromoteProfile) {
        if let Some(pos) = self
            .streams
            .iter()
            .position(|s| s.stream_id == profile.stream_id)
        {
            self.streams[pos] = profile;
        } else {
            self.streams.push(profile);
        }
    }

    /// Evaluate frame residency age and determine forwarding priority.
    pub fn evaluate_frame(&mut self, stream_id: u32, age_ns: u64) -> PriorityPromoteVerdict {
        let stream = match self.streams.iter_mut().find(|s| s.stream_id == stream_id) {
            Some(s) => s,
            None => {
                return PriorityPromoteVerdict::DeadlineMissDrop {
                    age_ns,
                    max_allowed_ns: 0,
                };
            }
        };

        if age_ns >= stream.drop_deadline_ns {
            stream.total_deadline_misses += 1;
            PriorityPromoteVerdict::DeadlineMissDrop {
                age_ns,
                max_allowed_ns: stream.drop_deadline_ns,
            }
        } else if age_ns >= stream.promote_threshold_ns {
            if self.high_prio_current_count < self.high_prio_capacity {
                self.high_prio_current_count += 1;
                stream.total_promoted += 1;
                PriorityPromoteVerdict::Promoted {
                    original_pcp: stream.base_pcp,
                    promoted_pcp: stream.promoted_pcp,
                    age_ns,
                }
            } else {
                stream.total_fallbacks += 1;
                PriorityPromoteVerdict::PreemptionFallback {
                    fallback_pcp: stream.fallback_pcp,
                }
            }
        } else {
            stream.total_normal += 1;
            PriorityPromoteVerdict::Normal {
                pcp: stream.base_pcp,
                age_ns,
            }
        }
    }

    /// Reset high-priority queue counter at cycle boundary.
    pub fn reset_cycle(&mut self) {
        self.high_prio_current_count = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_promotion_lifecycle() {
        let mut engine = TsnCqfPrioPromoteEngine::new(2);

        // Base PCP 3, Promoted PCP 7, Fallback PCP 1, Promote at 40µs, Drop at 80µs
        let profile = PrioPromoteProfile::new(10, "Avionics-Sensors", 3, 7, 1, 40_000, 80_000);
        engine.register_stream(profile);

        // 1. Normal age (20µs < 40µs)
        assert_eq!(
            engine.evaluate_frame(10, 20_000),
            PriorityPromoteVerdict::Normal {
                pcp: 3,
                age_ns: 20_000
            }
        );

        // 2. Promotion age (50µs >= 40µs) -> Promoted to 7
        assert_eq!(
            engine.evaluate_frame(10, 50_000),
            PriorityPromoteVerdict::Promoted {
                original_pcp: 3,
                promoted_pcp: 7,
                age_ns: 50_000
            }
        );

        // 3. Second promotion -> high prio count reaches 2 (capacity)
        assert_eq!(
            engine.evaluate_frame(10, 60_000),
            PriorityPromoteVerdict::Promoted {
                original_pcp: 3,
                promoted_pcp: 7,
                age_ns: 60_000
            }
        );

        // 4. Third promotion exceeds capacity (2) -> Fallback to PCP 1
        assert_eq!(
            engine.evaluate_frame(10, 65_000),
            PriorityPromoteVerdict::PreemptionFallback { fallback_pcp: 1 }
        );

        // 5. Exceeded deadline (90µs > 80µs) -> Miss Drop
        assert_eq!(
            engine.evaluate_frame(10, 90_000),
            PriorityPromoteVerdict::DeadlineMissDrop {
                age_ns: 90_000,
                max_allowed_ns: 80_000
            }
        );
    }
}
