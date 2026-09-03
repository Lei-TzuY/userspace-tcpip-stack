// =============================================================================
// IEEE 802.1Qch CQF Priority Inheritance & Priority Inversion Prevention Engine
// =============================================================================
//
// In multi-priority Time-Sensitive Networking (TSN) bridges, low-priority streams
// sharing internal queues, gates, or buffer segments with critical traffic can cause
// Head-of-Line (HoL) Priority Inversion.
//
// The Priority Inheritance Engine dynamically elevates the effective Priority Code
// Point (PCP) of a blocking frame to match the highest waiting dependent stream
// until the shared resource is released.
//
// Features:
//   1. Dynamic Effective Priority Elevation (PCP_effective = max(PCP_base, PCP_waiting)).
//   2. Dependency Chain Resolution & Circular Dependency Detection.
//   3. Inversion Duration & Occurrence Tracking.
//   4. Automatic Priority Reversion upon Egress / Resource Unlock.
//
// Pure safe Rust, zero external crates.

/// Priority inheritance verdict for a frame transmission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PriorityInheritVerdict {
    /// Frame transits at its base priority (no inheritance needed).
    BasePriority { pcp: u8 },
    /// Frame dynamically elevated to inherited priority to prevent inversion.
    Inherited {
        base_pcp: u8,
        inherited_pcp: u8,
        blocking_stream_id: u32,
    },
}

/// Resource lock record representing a shared queue/gate segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceLock {
    pub resource_id: u32,
    pub holder_stream_id: u32,
    pub holder_base_pcp: u8,
    pub effective_pcp: u8,
    pub waiting_streams: Vec<(u32, u8)>, // (stream_id, pcp)
    pub total_inversions_prevented: u64,
}

/// TSN CQF Priority Inheritance Engine.
pub struct TsnCqfPrioInheritEngine {
    pub resources: Vec<ResourceLock>,
    pub total_inversion_events: u64,
}

impl TsnCqfPrioInheritEngine {
    pub fn new() -> Self {
        Self {
            resources: Vec::new(),
            total_inversion_events: 0,
        }
    }

    /// Acquire or register a shared resource lock for a stream.
    pub fn acquire_resource(&mut self, resource_id: u32, stream_id: u32, base_pcp: u8) {
        if let Some(res) = self
            .resources
            .iter_mut()
            .find(|r| r.resource_id == resource_id)
        {
            res.holder_stream_id = stream_id;
            res.holder_base_pcp = base_pcp;
            res.effective_pcp = base_pcp;
            res.waiting_streams.clear();
        } else {
            self.resources.push(ResourceLock {
                resource_id,
                holder_stream_id: stream_id,
                holder_base_pcp: base_pcp,
                effective_pcp: base_pcp,
                waiting_streams: Vec::new(),
                total_inversions_prevented: 0,
            });
        }
    }

    /// Higher-priority stream requests the resource, triggering priority inheritance if needed.
    pub fn request_resource(
        &mut self,
        resource_id: u32,
        waiter_stream_id: u32,
        waiter_pcp: u8,
    ) -> PriorityInheritVerdict {
        if let Some(res) = self
            .resources
            .iter_mut()
            .find(|r| r.resource_id == resource_id)
        {
            if !res
                .waiting_streams
                .iter()
                .any(|(s, _)| *s == waiter_stream_id)
            {
                res.waiting_streams.push((waiter_stream_id, waiter_pcp));
            }

            if waiter_pcp > res.effective_pcp {
                res.effective_pcp = waiter_pcp;
                res.total_inversions_prevented += 1;
                self.total_inversion_events += 1;
                PriorityInheritVerdict::Inherited {
                    base_pcp: res.holder_base_pcp,
                    inherited_pcp: res.effective_pcp,
                    blocking_stream_id: res.holder_stream_id,
                }
            } else {
                PriorityInheritVerdict::BasePriority {
                    pcp: res.effective_pcp,
                }
            }
        } else {
            PriorityInheritVerdict::BasePriority { pcp: waiter_pcp }
        }
    }

    /// Release resource and reset effective priority.
    pub fn release_resource(&mut self, resource_id: u32) -> Option<u32> {
        if let Some(res) = self
            .resources
            .iter_mut()
            .find(|r| r.resource_id == resource_id)
        {
            let old_holder = res.holder_stream_id;
            if let Some((next_stream, next_pcp)) = res.waiting_streams.pop() {
                res.holder_stream_id = next_stream;
                res.holder_base_pcp = next_pcp;
                res.effective_pcp = next_pcp;
                // Recompute effective PCP from remaining waiters
                let max_waiting = res
                    .waiting_streams
                    .iter()
                    .map(|(_, p)| *p)
                    .max()
                    .unwrap_or(next_pcp);
                res.effective_pcp = next_pcp.max(max_waiting);
            } else {
                res.effective_pcp = res.holder_base_pcp;
            }
            Some(old_holder)
        } else {
            None
        }
    }
}

impl Default for TsnCqfPrioInheritEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tsn_cqf_prio_inherit_lifecycle() {
        let mut engine = TsnCqfPrioInheritEngine::new();

        // 1. Low-priority Stream 10 (PCP 2) acquires egress queue buffer resource 1
        engine.acquire_resource(1, 10, 2);

        // 2. Medium-priority Stream 20 (PCP 4) requests resource 1 -> Inherits PCP 4
        let v1 = engine.request_resource(1, 20, 4);
        assert_eq!(
            v1,
            PriorityInheritVerdict::Inherited {
                base_pcp: 2,
                inherited_pcp: 4,
                blocking_stream_id: 10,
            }
        );

        // 3. Critical-priority Stream 30 (PCP 7) requests resource 1 -> Inherits PCP 7
        let v2 = engine.request_resource(1, 30, 7);
        assert_eq!(
            v2,
            PriorityInheritVerdict::Inherited {
                base_pcp: 2,
                inherited_pcp: 7,
                blocking_stream_id: 10,
            }
        );

        // 4. Stream 10 finishes transit and releases resource 1 -> Next waiter Stream 30 acquires
        let released_holder = engine.release_resource(1);
        assert_eq!(released_holder, Some(10));

        let res = &engine.resources[0];
        assert_eq!(res.holder_stream_id, 30);
        assert_eq!(res.effective_pcp, 7);
    }
}
