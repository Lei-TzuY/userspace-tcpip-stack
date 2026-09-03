// =============================================================================
// EVPN Layer 2 Unknown Unicast Egress Horizon Filtering & Pruning Engine
// (RFC 7432)
// =============================================================================
//
// When a VTEP receives a flooded Unknown Unicast (UU) frame from the fabric,
// it must decide which local ports should egress-replicate the frame and which
// should be pruned.  Blindly flooding to all local ports wastes bandwidth,
// especially on multi-homed Ethernet Segments (ES) where the frame may have
// originated from the same ES on another leaf.
//
// This module implements:
//   1. **Egress Horizon Group** — each local port is assigned a "horizon"
//      label.  Frames that arrived *from* a given horizon are never flooded
//      back to ports in the same horizon (split-horizon for UU traffic).
//   2. **Source ES pruning** — if the UU frame carries an originating ESI
//      (Ethernet Segment Identifier), all local ports belonging to that ESI
//      are pruned from the egress list.
//   3. **VLAN membership pruning** — frames are only forwarded to ports
//      that are active members of the frame's VLAN / VNI.
//   4. **Pruning statistics** for observability and debugging.
//
// Pure safe Rust, zero external crates.

/// A 10-byte Ethernet Segment Identifier (simplified as [u8; 10]).
pub type Esi = [u8; 10];

/// Horizon group identifier (arbitrary u32 label).
pub type HorizonId = u32;

/// Unique port identifier within a VTEP.
pub type PortId = u32;

/// An egress port's configuration for UU filtering.
#[derive(Debug, Clone)]
pub struct EgressPortConfig {
    pub port_id: PortId,
    /// Horizon group this port belongs to (split-horizon filtering).
    pub horizon: HorizonId,
    /// Ethernet Segment Identifier this port is associated with (0 = none).
    pub esi: Esi,
    /// Set of VNIs this port is an active member of.
    pub active_vnis: Vec<u32>,
}

/// The egress filtering verdict for a single port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressVerdict {
    /// The frame should be forwarded out this port.
    Forward,
    /// Pruned due to split-horizon (same horizon as ingress).
    PrunedHorizon,
    /// Pruned because the port belongs to the originating ESI.
    PrunedEsi,
    /// Pruned because the port is not a member of the frame's VNI.
    PrunedVni,
}

/// Per-port filtering result.
#[derive(Debug, Clone)]
pub struct PortEgressResult {
    pub port_id: PortId,
    pub verdict: EgressVerdict,
}

/// Aggregate pruning statistics.
#[derive(Debug, Clone, Default)]
pub struct PruningStats {
    pub total_frames_evaluated: u64,
    pub total_port_decisions: u64,
    pub forwarded: u64,
    pub pruned_horizon: u64,
    pub pruned_esi: u64,
    pub pruned_vni: u64,
}

/// EVPN Unknown Unicast Egress Horizon Filtering Engine.
pub struct EvpnUuEgressFilterEngine {
    /// Configured egress ports.
    ports: Vec<EgressPortConfig>,
    /// Cumulative statistics.
    stats: PruningStats,
}

impl EvpnUuEgressFilterEngine {
    pub fn new() -> Self {
        Self {
            ports: Vec::new(),
            stats: PruningStats::default(),
        }
    }

    /// Add or replace an egress port configuration.
    pub fn configure_port(&mut self, cfg: EgressPortConfig) {
        // Remove existing entry for this port, if any.
        self.ports.retain(|p| p.port_id != cfg.port_id);
        self.ports.push(cfg);
    }

    /// Remove a port from the engine.
    pub fn remove_port(&mut self, port_id: PortId) {
        self.ports.retain(|p| p.port_id != port_id);
    }

    /// Return the number of configured egress ports.
    pub fn port_count(&self) -> usize {
        self.ports.len()
    }

    /// Return current pruning statistics.
    pub fn stats(&self) -> &PruningStats {
        &self.stats
    }

    /// Reset statistics counters.
    pub fn reset_stats(&mut self) {
        self.stats = PruningStats::default();
    }

    /// Evaluate a single Unknown Unicast frame against all egress ports.
    ///
    /// Arguments:
    ///   - `ingress_horizon`: horizon group of the port where the frame arrived.
    ///   - `source_esi`: ESI of the originating Ethernet Segment (all-zero = none).
    ///   - `frame_vni`: VNI / broadcast domain of the frame.
    ///
    /// Returns a per-port verdict list.
    pub fn evaluate(
        &mut self,
        ingress_horizon: HorizonId,
        source_esi: &Esi,
        frame_vni: u32,
    ) -> Vec<PortEgressResult> {
        self.stats.total_frames_evaluated += 1;
        let esi_is_set = source_esi.iter().any(|&b| b != 0);

        let mut results = Vec::with_capacity(self.ports.len());
        for port in &self.ports {
            self.stats.total_port_decisions += 1;

            // 1. Split-horizon: same horizon → prune.
            if port.horizon == ingress_horizon && ingress_horizon != 0 {
                self.stats.pruned_horizon += 1;
                results.push(PortEgressResult {
                    port_id: port.port_id,
                    verdict: EgressVerdict::PrunedHorizon,
                });
                continue;
            }

            // 2. Source ESI pruning.
            if esi_is_set && port.esi == *source_esi {
                self.stats.pruned_esi += 1;
                results.push(PortEgressResult {
                    port_id: port.port_id,
                    verdict: EgressVerdict::PrunedEsi,
                });
                continue;
            }

            // 3. VNI membership check.
            if !port.active_vnis.contains(&frame_vni) {
                self.stats.pruned_vni += 1;
                results.push(PortEgressResult {
                    port_id: port.port_id,
                    verdict: EgressVerdict::PrunedVni,
                });
                continue;
            }

            // All checks passed — forward.
            self.stats.forwarded += 1;
            results.push(PortEgressResult {
                port_id: port.port_id,
                verdict: EgressVerdict::Forward,
            });
        }
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_esi(val: u8) -> Esi {
        let mut e = [0u8; 10];
        e[9] = val;
        e
    }

    #[test]
    fn test_horizon_pruning() {
        let mut engine = EvpnUuEgressFilterEngine::new();
        engine.configure_port(EgressPortConfig {
            port_id: 1,
            horizon: 10,
            esi: [0; 10],
            active_vnis: vec![100],
        });
        engine.configure_port(EgressPortConfig {
            port_id: 2,
            horizon: 20,
            esi: [0; 10],
            active_vnis: vec![100],
        });

        let results = engine.evaluate(10, &[0; 10], 100);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].verdict, EgressVerdict::PrunedHorizon); // port 1, same horizon
        assert_eq!(results[1].verdict, EgressVerdict::Forward); // port 2, different horizon
    }

    #[test]
    fn test_esi_pruning() {
        let mut engine = EvpnUuEgressFilterEngine::new();
        let esi_a = make_esi(0xAA);
        engine.configure_port(EgressPortConfig {
            port_id: 1,
            horizon: 0,
            esi: esi_a,
            active_vnis: vec![200],
        });
        engine.configure_port(EgressPortConfig {
            port_id: 2,
            horizon: 0,
            esi: [0; 10],
            active_vnis: vec![200],
        });

        let results = engine.evaluate(0, &esi_a, 200);
        assert_eq!(results[0].verdict, EgressVerdict::PrunedEsi);
        assert_eq!(results[1].verdict, EgressVerdict::Forward);
    }

    #[test]
    fn test_vni_pruning() {
        let mut engine = EvpnUuEgressFilterEngine::new();
        engine.configure_port(EgressPortConfig {
            port_id: 1,
            horizon: 0,
            esi: [0; 10],
            active_vnis: vec![100, 200],
        });
        engine.configure_port(EgressPortConfig {
            port_id: 2,
            horizon: 0,
            esi: [0; 10],
            active_vnis: vec![300],
        });

        let results = engine.evaluate(0, &[0; 10], 200);
        assert_eq!(results[0].verdict, EgressVerdict::Forward);
        assert_eq!(results[1].verdict, EgressVerdict::PrunedVni);
    }

    #[test]
    fn test_stats_accumulation() {
        let mut engine = EvpnUuEgressFilterEngine::new();
        engine.configure_port(EgressPortConfig {
            port_id: 1,
            horizon: 5,
            esi: [0; 10],
            active_vnis: vec![100],
        });
        engine.configure_port(EgressPortConfig {
            port_id: 2,
            horizon: 0,
            esi: [0; 10],
            active_vnis: vec![100],
        });

        engine.evaluate(5, &[0; 10], 100);
        engine.evaluate(0, &[0; 10], 100);

        let s = engine.stats();
        assert_eq!(s.total_frames_evaluated, 2);
        assert_eq!(s.total_port_decisions, 4);
        assert_eq!(s.pruned_horizon, 1);
        assert_eq!(s.forwarded, 3);
    }
}
