// =============================================================================
// EVPN Layer 2 MAC Address Mobility Freeze & Move Flap Damping Engine
// (RFC 7432 Section 15)
// =============================================================================
//
// In EVPN fabrics, rapid host flapping (e.g. misconfigured teaming, bridging
// loops, or VM migration storms) causes high control plane churn and route
// oscillation. RFC 7432 specifies that if a MAC address moves more than `N`
// times within `M` seconds (the detection window), the VTEP must declare the
// MAC address as duplicate / frozen and cease generating further BGP EVPN
// MAC/IP Advertisement (Route Type 2) updates.
//
// Features:
//   1. Sliding Window Move Detection: Tracks move timestamps per (VNI, MAC).
//   2. Automatic Quarantine / Freeze: Locks MAC into `Frozen` state when moves
//      exceed the configured threshold.
//   3. Sequence Number Progression: Maintains sequence counter during valid
//      moves before threshold breach.
//   4. Timed Unfreeze & Manual Recovery: Automatically restores normal learning
//      after freeze timer expiry or manual administrative intervention.
//
// Pure safe Rust, zero external crates.

use crate::ethernet::MacAddress;
use crate::ipv4::Ipv4Address;

/// Default move limit threshold before freeze.
pub const DEFAULT_MAX_MOVES: u32 = 5;

/// Default move observation window in seconds.
pub const DEFAULT_MOVE_WINDOW_SECS: u64 = 180;

/// Default freeze quarantine duration in seconds.
pub const DEFAULT_FREEZE_DURATION_SECS: u64 = 300;

/// State of a MAC entry under mobility tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacMobilityState {
    /// Normal operating state.
    Normal,
    /// Frozen due to excessive flapping.
    Frozen { frozen_until_secs: u64 },
}

/// Record of a tracked MAC address in a specific VNI.
#[derive(Debug, Clone)]
pub struct TrackedMacEntry {
    pub vni: u32,
    pub mac: MacAddress,
    pub current_vtep: Ipv4Address,
    pub seq_number: u32,
    pub move_timestamps: Vec<u64>,
    pub state: MacMobilityState,
    pub total_moves: u64,
}

/// Action verdict from a MAC move attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacMoveVerdict {
    /// Move accepted and sequence number incremented.
    Accepted { new_seq: u32 },
    /// Move suppressed because the MAC is currently frozen.
    SuppressedFrozen,
    /// Move triggered a new freeze condition.
    FreezeTriggered { moves_in_window: usize },
    /// No move (same VTEP location).
    NoChange,
}

/// EVPN MAC Address Mobility Freeze & Damping Engine.
pub struct EvpnMacFreezeEngine {
    pub max_moves: u32,
    pub window_secs: u64,
    pub freeze_duration_secs: u64,
    pub tracked_macs: Vec<TrackedMacEntry>,
    pub total_freezes_triggered: u64,
    pub total_unfreezes: u64,
}

impl EvpnMacFreezeEngine {
    pub fn new(max_moves: u32, window_secs: u64, freeze_duration_secs: u64) -> Self {
        Self {
            max_moves: if max_moves == 0 {
                DEFAULT_MAX_MOVES
            } else {
                max_moves
            },
            window_secs: if window_secs == 0 {
                DEFAULT_MOVE_WINDOW_SECS
            } else {
                window_secs
            },
            freeze_duration_secs: if freeze_duration_secs == 0 {
                DEFAULT_FREEZE_DURATION_SECS
            } else {
                freeze_duration_secs
            },
            tracked_macs: Vec::new(),
            total_freezes_triggered: 0,
            total_unfreezes: 0,
        }
    }

    /// Register or learn an initial MAC location.
    pub fn learn_initial(&mut self, vni: u32, mac: MacAddress, vtep: Ipv4Address, now_secs: u64) {
        if !self
            .tracked_macs
            .iter()
            .any(|e| e.vni == vni && e.mac == mac)
        {
            self.tracked_macs.push(TrackedMacEntry {
                vni,
                mac,
                current_vtep: vtep,
                seq_number: 0,
                move_timestamps: vec![now_secs],
                state: MacMobilityState::Normal,
                total_moves: 0,
            });
        }
    }

    /// Record a MAC move to a new VTEP.
    pub fn record_move(
        &mut self,
        vni: u32,
        mac: MacAddress,
        new_vtep: Ipv4Address,
        now_secs: u64,
    ) -> MacMoveVerdict {
        // Clean up expired frozen states first
        self.cleanup_expired_freezes(now_secs);

        let window = self.window_secs;
        let freeze_dur = self.freeze_duration_secs;
        let max_m = self.max_moves;

        let entry = match self
            .tracked_macs
            .iter_mut()
            .find(|e| e.vni == vni && e.mac == mac)
        {
            Some(e) => e,
            None => {
                // First time seeing this MAC
                self.tracked_macs.push(TrackedMacEntry {
                    vni,
                    mac,
                    current_vtep: new_vtep,
                    seq_number: 0,
                    move_timestamps: vec![now_secs],
                    state: MacMobilityState::Normal,
                    total_moves: 0,
                });
                return MacMoveVerdict::Accepted { new_seq: 0 };
            }
        };

        if let MacMobilityState::Frozen { .. } = entry.state {
            return MacMoveVerdict::SuppressedFrozen;
        }

        if entry.current_vtep == new_vtep {
            return MacMoveVerdict::NoChange;
        }

        // Retain only moves within the sliding window
        entry
            .move_timestamps
            .retain(|&t| now_secs.saturating_sub(t) <= window);
        entry.move_timestamps.push(now_secs);
        entry.total_moves += 1;
        entry.current_vtep = new_vtep;
        entry.seq_number = entry.seq_number.saturating_add(1);

        let moves_count = entry.move_timestamps.len();
        if moves_count > max_m as usize {
            entry.state = MacMobilityState::Frozen {
                frozen_until_secs: now_secs.saturating_add(freeze_dur),
            };
            self.total_freezes_triggered += 1;
            MacMoveVerdict::FreezeTriggered {
                moves_in_window: moves_count,
            }
        } else {
            MacMoveVerdict::Accepted {
                new_seq: entry.seq_number,
            }
        }
    }

    /// Automatically unfreeze MACs whose freeze duration has elapsed.
    pub fn cleanup_expired_freezes(&mut self, now_secs: u64) {
        for entry in &mut self.tracked_macs {
            if let MacMobilityState::Frozen { frozen_until_secs } = entry.state {
                if now_secs >= frozen_until_secs {
                    entry.state = MacMobilityState::Normal;
                    entry.move_timestamps.clear();
                    self.total_unfreezes += 1;
                }
            }
        }
    }

    /// Manually unfreeze a specific MAC address.
    pub fn unfreeze_mac(&mut self, vni: u32, mac: MacAddress) -> bool {
        if let Some(entry) = self
            .tracked_macs
            .iter_mut()
            .find(|e| e.vni == vni && e.mac == mac)
        {
            if let MacMobilityState::Frozen { .. } = entry.state {
                entry.state = MacMobilityState::Normal;
                entry.move_timestamps.clear();
                self.total_unfreezes += 1;
                return true;
            }
        }
        false
    }

    /// Retrieve entry state for diagnostics.
    pub fn get_entry(&self, vni: u32, mac: MacAddress) -> Option<&TrackedMacEntry> {
        self.tracked_macs
            .iter()
            .find(|e| e.vni == vni && e.mac == mac)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_freeze_lifecycle() {
        let mut engine = EvpnMacFreezeEngine::new(3, 60, 120); // max 3 moves in 60s -> freeze for 120s
        let mac = MacAddress([0x52, 0x54, 0x00, 0x11, 0x22, 0x33]);
        let vtep_a = Ipv4Address::new(10, 0, 0, 1);
        let vtep_b = Ipv4Address::new(10, 0, 0, 2);
        let vtep_c = Ipv4Address::new(10, 0, 0, 3);

        engine.learn_initial(100, mac, vtep_a, 10);

        // Move 1
        assert!(matches!(
            engine.record_move(100, mac, vtep_b, 15),
            MacMoveVerdict::Accepted { new_seq: 1 }
        ));

        // Move 2
        assert!(matches!(
            engine.record_move(100, mac, vtep_c, 20),
            MacMoveVerdict::Accepted { new_seq: 2 }
        ));

        // Move 3 (4 moves in window [10, 15, 20, 25] > 3) -> Freeze!
        assert!(matches!(
            engine.record_move(100, mac, vtep_a, 25),
            MacMoveVerdict::FreezeTriggered { moves_in_window: 4 }
        ));

        // Next move while frozen -> Suppressed
        assert_eq!(
            engine.record_move(100, mac, vtep_b, 30),
            MacMoveVerdict::SuppressedFrozen
        );

        // Advance past freeze duration (25 + 120 = 145s) -> auto unfreeze
        engine.cleanup_expired_freezes(150);
        let entry = engine.get_entry(100, mac).unwrap();
        assert_eq!(entry.state, MacMobilityState::Normal);
    }
}
