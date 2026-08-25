//! IEEE 802.1Qbv Time-Aware Shaper (TAS) Dynamic GCL Reconfiguration & Hitless Admin-to-Oper Cycle Swap.
//!
//! In Time-Sensitive Networking (TSN), industrial automation and automotive networks
//! must dynamically update their Gate Control Lists (GCL) without interrupting ongoing
//! real-time traffic or causing frame truncation.
//!
//! IEEE 802.1Qbv Section 8.6.9 defines the Admin/Oper GCL state machine:
//! 1. **OperGcl**: The currently active operational gate schedule driving transmission gates.
//! 2. **AdminGcl**: The newly configured administrative schedule submitted by the Centralized Network Controller (CNC).
//! 3. **AdminBaseTime**: The exact future epoch nanosecond when `AdminGcl` replaces `OperGcl`.
//! 4. **ConfigChange**: Flag indicating a pending schedule update.
//! 5. **Hitless Transition**: At $T_{now} \ge \text{AdminBaseTime}$, `ConfigPending` transitions to false,
//!    and `AdminGcl` atomically becomes the active `OperGcl` aligned with the new cycle time.
//!
//! This module implements:
//! * Dual GCL containers (`OperGcl` and `AdminGcl`).
//! * IEEE 802.1Qbv Admin-to-Oper transition state machine.
//! * Cyclic time-offset modulo calculation with cycle time alignment.
//! * Gate state evaluation (8 Traffic Classes TC 0..7) at any nanosecond timestamp.

/// Single Gate Control List (GCL) Entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QbvGateEntry {
    /// 8-bit bitmask of open gates for Traffic Classes 0..7 (1 = open, 0 = closed).
    pub gate_states: u8,
    /// Duration of this time slot in nanoseconds.
    pub time_interval_ns: u64,
}

/// A complete GCL schedule cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QbvSchedule {
    pub base_time_ns: u64,
    pub cycle_time_ns: u64,
    pub entries: Vec<QbvGateEntry>,
}

impl QbvSchedule {
    pub fn new(base_time_ns: u64, entries: Vec<QbvGateEntry>) -> Self {
        let cycle_time_ns: u64 = entries.iter().map(|e| e.time_interval_ns).sum();
        QbvSchedule {
            base_time_ns,
            cycle_time_ns: cycle_time_ns.max(1),
            entries,
        }
    }

    /// Evaluates which gates are open at a specific nanosecond timestamp.
    pub fn get_gate_state_at(&self, timestamp_ns: u64) -> u8 {
        if self.entries.is_empty() || timestamp_ns < self.base_time_ns {
            return 0xFF; // All open by default before base time
        }

        let elapsed = timestamp_ns - self.base_time_ns;
        let offset_in_cycle = elapsed % self.cycle_time_ns;

        let mut accumulated_ns = 0;
        for entry in &self.entries {
            accumulated_ns += entry.time_interval_ns;
            if offset_in_cycle < accumulated_ns {
                return entry.gate_states;
            }
        }

        self.entries.last().map(|e| e.gate_states).unwrap_or(0xFF)
    }
}

/// Dynamic GCL Reconfiguration Engine.
#[derive(Debug, Clone)]
pub struct QbvDynamicReconfigEngine {
    pub oper_gcl: QbvSchedule,
    pub admin_gcl: Option<QbvSchedule>,
    pub config_change: bool,
    pub total_swaps_completed: u64,
}

impl QbvDynamicReconfigEngine {
    pub fn new(initial_oper: QbvSchedule) -> Self {
        QbvDynamicReconfigEngine {
            oper_gcl: initial_oper,
            admin_gcl: None,
            config_change: false,
            total_swaps_completed: 0,
        }
    }

    /// Submits a new administrative schedule to take effect at `admin_gcl.base_time_ns`.
    pub fn submit_admin_gcl(&mut self, admin_schedule: QbvSchedule) {
        self.admin_gcl = Some(admin_schedule);
        self.config_change = true;
    }

    /// Evaluates the active gate states at `current_time_ns` and performs hitless Admin->Oper swap when due.
    pub fn get_active_gate_states(&mut self, current_time_ns: u64) -> u8 {
        // Check if AdminGcl is due for atomic activation
        if self.config_change {
            if let Some(ref admin) = self.admin_gcl {
                if current_time_ns >= admin.base_time_ns {
                    // Atomic hitless swap!
                    self.oper_gcl = admin.clone();
                    self.admin_gcl = None;
                    self.config_change = false;
                    self.total_swaps_completed += 1;
                }
            }
        }

        self.oper_gcl.get_gate_state_at(current_time_ns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qbv_hitless_admin_to_oper_swap() {
        // Oper GCL: 100us cycle, TC 7 open first 30us (0x80), all open next 70us (0xFF)
        let oper_schedule = QbvSchedule::new(
            0,
            vec![
                QbvGateEntry {
                    gate_states: 0x80,
                    time_interval_ns: 30_000,
                },
                QbvGateEntry {
                    gate_states: 0xFF,
                    time_interval_ns: 70_000,
                },
            ],
        );
        let mut engine = QbvDynamicReconfigEngine::new(oper_schedule);

        // At t = 10us -> gate is 0x80
        assert_eq!(engine.get_active_gate_states(10_000), 0x80);
        // At t = 50us -> gate is 0xFF
        assert_eq!(engine.get_active_gate_states(50_000), 0xFF);

        // Submit Admin GCL to activate at t = 200us (200,000 ns)
        // New Admin: TC 7 & 6 open first 50us (0xC0), all open next 50us (0xFF)
        let admin_schedule = QbvSchedule::new(
            200_000,
            vec![
                QbvGateEntry {
                    gate_states: 0xC0,
                    time_interval_ns: 50_000,
                },
                QbvGateEntry {
                    gate_states: 0xFF,
                    time_interval_ns: 50_000,
                },
            ],
        );
        engine.submit_admin_gcl(admin_schedule);
        assert!(engine.config_change);

        // Before t = 200us (e.g. t = 110us in second cycle of Oper):
        // 110us - 0 = 110us % 100us = 10us -> still Oper GCL (0x80)
        assert_eq!(engine.get_active_gate_states(110_000), 0x80);
        assert!(engine.config_change);

        // At t = 210us (AdminBaseTime reached!):
        // Swapped to Admin! 210us - 200us = 10us < 50us -> 0xC0!
        assert_eq!(engine.get_active_gate_states(210_000), 0xC0);
        assert!(!engine.config_change);
        assert_eq!(engine.total_swaps_completed, 1);
    }
}
