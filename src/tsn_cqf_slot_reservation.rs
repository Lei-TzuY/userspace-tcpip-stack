// src/tsn_cqf_slot_reservation.rs
//
// IEEE 802.1Qch Cyclic Queuing and Forwarding (CQF) Time-Slot Dynamic
// Bandwidth Reservation & Admission Engine.
//
// Standard & Concept Reference:
//   - IEEE 802.1Qch (Cyclic Queuing and Forwarding)
//   - IEEE 802.1Qbv (Enhancements for Scheduled Traffic - Time-Slot Slicing)
//   - Deterministic Time-Slot Quota Reservation:
//     Divides each cycle duration T_cycle into discrete, non-overlapping
//     time slots (Slot 0..K-1). Streams reserve dedicated byte quotas and
//     timing windows within a designated slot.
//   - Zero-Jitter Admission:
//     Prevents intra-cycle burst collisions and queue starvation by strictly
//     verifying slot occupancy before granting transmission admission.
//
// Pure safe Rust, zero external crates.

/// Verdict for stream admission requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotAdmissionVerdict {
    /// Reservation granted.
    Admitted {
        stream_id: u32,
        slot_index: usize,
        reserved_bytes: usize,
        slot_start_ns: u64,
        slot_end_ns: u64,
    },
    /// Rejected due to insufficient remaining byte capacity in the requested slot.
    RejectedSlotFull {
        stream_id: u32,
        slot_index: usize,
        requested_bytes: usize,
        available_bytes: usize,
    },
    /// Rejected because the requested slot index is out of bounds.
    RejectedInvalidSlot {
        stream_id: u32,
        slot_index: usize,
        max_slots: usize,
    },
    /// Rejected because the stream is already registered.
    RejectedDuplicateStream { stream_id: u32 },
}

/// Verdict for frame transmission evaluation within a cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotTransmissionVerdict {
    /// Frame arrives within its reserved slot window and fits within the byte quota.
    TransmitWithinSlot {
        stream_id: u32,
        slot_index: usize,
        frame_bytes: usize,
        remaining_slot_quota: usize,
    },
    /// Frame arrived outside its allocated time-slot slice (too early or too late).
    LateSlotViolation {
        stream_id: u32,
        slot_index: usize,
        time_in_cycle_ns: u64,
        expected_start_ns: u64,
        expected_end_ns: u64,
    },
    /// Frame exceeds the remaining reserved byte quota for this cycle.
    QuotaExceededDrop {
        stream_id: u32,
        slot_index: usize,
        frame_bytes: usize,
        remaining_slot_quota: usize,
    },
    /// Stream has no active reservation in the CQF slot engine.
    UnreservedStreamDrop { stream_id: u32 },
}

/// Specification of a single time slot within a CQF cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CqfTimeSlot {
    /// Slot index (0..K-1).
    pub slot_index: usize,
    /// Offset from cycle start (nanoseconds).
    pub start_offset_ns: u64,
    /// Duration of the slot (nanoseconds).
    pub duration_ns: u64,
    /// Maximum byte capacity allowed in this slot across all streams.
    pub max_capacity_bytes: usize,
    /// Currently allocated byte capacity.
    pub allocated_bytes: usize,
    /// Number of streams assigned to this slot.
    pub assigned_streams: usize,
}

/// Active stream reservation record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamSlotReservation {
    pub stream_id: u32,
    pub slot_index: usize,
    pub reserved_bytes_per_cycle: usize,
    pub used_bytes_in_current_cycle: usize,
}

/// IEEE 802.1Qch CQF Time-Slot Dynamic Reservation Engine.
#[derive(Debug, Clone)]
pub struct TsnCqfSlotReservationEngine {
    /// Cycle duration in nanoseconds (e.g. 100_000 ns = 100 µs).
    pub cycle_duration_ns: u64,
    /// Configured time slots within the cycle.
    pub slots: Vec<CqfTimeSlot>,
    /// Active stream reservations.
    pub reservations: Vec<StreamSlotReservation>,
    /// Total admitted reservations.
    pub total_admitted: u64,
    /// Total rejected reservation requests.
    pub total_rejected: u64,
    /// Total conforming transmitted bytes.
    pub total_conforming_bytes: u64,
    /// Total dropped bytes due to violations or unreserved streams.
    pub total_dropped_bytes: u64,
    /// Total late timing violations.
    pub total_timing_violations: u64,
}

impl TsnCqfSlotReservationEngine {
    /// Creates a new CQF Slot Reservation Engine with uniform time slots.
    pub fn new(cycle_duration_ns: u64, num_slots: usize, slot_capacity_bytes: usize) -> Self {
        let num_slots = if num_slots == 0 { 1 } else { num_slots };
        let slot_duration_ns = cycle_duration_ns / (num_slots as u64);

        let mut slots = Vec::with_capacity(num_slots);
        for i in 0..num_slots {
            slots.push(CqfTimeSlot {
                slot_index: i,
                start_offset_ns: (i as u64) * slot_duration_ns,
                duration_ns: slot_duration_ns,
                max_capacity_bytes: slot_capacity_bytes,
                allocated_bytes: 0,
                assigned_streams: 0,
            });
        }

        Self {
            cycle_duration_ns,
            slots,
            reservations: Vec::new(),
            total_admitted: 0,
            total_rejected: 0,
            total_conforming_bytes: 0,
            total_dropped_bytes: 0,
            total_timing_violations: 0,
        }
    }

    /// Requests a dynamic bandwidth reservation in a specific CQF time slot.
    pub fn request_reservation(
        &mut self,
        stream_id: u32,
        slot_index: usize,
        reserved_bytes: usize,
    ) -> SlotAdmissionVerdict {
        if self.reservations.iter().any(|r| r.stream_id == stream_id) {
            self.total_rejected += 1;
            return SlotAdmissionVerdict::RejectedDuplicateStream { stream_id };
        }

        if slot_index >= self.slots.len() {
            self.total_rejected += 1;
            return SlotAdmissionVerdict::RejectedInvalidSlot {
                stream_id,
                slot_index,
                max_slots: self.slots.len(),
            };
        }

        let slot = &mut self.slots[slot_index];
        let available = slot.max_capacity_bytes.saturating_sub(slot.allocated_bytes);

        if reserved_bytes > available {
            self.total_rejected += 1;
            return SlotAdmissionVerdict::RejectedSlotFull {
                stream_id,
                slot_index,
                requested_bytes: reserved_bytes,
                available_bytes: available,
            };
        }

        // Grant reservation
        slot.allocated_bytes += reserved_bytes;
        slot.assigned_streams += 1;
        let start_ns = slot.start_offset_ns;
        let end_ns = slot.start_offset_ns + slot.duration_ns;

        self.reservations.push(StreamSlotReservation {
            stream_id,
            slot_index,
            reserved_bytes_per_cycle: reserved_bytes,
            used_bytes_in_current_cycle: 0,
        });

        self.total_admitted += 1;
        SlotAdmissionVerdict::Admitted {
            stream_id,
            slot_index,
            reserved_bytes,
            slot_start_ns: start_ns,
            slot_end_ns: end_ns,
        }
    }

    /// Releases an existing stream reservation.
    pub fn release_reservation(&mut self, stream_id: u32) -> bool {
        if let Some(pos) = self
            .reservations
            .iter()
            .position(|r| r.stream_id == stream_id)
        {
            let res = self.reservations.remove(pos);
            if res.slot_index < self.slots.len() {
                let slot = &mut self.slots[res.slot_index];
                slot.allocated_bytes = slot
                    .allocated_bytes
                    .saturating_sub(res.reserved_bytes_per_cycle);
                slot.assigned_streams = slot.assigned_streams.saturating_sub(1);
            }
            true
        } else {
            false
        }
    }

    /// Evaluates a frame transmission at a given nanosecond offset within the cycle.
    pub fn evaluate_transmission(
        &mut self,
        stream_id: u32,
        frame_bytes: usize,
        time_in_cycle_ns: u64,
    ) -> SlotTransmissionVerdict {
        let res_idx = match self
            .reservations
            .iter()
            .position(|r| r.stream_id == stream_id)
        {
            Some(idx) => idx,
            None => {
                self.total_dropped_bytes += frame_bytes as u64;
                return SlotTransmissionVerdict::UnreservedStreamDrop { stream_id };
            }
        };

        let slot_idx = self.reservations[res_idx].slot_index;
        let slot = &self.slots[slot_idx];
        let slot_start = slot.start_offset_ns;
        let slot_end = slot_start + slot.duration_ns;

        // Check if transmission falls within the allocated time slot window
        if time_in_cycle_ns < slot_start || time_in_cycle_ns >= slot_end {
            self.total_timing_violations += 1;
            self.total_dropped_bytes += frame_bytes as u64;
            return SlotTransmissionVerdict::LateSlotViolation {
                stream_id,
                slot_index: slot_idx,
                time_in_cycle_ns,
                expected_start_ns: slot_start,
                expected_end_ns: slot_end,
            };
        }

        // Check byte quota
        let res = &mut self.reservations[res_idx];
        let remaining_quota = res
            .reserved_bytes_per_cycle
            .saturating_sub(res.used_bytes_in_current_cycle);

        if frame_bytes > remaining_quota {
            self.total_dropped_bytes += frame_bytes as u64;
            return SlotTransmissionVerdict::QuotaExceededDrop {
                stream_id,
                slot_index: slot_idx,
                frame_bytes,
                remaining_slot_quota: remaining_quota,
            };
        }

        res.used_bytes_in_current_cycle += frame_bytes;
        self.total_conforming_bytes += frame_bytes as u64;

        SlotTransmissionVerdict::TransmitWithinSlot {
            stream_id,
            slot_index: slot_idx,
            frame_bytes,
            remaining_slot_quota: res.reserved_bytes_per_cycle - res.used_bytes_in_current_cycle,
        }
    }

    /// Resets byte consumption counters at the start of a new CQF cycle epoch.
    pub fn start_new_cycle(&mut self) {
        for res in &mut self.reservations {
            res.used_bytes_in_current_cycle = 0;
        }
    }

    /// Clears all slots and reservations.
    pub fn reset(&mut self) {
        for slot in &mut self.slots {
            slot.allocated_bytes = 0;
            slot.assigned_streams = 0;
        }
        self.reservations.clear();
        self.total_admitted = 0;
        self.total_rejected = 0;
        self.total_conforming_bytes = 0;
        self.total_dropped_bytes = 0;
        self.total_timing_violations = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cqf_slot_reservation_lifecycle() {
        let mut engine = TsnCqfSlotReservationEngine::new(100_000, 4, 3000);
        assert_eq!(engine.slots.len(), 4);
        assert_eq!(engine.slots[0].duration_ns, 25_000);
        assert_eq!(engine.slots[1].start_offset_ns, 25_000);

        // 1. Reserve 1500 bytes in Slot 1
        let v1 = engine.request_reservation(101, 1, 1500);
        assert_eq!(
            v1,
            SlotAdmissionVerdict::Admitted {
                stream_id: 101,
                slot_index: 1,
                reserved_bytes: 1500,
                slot_start_ns: 25_000,
                slot_end_ns: 50_000,
            }
        );

        // 2. Transmit conforming frame within Slot 1 (time = 30_000 ns)
        let t1 = engine.evaluate_transmission(101, 1000, 30_000);
        assert_eq!(
            t1,
            SlotTransmissionVerdict::TransmitWithinSlot {
                stream_id: 101,
                slot_index: 1,
                frame_bytes: 1000,
                remaining_slot_quota: 500,
            }
        );

        // 3. Transmit late frame in Slot 2 (time = 60_000 ns) -> Timing Violation
        let t2 = engine.evaluate_transmission(101, 500, 60_000);
        match t2 {
            SlotTransmissionVerdict::LateSlotViolation { stream_id, .. } => {
                assert_eq!(stream_id, 101);
            }
            _ => panic!("Expected LateSlotViolation"),
        }

        // 4. Advance cycle and transmit again
        engine.start_new_cycle();
        let t3 = engine.evaluate_transmission(101, 1500, 35_000);
        assert_eq!(
            t3,
            SlotTransmissionVerdict::TransmitWithinSlot {
                stream_id: 101,
                slot_index: 1,
                frame_bytes: 1500,
                remaining_slot_quota: 0,
            }
        );
    }
}
