// tests/test_tsn_cqf_slot_reservation.rs

use toy_tcpip::tsn_cqf_slot_reservation::{
    SlotAdmissionVerdict, SlotTransmissionVerdict, TsnCqfSlotReservationEngine,
};

#[test]
fn test_tsn_cqf_slot_reservation_lifecycle() {
    // 100 µs cycle, 4 slots (25 µs each), 2000 bytes max capacity per slot
    let mut engine = TsnCqfSlotReservationEngine::new(100_000, 4, 2000);

    // 1. Reserve 1200 bytes for Stream 1 in Slot 0 (0..25,000 ns)
    let v1 = engine.request_reservation(1, 0, 1200);
    assert_eq!(
        v1,
        SlotAdmissionVerdict::Admitted {
            stream_id: 1,
            slot_index: 0,
            reserved_bytes: 1200,
            slot_start_ns: 0,
            slot_end_ns: 25_000,
        }
    );

    // 2. Reserve 800 bytes for Stream 2 in Slot 0 (0..25,000 ns) -> exactly fits 2000 bytes
    let v2 = engine.request_reservation(2, 0, 800);
    assert_eq!(
        v2,
        SlotAdmissionVerdict::Admitted {
            stream_id: 2,
            slot_index: 0,
            reserved_bytes: 800,
            slot_start_ns: 0,
            slot_end_ns: 25_000,
        }
    );

    // 3. Try to reserve 100 bytes for Stream 3 in Slot 0 -> rejected SlotFull
    let v3 = engine.request_reservation(3, 0, 100);
    assert_eq!(
        v3,
        SlotAdmissionVerdict::RejectedSlotFull {
            stream_id: 3,
            slot_index: 0,
            requested_bytes: 100,
            available_bytes: 0,
        }
    );

    // 4. Reserve 1500 bytes for Stream 3 in Slot 2 (50,000..75,000 ns)
    let v4 = engine.request_reservation(3, 2, 1500);
    assert_eq!(
        v4,
        SlotAdmissionVerdict::Admitted {
            stream_id: 3,
            slot_index: 2,
            reserved_bytes: 1500,
            slot_start_ns: 50_000,
            slot_end_ns: 75_000,
        }
    );

    // 5. Evaluate transmissions
    // Stream 1 frame 600B at 10,000 ns -> Transmit within slot
    let t1 = engine.evaluate_transmission(1, 600, 10_000);
    assert_eq!(
        t1,
        SlotTransmissionVerdict::TransmitWithinSlot {
            stream_id: 1,
            slot_index: 0,
            frame_bytes: 600,
            remaining_slot_quota: 600,
        }
    );

    // Stream 1 frame 500B at 20,000 ns -> Transmit within slot
    let t2 = engine.evaluate_transmission(1, 500, 20_000);
    assert_eq!(
        t2,
        SlotTransmissionVerdict::TransmitWithinSlot {
            stream_id: 1,
            slot_index: 0,
            frame_bytes: 500,
            remaining_slot_quota: 100,
        }
    );

    // Stream 1 frame 200B at 24,000 ns -> Quota exceeded (only 100B left)
    let t3 = engine.evaluate_transmission(1, 200, 24_000);
    assert_eq!(
        t3,
        SlotTransmissionVerdict::QuotaExceededDrop {
            stream_id: 1,
            slot_index: 0,
            frame_bytes: 200,
            remaining_slot_quota: 100,
        }
    );

    // Stream 3 frame 800B at 15,000 ns (in Slot 0 timing, but reserved in Slot 2) -> Late/Early Slot Violation
    let t4 = engine.evaluate_transmission(3, 800, 15_000);
    match t4 {
        SlotTransmissionVerdict::LateSlotViolation {
            stream_id,
            slot_index,
            expected_start_ns,
            ..
        } => {
            assert_eq!(stream_id, 3);
            assert_eq!(slot_index, 2);
            assert_eq!(expected_start_ns, 50_000);
        }
        _ => panic!("Expected LateSlotViolation"),
    }

    // Stream 3 frame 800B at 55,000 ns (in Slot 2) -> Conforming transmission
    let t5 = engine.evaluate_transmission(3, 800, 55_000);
    assert_eq!(
        t5,
        SlotTransmissionVerdict::TransmitWithinSlot {
            stream_id: 3,
            slot_index: 2,
            frame_bytes: 800,
            remaining_slot_quota: 700,
        }
    );

    // Unregistered stream 99 -> UnreservedStreamDrop
    let t6 = engine.evaluate_transmission(99, 500, 55_000);
    assert_eq!(
        t6,
        SlotTransmissionVerdict::UnreservedStreamDrop { stream_id: 99 }
    );

    // Release reservation
    assert!(engine.release_reservation(1));
    assert_eq!(engine.slots[0].allocated_bytes, 800); // 1200 freed, 800 left for Stream 2
}
