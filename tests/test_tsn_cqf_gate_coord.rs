use toy_tcpip::tsn_cqf_gate_coord::{CoordinatedCqfFrame, GateCoordVerdict, TsnCqfGateCoordEngine};

#[test]
fn test_tsn_cqf_gate_coordination_lifecycle() {
    let mut engine = TsnCqfGateCoordEngine::new(100_000); // 100 µs cycle

    // Gate configuration:
    // Cycle 0 TX: Priorities 7, 6, 5, 4 open (0xF0)
    // Cycle 1 TX: Priorities 3, 2, 1, 0 open (0x0F)
    engine.set_gate_masks(0xF0, 0x0F);

    // Initial state: active_tx_buffer is 0 (Cycle 0), receiving into buffer 1 (Cycle 1)
    assert_eq!(engine.active_tx_buffer, 0);

    // Ingress frame with priority 1 (admitted into buffer 1 because Cycle 1 mask has P1 enabled)
    let frame1 = CoordinatedCqfFrame {
        stream_id: 101,
        priority: 1,
        payload_bytes: 300,
        enqueue_time_ns: 10_000,
    };
    let v1 = engine.ingest_frame(frame1);
    assert_eq!(
        v1,
        GateCoordVerdict::Admitted {
            cycle_index: 0,
            cycle_buffer: 1,
        }
    );

    // Ingress frame with priority 7 (rejected from buffer 1 because Cycle 1 mask has P7 disabled)
    let frame2 = CoordinatedCqfFrame {
        stream_id: 102,
        priority: 7,
        payload_bytes: 600,
        enqueue_time_ns: 15_000,
    };
    let v2 = engine.ingest_frame(frame2);
    assert_eq!(v2, GateCoordVerdict::DroppedGateClosed);

    // Advance cycle by 100 µs to rotate buffer 1 into active TX mode
    let rotations = engine.advance_time(100_000);
    assert_eq!(rotations, 1);
    assert_eq!(engine.active_tx_buffer, 1);

    // Dispatch from active buffer 1
    let dispatched = engine.dispatch_active_buffer();
    assert_eq!(dispatched.len(), 1);
    assert_eq!(dispatched[0].stream_id, 101);
    assert_eq!(dispatched[0].priority, 1);

    // Check priority statistics
    assert_eq!(engine.stats[1].frames_admitted, 1);
    assert_eq!(engine.stats[1].frames_dispatched, 1);
    assert_eq!(engine.stats[7].frames_gate_blocked, 1);
}
