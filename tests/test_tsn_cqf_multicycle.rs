use toy_tcpip::tsn_cqf_multicycle::{CqfMultiCycleEngine, CqfQueueRole};

#[test]
fn test_tsn_cqf_multicycle_peristaltic_shaper() {
    // 125 µs cycle time ($T_{cycle}$), 0 phase offset, 64 KiB buffer per queue
    let mut engine = CqfMultiCycleEngine::new(125_000, 0, 65536);

    // Initial state: Cycle 0
    assert_eq!(engine.current_cycle, 0);
    assert_eq!(engine.queues[0].role, CqfQueueRole::Receiving);
    assert_eq!(engine.queues[1].role, CqfQueueRole::Transmitting);
    assert_eq!(engine.queues[2].role, CqfQueueRole::Gated);

    // Ingest 3 frames in Cycle 0 (at 10µs, 50µs, 100µs)
    assert!(engine.ingest_frame(101, 7, vec![0xAA; 128], 10_000).is_ok());
    assert!(engine.ingest_frame(101, 7, vec![0xBB; 256], 50_000).is_ok());
    assert!(
        engine
            .ingest_frame(102, 6, vec![0xCC; 512], 100_000)
            .is_ok()
    );
    assert_eq!(engine.queues[0].frames.len(), 3);
    assert_eq!(engine.queues[0].current_bytes, 128 + 256 + 512);

    // Advance to Cycle 1 (at 130µs)
    let drained_c1 = engine.advance_time(130_000);
    assert_eq!(drained_c1.len(), 0); // Transmitting queue Q2 was empty
    assert_eq!(engine.current_cycle, 1);
    assert_eq!(engine.queues[0].role, CqfQueueRole::Gated);
    assert_eq!(engine.queues[1].role, CqfQueueRole::Receiving);
    assert_eq!(engine.queues[2].role, CqfQueueRole::Transmitting);

    // Ingest 1 frame in Cycle 1 -> enters Q1
    assert!(engine.ingest_frame(103, 5, vec![0xDD; 64], 150_000).is_ok());
    assert_eq!(engine.queues[1].frames.len(), 1);

    // Advance to Cycle 2 (at 260µs) -> Q0 becomes Transmitting and drains all Cycle 0 frames!
    let drained_c2 = engine.advance_time(260_000);
    assert_eq!(drained_c2.len(), 3);
    assert_eq!(drained_c2[0].payload[0], 0xAA);
    assert_eq!(drained_c2[1].payload[0], 0xBB);
    assert_eq!(drained_c2[2].payload[0], 0xCC);
    assert_eq!(engine.frames_forwarded, 3);

    // Advance to Cycle 3 (at 380µs) -> Q1 becomes Transmitting and drains Cycle 1 frame!
    let drained_c3 = engine.advance_time(380_000);
    assert_eq!(drained_c3.len(), 1);
    assert_eq!(drained_c3[0].payload[0], 0xDD);
    assert_eq!(engine.frames_forwarded, 4);

    // Latency bounds check
    let (min_l, max_l) = engine.hop_latency_bounds();
    assert_eq!(min_l, 125_000);
    assert_eq!(max_l, 250_000);
}

#[test]
fn test_tsn_cqf_buffer_overflow_drop() {
    let mut engine = CqfMultiCycleEngine::new(100_000, 0, 500); // 500 bytes buffer capacity
    assert!(engine.ingest_frame(1, 7, vec![0x11; 400], 1_000).is_ok());

    // Next frame of 200B exceeds 500B limit -> dropped
    let res = engine.ingest_frame(1, 7, vec![0x22; 200], 2_000);
    assert!(res.is_err());
    assert_eq!(engine.frames_dropped, 1);
}
