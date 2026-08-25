use toy_tcpip::tsn_psfp_stream_filter::{
    FlowMeterInstance, PsfpEngine, PsfpVerdict, StreamFilterInstance, StreamGateInstance,
};

#[test]
fn test_tsn_psfp_cascaded_filtering_pipeline() {
    let mut engine = PsfpEngine::new();

    // SFI: Stream 100, Priority 7, Max SDU 1200B, Gate 1, Meter 1
    engine.add_filter(StreamFilterInstance {
        stream_id: 100,
        priority: 7,
        max_sdu_bytes: 1200,
        gate_id: 1,
        meter_id: Some(1),
        matching_frames: 0,
        sdu_oversized_drops: 0,
    });

    // SGI: Gate 1 is Open
    engine.add_gate(StreamGateInstance {
        gate_id: 1,
        is_open: true,
        gate_closed_drops: 0,
        invalid_rx_count: 0,
    });

    // FMI: Meter 1 with CIR 100KB/s (100,000), CBS 1000B, PIR 200KB/s (200,000), PBS 2000B
    engine.add_meter(FlowMeterInstance::new(1, 100_000, 1_000, 200_000, 2_000));

    // Test 1: Conforming frame 300B -> Pass (Green)
    assert_eq!(engine.process_frame(100, 7, 300, 0), PsfpVerdict::Pass);

    // Test 2: Next frame 800B -> Exceeds CBS (700B remaining) but fits PBS (1700B remaining) -> MarkYellow
    assert_eq!(engine.process_frame(100, 7, 800, 0), PsfpVerdict::MarkYellow);

    // Test 3: Next frame 1500B -> Exceeds Max SDU (1200B) -> DropMaxSduExceeded
    assert_eq!(engine.process_frame(100, 7, 1500, 0), PsfpVerdict::DropMaxSduExceeded);

    // Test 4: Frame of 1000B when PBS tokens (900B) are insufficient -> DropMeterRed
    assert_eq!(engine.process_frame(100, 7, 1000, 0), PsfpVerdict::DropMeterRed);

    // Test 5: Close Gate 1 -> frame is dropped at Gate stage
    engine.gates[0].is_open = false;
    assert_eq!(engine.process_frame(100, 7, 100, 0), PsfpVerdict::DropGateClosed);
}

#[test]
fn test_tsn_psfp_unmanaged_stream_passes() {
    let mut engine = PsfpEngine::new();
    // Stream 999 is unmanaged
    assert_eq!(engine.process_frame(999, 0, 1500, 1000), PsfpVerdict::Pass);
}
