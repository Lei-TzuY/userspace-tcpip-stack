use toy_tcpip::ats::{AtsFrame, AtsStreamShaper, UrgencyBasedScheduler};

#[test]
fn test_ats_stream_shaper_eligibility_time() {
    let mut shaper = AtsStreamShaper::new(1, 16_000_000, 1000); // 2 bytes/µs, 1000-byte burst

    // The committed burst starts full, so frames that fit within available credit are immediately
    // eligible. Once that credit is exhausted, CIR determines how quickly more bytes recover.
    let et1 = shaper.compute_eligibility_time(500, 1000);
    assert_eq!(et1, 1000);

    let frame = AtsFrame {
        stream_id: 1,
        frame_length_bytes: 500,
        arrival_time_us: 1000,
        eligibility_time_us: et1,
        payload: vec![0x11; 500],
    };
    assert_eq!(frame.stream_id, 1);
    assert_eq!(frame.eligibility_time_us, 1000);

    let et2 = shaper.compute_eligibility_time(500, 1100);
    assert_eq!(et2, 1100);

    // No additional refill time has elapsed, so this frame must wait for CIR recovery.
    let et3 = shaper.compute_eligibility_time(500, 1100);
    assert_eq!(et3, 1250);
}

#[test]
fn test_urgency_based_scheduler_flow_prioritization() {
    let mut ubs = UrgencyBasedScheduler::new();
    // CBS=0 disables burst credit so this integration test isolates CIR-based eligibility ordering.
    ubs.register_shaper(AtsStreamShaper::new(1, 8_000_000, 0)); // 1 byte/µs
    ubs.register_shaper(AtsStreamShaper::new(2, 16_000_000, 0)); // 2 bytes/µs

    // Enqueue 1000 bytes for stream 1 at t=0 -> ET=1000µs
    ubs.enqueue_frame(1, 0, vec![0x11; 1000]).unwrap();
    // Enqueue 400 bytes for stream 2 at t=0 -> ET=200µs
    ubs.enqueue_frame(2, 0, vec![0x22; 400]).unwrap();

    // At t=300µs: Stream 2 is eligible, Stream 1 is not
    let frame_first = ubs.dequeue_eligible_frame(300).unwrap();
    assert_eq!(frame_first.stream_id, 2);

    // At t=1000µs: Stream 1 becomes eligible
    let frame_second = ubs.dequeue_eligible_frame(1000).unwrap();
    assert_eq!(frame_second.stream_id, 1);
    assert_eq!(ubs.transmitted_frames_count, 2);
}
