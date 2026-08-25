use toy_tcpip::frer_srf::{FrerSrfEngine, SrfInstance, SrfVerdict};

#[test]
fn test_frer_srf_vector_recovery_algorithm() {
    // ── Multi-stream SRF engine with 64-entry history window ──
    let mut engine = FrerSrfEngine::new(64);

    // Stream 1: in-order delivery
    assert_eq!(engine.process_frame(1, 100), SrfVerdict::Accept); // take_any
    assert_eq!(engine.process_frame(1, 101), SrfVerdict::Accept);
    assert_eq!(engine.process_frame(1, 102), SrfVerdict::Accept);

    // Stream 1: duplicate of seq 102 from redundant path → eliminated
    assert_eq!(engine.process_frame(1, 102), SrfVerdict::EliminateDuplicate);

    // Stream 1: out-of-order seq 101 (duplicate) → eliminated
    assert_eq!(engine.process_frame(1, 101), SrfVerdict::EliminateDuplicate);

    // Stream 1: gap — seq 105 arrives, skipping 103 and 104
    assert_eq!(engine.process_frame(1, 105), SrfVerdict::AcceptOutOfOrder);

    // Stream 1: late arrival of seq 103 within history window → accepted
    assert_eq!(engine.process_frame(1, 103), SrfVerdict::AcceptOutOfOrder);

    // Stream 1: late arrival of seq 104 → accepted
    assert_eq!(engine.process_frame(1, 104), SrfVerdict::AcceptOutOfOrder);

    // Stream 1: duplicate of 103 → eliminated
    assert_eq!(engine.process_frame(1, 103), SrfVerdict::EliminateDuplicate);

    // ── Stream 2: independent state ──
    assert_eq!(engine.process_frame(2, 0), SrfVerdict::Accept); // take_any
    assert_eq!(engine.process_frame(2, 1), SrfVerdict::Accept);

    // Verify per-stream stats
    let s1 = engine.streams.iter().find(|(h, _)| *h == 1).unwrap();
    assert_eq!(s1.1.stats.accepted, 6); // 100,101,102,105,103,104
    assert_eq!(s1.1.stats.duplicates_eliminated, 3); // 102,101,103

    let s2 = engine.streams.iter().find(|(h, _)| *h == 2).unwrap();
    assert_eq!(s2.1.stats.accepted, 2);

    // Total stats
    let total = engine.total_stats();
    assert_eq!(total.accepted, 8);
    assert_eq!(total.duplicates_eliminated, 3);
}

#[test]
fn test_frer_srf_rogue_and_wraparound() {
    let mut srf = SrfInstance::new(16);

    // Bootstrap with take_any
    assert_eq!(srf.process(0xFFF0), SrfVerdict::Accept);

    // Advance past the small 16-entry window
    for i in 1u16..20 {
        srf.process(0xFFF0u16.wrapping_add(i));
    }

    // Ancient sequence is outside window → rogue
    assert_eq!(srf.process(0xFFF0), SrfVerdict::DropRogue);
    assert_eq!(srf.stats.rogue_dropped, 1);

    // Verify wrap-around: after advancing through 0xFFFF → 0x0000..
    // the engine should seamlessly accept new sequences past 0x0000.
    let next_expected = 0xFFF0u16.wrapping_add(20);
    assert_eq!(srf.process(next_expected), SrfVerdict::Accept);
}

#[test]
fn test_frer_srf_reset() {
    let mut srf = SrfInstance::new(32);
    srf.process(50);
    srf.process(51);
    srf.process(52);
    assert_eq!(srf.stats.accepted, 3);

    srf.reset();
    assert!(srf.take_any);
    assert_eq!(srf.stats.accepted, 0);

    // After reset, should accept any sequence again
    assert_eq!(srf.process(999), SrfVerdict::Accept);
    assert_eq!(srf.recv_seq, 1000);
}
