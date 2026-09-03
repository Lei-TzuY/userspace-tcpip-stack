use toy_tcpip::gtpu_rtt_variance::{
    AsymmetryVerdict, DEFAULT_GRANULARITY_US, GtpuRttVarianceEngine, MIN_RTO_US,
};

#[test]
fn test_gtpu_rtt_variance_and_rto_lifecycle() {
    let mut engine = GtpuRttVarianceEngine::new(DEFAULT_GRANULARITY_US, 10_000); // 10 ms threshold for asymmetry

    let teid_a = 0x1001;
    let teid_b = 0x2002;

    engine.register_path(teid_a);
    engine.register_path(teid_b);

    assert_eq!(engine.tracked_teids().len(), 2);

    // ── Path A: First RTT measurement (RFC 6298 bootstrap) ──
    engine.update_rtt(teid_a, 20_000); // 20 ms
    let state_a = engine.path_state(teid_a).expect("path A state");
    assert_eq!(state_a.srtt_us(), 20_000);
    assert_eq!(state_a.rttvar_us(), 10_000); // R / 2
    assert_eq!(state_a.sample_count(), 1);
    assert_eq!(state_a.latest_rtt_us(), 20_000);
    assert_eq!(state_a.min_rtt_us(), 20_000);
    assert_eq!(state_a.max_rtt_us(), 20_000);
    assert!(state_a.rto_us() >= MIN_RTO_US);

    // ── Subsequent samples with jitter on Path A ──
    engine.update_rtt(teid_a, 25_000);
    engine.update_rtt(teid_a, 15_000);
    let state_a2 = engine.path_state(teid_a).unwrap();
    assert_eq!(state_a2.sample_count(), 3);
    assert_eq!(state_a2.min_rtt_us(), 15_000);
    assert_eq!(state_a2.max_rtt_us(), 25_000);
    assert!(state_a2.rttvar_us() > 0);

    // ── Path B: Smooth stable RTT ──
    for _ in 0..15 {
        engine.update_rtt(teid_b, 5_000);
    }
    let state_b = engine.path_state(teid_b).unwrap();
    assert_eq!(state_b.srtt_us(), 5_000);
    assert!(state_b.rttvar_us() < 1_000);

    // ── Timeout Backoff ──
    let initial_rto = state_b.rto_us();
    engine.notify_timeout(teid_b);
    let backoff_rto = engine.path_state(teid_b).unwrap().rto_us();
    assert_eq!(backoff_rto, initial_rto * 2);
    assert_eq!(engine.path_state(teid_b).unwrap().consecutive_timeouts(), 1);

    // After a new successful sample, consecutive timeouts should reset to 0
    engine.update_rtt(teid_b, 5_000);
    assert_eq!(engine.path_state(teid_b).unwrap().consecutive_timeouts(), 0);

    // ── Asymmetry Checks ──
    let sym = engine.check_asymmetry(12_000, 15_000); // diff = 3 ms < 10 ms
    assert_eq!(sym, AsymmetryVerdict::Symmetric);

    let asym = engine.check_asymmetry(5_000, 20_000); // diff = 15 ms > 10 ms
    assert_eq!(
        asym,
        AsymmetryVerdict::Asymmetric {
            forward_us: 5_000,
            reverse_us: 20_000,
        }
    );
}
