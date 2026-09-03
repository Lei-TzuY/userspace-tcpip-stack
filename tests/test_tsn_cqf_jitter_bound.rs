use toy_tcpip::tsn_cqf_jitter_bound::{
    CqfHopProfile, SlaComplianceResult, TsnCqfJitterBoundEngine,
};

#[test]
fn test_tsn_cqf_jitter_bound_lifecycle() {
    let mut engine = TsnCqfJitterBoundEngine::new();

    // Configure a 3-hop industrial TSN bridge network:
    // Hop 1: Ingress Gateway (50 µs cycle, 2 µs prop, 1..3 µs proc)
    engine.add_hop(CqfHopProfile {
        hop_id: 1,
        name: "Ingress-GW".to_string(),
        cycle_time_ns: 50_000,
        link_prop_ns: 2_000,
        bridge_proc_min_ns: 1_000,
        bridge_proc_max_ns: 3_000,
    });

    // Hop 2: Backbone Switch (50 µs cycle, 4 µs prop, 1..2 µs proc)
    engine.add_hop(CqfHopProfile {
        hop_id: 2,
        name: "Backbone-SW".to_string(),
        cycle_time_ns: 50_000,
        link_prop_ns: 4_000,
        bridge_proc_min_ns: 1_000,
        bridge_proc_max_ns: 2_000,
    });

    // Hop 3: Egress Node (50 µs cycle, 2 µs prop, 1..3 µs proc)
    engine.add_hop(CqfHopProfile {
        hop_id: 3,
        name: "Egress-Node".to_string(),
        cycle_time_ns: 50_000,
        link_prop_ns: 2_000,
        bridge_proc_min_ns: 1_000,
        bridge_proc_max_ns: 3_000,
    });

    let bounds = engine.compute_bounds();
    assert_eq!(bounds.hop_count, 3);
    // Min delay = (50k+2k+1k) + (50k+4k+1k) + (50k+2k+1k) = 53k + 55k + 53k = 161,000 ns (161 µs)
    assert_eq!(bounds.min_delay_ns, 161_000);
    // Max delay = (100k+2k+3k) + (100k+4k+2k) + (100k+2k+3k) = 105k + 106k + 105k = 316,000 ns (316 µs)
    assert_eq!(bounds.max_delay_ns, 316_000);
    // Jitter = 316,000 - 161,000 = 155,000 ns (155 µs)
    assert_eq!(bounds.jitter_bound_ns, 155_000);

    // Evaluate strict SLA: Max 400 µs delay, 200 µs jitter
    let compliance = engine.evaluate_stream_sla(400_000, 200_000);
    assert_eq!(compliance, SlaComplianceResult::Compliant);

    // Evaluate violating SLA: Max 300 µs delay (< 316 µs)
    let violation = engine.evaluate_stream_sla(300_000, 200_000);
    assert!(matches!(
        violation,
        SlaComplianceResult::LatencyViolation { .. }
    ));
}
