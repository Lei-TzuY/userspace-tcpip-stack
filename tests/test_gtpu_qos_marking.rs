// tests/test_gtpu_qos_marking.rs

use toy_tcpip::gtpu_qos_marking::{FiveQiProfile, FiveQiResourceType, GtpuQosMarkingEngine};

#[test]
fn test_gtpu_qos_marking_lifecycle() {
    let mut engine = GtpuQosMarkingEngine::new();

    // 1. Evaluate Voice (QFI 1) with ECN=2 (ECT0)
    let m1 = engine.evaluate_marking(1, 2);
    assert_eq!(m1.five_qi, 1);
    assert_eq!(m1.dscp, 46); // EF
    assert_eq!(m1.pcp, 5);
    assert_eq!(m1.tos_byte, (46 << 2) | 2); // 186
    assert_eq!(m1.delay_budget_ms, 100);

    // 2. Evaluate Video (QFI 2) with ECN=0
    let m2 = engine.evaluate_marking(2, 0);
    assert_eq!(m2.five_qi, 2);
    assert_eq!(m2.dscp, 34); // AF41
    assert_eq!(m2.pcp, 4);
    assert_eq!(m2.tos_byte, 34 << 2);

    // 3. Register Custom 5QI 85 for Ultra-Low Latency Factory Automation (1ms delay budget)
    engine.register_profile(FiveQiProfile {
        five_qi: 85,
        resource_type: FiveQiResourceType::DelayCriticalGbr,
        default_dscp: 48,
        default_pcp: 7,
        packet_delay_budget_ms: 1,
        description: "Industrial Automation TSN Interworking".to_string(),
    });
    engine.bind_qfi(15, 85);

    let m_custom = engine.evaluate_marking(15, 3); // ECN = CE (Congestion Experienced)
    assert_eq!(m_custom.five_qi, 85);
    assert_eq!(m_custom.dscp, 48);
    assert_eq!(m_custom.pcp, 7);
    assert_eq!(m_custom.tos_byte, (48 << 2) | 3);
    assert!(m_custom.is_delay_critical);
    assert_eq!(m_custom.delay_budget_ms, 1);

    // 4. Statistics check
    assert_eq!(engine.total_packets_marked, 3);
    assert_eq!(engine.total_delay_critical, 1);
}
