use toy_tcpip::srv6_mup_qos::{FiveQiProfile, FiveQiResourceType, Srv6MupQosEngine};

#[test]
fn test_srv6_mup_qos_5qi_classification_and_custom_profiles() {
    let mut engine = Srv6MupQosEngine::new();

    // 1. Check Standard 5QI 1 (Voice)
    let voice = engine.classify_qos_flow(1, 0b10).unwrap(); // ECT1
    assert_eq!(voice.dscp, 46); // EF
    assert_eq!(voice.ecn, 2);
    assert_eq!(voice.ipv6_traffic_class, (46 << 2) | 2);
    assert_eq!(voice.srv6_color, 200);

    // 2. Check Standard 5QI 82 (Discrete Automation URLLC)
    let urllc = engine.classify_qos_flow(82, 0).unwrap();
    assert_eq!(urllc.dscp, 56);
    assert_eq!(urllc.srv6_color, 100);

    // 3. Register Custom 5QI profile (e.g. 5QI 75 for Special Drone Control)
    engine.register_profile(FiveQiProfile {
        five_qi: 75,
        resource_type: FiveQiResourceType::DelayCriticalGbr,
        default_priority_level: 15,
        packet_delay_budget_ms: 8,
        packet_error_rate_exp: -5,
        default_dscp: 48, // CS6
        srv6_slice_color: 150,
    });

    let drone = engine.classify_qos_flow(75, 1).unwrap();
    assert_eq!(drone.dscp, 48);
    assert_eq!(drone.ipv6_traffic_class, (48 << 2) | 1);
    assert_eq!(drone.srv6_color, 150);

    // 4. Invalid 5QI error check
    assert!(engine.classify_qos_flow(250, 0).is_err());
}
