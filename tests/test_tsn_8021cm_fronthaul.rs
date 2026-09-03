//! Integration tests for IEEE 802.1CM / eCPRI Time-Sensitive Networking for Fronthaul Profile Engine.

use toy_tcpip::tsn_8021cm_fronthaul::{
    EcpriTrafficClass, FronthaulBridgeHop, Ieee8021CmEngine, Ieee8021CmProfile,
};

#[test]
fn test_8021cm_profile_a_strict_latency_and_jitter_pass() {
    let mut engine = Ieee8021CmEngine::new(Ieee8021CmProfile::ProfileA);
    assert_eq!(engine.profile.max_owtd_ns(), 100_000); // 100 µs
    assert_eq!(engine.profile.max_pdv_ns(), 10_000); // 10 µs

    // 3-hop bridged fronthaul path with IEEE 802.1Qbu frame preemption enabled
    // Hop 1: Cell Site Gateway (CSG) -> 2 km fiber
    engine.add_bridge_hop(FronthaulBridgeHop::new("CSG-01", 1500, 1200, 2000.0, true));
    // Hop 2: Aggregation Switch (AGS) -> 5 km fiber
    engine.add_bridge_hop(FronthaulBridgeHop::new("AGS-01", 2000, 1500, 5000.0, true));
    // Hop 3: Central Office Hub (COH) -> 1 km fiber
    engine.add_bridge_hop(FronthaulBridgeHop::new("COH-01", 1500, 1000, 1000.0, true));

    // High-priority User Plane IQ stream (Express traffic)
    let eval = engine.evaluate_fronthaul_path(EcpriTrafficClass::UserPlaneHigh);

    // Total fiber length = 2000 + 5000 + 1000 = 8000 meters -> cable delay = 40,000 ns
    assert_eq!(eval.total_fiber_length_meters, 8000.0);
    assert_eq!(eval.hop_count, 3);

    // With preemption, express jitter per hop is capped at 100 ns -> total PDV = 300 ns <= 10,000 ns
    assert_eq!(eval.total_pdv_ns, 300);
    assert!(eval.pdv_compliant);

    // Total OWTD = (1500 + 10000 + 100) + (2000 + 25000 + 100) + (1500 + 5000 + 100) = 45,300 ns <= 100,000 ns
    assert_eq!(eval.total_owtd_ns, 45_300);
    assert!(eval.owtd_compliant);
    assert!(eval.is_fully_compliant);
}

#[test]
fn test_8021cm_profile_a_violation_and_fallback_to_profile_b() {
    let mut engine_a = Ieee8021CmEngine::new(Ieee8021CmProfile::ProfileA);

    // Long-distance rural fronthaul: 20 km optical fiber
    // Cable propagation delay alone = 20,000m * 5 ns/m = 100,000 ns
    engine_a.add_bridge_hop(FronthaulBridgeHop::new(
        "CSG-Rural",
        3000,
        2000,
        20_000.0,
        true,
    ));

    let eval_a = engine_a.evaluate_fronthaul_path(EcpriTrafficClass::UserPlaneHigh);

    // Total delay = 3000 (proc) + 100,000 (cable) + 100 (express jitter) = 103,100 ns > 100,000 ns
    assert_eq!(eval_a.total_owtd_ns, 103_100);
    assert!(!eval_a.owtd_compliant);
    assert!(!eval_a.is_fully_compliant);

    // Fallback to Profile B (allows up to 1,000,000 ns / 1 ms OWTD and 200 µs PDV)
    let mut engine_b = Ieee8021CmEngine::new(Ieee8021CmProfile::ProfileB);
    engine_b.add_bridge_hop(FronthaulBridgeHop::new(
        "CSG-Rural",
        3000,
        2000,
        20_000.0,
        true,
    ));

    let eval_b = engine_b.evaluate_fronthaul_path(EcpriTrafficClass::UserPlaneHigh);
    assert!(eval_b.owtd_compliant);
    assert!(eval_b.pdv_compliant);
    assert!(eval_b.is_fully_compliant);
}

#[test]
fn test_8021cm_frame_preemption_jitter_reduction() {
    let mut engine_no_preempt = Ieee8021CmEngine::new(Ieee8021CmProfile::ProfileA);
    let mut engine_with_preempt = Ieee8021CmEngine::new(Ieee8021CmProfile::ProfileA);

    // 4-hop network where legacy jumbo packets cause 4000 ns queuing delay per hop
    for i in 1..=4 {
        let name = format!("Bridge-{}", i);
        // Preemption disabled: full 4000 ns queuing jitter
        engine_no_preempt.add_bridge_hop(FronthaulBridgeHop::new(&name, 1500, 4000, 500.0, false));
        // Preemption enabled: express jitter bounded to 100 ns
        engine_with_preempt.add_bridge_hop(FronthaulBridgeHop::new(&name, 1500, 4000, 500.0, true));
    }

    // Evaluate Synchronization stream (Express traffic)
    let eval_no_preempt =
        engine_no_preempt.evaluate_fronthaul_path(EcpriTrafficClass::Synchronization);
    let eval_with_preempt =
        engine_with_preempt.evaluate_fronthaul_path(EcpriTrafficClass::Synchronization);

    // Without preemption: PDV = 4 * 4000 = 16,000 ns > 10,000 ns Profile A limit -> VIOLATION
    assert_eq!(eval_no_preempt.total_pdv_ns, 16_000);
    assert!(!eval_no_preempt.pdv_compliant);
    assert!(!eval_no_preempt.is_fully_compliant);

    // With preemption: PDV = 4 * 100 = 400 ns <= 10,000 ns Profile A limit -> COMPLIANT
    assert_eq!(eval_with_preempt.total_pdv_ns, 400);
    assert!(eval_with_preempt.pdv_compliant);
    assert!(eval_with_preempt.is_fully_compliant);
}

#[test]
fn test_8021cm_ecpri_traffic_class_and_pcp_validation() {
    let engine = Ieee8021CmEngine::new(Ieee8021CmProfile::ProfileA);

    // User Plane IQ (Type 0): PCP 7 -> UserPlaneHigh, PCP 6 -> UserPlaneLow
    assert_eq!(
        engine.validate_ecpri_mapping(0, 7),
        Ok(EcpriTrafficClass::UserPlaneHigh)
    );
    assert_eq!(
        engine.validate_ecpri_mapping(0, 6),
        Ok(EcpriTrafficClass::UserPlaneLow)
    );
    // User Plane IQ mapped to low priority PCP 3 must fail
    assert!(engine.validate_ecpri_mapping(0, 3).is_err());

    // Synchronization (Type 5): requires highest PCP 7
    assert_eq!(
        engine.validate_ecpri_mapping(5, 7),
        Ok(EcpriTrafficClass::Synchronization)
    );
    assert!(engine.validate_ecpri_mapping(5, 6).is_err());

    // Real-Time Control (Type 2): requires PCP >= 5
    assert_eq!(
        engine.validate_ecpri_mapping(2, 5),
        Ok(EcpriTrafficClass::RealTimeControl)
    );
    assert!(engine.validate_ecpri_mapping(2, 4).is_err());

    // Express queue flag verification
    assert!(EcpriTrafficClass::UserPlaneHigh.is_express_traffic());
    assert!(EcpriTrafficClass::Synchronization.is_express_traffic());
    assert!(!EcpriTrafficClass::UserPlaneLow.is_express_traffic());
    assert!(!EcpriTrafficClass::RealTimeControl.is_express_traffic());
    assert!(!EcpriTrafficClass::OamManagement.is_express_traffic());
}
