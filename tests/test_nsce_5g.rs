//! Integration tests for 3GPP TS 29.537 / TS 23.256 5G NSCE (Network Slice Capability Enablement).

use toy_tcpip::nsce_5g::*;

// ---------------------------------------------------------------------------
// 1. Slice Capability Discovery and Nominal SLA Verification Happy Path
// ---------------------------------------------------------------------------

#[test]
fn test_nsce_slice_discovery_and_sla_happy_path() {
    let mut nsce = NsceServerEngine::new("nsce-server-tokyo-01");

    let v2x_slice = SliceCapabilityProfile {
        s_nssai: "SST1-SD000001".to_string(),
        dnn: "v2x.autonomous-driving.net".to_string(),
        capabilities: vec![
            SliceCapability::UrllcUltraLowLatency,
            SliceCapability::EdgeLocalBreakout,
        ],
        sla_contract: SliceSlaContract {
            max_latency_ms: 5,
            max_packet_loss_rate_ppm: 10,
            guaranteed_throughput_mbps: 1000,
        },
        allocated_throughput_mbps: 1000,
        adaptation_state: SliceAdaptationState::Nominal,
    };

    nsce.register_slice_profile(v2x_slice);

    // Step 1: Discover capabilities
    let caps = nsce.discover_slice_capabilities("SST1-SD000001").unwrap();
    assert_eq!(caps.len(), 2);
    assert!(caps.contains(&SliceCapability::UrllcUltraLowLatency));
    assert!(caps.contains(&SliceCapability::EdgeLocalBreakout));

    // Step 2: Assess SLA within contract (3ms latency, 5 ppm loss)
    let res = nsce.assess_slice_sla("SST1-SD000001", 3, 5).unwrap();
    assert_eq!(res, SlaAssessmentResult::WithinContract);
    assert_eq!(
        nsce.slice_profiles
            .get("SST1-SD000001")
            .unwrap()
            .adaptation_state,
        SliceAdaptationState::Nominal
    );
}

// ---------------------------------------------------------------------------
// 2. Latency SLA Violation Alert
// ---------------------------------------------------------------------------

#[test]
fn test_nsce_latency_sla_violation_alert() {
    let mut nsce = NsceServerEngine::new("nsce-server-02");

    let profile = SliceCapabilityProfile {
        s_nssai: "SST2-SD000002".to_string(),
        dnn: "smart-grid.power.net".to_string(),
        capabilities: vec![SliceCapability::TsnDeterministic],
        sla_contract: SliceSlaContract {
            max_latency_ms: 4,
            max_packet_loss_rate_ppm: 5,
            guaranteed_throughput_mbps: 500,
        },
        allocated_throughput_mbps: 500,
        adaptation_state: SliceAdaptationState::Nominal,
    };

    nsce.register_slice_profile(profile);

    // Latency is 9ms (exceeds 4ms threshold)
    let res = nsce.assess_slice_sla("SST2-SD000002", 9, 2).unwrap();
    match res {
        SlaAssessmentResult::SlaViolationAlert {
            observed_value,
            threshold_value,
            ..
        } => {
            assert_eq!(observed_value, 9);
            assert_eq!(threshold_value, 4);
        }
        _ => panic!("Expected SlaViolationAlert"),
    }

    assert_eq!(
        nsce.slice_profiles
            .get("SST2-SD000002")
            .unwrap()
            .adaptation_state,
        SliceAdaptationState::SlaDegraded
    );
}

// ---------------------------------------------------------------------------
// 3. Packet Loss Rate SLA Violation Alert
// ---------------------------------------------------------------------------

#[test]
fn test_nsce_packet_loss_sla_violation_alert() {
    let mut nsce = NsceServerEngine::new("nsce-server-03");

    let profile = SliceCapabilityProfile {
        s_nssai: "SST3-SD000003".to_string(),
        dnn: "industrial-iot.factory.net".to_string(),
        capabilities: vec![SliceCapability::MassiveIot],
        sla_contract: SliceSlaContract {
            max_latency_ms: 20,
            max_packet_loss_rate_ppm: 10, // 0.001%
            guaranteed_throughput_mbps: 200,
        },
        allocated_throughput_mbps: 200,
        adaptation_state: SliceAdaptationState::Nominal,
    };

    nsce.register_slice_profile(profile);

    // Loss rate is 35 ppm (exceeds 10 ppm threshold)
    let res = nsce.assess_slice_sla("SST3-SD000003", 10, 35).unwrap();
    match res {
        SlaAssessmentResult::SlaViolationAlert {
            observed_value,
            threshold_value,
            ..
        } => {
            assert_eq!(observed_value, 35);
            assert_eq!(threshold_value, 10);
        }
        _ => panic!("Expected SlaViolationAlert"),
    }
}

// ---------------------------------------------------------------------------
// 4. Dynamic Slice Adaptation and Reset
// ---------------------------------------------------------------------------

#[test]
fn test_nsce_dynamic_slice_adaptation_and_reset() {
    let mut nsce = NsceServerEngine::new("nsce-server-04");

    let profile = SliceCapabilityProfile {
        s_nssai: "SST4-SD000004".to_string(),
        dnn: "ar-gaming.cloud.net".to_string(),
        capabilities: vec![SliceCapability::HighThroughput],
        sla_contract: SliceSlaContract {
            max_latency_ms: 15,
            max_packet_loss_rate_ppm: 50,
            guaranteed_throughput_mbps: 2000,
        },
        allocated_throughput_mbps: 2000,
        adaptation_state: SliceAdaptationState::Nominal,
    };

    nsce.register_slice_profile(profile);

    // Request 1000 Mbps bandwidth boost
    let new_tp = nsce
        .request_slice_adaptation("SST4-SD000004", 1000)
        .unwrap();
    assert_eq!(new_tp, 3000);
    assert_eq!(
        nsce.slice_profiles
            .get("SST4-SD000004")
            .unwrap()
            .adaptation_state,
        SliceAdaptationState::AdaptedBoosted
    );

    // Reset back to nominal
    nsce.reset_slice_adaptation("SST4-SD000004")
        .expect("Reset failed");
    assert_eq!(
        nsce.slice_profiles
            .get("SST4-SD000004")
            .unwrap()
            .allocated_throughput_mbps,
        2000
    );
    assert_eq!(
        nsce.slice_profiles
            .get("SST4-SD000004")
            .unwrap()
            .adaptation_state,
        SliceAdaptationState::Nominal
    );
}

// ---------------------------------------------------------------------------
// 5. Slice Not Found and Invalid Throughput Handling
// ---------------------------------------------------------------------------

#[test]
fn test_nsce_slice_not_found_and_invalid_throughput() {
    let mut nsce = NsceServerEngine::new("nsce-server-05");

    let err1 = nsce.discover_slice_capabilities("NON-EXISTENT-SLICE");
    assert_eq!(err1, Err(NsceError::SliceNotFound));

    let err2 = nsce.request_slice_adaptation("NON-EXISTENT-SLICE", 100);
    assert_eq!(err2, Err(NsceError::SliceNotFound));

    // Register a valid slice then request 0 Mbps boost
    let profile = SliceCapabilityProfile {
        s_nssai: "SST1-TEST".to_string(),
        dnn: "test.net".to_string(),
        capabilities: vec![],
        sla_contract: SliceSlaContract {
            max_latency_ms: 10,
            max_packet_loss_rate_ppm: 10,
            guaranteed_throughput_mbps: 100,
        },
        allocated_throughput_mbps: 100,
        adaptation_state: SliceAdaptationState::Nominal,
    };
    nsce.register_slice_profile(profile);

    let err3 = nsce.request_slice_adaptation("SST1-TEST", 0);
    assert_eq!(err3, Err(NsceError::InvalidThroughputValue));
}
