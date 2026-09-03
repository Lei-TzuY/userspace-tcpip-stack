//! Integration tests for O-RAN Alliance WG3 E2SM (E2 Service Model) Engine.

use toy_tcpip::ngap_5g::Snssai;
use toy_tcpip::oran_a1_interface::SliceSlaPolicyPayload;
use toy_tcpip::oran_e2sm::*;

// ---------------------------------------------------------------------------
// 1. E2SM-KPM Telemetry Collection & Binary Container Roundtrip
// ---------------------------------------------------------------------------

#[test]
fn test_e2sm_kpm_telemetry_collection_and_serialization() {
    let e2_node = E2NodeSmEngine::new(0x001001_00000001);

    let slice_stats = vec![KpmSliceMeasurement {
        s_nssai: Snssai { sst: 1, sd: None },
        qfi: Some(9),
        dl_prb_usage_ppm: 350_000,
        ul_prb_usage_ppm: 120_000,
        throughput_dl_mbps: 185.5,
    }];

    let ue_stats = vec![KpmUeMeasurement {
        crnti: 0x4001,
        ue_identity_5g_s_tmsi: Some(0x11223344),
        dl_throughput_mbps: 92.4,
        ul_throughput_mbps: 15.1,
        dl_packet_delay_us: 1200,
        dl_packet_loss_ppm: 50,
    }];

    let kpm_msg = e2_node.collect_kpm_telemetry(650_000, 350.0, 42, slice_stats, ue_stats);

    assert_eq!(kpm_msg.cell_id, 0x001001_00000001);
    assert_eq!(kpm_msg.cell_records.len(), 4);
    assert_eq!(kpm_msg.slice_measurements.len(), 1);
    assert_eq!(kpm_msg.ue_measurements.len(), 1);

    // Test wire container binary roundtrip
    let wire = kpm_msg.to_bytes();
    assert!(!wire.is_empty());

    let parsed = KpmIndicationMessage::from_bytes(&wire).expect("Failed to parse KPM wire bytes");
    assert_eq!(parsed.cell_id, kpm_msg.cell_id);
    assert_eq!(parsed.cell_records.len(), 4);
    assert_eq!(parsed.slice_measurements.len(), 1);
    assert_eq!(parsed.slice_measurements[0].s_nssai.sst, 1);
    assert_eq!(parsed.slice_measurements[0].dl_prb_usage_ppm, 350_000);
    assert_eq!(parsed.ue_measurements.len(), 1);
    assert_eq!(parsed.ue_measurements[0].crnti, 0x4001);
    assert_eq!(parsed.ue_measurements[0].dl_packet_delay_us, 1200);
}

// ---------------------------------------------------------------------------
// 2. E2SM-RC Control Message Execution on E2 Node
// ---------------------------------------------------------------------------

#[test]
fn test_e2sm_rc_control_execution_on_e2_node() {
    let mut e2_node = E2NodeSmEngine::new(0x001001_00000002);
    assert_eq!(e2_node.current_prb_quota_ppm, 0);
    assert_eq!(e2_node.current_a3_offset_db, 0);

    let header = RcControlHeader {
        ue_id: None,
        ric_control_style_type: RC_STYLE_RADIO_RESOURCE_ALLOCATION,
        ric_control_action_id: RC_ACTION_SET_PRB_QUOTA,
    };

    let message = RcControlMessage {
        parameters: vec![
            RcControlParameter {
                param_id: RC_PARAM_ID_GUARANTEED_PRB_PPM,
                param_name: "GuaranteedPRB-Ppm",
                param_value: RcParameterValue::Integer(250_000), // 25%
            },
            RcControlParameter {
                param_id: RC_PARAM_ID_A3_OFFSET_DB,
                param_name: "A3-Offset-dB",
                param_value: RcParameterValue::Integer(2),
            },
        ],
    };

    let outcome = e2_node.execute_rc_control(&header, &message);
    assert!(outcome.success);
    assert_eq!(outcome.executed_parameter_ids.len(), 2);
    assert_eq!(e2_node.current_prb_quota_ppm, 250_000);
    assert_eq!(e2_node.current_a3_offset_db, 2);
    assert_eq!(e2_node.executed_controls.len(), 1);
}

// ---------------------------------------------------------------------------
// 3. Closed-Loop xApp: PRB Congestion Detection & Mobility Mitigation
// ---------------------------------------------------------------------------

#[test]
fn test_xapp_closed_loop_prb_congestion_mitigation() {
    let cell_id = 0x001001_00000003;
    let mut xapp = SliceSlaAssuranceXApp::new("xapp-sla-001", vec![cell_id]);
    let e2_node = E2NodeSmEngine::new(cell_id);

    // 1. Normal PRB load (600,000 PPM = 60% < 85% threshold)
    let normal_kpm = e2_node.collect_kpm_telemetry(600_000, 200.0, 30, Vec::new(), Vec::new());
    let action_opt = xapp.process_kpm_indication(&normal_kpm);
    assert!(action_opt.is_none());

    // 2. High PRB load (920,000 PPM = 92% > 85% threshold)
    let congested_kpm = e2_node.collect_kpm_telemetry(920_000, 450.0, 85, Vec::new(), Vec::new());
    let action_opt = xapp.process_kpm_indication(&congested_kpm);
    assert!(action_opt.is_some());

    let (header, message) = action_opt.unwrap();
    assert_eq!(
        header.ric_control_style_type,
        RC_STYLE_CONNECTED_MODE_MOBILITY
    );
    assert_eq!(header.ric_control_action_id, RC_ACTION_ADJUST_A3_OFFSET);
    assert_eq!(message.parameters[0].param_id, RC_PARAM_ID_A3_OFFSET_DB);
    assert_eq!(
        message.parameters[0].param_value,
        RcParameterValue::Integer(-3)
    );
}

// ---------------------------------------------------------------------------
// 4. Closed-Loop xApp: Slice SLA Delay Violation & PRB Remediation
// ---------------------------------------------------------------------------

#[test]
fn test_xapp_closed_loop_slice_sla_delay_violation() {
    let cell_id = 0x001001_00000004;
    let mut xapp = SliceSlaAssuranceXApp::new("xapp-sla-002", vec![cell_id]);
    let e2_node = E2NodeSmEngine::new(cell_id);

    // UE experiencing excessive packet delay (7,200 µs > 5,000 µs threshold)
    let bad_ue = vec![KpmUeMeasurement {
        crnti: 0x5002,
        ue_identity_5g_s_tmsi: Some(0x99887766),
        dl_throughput_mbps: 12.0,
        ul_throughput_mbps: 2.0,
        dl_packet_delay_us: 7_200,
        dl_packet_loss_ppm: 200,
    }];

    let kpm = e2_node.collect_kpm_telemetry(500_000, 100.0, 10, Vec::new(), bad_ue);
    let action_opt = xapp.process_kpm_indication(&kpm);
    assert!(action_opt.is_some());

    let (header, message) = action_opt.unwrap();
    assert_eq!(header.ue_id, Some(0x5002));
    assert_eq!(
        header.ric_control_style_type,
        RC_STYLE_SLICE_SLA_ENFORCEMENT
    );
    assert_eq!(header.ric_control_action_id, RC_ACTION_SET_PRB_QUOTA);
    assert_eq!(
        message.parameters[0].param_id,
        RC_PARAM_ID_GUARANTEED_PRB_PPM
    );
    assert_eq!(
        message.parameters[0].param_value,
        RcParameterValue::Integer(100_000)
    );
}

// ---------------------------------------------------------------------------
// 5. A1 Policy Translation to E2SM-RC Control Message
// ---------------------------------------------------------------------------

#[test]
fn test_a1_policy_translation_to_e2sm_rc() {
    let mut xapp = SliceSlaAssuranceXApp::new("xapp-a1-translator", vec![0x1001]);

    let a1_policy = SliceSlaPolicyPayload {
        target_slice_sst: 1,
        target_slice_sd: None,
        guaranteed_prb_quota_ppm: 300_000,
        max_latency_ms: 4,
    };

    let (header, message) = xapp.translate_a1_policy_to_rc_control(&a1_policy);
    assert_eq!(
        header.ric_control_style_type,
        RC_STYLE_SLICE_SLA_ENFORCEMENT
    );
    assert_eq!(message.parameters.len(), 2);
    assert_eq!(
        message.parameters[0].param_id,
        RC_PARAM_ID_GUARANTEED_PRB_PPM
    );
    assert_eq!(
        message.parameters[0].param_value,
        RcParameterValue::Integer(300_000)
    );
    assert_eq!(
        message.parameters[1].param_value,
        RcParameterValue::Integer(4)
    );
}
