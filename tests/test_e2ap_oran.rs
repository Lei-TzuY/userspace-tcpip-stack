//! Integration tests for O-RAN WG3 E2AP Engine.

use toy_tcpip::e2ap_oran::{
    E2NodeType, E2apEngine, E2apRole, E2apState, GlobalE2NodeId, KpmMetricsPayload,
    RAN_FUNCTION_ID_KPM, RAN_FUNCTION_ID_RC, RanFunctionDefinition, RicActionItem, RicActionType,
    RicControlRequest, RicIndicationType, RicRequestId, RicSubscriptionRequest,
};

fn make_test_e2_node_id(node_type: E2NodeType, node_id: u64) -> GlobalE2NodeId {
    GlobalE2NodeId {
        node_type,
        node_id,
        plmn_id: [2, 0, 8],
    }
}

#[test]
fn test_e2_setup_procedure_happy_path() {
    let mut odu = E2apEngine::new(
        E2apRole::E2Node,
        make_test_e2_node_id(E2NodeType::ODu, 0x10001),
    );
    let mut ric = E2apEngine::new(
        E2apRole::NearRtRic,
        make_test_e2_node_id(E2NodeType::ODu, 0x00000), // RIC dummy ID
    );

    assert_eq!(odu.state, E2apState::Idle);
    assert_eq!(ric.state, E2apState::Idle);

    let kpm = RanFunctionDefinition {
        ran_function_id: RAN_FUNCTION_ID_KPM,
        ran_function_revision: 1,
        description: "E2SM-KPM v2.0".to_string(),
    };
    let rc = RanFunctionDefinition {
        ran_function_id: RAN_FUNCTION_ID_RC,
        ran_function_revision: 1,
        description: "E2SM-RC v1.0".to_string(),
    };

    // 1. E2 Node initiates E2 Setup
    let req = odu.initiate_e2_setup(vec![kpm, rc]);
    assert_eq!(odu.state, E2apState::SetupPending);
    assert_eq!(req.ran_functions_added.len(), 2);

    // 2. Near-RT RIC processes E2SetupRequest
    let resp = ric
        .handle_e2_setup_request(&req)
        .expect("RIC failed to process E2SetupRequest");
    assert_eq!(ric.state, E2apState::Active);
    assert_eq!(resp.ran_functions_accepted.len(), 2);
    assert!(resp.ran_functions_rejected.is_empty());

    // 3. E2 Node processes E2SetupResponse
    assert!(odu.handle_e2_setup_response(&resp).is_ok());
    assert_eq!(odu.state, E2apState::Active);
    assert_eq!(odu.accepted_ran_functions.len(), 2);
}

#[test]
fn test_e2_setup_failure_on_empty_ran_functions() {
    let mut odu = E2apEngine::new(
        E2apRole::E2Node,
        make_test_e2_node_id(E2NodeType::ODu, 0x10002),
    );
    let mut ric = E2apEngine::new(
        E2apRole::NearRtRic,
        make_test_e2_node_id(E2NodeType::ODu, 0x00000),
    );

    let req = odu.initiate_e2_setup(Vec::new());
    let err = ric.handle_e2_setup_request(&req).unwrap_err();
    assert_eq!(err.cause, "No RAN functions advertised by E2 Node");
    assert_eq!(ric.state, E2apState::Idle);
}

#[test]
fn test_ric_subscription_and_kpm_indication_telemetry() {
    let mut odu = E2apEngine::new(
        E2apRole::E2Node,
        make_test_e2_node_id(E2NodeType::ODu, 0x10003),
    );
    let mut ric = E2apEngine::new(
        E2apRole::NearRtRic,
        make_test_e2_node_id(E2NodeType::ODu, 0x00000),
    );

    let kpm = RanFunctionDefinition {
        ran_function_id: RAN_FUNCTION_ID_KPM,
        ran_function_revision: 1,
        description: "E2SM-KPM v2.0".to_string(),
    };

    let req = odu.initiate_e2_setup(vec![kpm]);
    let resp = ric.handle_e2_setup_request(&req).unwrap();
    odu.handle_e2_setup_response(&resp).unwrap();

    let req_id = RicRequestId {
        ric_requestor_id: 101,
        ric_instance_id: 1,
    };

    // 1. RIC sends RicSubscriptionRequest for periodic 100ms KPM telemetry
    let sub_req = RicSubscriptionRequest {
        ric_request_id: req_id,
        ran_function_id: RAN_FUNCTION_ID_KPM,
        event_trigger_period_ms: 100,
        actions: vec![RicActionItem {
            ric_action_id: 1,
            ric_action_type: RicActionType::Report,
            ric_action_definition: None,
        }],
    };

    // 2. E2 Node admits subscription
    let sub_resp = odu.handle_subscription_request(&sub_req).unwrap();
    assert_eq!(sub_resp.actions_admitted, vec![1]);
    assert!(sub_resp.actions_not_admitted.is_empty());

    // 3. E2 Node emits RicIndication with KPM telemetry
    let metrics = KpmMetricsPayload {
        cell_id: 0x001001_00000001,
        dl_prb_usage_ppm: 450_000, // 45%
        ul_prb_usage_ppm: 250_000, // 25%
        dl_throughput_mbps: 850.5,
        ul_throughput_mbps: 120.0,
        active_ue_count: 64,
        avg_packet_delay_us: 450,
    };

    let indication = odu.emit_kpm_indication(req_id, 1, metrics.clone()).unwrap();
    assert_eq!(indication.ric_request_id, req_id);
    assert_eq!(indication.ran_function_id, RAN_FUNCTION_ID_KPM);
    assert_eq!(indication.ric_action_id, 1);
    assert_eq!(indication.ric_indication_sn, 1);
    assert_eq!(indication.ric_indication_type, RicIndicationType::Report);
    assert_eq!(indication.kpm_metrics, Some(metrics));
}

#[test]
fn test_ric_control_prb_quota_reallocation() {
    let mut odu = E2apEngine::new(
        E2apRole::E2Node,
        make_test_e2_node_id(E2NodeType::ODu, 0x10004),
    );
    let mut ric = E2apEngine::new(
        E2apRole::NearRtRic,
        make_test_e2_node_id(E2NodeType::ODu, 0x00000),
    );

    let rc = RanFunctionDefinition {
        ran_function_id: RAN_FUNCTION_ID_RC,
        ran_function_revision: 1,
        description: "E2SM-RC v1.0".to_string(),
    };

    let req = odu.initiate_e2_setup(vec![rc]);
    let resp = ric.handle_e2_setup_request(&req).unwrap();
    odu.handle_e2_setup_response(&resp).unwrap();

    // RIC requests dynamic PRB quota reallocation for slice SST=1 (eMBB) to 60% (600,000 ppm)
    let ctrl = RicControlRequest {
        ric_request_id: RicRequestId {
            ric_requestor_id: 202,
            ric_instance_id: 1,
        },
        ran_function_id: RAN_FUNCTION_ID_RC,
        target_slice_sst: 1,
        target_slice_sd: None,
        allocated_prb_quota_ppm: 600_000,
        ack_request: true,
    };

    let ack = odu.handle_control_request(&ctrl).unwrap();
    assert!(ack.is_some());
    let ack = ack.unwrap();
    assert_eq!(ack.status, "Success");
    assert_eq!(ack.ric_request_id, ctrl.ric_request_id);

    // Verify slice PRB quota updated in E2 Node baseband scheduler
    assert_eq!(odu.slice_prb_quotas.get(&1), Some(&600_000));
}
