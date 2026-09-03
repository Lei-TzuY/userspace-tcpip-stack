//! Integration tests for O-RAN WG2 A1 Interface Engine.

use toy_tcpip::e2ap_oran::{
    E2NodeType, E2apEngine, E2apRole, GlobalE2NodeId, RAN_FUNCTION_ID_RC, RanFunctionDefinition,
    RicRequestId,
};
use toy_tcpip::oran_a1_interface::{
    A1EiJob, A1EiType, A1EnforcementState, A1InterfaceEngine, A1PolicyInstance, A1PolicyType,
    A1Role, A1StatusCode, SliceSlaPolicyPayload,
};

#[test]
fn test_a1_policy_type_registration_and_instance_crud() {
    let mut a1 = A1InterfaceEngine::new(A1Role::NearRtRic);

    let policy_type = A1PolicyType {
        policy_type_id: 101,
        name: "SliceSlaAssurance".to_string(),
        description: "Enforces minimum guaranteed PRB share per network slice".to_string(),
        schema_version: "1.0.0".to_string(),
    };

    a1.register_policy_type(policy_type);

    let payload = SliceSlaPolicyPayload {
        target_slice_sst: 1,
        target_slice_sd: None,
        guaranteed_prb_quota_ppm: 500_000, // 50%
        max_latency_ms: 10,
    };

    let instance = A1PolicyInstance {
        policy_type_id: 101,
        policy_instance_id: "policy-embb-01".to_string(),
        payload: payload.clone(),
    };

    // 1. Create Policy Instance -> 201 Created
    let create_resp = a1.put_policy(instance.clone());
    assert_eq!(create_resp.status_code, A1StatusCode::Created201);

    // 2. Read Policy Instance -> 200 OK
    let get_resp = a1.get_policy(101, "policy-embb-01");
    assert_eq!(get_resp.status_code, A1StatusCode::Ok200);
    assert!(get_resp.body.unwrap().contains("prb_ppm=500000"));

    // 3. Read Policy Status -> 200 OK, Enforcing
    let status_resp = a1.get_policy_status(101, "policy-embb-01");
    assert_eq!(status_resp.status_code, A1StatusCode::Ok200);
    assert_eq!(
        status_resp.body.unwrap(),
        format!("{:?}", A1EnforcementState::Enforcing)
    );

    // 4. Update Policy Instance -> 200 OK
    let mut updated_instance = instance;
    updated_instance.payload.guaranteed_prb_quota_ppm = 550_000;
    let update_resp = a1.put_policy(updated_instance);
    assert_eq!(update_resp.status_code, A1StatusCode::Ok200);

    let get_updated = a1.get_policy(101, "policy-embb-01");
    assert!(get_updated.body.unwrap().contains("prb_ppm=550000"));

    // 5. Delete Policy Instance -> 204 No Content
    let del_resp = a1.delete_policy(101, "policy-embb-01");
    assert_eq!(del_resp.status_code, A1StatusCode::NoContent204);

    // 6. Verify Deleted -> 404 Not Found
    let get_del = a1.get_policy(101, "policy-embb-01");
    assert_eq!(get_del.status_code, A1StatusCode::NotFound404);
}

#[test]
fn test_a1_policy_validation_rejects_invalid_quota() {
    let mut a1 = A1InterfaceEngine::new(A1Role::NearRtRic);

    let policy_type = A1PolicyType {
        policy_type_id: 102,
        name: "InvalidQuotaCheck".to_string(),
        description: "Validation test".to_string(),
        schema_version: "1.0.0".to_string(),
    };
    a1.register_policy_type(policy_type);

    let invalid_instance = A1PolicyInstance {
        policy_type_id: 102,
        policy_instance_id: "policy-bad-01".to_string(),
        payload: SliceSlaPolicyPayload {
            target_slice_sst: 1,
            target_slice_sd: None,
            guaranteed_prb_quota_ppm: 1_200_000, // Invalid: > 1,000,000 ppm
            max_latency_ms: 10,
        },
    };

    let resp = a1.put_policy(invalid_instance);
    assert_eq!(resp.status_code, A1StatusCode::BadRequest400);
}

#[test]
fn test_a1_policy_translation_to_e2_control() {
    let mut a1 = A1InterfaceEngine::new(A1Role::NearRtRic);
    a1.register_policy_type(A1PolicyType {
        policy_type_id: 103,
        name: "UrllcPriorityPolicy".to_string(),
        description: "Translates A1 intent to E2 closed loop control".to_string(),
        schema_version: "1.0.0".to_string(),
    });

    let instance = A1PolicyInstance {
        policy_type_id: 103,
        policy_instance_id: "policy-urllc-01".to_string(),
        payload: SliceSlaPolicyPayload {
            target_slice_sst: 2, // URLLC
            target_slice_sd: None,
            guaranteed_prb_quota_ppm: 300_000, // 30%
            max_latency_ms: 2,
        },
    };
    a1.put_policy(instance);

    // Translate A1 declarative policy into E2AP RicControlRequest
    let ric_req_id = RicRequestId {
        ric_requestor_id: 301,
        ric_instance_id: 1,
    };
    let e2_ctrl = a1
        .translate_to_e2_control(103, "policy-urllc-01", ric_req_id)
        .unwrap();

    assert_eq!(e2_ctrl.ran_function_id, RAN_FUNCTION_ID_RC);
    assert_eq!(e2_ctrl.target_slice_sst, 2);
    assert_eq!(e2_ctrl.allocated_prb_quota_ppm, 300_000);

    // Verify E2 Node accepts and executes the translated control directive!
    let mut odu = E2apEngine::new(
        E2apRole::E2Node,
        GlobalE2NodeId {
            node_type: E2NodeType::ODu,
            node_id: 0x20001,
            plmn_id: [2, 0, 8],
        },
    );
    let rc = RanFunctionDefinition {
        ran_function_id: RAN_FUNCTION_ID_RC,
        ran_function_revision: 1,
        description: "E2SM-RC v1.0".to_string(),
    };
    let mut ric_e2 = E2apEngine::new(
        E2apRole::NearRtRic,
        GlobalE2NodeId {
            node_type: E2NodeType::ODu,
            node_id: 0x00000,
            plmn_id: [2, 0, 8],
        },
    );
    let setup_req = odu.initiate_e2_setup(vec![rc]);
    let setup_resp = ric_e2.handle_e2_setup_request(&setup_req).unwrap();
    odu.handle_e2_setup_response(&setup_resp).unwrap();

    let ack = odu.handle_control_request(&e2_ctrl).unwrap();
    assert!(ack.is_some());
    assert_eq!(ack.unwrap().status, "Success");
    assert_eq!(odu.slice_prb_quotas.get(&2), Some(&300_000));
}

#[test]
fn test_a1_enrichment_information_job_lifecycle() {
    let mut a1 = A1InterfaceEngine::new(A1Role::NearRtRic);

    let ei_type = A1EiType {
        ei_type_id: "GeoWeatherForecast".to_string(),
        description: "Hyper-local precipitation and wind forecast".to_string(),
    };
    a1.ei_types.insert(ei_type.ei_type_id.clone(), ei_type);

    let job = A1EiJob {
        ei_job_id: "job-weather-01".to_string(),
        ei_type_id: "GeoWeatherForecast".to_string(),
        target_xapp: "traffic-steering-xapp".to_string(),
        job_data: "{\"cell_id\": 1001, \"forecast\": \"HeavyRain\"}".to_string(),
    };

    // 1. Create EI Job -> 201 Created
    let create_resp = a1.create_ei_job(job);
    assert_eq!(create_resp.status_code, A1StatusCode::Created201);
    assert_eq!(a1.ei_jobs.len(), 1);

    // 2. Delete EI Job -> 204 No Content
    let del_resp = a1.delete_ei_job("job-weather-01");
    assert_eq!(del_resp.status_code, A1StatusCode::NoContent204);
    assert_eq!(a1.ei_jobs.len(), 0);
}
