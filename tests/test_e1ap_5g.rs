//! Integration tests for 3GPP TS 38.463 E1AP Control Plane Engine.

use toy_tcpip::e1ap_5g::{E1apDrbSetupItem, E1apEngine, E1apPduSessionItem, E1apRole, E1apState};
use toy_tcpip::f1ap_5g::RlcMode;
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ngap_5g::{PlmnId, Snssai};

fn make_test_plmn() -> PlmnId {
    PlmnId {
        mcc: [2, 0, 8],
        mnc: [9, 5, 0],
    }
}

#[test]
fn test_e1_setup_procedure_happy_path() {
    let mut cu_up = E1apEngine::new(E1apRole::CuUp, 8001, "gNB-CU-UP-Edge");
    let mut cu_cp = E1apEngine::new(E1apRole::CuCp, 9001, "gNB-CU-CP-Main");

    assert_eq!(cu_up.state, E1apState::Idle);
    assert_eq!(cu_cp.state, E1apState::Idle);

    let supported_plmns = vec![(make_test_plmn(), vec![Snssai { sst: 1, sd: None }])];

    // 1. CU-UP initiates E1 Setup
    let req = cu_up.initiate_e1_setup(supported_plmns);
    assert_eq!(cu_up.state, E1apState::SetupPending);
    assert_eq!(req.gnb_cu_up_id, 8001);
    assert!(req.cn_support);

    // 2. CU-CP handles E1 Setup Request
    let resp = cu_cp
        .handle_e1_setup_request(&req)
        .expect("CU-CP failed to handle E1SetupRequest");
    assert_eq!(cu_cp.state, E1apState::Active);
    assert_eq!(resp.gnb_cu_cp_name, Some("gNB-CU-CP-Main".to_string()));

    // 3. CU-UP handles E1 Setup Response
    assert!(cu_up.handle_e1_setup_response(&resp).is_ok());
    assert_eq!(cu_up.state, E1apState::Active);
}

#[test]
fn test_e1_setup_failure_on_empty_plmns() {
    let mut cu_up = E1apEngine::new(E1apRole::CuUp, 8002, "gNB-CU-UP-Empty");
    let mut cu_cp = E1apEngine::new(E1apRole::CuCp, 9002, "gNB-CU-CP-Main");

    let req = cu_up.initiate_e1_setup(Vec::new());
    let err = cu_cp.handle_e1_setup_request(&req).unwrap_err();
    assert_eq!(err.cause, "No supported PLMNs provided by CU-UP");
    assert_eq!(cu_cp.state, E1apState::Idle);
}

#[test]
fn test_bearer_context_setup_and_dual_tunnel_allocation() {
    let mut cu_up = E1apEngine::new(E1apRole::CuUp, 8003, "gNB-CU-UP-Data");
    let mut cu_cp = E1apEngine::new(E1apRole::CuCp, 9003, "gNB-CU-CP-Ctrl");

    let supported_plmns = vec![(make_test_plmn(), vec![Snssai { sst: 1, sd: None }])];
    let req = cu_up.initiate_e1_setup(supported_plmns);
    let resp = cu_cp.handle_e1_setup_request(&req).unwrap();
    cu_up.handle_e1_setup_response(&resp).unwrap();

    let cp_ue_id = 10001;
    let drb1 = E1apDrbSetupItem {
        drb_id: 1,
        qfi_list: vec![1, 2],
        pdcp_sn_size: 18,
        rlc_mode: RlcMode::RlcAm,
        du_f1u_dl_transport_ip: Ipv4Address::new(10, 0, 1, 20),
        du_f1u_dl_gtp_teid: 0x20001,
    };

    let pdu_session1 = E1apPduSessionItem {
        pdu_session_id: 1,
        snssai: Snssai { sst: 1, sd: None },
        drb_to_setup_list: vec![drb1],
    };

    // 1. CU-CP builds BearerContextSetupRequest
    let setup_req = cu_cp
        .build_bearer_context_setup_request(cp_ue_id, vec![pdu_session1])
        .unwrap();

    // 2. CU-UP handles BearerContextSetupRequest and allocates both F1-U and N3 TEIDs
    let cu_up_ip = Ipv4Address::new(10, 0, 2, 30);
    let setup_resp = cu_up
        .handle_bearer_context_setup_request(&setup_req, cu_up_ip, 0x30001)
        .unwrap();

    assert_eq!(setup_resp.gnb_cu_cp_ue_e1ap_id, 10001);
    let up_ue_id = setup_resp.gnb_cu_up_ue_e1ap_id;
    assert_eq!(setup_resp.pdu_sessions.len(), 1);

    let drb_resp = &setup_resp.pdu_sessions[0].drb_setup_list[0];
    assert_eq!(drb_resp.drb_id, 1);
    assert_eq!(drb_resp.cu_up_f1u_dl_transport_ip, cu_up_ip);
    assert_eq!(drb_resp.cu_up_f1u_dl_gtp_teid, 0x30001); // F1-U DL tunnel
    assert_eq!(drb_resp.cu_up_ngu_ul_transport_ip, cu_up_ip);
    assert_eq!(drb_resp.cu_up_ngu_ul_gtp_teid, 0x30002); // N3 UL tunnel

    // 3. CU-CP handles BearerContextSetupResponse
    assert!(
        cu_cp
            .handle_bearer_context_setup_response(&setup_resp)
            .is_ok()
    );

    // 4. Verify bidirectional lookups on both CU-CP and CU-UP!
    let cp_ctx = cu_cp.lookup_by_cp_ue_id(cp_ue_id).unwrap();
    assert_eq!(cp_ctx.gnb_cu_up_ue_e1ap_id, up_ue_id);
    assert_eq!(
        cp_ctx.pdu_sessions[0].drb_setup_list[0].cu_up_f1u_dl_gtp_teid,
        0x30001
    );
    assert_eq!(
        cp_ctx.pdu_sessions[0].drb_setup_list[0].cu_up_ngu_ul_gtp_teid,
        0x30002
    );

    let up_ctx = cu_up.lookup_by_up_ue_id(up_ue_id).unwrap();
    assert_eq!(up_ctx.gnb_cu_cp_ue_e1ap_id, cp_ue_id);
    assert_eq!(
        up_ctx.pdu_sessions[0].drb_setup_list[0].cu_up_f1u_dl_gtp_teid,
        0x30001
    );
    assert_eq!(
        up_ctx.pdu_sessions[0].drb_setup_list[0].cu_up_ngu_ul_gtp_teid,
        0x30002
    );

    // 5. Test Bearer Context Release
    assert!(cu_cp.release_bearer_context(cp_ue_id));
    assert!(cu_cp.lookup_by_cp_ue_id(cp_ue_id).is_none());
    assert!(cu_cp.lookup_by_up_ue_id(up_ue_id).is_none());
}
