//! Integration tests for 3GPP TS 29.502 / TS 23.502 5G Session Management Function (SMF) Engine.

use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::nas_5g::{
    Nas5GsmMessage, NasPdu, PduSessionEstablishmentRequest, PduSessionType, SscMode,
};
use toy_tcpip::ngap_5g::Snssai;
use toy_tcpip::smf_5g::*;

fn make_nas_establishment_request(session_id: u8) -> Vec<u8> {
    let req = PduSessionEstablishmentRequest {
        pdu_session_id: session_id,
        pti: 5,
        pdu_session_type: PduSessionType::Ipv4,
        ssc_mode: SscMode::Ssc1,
    };
    let plain_gsm = NasPdu::new_plain_gsm(Nas5GsmMessage::EstablishmentRequest(req));
    plain_gsm.to_bytes()
}

// ---------------------------------------------------------------------------
// 1. Nsmf_PDUSession_CreateSMContext Happy Path
// ---------------------------------------------------------------------------

#[test]
fn test_smf_pdu_session_create_sm_context_happy_path() {
    let upf_ip = Ipv4Address::new(192, 168, 100, 1);
    let mut smf = SmfEngine::new("smf-control-001", upf_ip, [10, 45, 0]);

    let raw_nas_req = make_nas_establishment_request(1);

    let create_req = CreateSmContextRequest {
        supi: "imsi-208950000000001".to_string(),
        pdu_session_id: 1,
        dnn: "internet".to_string(),
        s_nssai: Snssai { sst: 1, sd: None },
        amf_id: "amf-core-001".to_string(),
        user_location_tai: 2001,
        n1_sm_container: raw_nas_req,
    };

    // 1. SMF handles CreateSMContext
    let resp = smf
        .handle_create_sm_context(&create_req)
        .expect("SMF failed to create SM Context");

    assert_eq!(resp.allocated_ipv4, Ipv4Address::new(10, 45, 0, 2));
    assert_eq!(resp.upf_n3_transport_ip, upf_ip);
    assert_eq!(resp.qfi, 9);
    assert_eq!(resp.n2_sm_info.pdu_session_id, 1);
    assert_eq!(resp.n2_sm_info.upf_gtpu_teid, resp.upf_n3_ul_teid);

    // 2. Verify N1 SM Container contains valid PduSessionEstablishmentAccept
    let n1_pdu =
        NasPdu::from_bytes(&resp.n1_sm_container).expect("Failed to parse N1 SM container");
    match n1_pdu.gsm_message {
        Some(Nas5GsmMessage::EstablishmentAccept(ref acc)) => {
            assert_eq!(acc.pdu_session_id, 1);
            assert_eq!(acc.allocated_ipv4, Some(Ipv4Address::new(10, 45, 0, 2)));
            assert_eq!(acc.authorized_qfi, 9);
        }
        _ => panic!("Expected EstablishmentAccept"),
    }

    // 3. Verify N4 PFCP Session programmed on UPF with Uplink rules
    let sess = smf.active_sessions.get(&resp.sm_context_ref).unwrap();
    assert_eq!(sess.state, SmContextState::ActivePending);

    let upf_sess = smf.pfcp_node.sessions.get(&sess.pfcp_session_seid).unwrap();
    assert_eq!(upf_sess.pdrs.len(), 1);
    assert_eq!(upf_sess.pdrs[0].teid, Some(resp.upf_n3_ul_teid));
    assert_eq!(upf_sess.fars.len(), 1);
}

// ---------------------------------------------------------------------------
// 2. Nsmf_PDUSession_UpdateSMContext (Initial Downlink Tunnel Setup)
// ---------------------------------------------------------------------------

#[test]
fn test_smf_pdu_session_update_sm_context_initial_dl_tunnel() {
    let upf_ip = Ipv4Address::new(192, 168, 100, 1);
    let mut smf = SmfEngine::new("smf-control-002", upf_ip, [10, 45, 0]);

    let create_req = CreateSmContextRequest {
        supi: "imsi-208950000000002".to_string(),
        pdu_session_id: 2,
        dnn: "ims".to_string(),
        s_nssai: Snssai { sst: 2, sd: None },
        amf_id: "amf-core-001".to_string(),
        user_location_tai: 2001,
        n1_sm_container: make_nas_establishment_request(2),
    };

    let create_resp = smf.handle_create_sm_context(&create_req).unwrap();

    // gNodeB allocates DL IP and DL GTP-U TEID
    let gnb_dl_ip = Ipv4Address::new(10, 0, 1, 50);
    let gnb_dl_teid = 0x8000_1234;

    let update_req = UpdateSmContextRequest {
        sm_context_ref: create_resp.sm_context_ref.clone(),
        update_type: SmContextUpdateType::InitialDlTunnelSetup,
        an_tunnel_ip: gnb_dl_ip,
        an_tunnel_teid: gnb_dl_teid,
    };

    let update_resp = smf
        .handle_update_sm_context(&update_req)
        .expect("SMF update failed");
    assert!(update_resp.success);
    assert_eq!(update_resp.current_state, SmContextState::Active);

    // Verify UPF PFCP session now contains Downlink PDR & FAR pointing to gNB
    let sess = smf
        .active_sessions
        .get(&create_resp.sm_context_ref)
        .unwrap();
    assert_eq!(sess.state, SmContextState::Active);
    assert_eq!(sess.gnb_n3_dl_ip, Some(gnb_dl_ip));
    assert_eq!(sess.gnb_n3_dl_teid, Some(gnb_dl_teid));

    let upf_sess = smf.pfcp_node.sessions.get(&sess.pfcp_session_seid).unwrap();
    assert_eq!(upf_sess.pdrs.len(), 2); // 1 UL + 1 DL
    assert_eq!(upf_sess.fars.len(), 2);

    let dl_far = upf_sess.fars.iter().find(|f| f.far_id == 2).unwrap();
    assert_eq!(dl_far.outer_header_creation, Some((gnb_dl_teid, gnb_dl_ip)));
}

// ---------------------------------------------------------------------------
// 3. Handover Execution (Downlink Tunnel Re-anchoring)
// ---------------------------------------------------------------------------

#[test]
fn test_smf_pdu_session_handover_execution_dl_tunnel_switch() {
    let upf_ip = Ipv4Address::new(192, 168, 100, 1);
    let mut smf = SmfEngine::new("smf-control-003", upf_ip, [10, 45, 0]);

    let create_req = CreateSmContextRequest {
        supi: "imsi-208950000000003".to_string(),
        pdu_session_id: 1,
        dnn: "internet".to_string(),
        s_nssai: Snssai { sst: 1, sd: None },
        amf_id: "amf-core-001".to_string(),
        user_location_tai: 2001,
        n1_sm_container: make_nas_establishment_request(1),
    };
    let create_resp = smf.handle_create_sm_context(&create_req).unwrap();

    // Source gNB initial setup
    smf.handle_update_sm_context(&UpdateSmContextRequest {
        sm_context_ref: create_resp.sm_context_ref.clone(),
        update_type: SmContextUpdateType::InitialDlTunnelSetup,
        an_tunnel_ip: Ipv4Address::new(10, 0, 1, 10),
        an_tunnel_teid: 0x1111,
    })
    .unwrap();

    // Handover occurs: Target gNB DL IP/TEID
    let target_gnb_ip = Ipv4Address::new(10, 0, 2, 20);
    let target_gnb_teid = 0x2222;

    let ho_update = UpdateSmContextRequest {
        sm_context_ref: create_resp.sm_context_ref.clone(),
        update_type: SmContextUpdateType::HandoverExecution,
        an_tunnel_ip: target_gnb_ip,
        an_tunnel_teid: target_gnb_teid,
    };
    let ho_resp = smf.handle_update_sm_context(&ho_update).unwrap();
    assert!(ho_resp.success);
    assert_eq!(ho_resp.current_state, SmContextState::Active);

    // Verify UPF FAR was updated to target gNodeB
    let sess = smf
        .active_sessions
        .get(&create_resp.sm_context_ref)
        .unwrap();
    assert_eq!(sess.gnb_n3_dl_ip, Some(target_gnb_ip));
    assert_eq!(sess.gnb_n3_dl_teid, Some(target_gnb_teid));

    let upf_sess = smf.pfcp_node.sessions.get(&sess.pfcp_session_seid).unwrap();
    let dl_far = upf_sess.fars.iter().find(|f| f.far_id == 2).unwrap();
    assert_eq!(
        dl_far.outer_header_creation,
        Some((target_gnb_teid, target_gnb_ip))
    );
}

// ---------------------------------------------------------------------------
// 4. Nsmf_PDUSession_ReleaseSMContext
// ---------------------------------------------------------------------------

#[test]
fn test_smf_pdu_session_release_sm_context() {
    let upf_ip = Ipv4Address::new(192, 168, 100, 1);
    let mut smf = SmfEngine::new("smf-control-004", upf_ip, [10, 45, 0]);

    let create_req = CreateSmContextRequest {
        supi: "imsi-208950000000004".to_string(),
        pdu_session_id: 1,
        dnn: "internet".to_string(),
        s_nssai: Snssai { sst: 1, sd: None },
        amf_id: "amf-core-001".to_string(),
        user_location_tai: 2001,
        n1_sm_container: make_nas_establishment_request(1),
    };
    let create_resp = smf.handle_create_sm_context(&create_req).unwrap();
    let sm_ref = create_resp.sm_context_ref.clone();

    assert_eq!(smf.active_sessions.len(), 1);
    assert_eq!(smf.ipam.allocated_ips.len(), 1);
    assert_eq!(smf.pfcp_node.sessions.len(), 1);

    // Release SM Context
    let rel_req = ReleaseSmContextRequest {
        sm_context_ref: sm_ref.clone(),
        cause: Some("RegularDeactivation".to_string()),
    };
    let rel_resp = smf.handle_release_sm_context(&rel_req).unwrap();
    assert!(rel_resp.success);
    assert_eq!(rel_resp.released_ipv4, Some(Ipv4Address::new(10, 45, 0, 2)));

    // Verify all resources freed
    assert!(smf.active_sessions.is_empty());
    assert!(smf.ipam.allocated_ips.is_empty());
    assert!(smf.pfcp_node.sessions.is_empty());
}

// ---------------------------------------------------------------------------
// 5. IPAM Pool Exhaustion
// ---------------------------------------------------------------------------

#[test]
fn test_smf_ipam_pool_exhaustion() {
    let upf_ip = Ipv4Address::new(192, 168, 100, 1);
    // Tiny pool of only 2 addresses: host 2 to host 3
    let mut smf = SmfEngine::new("smf-tiny", upf_ip, [10, 45, 0]);
    smf.ipam.max_host = 3;

    let req1 = CreateSmContextRequest {
        supi: "imsi-1".to_string(),
        pdu_session_id: 1,
        dnn: "internet".to_string(),
        s_nssai: Snssai { sst: 1, sd: None },
        amf_id: "amf-1".to_string(),
        user_location_tai: 1,
        n1_sm_container: make_nas_establishment_request(1),
    };
    let req2 = CreateSmContextRequest {
        supi: "imsi-2".to_string(),
        pdu_session_id: 2,
        dnn: "internet".to_string(),
        s_nssai: Snssai { sst: 1, sd: None },
        amf_id: "amf-1".to_string(),
        user_location_tai: 1,
        n1_sm_container: make_nas_establishment_request(2),
    };
    let req3 = CreateSmContextRequest {
        supi: "imsi-3".to_string(),
        pdu_session_id: 3,
        dnn: "internet".to_string(),
        s_nssai: Snssai { sst: 1, sd: None },
        amf_id: "amf-1".to_string(),
        user_location_tai: 1,
        n1_sm_container: make_nas_establishment_request(3),
    };

    assert!(smf.handle_create_sm_context(&req1).is_ok());
    assert!(smf.handle_create_sm_context(&req2).is_ok());
    // Third allocation should fail with IPAM exhaustion
    let err = smf
        .handle_create_sm_context(&req3)
        .expect_err("Should exhaust IP pool");
    assert!(err.contains("IPAM"));
}

// ---------------------------------------------------------------------------
// 6. Cross-Layer End-to-End Orchestration (NAS -> AMF -> SMF -> UPF PFCP -> NGAP)
// ---------------------------------------------------------------------------

#[test]
fn test_end_to_end_5g_nas_smf_pfcp_ngap_pipeline() {
    let upf_ip = Ipv4Address::new(192, 168, 100, 1);
    let mut smf = SmfEngine::new("smf-core-orchestrator", upf_ip, [10, 45, 0]);

    // 1. UE sends NAS PduSessionEstablishmentRequest inside UL NAS Transport
    let ue_nas_pdu = make_nas_establishment_request(1);

    // 2. AMF invokes Nsmf_PDUSession_CreateSMContext
    let create_req = CreateSmContextRequest {
        supi: "imsi-208950000000099".to_string(),
        pdu_session_id: 1,
        dnn: "internet".to_string(),
        s_nssai: Snssai { sst: 1, sd: None },
        amf_id: "amf-core-001".to_string(),
        user_location_tai: 100,
        n1_sm_container: ue_nas_pdu,
    };
    let create_resp = smf
        .handle_create_sm_context(&create_req)
        .expect("Create SM Context failed");

    // 3. AMF forwards n2_sm_info (PduSessionResourceSetupRequest) to gNodeB over NGAP (N2)
    let n2_req = &create_resp.n2_sm_info;
    assert_eq!(n2_req.pdu_session_id, 1);
    assert_eq!(n2_req.upf_transport_ip, upf_ip);
    assert_eq!(n2_req.upf_gtpu_teid, create_resp.upf_n3_ul_teid);

    // 4. gNodeB accepts and allocates DL tunnel (e.g. 10.0.0.10:0x5555)
    let gnb_dl_ip = Ipv4Address::new(10, 0, 0, 10);
    let gnb_dl_teid = 0x5555;

    // 5. AMF forwards gNB DL info to SMF via UpdateSMContext
    let update_req = UpdateSmContextRequest {
        sm_context_ref: create_resp.sm_context_ref.clone(),
        update_type: SmContextUpdateType::InitialDlTunnelSetup,
        an_tunnel_ip: gnb_dl_ip,
        an_tunnel_teid: gnb_dl_teid,
    };
    let update_resp = smf
        .handle_update_sm_context(&update_req)
        .expect("Update SM Context failed");
    assert_eq!(update_resp.current_state, SmContextState::Active);

    // 6. AMF delivers N1 SM container (PduSessionEstablishmentAccept) to UE via DL NAS Transport
    let dl_nas = NasPdu::from_bytes(&create_resp.n1_sm_container).unwrap();
    if let Some(Nas5GsmMessage::EstablishmentAccept(acc)) = dl_nas.gsm_message {
        assert_eq!(acc.pdu_session_id, 1);
        assert_eq!(acc.allocated_ipv4, Some(create_resp.allocated_ipv4));
    } else {
        panic!("Missing NAS establishment accept");
    }

    // 7. Verify UPF PFCP session has both UL and DL forwarding paths ready
    let ctx = smf
        .active_sessions
        .get(&create_resp.sm_context_ref)
        .unwrap();
    let upf_sess = smf.pfcp_node.sessions.get(&ctx.pfcp_session_seid).unwrap();
    assert_eq!(upf_sess.pdrs.len(), 2);
    assert_eq!(upf_sess.fars.len(), 2);
}
