//! Integration tests for 3GPP TS 38.423 5G XnAP Control Plane Protocol Engine.

use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ngap_5g::{PlmnId, Snssai};
use toy_tcpip::xnap_5g::*;

fn test_plmn() -> PlmnId {
    PlmnId {
        mcc: [2, 0, 8],
        mnc: [9, 5, 0],
    }
}

fn make_cell(nr_cgi: u64, pci: u16) -> XnServedCellInfo {
    XnServedCellInfo {
        nr_cgi,
        nr_pci: pci,
        tac: 2001,
        plmn: test_plmn(),
        arfcn_nr: 632000,
        supported_slices: vec![Snssai { sst: 1, sd: None }],
    }
}

// ---------------------------------------------------------------------------
// 1. Xn Setup Procedure (TS 38.423 Section 8.4.1)
// ---------------------------------------------------------------------------

#[test]
fn test_xn_setup_procedure_happy_path() {
    let mut gnb1 = XnapEngine::new(1001, "gNB-Alpha");
    let mut gnb2 = XnapEngine::new(2001, "gNB-Beta");

    let cell1 = make_cell(0x001001_00000001, 101);
    let cell2 = make_cell(0x002001_00000002, 202);

    gnb1.register_served_cell(cell1.clone());
    gnb2.register_served_cell(cell2.clone());

    assert_eq!(gnb1.peer_state, XnPeerState::Disconnected);
    assert_eq!(gnb2.peer_state, XnPeerState::Disconnected);

    // 1. gNB1 initiates Xn Setup toward gNB2
    let req = gnb1
        .initiate_xn_setup()
        .expect("gNB1 setup initiation failed");
    assert_eq!(gnb1.peer_state, XnPeerState::SetupPending);
    assert_eq!(req.global_gnb_id, 1001);
    assert_eq!(req.served_cells.len(), 1);

    // 2. gNB2 handles Xn Setup Request
    let resp = gnb2
        .handle_xn_setup_request(&req)
        .expect("gNB2 handle setup request failed");
    assert_eq!(gnb2.peer_state, XnPeerState::Active);
    assert_eq!(gnb2.peer_gnb_id, Some(1001));
    assert_eq!(gnb2.peer_cells.len(), 1);

    // 3. gNB1 handles Xn Setup Response
    assert!(gnb1.handle_xn_setup_response(&resp).is_ok());
    assert_eq!(gnb1.peer_state, XnPeerState::Active);
    assert_eq!(gnb1.peer_gnb_id, Some(2001));
    assert_eq!(gnb1.peer_cells.len(), 1);
}

#[test]
fn test_xn_setup_failure_on_empty_cells() {
    let mut gnb1 = XnapEngine::new(1001, "gNB-NoCells");
    assert!(gnb1.initiate_xn_setup().is_err());
}

// ---------------------------------------------------------------------------
// 2. Xn Handover Preparation & Request Acknowledge with Forwarding Tunnels
// ---------------------------------------------------------------------------

#[test]
fn test_xn_handover_preparation_and_acknowledgement() {
    let mut source_gnb = XnapEngine::new(1001, "gNB-Source");
    let mut target_gnb = XnapEngine::new(2001, "gNB-Target");

    let source_cell = make_cell(0x001001_00000001, 101);
    let target_cell = make_cell(0x002001_00000002, 202);
    source_gnb.register_served_cell(source_cell);
    target_gnb.register_served_cell(target_cell.clone());

    // Build PDU Session Resources to be setup
    let drb1 = XnDrbItem {
        drb_id: 1,
        qfi_list: vec![9],
        dl_forwarding_required: true,
        ul_forwarding_required: false,
    };
    let drb2 = XnDrbItem {
        drb_id: 2,
        qfi_list: vec![15],
        dl_forwarding_required: false,
        ul_forwarding_required: false,
    };
    let pdu_session = PduSessionResourceToBeSetup {
        pdu_session_id: 1,
        s_nssai: Snssai { sst: 1, sd: None },
        upf_transport_ip: Ipv4Address::new(10, 0, 100, 1),
        upf_gtp_teid: 0x10001,
        drb_to_setup_list: vec![drb1, drb2],
    };

    let rrc_handover_prep_info = vec![0x11, 0x22, 0x33, 0x44]; // Mock RRC container

    // 1. Source gNB builds HandoverRequest
    let ho_req = source_gnb.build_handover_request(
        XnCause::HandoverDesirableForRadioReason,
        target_cell.nr_cgi,
        0x5001_0001,
        vec![pdu_session],
        rrc_handover_prep_info,
    );
    assert_eq!(ho_req.target_cell_nr_cgi, target_cell.nr_cgi);
    assert_eq!(source_gnb.outgoing_handovers.len(), 1);

    // 2. Target gNB handles HandoverRequest, allocates DL forwarding tunnel for DRB1
    let target_ip = Ipv4Address::new(192, 168, 50, 2);
    let rrc_reconfig_sync = vec![0x55, 0x66, 0x77]; // Mock RrcReconfiguration with sync
    let ho_ack = target_gnb
        .handle_handover_request(&ho_req, target_ip, 0x20001, rrc_reconfig_sync.clone())
        .expect("Target gNB handle handover request failed");

    assert_eq!(ho_ack.source_ue_xnap_id, ho_req.source_ue_xnap_id);
    assert_eq!(ho_ack.pdu_session_resources_admitted.len(), 1);
    assert_eq!(
        ho_ack.target_to_source_transparent_container,
        rrc_reconfig_sync
    );

    // Verify DL forwarding tunnel allocated on target
    let admitted = &ho_ack.pdu_session_resources_admitted[0];
    assert_eq!(admitted.admitted_drbs.len(), 2);
    assert_eq!(admitted.forwarding_tunnels.len(), 1);
    assert_eq!(admitted.forwarding_tunnels[0].drb_id, 1);
    assert_eq!(admitted.forwarding_tunnels[0].dl_forwarding_ip, target_ip);
    assert_eq!(admitted.forwarding_tunnels[0].dl_forwarding_teid, 0x20001);

    // 3. Source gNB handles HandoverRequestAcknowledge
    assert!(source_gnb.handle_handover_request_ack(&ho_ack).is_ok());
    let src_ctx = source_gnb
        .outgoing_handovers
        .get(&ho_req.source_ue_xnap_id)
        .unwrap();
    assert_eq!(src_ctx.status, HandoverStatus::Execution);
    assert_eq!(src_ctx.forwarding_tunnels.len(), 1);
    assert_eq!(src_ctx.forwarding_tunnels[0].dl_forwarding_teid, 0x20001);
}

// ---------------------------------------------------------------------------
// 3. Handover Preparation Failure on Unknown Cell
// ---------------------------------------------------------------------------

#[test]
fn test_xn_handover_preparation_failure_cell_not_found() {
    let mut source_gnb = XnapEngine::new(1001, "gNB-Source");
    let mut target_gnb = XnapEngine::new(2001, "gNB-Target");

    let ho_req = source_gnb.build_handover_request(
        XnCause::TimeCriticalHandover,
        0xDEAD_BEEF, // Unknown cell
        0x9001,
        Vec::new(),
        Vec::new(),
    );

    let err = target_gnb
        .handle_handover_request(&ho_req, Ipv4Address::new(10, 0, 0, 1), 0x1000, Vec::new())
        .expect_err("Should fail with target cell not available");

    assert_eq!(err.cause, XnCause::TargetCellNotAvailable);
    assert_eq!(err.source_ue_xnap_id, ho_req.source_ue_xnap_id);
}

// ---------------------------------------------------------------------------
// 4. SN Status Transfer (PDCP COUNT synchronization)
// ---------------------------------------------------------------------------

#[test]
fn test_xn_sn_status_transfer_pdcp_count_sync() {
    let mut source_gnb = XnapEngine::new(1001, "gNB-Source");
    let mut target_gnb = XnapEngine::new(2001, "gNB-Target");
    let target_cell = make_cell(0x002001_00000002, 202);
    target_gnb.register_served_cell(target_cell.clone());

    // Setup ongoing handover
    let ho_req = source_gnb.build_handover_request(
        XnCause::HandoverDesirableForRadioReason,
        target_cell.nr_cgi,
        0x1001,
        Vec::new(),
        Vec::new(),
    );
    let ho_ack = target_gnb
        .handle_handover_request(&ho_req, Ipv4Address::new(10, 0, 0, 2), 0x5000, Vec::new())
        .unwrap();
    source_gnb.handle_handover_request_ack(&ho_ack).unwrap();

    // Source builds SN Status Transfer (PDCP COUNT status per TS 38.423 Section 8.2.2)
    let sn_status = vec![SnStatusItem {
        drb_id: 1,
        dl_count: 1042,
        ul_count: 512,
        receive_status_bitmap: Some(vec![0b10110000]),
    }];

    let transfer = source_gnb
        .build_sn_status_transfer(ho_req.source_ue_xnap_id, sn_status)
        .expect("Build SN status transfer failed");
    assert_eq!(transfer.source_ue_xnap_id, ho_req.source_ue_xnap_id);
    assert_eq!(transfer.target_ue_xnap_id, ho_ack.target_ue_xnap_id);

    // Target handles SN Status Transfer
    assert!(target_gnb.handle_sn_status_transfer(&transfer));
    let tgt_ctx = target_gnb
        .incoming_handovers
        .get(&ho_ack.target_ue_xnap_id)
        .unwrap();
    assert_eq!(tgt_ctx.sn_status.len(), 1);
    assert_eq!(tgt_ctx.sn_status[0].dl_count, 1042);
    assert_eq!(tgt_ctx.sn_status[0].ul_count, 512);
}

// ---------------------------------------------------------------------------
// 5. UE Context Release Lifecycle
// ---------------------------------------------------------------------------

#[test]
fn test_xn_ue_context_release_lifecycle() {
    let mut source_gnb = XnapEngine::new(1001, "gNB-Source");
    let mut target_gnb = XnapEngine::new(2001, "gNB-Target");
    let target_cell = make_cell(0x002001_00000002, 202);
    target_gnb.register_served_cell(target_cell.clone());

    let ho_req = source_gnb.build_handover_request(
        XnCause::HandoverDesirableForRadioReason,
        target_cell.nr_cgi,
        0x1001,
        Vec::new(),
        Vec::new(),
    );
    let ho_ack = target_gnb
        .handle_handover_request(&ho_req, Ipv4Address::new(10, 0, 0, 2), 0x5000, Vec::new())
        .unwrap();
    source_gnb.handle_handover_request_ack(&ho_ack).unwrap();

    // Handover executed successfully: target commands source to release UE context
    let release_msg = target_gnb
        .build_ue_context_release(ho_ack.target_ue_xnap_id)
        .expect("Build UE Context Release failed");
    assert_eq!(release_msg.source_ue_xnap_id, ho_req.source_ue_xnap_id);

    // Source handles UE Context Release
    assert!(source_gnb.handle_ue_context_release(&release_msg));
    assert!(source_gnb.outgoing_handovers.is_empty());
}

// ---------------------------------------------------------------------------
// 6. Handover Cancel
// ---------------------------------------------------------------------------

#[test]
fn test_xn_handover_cancel() {
    let mut source_gnb = XnapEngine::new(1001, "gNB-Source");
    let mut target_gnb = XnapEngine::new(2001, "gNB-Target");
    let target_cell = make_cell(0x002001_00000002, 202);
    target_gnb.register_served_cell(target_cell.clone());

    let ho_req = source_gnb.build_handover_request(
        XnCause::HandoverDesirableForRadioReason,
        target_cell.nr_cgi,
        0x1001,
        Vec::new(),
        Vec::new(),
    );
    let ho_ack = target_gnb
        .handle_handover_request(&ho_req, Ipv4Address::new(10, 0, 0, 2), 0x5000, Vec::new())
        .unwrap();
    source_gnb.handle_handover_request_ack(&ho_ack).unwrap();

    // Source cancels handover
    let cancel = source_gnb
        .build_handover_cancel(ho_req.source_ue_xnap_id, XnCause::TimeCriticalHandover)
        .expect("Build cancel failed");

    assert!(target_gnb.handle_handover_cancel(&cancel));
    assert!(target_gnb.incoming_handovers.is_empty());
}

// ---------------------------------------------------------------------------
// 7. Dual Connectivity (S-gNB Addition)
// ---------------------------------------------------------------------------

#[test]
fn test_xn_dual_connectivity_sgnb_addition() {
    let mut m_gnb = XnapEngine::new(1001, "M-gNB");
    let mut s_gnb = XnapEngine::new(2001, "S-gNB");

    let s_cell = make_cell(0x002001_00000005, 303);
    s_gnb.register_served_cell(s_cell.clone());

    let offload_drb = XnDrbItem {
        drb_id: 3,
        qfi_list: vec![7, 8],
        dl_forwarding_required: false,
        ul_forwarding_required: false,
    };

    // Master gNB requests S-gNB Addition
    let req = m_gnb.build_sgnb_addition_request(5001, s_cell.nr_cgi, vec![offload_drb]);
    assert_eq!(req.m_gnb_ue_xnap_id, 5001);
    assert_eq!(req.drb_to_offload_list.len(), 1);

    // Secondary gNB acknowledges S-gNB Addition
    let s_ip = Ipv4Address::new(192, 168, 88, 1);
    let ack = s_gnb.handle_sgnb_addition_request(&req, s_ip, 0x8001);
    assert_eq!(ack.m_gnb_ue_xnap_id, 5001);
    assert_eq!(ack.admitted_drbs, vec![3]);
    assert_eq!(ack.s_gnb_transport_ip, s_ip);
    assert_eq!(ack.s_gnb_gtp_teid, 0x8001);
}
