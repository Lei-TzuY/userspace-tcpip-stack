//! Integration tests for 3GPP TS 38.473 F1AP Control Plane Engine.

use toy_tcpip::f1ap_5g::{
    DlRrcMessageTransfer, DrbSetupItem, F1apEngine, F1apRole, F1apState,
    InitialUlRrcMessageTransfer, RlcMode, ServedCellInfo,
};
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ngap_5g::{PlmnId, Snssai};

fn make_test_served_cell(nr_cgi: u64, nr_pci: u16) -> ServedCellInfo {
    ServedCellInfo {
        nr_cgi,
        nr_pci,
        tac: 5001,
        plmn: PlmnId {
            mcc: [2, 0, 8],
            mnc: [9, 5, 0],
        },
        arfcn_nr: 632000,
        subcarrier_spacing_khz: 30,
        supported_slices: vec![Snssai { sst: 1, sd: None }],
    }
}

#[test]
fn test_f1_setup_procedure_happy_path() {
    let mut du = F1apEngine::new(F1apRole::Du, 1001, "gNB-DU-North");
    let mut cu = F1apEngine::new(F1apRole::Cu, 2001, "gNB-CU-Central");

    assert_eq!(du.state, F1apState::Idle);
    assert_eq!(cu.state, F1apState::Idle);

    let cell1 = make_test_served_cell(0x001001_00000001, 120);
    let cell2 = make_test_served_cell(0x001001_00000002, 121);

    // 1. DU initiates F1 Setup
    let req = du.initiate_f1_setup(vec![cell1.clone(), cell2.clone()]);
    assert_eq!(du.state, F1apState::SetupPending);
    assert_eq!(req.gnb_du_id, 1001);
    assert_eq!(req.served_cells.len(), 2);

    // 2. CU handles F1 Setup Request
    let resp = cu
        .handle_f1_setup_request(&req)
        .expect("CU failed to handle F1SetupRequest");
    assert_eq!(cu.state, F1apState::Active);
    assert_eq!(resp.cells_to_activate.len(), 2);
    assert_eq!(resp.cells_to_activate[0], 0x001001_00000001);
    assert_eq!(resp.cells_to_activate[1], 0x001001_00000002);

    // 3. DU handles F1 Setup Response
    assert!(du.handle_f1_setup_response(&resp).is_ok());
    assert_eq!(du.state, F1apState::Active);
    assert_eq!(du.active_cells.len(), 2);
}

#[test]
fn test_f1_setup_failure_on_empty_cells() {
    let mut du = F1apEngine::new(F1apRole::Du, 1002, "gNB-DU-Empty");
    let mut cu = F1apEngine::new(F1apRole::Cu, 2002, "gNB-CU-Central");

    let req = du.initiate_f1_setup(Vec::new());
    let err = cu.handle_f1_setup_request(&req).unwrap_err();
    assert_eq!(err.cause, "No served cells provided by DU");
    assert_eq!(cu.state, F1apState::Idle);
}

#[test]
fn test_ue_context_setup_and_f1u_drb_tunnel_binding() {
    let mut du = F1apEngine::new(F1apRole::Du, 1003, "gNB-DU-Edge");
    let mut cu = F1apEngine::new(F1apRole::Cu, 2003, "gNB-CU-Central");

    let cell = make_test_served_cell(0x001001_00000010, 200);
    let req = du.initiate_f1_setup(vec![cell.clone()]);
    let resp = cu.handle_f1_setup_request(&req).unwrap();
    du.handle_f1_setup_response(&resp).unwrap();

    let cu_ue_id = 5001;
    let drb1 = DrbSetupItem {
        drb_id: 1,
        cu_up_transport_ip: Ipv4Address::new(10, 0, 1, 10),
        cu_up_gtp_teid: 0x10001,
        qfi: 9,
        rlc_mode: RlcMode::RlcAm,
    };

    // 1. CU builds UeContextSetupRequest
    let ue_req = cu
        .build_ue_context_setup_request(
            cu_ue_id,
            None,
            cell.nr_cgi,
            vec![drb1],
            Some(vec![0x01, 0x02, 0x03]),
        )
        .unwrap();

    // 2. DU handles UeContextSetupRequest and assigns F1-U Uplink TEID
    let du_transport_ip = Ipv4Address::new(10, 0, 1, 20);
    let ue_resp = du
        .handle_ue_context_setup_request(&ue_req, du_transport_ip, 0x20001)
        .unwrap();
    assert_eq!(ue_resp.gnb_cu_ue_f1ap_id, 5001);
    let du_ue_id = ue_resp.gnb_du_ue_f1ap_id;
    assert_eq!(ue_resp.drb_setup_list.len(), 1);
    assert_eq!(
        ue_resp.drb_setup_list[0].du_up_transport_ip,
        du_transport_ip
    );
    assert_eq!(ue_resp.drb_setup_list[0].du_up_gtp_teid, 0x20001);

    // 3. CU handles UeContextSetupResponse
    assert!(
        cu.handle_ue_context_setup_response(&ue_resp, cell.nr_cgi)
            .is_ok()
    );

    // 4. Verify bidirectional lookups on both CU and DU!
    let cu_ctx = cu.lookup_by_cu_ue_id(cu_ue_id).unwrap();
    assert_eq!(cu_ctx.gnb_du_ue_f1ap_id, du_ue_id);
    assert_eq!(cu_ctx.drbs[0].du_up_gtp_teid, 0x20001);

    let du_ctx = du.lookup_by_du_ue_id(du_ue_id).unwrap();
    assert_eq!(du_ctx.gnb_cu_ue_f1ap_id, cu_ue_id);
    assert_eq!(du_ctx.drbs[0].du_up_gtp_teid, 0x20001);

    // 5. Test UE Context Release
    assert!(cu.release_ue_context(cu_ue_id));
    assert!(cu.lookup_by_cu_ue_id(cu_ue_id).is_none());
    assert!(cu.lookup_by_du_ue_id(du_ue_id).is_none());
}

#[test]
fn test_initial_ul_rrc_and_dl_rrc_transfer() {
    let initial_rrc = InitialUlRrcMessageTransfer {
        gnb_du_ue_f1ap_id: 6001,
        nr_cgi: 0x001001_00000005,
        crnti: 0x4A12,
        rrc_container: vec![0x11, 0x22, 0x33, 0x44], // RRCSetupRequest
    };

    assert_eq!(initial_rrc.gnb_du_ue_f1ap_id, 6001);
    assert_eq!(initial_rrc.crnti, 0x4A12);
    assert_eq!(initial_rrc.rrc_container.len(), 4);

    let dl_rrc = DlRrcMessageTransfer {
        gnb_cu_ue_f1ap_id: 7001,
        gnb_du_ue_f1ap_id: 6001,
        srb_id: 1,
        rrc_container: vec![0x55, 0x66, 0x77, 0x88], // RRCSetup
    };

    assert_eq!(dl_rrc.gnb_cu_ue_f1ap_id, 7001);
    assert_eq!(dl_rrc.gnb_du_ue_f1ap_id, 6001);
    assert_eq!(dl_rrc.srb_id, 1);
    assert_eq!(dl_rrc.rrc_container.len(), 4);
}
