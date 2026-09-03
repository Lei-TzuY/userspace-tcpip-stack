//! Integration tests for 3GPP TS 29.531 / TS 23.501 5G Network Slice Selection Function (NSSF) Engine.

use toy_tcpip::ngap_5g::{PlmnId, Snssai};
use toy_tcpip::nssf_5g::*;
use toy_tcpip::sba_5g::NfType;

// ---------------------------------------------------------------------------
// 1. Nnssf_NSSelection Happy Path (eMBB & URLLC Admitted with NSI)
// ---------------------------------------------------------------------------

#[test]
fn test_nssf_registration_slice_selection_happy_path() {
    let mut nssf = NssfEngine::new("nssf-core-001");
    let plmn = PlmnId {
        mcc: [2, 0, 8],
        mnc: [9, 5, 0],
    };

    let embb = Snssai { sst: 1, sd: None };
    let urllc = Snssai {
        sst: 2,
        sd: Some([1, 2, 3]),
    };

    // Configure PLMN slices
    nssf.configure_plmn_slices(plmn, vec![embb.clone(), urllc.clone()]);
    nssf.set_slice_nsi(plmn, embb.clone(), "nsi-embb-edge-01");
    nssf.set_slice_nsi(plmn, urllc.clone(), "nsi-urllc-factory-01");

    // AMF registers supported slices in TAC 100
    nssf.handle_availability_update(NssaiAvailabilityUpdate {
        amf_instance_id: "amf-inst-01".to_string(),
        amf_set_id: "amf-set-01".to_string(),
        plmn_id: plmn,
        tai: 100,
        supported_snssais: vec![embb.clone(), urllc.clone()],
        capacity: 100,
    });

    // UE requests eMBB and URLLC during Registration
    let req = NsSelectionRequest {
        nf_type: NfType::Amf,
        nf_id: "amf-inst-01".to_string(),
        slice_info_type: SliceInfoType::Registration,
        requested_nssai: vec![embb.clone(), urllc.clone()],
        subscribed_snssais: vec![embb.clone(), urllc.clone()],
        plmn_id: plmn,
        tai: 100,
    };

    let resp = nssf.handle_ns_selection(&req).expect("NSSelection failed");
    let info = &resp.authorized_network_slice_info;

    assert_eq!(info.allowed_nssai_list.len(), 2);
    assert_eq!(info.allowed_nssai_list[0].snssai, embb);
    assert_eq!(
        info.allowed_nssai_list[0].nsi_id.as_deref(),
        Some("nsi-embb-edge-01")
    );
    assert_eq!(info.allowed_nssai_list[1].snssai, urllc);
    assert_eq!(
        info.allowed_nssai_list[1].nsi_id.as_deref(),
        Some("nsi-urllc-factory-01")
    );

    assert!(info.rejected_nssai_list.is_empty());
    assert_eq!(info.target_amf_set_id.as_deref(), Some("amf-set-01"));
    assert_eq!(info.candidate_amf_list.len(), 1);
    assert_eq!(info.candidate_amf_list[0].amf_instance_id, "amf-inst-01");
}

// ---------------------------------------------------------------------------
// 2. Rejection: Not Subscribed
// ---------------------------------------------------------------------------

#[test]
fn test_nssf_rejection_not_subscribed() {
    let mut nssf = NssfEngine::new("nssf-core-002");
    let plmn = PlmnId {
        mcc: [2, 0, 8],
        mnc: [9, 5, 0],
    };

    let embb = Snssai { sst: 1, sd: None };
    let miot = Snssai { sst: 3, sd: None }; // Not in subscriber's subscription

    nssf.configure_plmn_slices(plmn, vec![embb.clone(), miot.clone()]);
    nssf.handle_availability_update(NssaiAvailabilityUpdate {
        amf_instance_id: "amf-inst-01".to_string(),
        amf_set_id: "amf-set-01".to_string(),
        plmn_id: plmn,
        tai: 200,
        supported_snssais: vec![embb.clone(), miot.clone()],
        capacity: 100,
    });

    let req = NsSelectionRequest {
        nf_type: NfType::Amf,
        nf_id: "amf-inst-01".to_string(),
        slice_info_type: SliceInfoType::Registration,
        requested_nssai: vec![embb.clone(), miot.clone()],
        subscribed_snssais: vec![embb.clone()], // Only eMBB is subscribed!
        plmn_id: plmn,
        tai: 200,
    };

    let resp = nssf.handle_ns_selection(&req).unwrap();
    let info = &resp.authorized_network_slice_info;

    assert_eq!(info.allowed_nssai_list.len(), 1);
    assert_eq!(info.allowed_nssai_list[0].snssai, embb);

    assert_eq!(info.rejected_nssai_list.len(), 1);
    assert_eq!(info.rejected_nssai_list[0].0, miot);
    assert_eq!(
        info.rejected_nssai_list[0].1,
        SnssaiRejectionCause::NotSubscribed
    );
}

// ---------------------------------------------------------------------------
// 3. Rejection: Not Available in Current TA
// ---------------------------------------------------------------------------

#[test]
fn test_nssf_rejection_not_available_in_current_ta() {
    let mut nssf = NssfEngine::new("nssf-core-003");
    let plmn = PlmnId {
        mcc: [2, 0, 8],
        mnc: [9, 5, 0],
    };

    let embb = Snssai { sst: 1, sd: None };
    let urllc = Snssai { sst: 2, sd: None };

    nssf.configure_plmn_slices(plmn, vec![embb.clone(), urllc.clone()]);

    // AMF in rural area (TAC 300) only supports eMBB
    nssf.handle_availability_update(NssaiAvailabilityUpdate {
        amf_instance_id: "amf-rural-01".to_string(),
        amf_set_id: "amf-set-rural".to_string(),
        plmn_id: plmn,
        tai: 300,
        supported_snssais: vec![embb.clone()], // No URLLC in this TAC!
        capacity: 50,
    });

    let req = NsSelectionRequest {
        nf_type: NfType::Amf,
        nf_id: "amf-rural-01".to_string(),
        slice_info_type: SliceInfoType::Registration,
        requested_nssai: vec![embb.clone(), urllc.clone()],
        subscribed_snssais: vec![embb.clone(), urllc.clone()],
        plmn_id: plmn,
        tai: 300,
    };

    let resp = nssf.handle_ns_selection(&req).unwrap();
    let info = &resp.authorized_network_slice_info;

    assert_eq!(info.allowed_nssai_list.len(), 1);
    assert_eq!(info.allowed_nssai_list[0].snssai, embb);

    assert_eq!(info.rejected_nssai_list.len(), 1);
    assert_eq!(info.rejected_nssai_list[0].0, urllc);
    assert_eq!(
        info.rejected_nssai_list[0].1,
        SnssaiRejectionCause::NotAvailableInCurrentTa
    );
}

// ---------------------------------------------------------------------------
// 4. Fallback to Subscribed S-NSSAIs when Requested NSSAI is Empty
// ---------------------------------------------------------------------------

#[test]
fn test_nssf_default_to_subscribed_when_no_requested_nssai() {
    let mut nssf = NssfEngine::new("nssf-core-004");
    let plmn = PlmnId {
        mcc: [2, 0, 8],
        mnc: [9, 5, 0],
    };
    let embb = Snssai { sst: 1, sd: None };

    nssf.configure_plmn_slices(plmn, vec![embb.clone()]);
    nssf.handle_availability_update(NssaiAvailabilityUpdate {
        amf_instance_id: "amf-01".to_string(),
        amf_set_id: "amf-set-01".to_string(),
        plmn_id: plmn,
        tai: 10,
        supported_snssais: vec![embb.clone()],
        capacity: 100,
    });

    let req = NsSelectionRequest {
        nf_type: NfType::Amf,
        nf_id: "amf-01".to_string(),
        slice_info_type: SliceInfoType::Registration,
        requested_nssai: Vec::new(), // Empty requested NSSAI
        subscribed_snssais: vec![embb.clone()],
        plmn_id: plmn,
        tai: 10,
    };

    let resp = nssf.handle_ns_selection(&req).unwrap();
    let info = &resp.authorized_network_slice_info;
    assert_eq!(info.allowed_nssai_list.len(), 1);
    assert_eq!(info.allowed_nssai_list[0].snssai, embb);
}

// ---------------------------------------------------------------------------
// 5. Candidate AMF Resolution & Selection
// ---------------------------------------------------------------------------

#[test]
fn test_nssf_candidate_amf_set_resolution() {
    let mut nssf = NssfEngine::new("nssf-core-005");
    let plmn = PlmnId {
        mcc: [2, 0, 8],
        mnc: [9, 5, 0],
    };
    let embb = Snssai { sst: 1, sd: None };

    nssf.configure_plmn_slices(plmn, vec![embb.clone()]);

    // Register two AMF instances in the same AMF set
    nssf.handle_availability_update(NssaiAvailabilityUpdate {
        amf_instance_id: "amf-node-01".to_string(),
        amf_set_id: "amf-set-metro".to_string(),
        plmn_id: plmn,
        tai: 50,
        supported_snssais: vec![embb.clone()],
        capacity: 100,
    });
    nssf.handle_availability_update(NssaiAvailabilityUpdate {
        amf_instance_id: "amf-node-02".to_string(),
        amf_set_id: "amf-set-metro".to_string(),
        plmn_id: plmn,
        tai: 50,
        supported_snssais: vec![embb.clone()],
        capacity: 80,
    });

    let req = NsSelectionRequest {
        nf_type: NfType::Amf,
        nf_id: "amf-node-01".to_string(),
        slice_info_type: SliceInfoType::Registration,
        requested_nssai: vec![embb.clone()],
        subscribed_snssais: vec![embb.clone()],
        plmn_id: plmn,
        tai: 50,
    };

    let resp = nssf.handle_ns_selection(&req).unwrap();
    let info = &resp.authorized_network_slice_info;
    assert_eq!(info.candidate_amf_list.len(), 2);
    assert_eq!(info.target_amf_set_id.as_deref(), Some("amf-set-metro"));
}
