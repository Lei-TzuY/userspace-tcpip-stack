//! Integration tests for 3GPP TS 29.518 / TS 23.501 / TS 23.502 Rel-17 5G AMF Service-Based Engine.

use toy_tcpip::amf_sbi_5g::{
    AmfError, AmfEventType, AmfSbiEngine, CmState, ContextTransferReason, Guami,
    N1N2MessageTransferRequest, N1N2MessageTransferStatus, NasCipheringAlgorithm,
    NasIntegrityAlgorithm, NrCgi, PlmnId, RegistrationCommitStatus, RmState, Snssai, Tai,
    UeContextTransferRequest, derive_k_amf, derive_k_gnb, derive_k_nas,
};

#[test]
fn test_amf_initial_registration_and_security_derivation() {
    let plmn = PlmnId::new([2, 0, 8], [9, 5, 0]);
    let guami = Guami::new(plmn, 0x01, 0x001, 0x01);
    let mut amf = AmfSbiEngine::new("amf-east-01", guami);

    let supi = "208950000000001";
    let pei = "860000000000001";
    let k_seaf = [0x55u8; 32];
    let serving_cell = NrCgi::new(plmn, 0x0001_0000);
    let current_tai = Tai::new(plmn, 0x000001);
    let registration_area = vec![Tai::new(plmn, 0x000001), Tai::new(plmn, 0x000002)];
    let allowed_nssai = vec![Snssai::new(1, Some([0, 0, 1]))];
    let ran_ue_id = 42;

    // 1. Register UE
    let guti = amf.register_ue(
        supi,
        Some(pei),
        &k_seaf,
        serving_cell,
        current_tai,
        registration_area,
        allowed_nssai,
        ran_ue_id,
        1000,
    );

    assert_eq!(guti.guami, guami);
    assert_eq!(guti.five_g_tmsi, 0x1000_0001);

    // 2. Check UE Context state
    let ue = amf.ue_contexts.get(supi).expect("UE context must exist");
    assert_eq!(ue.rm_state, RmState::Registered);
    assert_eq!(ue.cm_state, CmState::Connected);
    assert_eq!(ue.ran_ue_ngap_id, Some(42));
    assert_eq!(ue.amf_ue_ngap_id, 100);

    // 3. Verify security keys derived
    let sec_ctx = ue
        .security_ctx
        .as_ref()
        .expect("Security context must be set");
    assert_eq!(sec_ctx.cipher_algo, NasCipheringAlgorithm::Nea2AesCtr);
    assert_eq!(sec_ctx.integrity_algo, NasIntegrityAlgorithm::Nia2AesCmac);
    assert_ne!(sec_ctx.k_amf, [0u8; 32]);
    assert_ne!(sec_ctx.k_gnb, [0u8; 32]);
    assert_ne!(sec_ctx.k_nas_enc, [0u8; 16]);
    assert_ne!(sec_ctx.k_nas_int, [0u8; 16]);

    // 4. Verify direct cryptographic derivation consistency
    let expected_k_amf = derive_k_amf(&k_seaf, supi, &[0x00, 0x00]);
    assert_eq!(sec_ctx.k_amf, expected_k_amf);
    let expected_k_gnb = derive_k_gnb(&expected_k_amf, 0);
    assert_eq!(sec_ctx.k_gnb, expected_k_gnb);
    let expected_k_enc = derive_k_nas(
        &expected_k_amf,
        0x01,
        NasCipheringAlgorithm::Nea2AesCtr as u8,
    );
    assert_eq!(sec_ctx.k_nas_enc, expected_k_enc);
    let expected_k_int = derive_k_nas(
        &expected_k_amf,
        0x02,
        NasIntegrityAlgorithm::Nia2AesCmac as u8,
    );
    assert_eq!(sec_ctx.k_nas_int, expected_k_int);
}

#[test]
fn test_amf_ue_context_transfer_inter_amf() {
    let plmn = PlmnId::new([2, 0, 8], [9, 5, 0]);
    let source_guami = Guami::new(plmn, 0x01, 0x001, 0x01);
    let target_guami = Guami::new(plmn, 0x01, 0x002, 0x01);

    let mut source_amf = AmfSbiEngine::new("amf-source", source_guami);
    let target_amf = AmfSbiEngine::new("amf-target", target_guami);
    assert_eq!(target_amf.amf_id, "amf-target");
    assert_eq!(target_amf.guami, target_guami);

    let supi = "208950000000002";
    let k_seaf = [0x77u8; 32];
    let serving_cell = NrCgi::new(plmn, 0x0002_0000);
    let current_tai = Tai::new(plmn, 0x000010);
    let reg_area = vec![current_tai];
    let allowed_nssai = vec![Snssai::new(1, None)];

    // Register on Source AMF
    let guti = source_amf.register_ue(
        supi,
        None,
        &k_seaf,
        serving_cell,
        current_tai,
        reg_area.clone(),
        allowed_nssai.clone(),
        101,
        2000,
    );

    // Bind two PDU sessions on Source AMF
    source_amf
        .add_pdu_session(
            supi,
            1,
            "smf-internet",
            "https://smf-01.core.5g/nsmf-pdusession/v1/sm-contexts/1",
            Snssai::new(1, None),
            "internet",
        )
        .expect("PDU session 1 addition should succeed");
    source_amf
        .add_pdu_session(
            supi,
            2,
            "smf-ims",
            "https://smf-02.core.5g/nsmf-pdusession/v1/sm-contexts/2",
            Snssai::new(1, None),
            "ims",
        )
        .expect("PDU session 2 addition should succeed");

    // Target AMF requests UE Context Transfer
    let ue_src = source_amf.ue_contexts.get(supi).unwrap();
    let sec_src = ue_src.security_ctx.as_ref().unwrap();
    let valid_token = [
        sec_src.k_nas_int[0],
        sec_src.k_nas_int[1],
        0xAA,
        0xBB,
        0xCC,
        0xDD,
        0xEE,
        0xFF,
    ];

    let xfer_req = UeContextTransferRequest {
        reason: ContextTransferReason::MobilityRegistration,
        guti: guti.clone(),
        integrity_token: valid_token,
    };

    let xfer_resp = source_amf
        .ue_context_transfer(&xfer_req)
        .expect("Context transfer must succeed with valid token");

    assert_eq!(xfer_resp.supi, supi);
    assert_eq!(xfer_resp.pdu_sessions.len(), 2);
    assert_eq!(xfer_resp.security_ctx.k_amf, sec_src.k_amf);

    // Target AMF commits relocation
    source_amf
        .registration_status_update(supi, RegistrationCommitStatus::Success)
        .expect("Registration status update should succeed");

    // Verify Source AMF purged UE context
    assert!(!source_amf.ue_contexts.contains_key(supi));
    assert!(
        !source_amf
            .guti_to_supi
            .contains_key(&guti.to_formatted_string())
    );

    // Negative test: invalid token rejected
    let new_guti = source_amf.register_ue(
        supi,
        None,
        &k_seaf,
        serving_cell,
        current_tai,
        reg_area,
        allowed_nssai,
        102,
        2010,
    );
    let invalid_xfer_req = UeContextTransferRequest {
        reason: ContextTransferReason::MobilityRegistration,
        guti: new_guti,
        integrity_token: [0x00; 8],
    };
    let err = source_amf.ue_context_transfer(&invalid_xfer_req);
    assert_eq!(err.err(), Some(AmfError::IntegrityCheckFailed));
}

#[test]
fn test_amf_n1_n2_message_transfer_connected() {
    let plmn = PlmnId::new([2, 0, 8], [9, 5, 0]);
    let guami = Guami::new(plmn, 0x01, 0x001, 0x01);
    let mut amf = AmfSbiEngine::new("amf-01", guami);

    let supi = "208950000000003";
    let k_seaf = [0x88u8; 32];
    amf.register_ue(
        supi,
        None,
        &k_seaf,
        NrCgi::new(plmn, 0x10),
        Tai::new(plmn, 1),
        vec![Tai::new(plmn, 1)],
        vec![Snssai::new(1, None)],
        88,
        3000,
    );

    // SMF requests N1/N2 message transfer while UE is CM-CONNECTED
    let n2_info = vec![0x12, 0x34, 0x56]; // e.g. PDU Session Setup Request NGAP container
    let req = N1N2MessageTransferRequest {
        supi: supi.to_string(),
        n1_msg: None,
        n2_info: Some(n2_info),
        ppi: None,
        arp: 1,
    };

    let status = amf
        .n1_n2_message_transfer(req, 3001)
        .expect("Message transfer must succeed in CONNECTED mode");

    assert_eq!(
        status,
        N1N2MessageTransferStatus::Delivered {
            amf_ue_ngap_id: 100,
            ran_ue_ngap_id: 88,
        }
    );
}

#[test]
fn test_amf_n1_n2_message_transfer_idle_paging() {
    let plmn = PlmnId::new([2, 0, 8], [9, 5, 0]);
    let guami = Guami::new(plmn, 0x01, 0x001, 0x01);
    let mut amf = AmfSbiEngine::new("amf-01", guami);

    let supi = "208950000000004";
    let k_seaf = [0x99u8; 32];
    let reg_area = vec![
        Tai::new(plmn, 0x000100),
        Tai::new(plmn, 0x000101),
        Tai::new(plmn, 0x000102),
    ];

    amf.register_ue(
        supi,
        None,
        &k_seaf,
        NrCgi::new(plmn, 0x20),
        Tai::new(plmn, 0x000100),
        reg_area,
        vec![Snssai::new(1, None)],
        55,
        4000,
    );

    // Transition UE to CM-IDLE
    amf.set_ue_cm_idle(supi, 4010)
        .expect("Setting CM-IDLE should succeed");
    assert_eq!(amf.ue_contexts[supi].cm_state, CmState::Idle);

    // SMF sends downlink data notification (N1/N2 transfer) with voice PPI
    let n1_msg = vec![0xAA, 0xBB, 0xCC];
    let req = N1N2MessageTransferRequest {
        supi: supi.to_string(),
        n1_msg: Some(n1_msg.clone()),
        n2_info: None,
        ppi: Some(1), // Mission critical voice paging
        arp: 1,
    };

    let status = amf
        .n1_n2_message_transfer(req, 4012)
        .expect("N1/N2 transfer in IDLE mode must succeed and trigger paging");

    match status {
        N1N2MessageTransferStatus::BufferedAndPaging { paging_tacs } => {
            assert_eq!(paging_tacs, vec![0x000100, 0x000101, 0x000102]);
        }
        _ => panic!("Expected BufferedAndPaging"),
    }

    assert_eq!(amf.ue_contexts[supi].buffered_messages.len(), 1);

    // UE receives Paging and sends Service Request via gNodeB
    let flushed_messages = amf
        .handle_service_request(supi, 99, 4015)
        .expect("Service Request processing must succeed");

    assert_eq!(flushed_messages.len(), 1);
    assert_eq!(flushed_messages[0].n1_msg, Some(n1_msg));
    assert_eq!(amf.ue_contexts[supi].cm_state, CmState::Connected);
    assert_eq!(amf.ue_contexts[supi].ran_ue_ngap_id, Some(99));
    assert!(amf.ue_contexts[supi].buffered_messages.is_empty());
}

#[test]
fn test_amf_event_exposure_subscriptions_and_notifications() {
    let plmn = PlmnId::new([2, 0, 8], [9, 5, 0]);
    let guami = Guami::new(plmn, 0x01, 0x001, 0x01);
    let mut amf = AmfSbiEngine::new("amf-01", guami);

    let supi = "208950000000005";
    let k_seaf = [0xABu8; 32];

    // 1. Subscribe to LocationReport, ReachabilityState, and PresenceInAoI
    let sub_id = amf.subscribe_event(
        "nwdaf-01",
        "https://nwdaf-01.core.5g/nnwdaf-eventsubscription/v1/notify",
        vec![
            AmfEventType::LocationReport,
            AmfEventType::ReachabilityState,
            AmfEventType::PresenceInAoI,
            AmfEventType::RegistrationStateChange,
        ],
        Some(vec![0x000050]), // Area of Interest: TAC 0x000050
    );

    // 2. Register UE in TAC 0x000010 (outside AoI)
    amf.register_ue(
        supi,
        None,
        &k_seaf,
        NrCgi::new(plmn, 0x01),
        Tai::new(plmn, 0x000010),
        vec![Tai::new(plmn, 0x000010)],
        vec![Snssai::new(1, None)],
        10,
        5000,
    );

    // Initial registration event notification
    assert!(
        amf.dispatched_notifications
            .iter()
            .any(|n| n.event_type == AmfEventType::RegistrationStateChange)
    );

    // 3. UE transitions to CM-IDLE
    amf.set_ue_cm_idle(supi, 5010).unwrap();
    assert!(
        amf.dispatched_notifications
            .iter()
            .any(|n| n.event_type == AmfEventType::ReachabilityState && n.details == "CM-IDLE")
    );

    // 4. UE moves into Area of Interest (TAC 0x000050)
    amf.update_ue_location(supi, NrCgi::new(plmn, 0x02), Tai::new(plmn, 0x000050), 5020)
        .unwrap();

    assert!(
        amf.dispatched_notifications
            .iter()
            .any(|n| n.event_type == AmfEventType::LocationReport)
    );
    assert!(
        amf.dispatched_notifications
            .iter()
            .any(|n| n.event_type == AmfEventType::PresenceInAoI && n.details.contains("IN_AREA"))
    );

    // 5. UE moves out of Area of Interest to TAC 0x000060
    amf.update_ue_location(supi, NrCgi::new(plmn, 0x03), Tai::new(plmn, 0x000060), 5030)
        .unwrap();

    assert!(
        amf.dispatched_notifications
            .iter()
            .any(|n| n.event_type == AmfEventType::PresenceInAoI
                && n.details.contains("OUT_OF_AREA"))
    );

    // 6. Unsubscribe
    amf.unsubscribe_event(&sub_id).unwrap();
    assert!(!amf.event_subscriptions.contains_key(&sub_id));
}
