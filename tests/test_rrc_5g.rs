//! Integration tests for 3GPP TS 38.331 5G NR Radio Resource Control (RRC) Engine.

use toy_tcpip::ngap_5g::PlmnId;
use toy_tcpip::rrc_5g::*;

fn test_plmn() -> PlmnId {
    PlmnId {
        mcc: [2, 0, 8],
        mnc: [9, 5, 0],
    }
}

// ---------------------------------------------------------------------------
// 1. MIB and SIB1 Broadcast System Information
// ---------------------------------------------------------------------------

#[test]
fn test_rrc_mib_and_sib1_broadcast() {
    let mut gnb = RrcEngine::new(RrcRole::Gnb);

    let mib = MasterInformationBlock {
        system_frame_number: 512,
        subcarrier_spacing_khz: 30,
        ssb_subcarrier_offset: 4,
        dmrs_type_a_position: 2,
        pdcch_config_sib1: 0x12,
        cell_barred: false,
        intra_freq_reselection: true,
    };
    gnb.set_mib(mib.clone());

    let sib1 = SystemInformationBlockType1 {
        plmn: test_plmn(),
        tac: 10050,
        cell_identity: 0x001001_00000001,
        q_rx_lev_min_dbm: -70,
        ranac: Some(42),
        si_window_length_slots: 20,
    };
    gnb.set_sib1(sib1.clone());

    assert_eq!(gnb.mib.as_ref(), Some(&mib));
    assert_eq!(gnb.sib1.as_ref(), Some(&sib1));
    assert_eq!(gnb.sib1.as_ref().unwrap().tac, 10050);
}

// ---------------------------------------------------------------------------
// 2. Initial RRC Connection Setup: Idle -> Connected + NAS PDU Transfer
// ---------------------------------------------------------------------------

#[test]
fn test_rrc_connection_setup_procedure() {
    let mut ue = RrcEngine::new(RrcRole::Ue);
    let mut gnb = RrcEngine::new(RrcRole::Gnb);

    let ue_s_tmsi: u64 = 0x00A1_B2C3_D4E5_F607;
    let registration_request_nas = vec![0x7E, 0x00, 0x41, 0x01, 0x02, 0x03, 0x04]; // Mock 5GS Registration

    // 1. UE in RRC_IDLE initiates RrcSetupRequest
    let setup_req = ue.ue_initiate_setup_request(ue_s_tmsi, RrcEstablishmentCause::MoSignalling);
    assert_eq!(setup_req.ue_identity, ue_s_tmsi);
    assert_eq!(
        setup_req.establishment_cause,
        RrcEstablishmentCause::MoSignalling
    );

    // 2. gNB handles RrcSetupRequest and returns RrcSetup
    let (gnb_crnti, setup_msg) = gnb.gnb_handle_setup_request(&setup_req);
    assert_eq!(gnb_crnti, 0x4001);
    assert_eq!(setup_msg.master_cell_group_allocated_crnti, 0x4001);
    assert_eq!(setup_msg.radio_bearer_config.srb_to_add_mod_list.len(), 1);
    assert_eq!(
        setup_msg.radio_bearer_config.srb_to_add_mod_list[0].srb_id,
        SRB1_ID
    );

    // 3. UE applies RrcSetup, transitions to RRC_CONNECTED, and builds RrcSetupComplete with NAS
    let setup_comp = ue
        .ue_handle_setup(&setup_msg, test_plmn(), registration_request_nas.clone())
        .expect("UE failed to handle RrcSetup");
    assert_eq!(setup_comp.dedicated_nas_message, registration_request_nas);

    // Verify UE state
    let ue_ctx = ue
        .contexts
        .get(&0x4001)
        .expect("UE context not found with C-RNTI 0x4001");
    assert_eq!(ue_ctx.state, RrcState::RrcConnected);
    assert!(ue_ctx.srbs.contains_key(&SRB0_ID));
    assert!(ue_ctx.srbs.contains_key(&SRB1_ID));

    // 4. gNB receives RrcSetupComplete
    assert!(gnb.gnb_handle_setup_complete(gnb_crnti, &setup_comp));
    let gnb_ctx = gnb.contexts.get(&gnb_crnti).expect("gNB context missing");
    assert_eq!(gnb_ctx.state, RrcState::RrcConnected);
    assert_eq!(
        gnb_ctx.last_nas_pdu.as_ref(),
        Some(&registration_request_nas)
    );
}

// ---------------------------------------------------------------------------
// 3. RRC Reconfiguration: Establishing DRBs with QoS Flows
// ---------------------------------------------------------------------------

#[test]
fn test_rrc_reconfiguration_drb_establishment() {
    let mut ue = RrcEngine::new(RrcRole::Ue);
    let mut gnb = RrcEngine::new(RrcRole::Gnb);

    // Setup initial connection first
    let req = ue.ue_initiate_setup_request(0x12345678, RrcEstablishmentCause::MoData);
    let (crnti, setup) = gnb.gnb_handle_setup_request(&req);
    let comp = ue.ue_handle_setup(&setup, test_plmn(), vec![0x01]).unwrap();
    gnb.gnb_handle_setup_complete(crnti, &comp);

    // gNB sends RrcReconfiguration configuring DRB1 (eMBB QFI 9) and DRB2 (URLLC QFI 15)
    let drb1 = RrcDrbConfig {
        drb_id: 1,
        qfi_list: vec![9],
        pdcp_sn_size_bits: 18,
        rlc_mode: RrcRlcMode::Acknowledged,
    };
    let drb2 = RrcDrbConfig {
        drb_id: 2,
        qfi_list: vec![15],
        pdcp_sn_size_bits: 12,
        rlc_mode: RrcRlcMode::Acknowledged,
    };
    let reconfig = gnb
        .gnb_build_reconfiguration(crnti, vec![drb1.clone(), drb2.clone()])
        .expect("gNB build reconfig failed");

    // UE handles RrcReconfiguration
    let reconfig_comp = ue
        .ue_handle_reconfiguration(crnti, &reconfig)
        .expect("UE handle reconfig failed");
    assert!(gnb.gnb_handle_reconfiguration_complete(crnti, &reconfig_comp));

    // Verify DRBs active on both sides
    let ue_ctx = ue.contexts.get(&crnti).unwrap();
    assert_eq!(ue_ctx.drbs.len(), 2);
    assert_eq!(ue_ctx.drbs.get(&1).unwrap().qfi_list, vec![9]);
    assert_eq!(ue_ctx.drbs.get(&2).unwrap().qfi_list, vec![15]);

    let gnb_ctx = gnb.contexts.get(&crnti).unwrap();
    assert_eq!(gnb_ctx.drbs.len(), 2);
    assert_eq!(gnb_ctx.drbs.get(&1).unwrap().pdcp_sn_size_bits, 18);
}

// ---------------------------------------------------------------------------
// 4. RRC Release with Suspend to RRC_INACTIVE
// ---------------------------------------------------------------------------

#[test]
fn test_rrc_release_to_inactive_with_suspend_config() {
    let mut ue = RrcEngine::new(RrcRole::Ue);
    let mut gnb = RrcEngine::new(RrcRole::Gnb);

    let req = ue.ue_initiate_setup_request(0x8888, RrcEstablishmentCause::MoData);
    let (crnti, setup) = gnb.gnb_handle_setup_request(&req);
    let comp = ue.ue_handle_setup(&setup, test_plmn(), vec![]).unwrap();
    gnb.gnb_handle_setup_complete(crnti, &comp);

    // gNB sends RrcRelease with suspend = true (to RRC_INACTIVE)
    let release_msg = gnb
        .gnb_build_release(crnti, true)
        .expect("build release failed");
    assert_eq!(release_msg.release_cause, RrcReleaseCause::RrcSuspend);
    assert!(release_msg.suspend_config.is_some());

    let suspend_cfg = release_msg.suspend_config.as_ref().unwrap();
    assert_eq!(suspend_cfg.t380_periodic_ran_update_mins, 60);

    // UE handles RrcRelease
    assert!(ue.ue_handle_release(crnti, &release_msg));
    assert_eq!(
        ue.contexts.get(&crnti).unwrap().state,
        RrcState::RrcInactive
    );
    assert_eq!(
        gnb.contexts.get(&crnti).unwrap().state,
        RrcState::RrcInactive
    );
}

// ---------------------------------------------------------------------------
// 5. Fast RRC Resume from RRC_INACTIVE to RRC_CONNECTED
// ---------------------------------------------------------------------------

#[test]
fn test_rrc_resume_procedure_from_inactive() {
    let mut ue = RrcEngine::new(RrcRole::Ue);
    let mut gnb = RrcEngine::new(RrcRole::Gnb);

    // Setup and then suspend to RRC_INACTIVE
    let req = ue.ue_initiate_setup_request(0x9999, RrcEstablishmentCause::MoData);
    let (crnti, setup) = gnb.gnb_handle_setup_request(&req);
    let comp = ue.ue_handle_setup(&setup, test_plmn(), vec![]).unwrap();
    gnb.gnb_handle_setup_complete(crnti, &comp);
    let release = gnb.gnb_build_release(crnti, true).unwrap();
    ue.ue_handle_release(crnti, &release);

    assert_eq!(
        ue.contexts.get(&crnti).unwrap().state,
        RrcState::RrcInactive
    );
    assert_eq!(
        gnb.contexts.get(&crnti).unwrap().state,
        RrcState::RrcInactive
    );

    // 1. UE initiates RrcResumeRequest
    let resume_req = ue
        .ue_initiate_resume_request(crnti, RrcResumeCause::MoData)
        .expect("UE resume request build failed");
    assert_eq!(resume_req.resume_cause, RrcResumeCause::MoData);

    // 2. gNB matches suspended context by Short I-RNTI and returns RrcResume
    let (restored_crnti, resume_msg) = gnb
        .gnb_handle_resume_request(&resume_req)
        .expect("gNB resume handle failed");
    assert_eq!(restored_crnti, crnti);

    // 3. UE handles RrcResume and transitions back to RRC_CONNECTED
    let resume_comp = ue
        .ue_handle_resume(crnti, &resume_msg)
        .expect("UE resume handle failed");
    assert_eq!(
        ue.contexts.get(&crnti).unwrap().state,
        RrcState::RrcConnected
    );

    // 4. gNB finishes resume procedure
    assert!(gnb.gnb_handle_resume_complete(restored_crnti, &resume_comp));
    assert_eq!(
        gnb.contexts.get(&crnti).unwrap().state,
        RrcState::RrcConnected
    );
}

// ---------------------------------------------------------------------------
// 6. Paging Message Creation and Record Extraction
// ---------------------------------------------------------------------------

#[test]
fn test_rrc_paging_generation() {
    let gnb = RrcEngine::new(RrcRole::Gnb);

    let target_ues = vec![0x1122334455667788, 0x8877665544332211];
    let paging = gnb.gnb_build_paging(&target_ues);

    assert_eq!(paging.paging_records.len(), 2);
    assert_eq!(
        paging.paging_records[0].ue_identity_5g_s_tmsi,
        0x1122334455667788
    );
    assert!(!paging.paging_records[0].access_type_non_3gpp);
    assert_eq!(
        paging.paging_records[1].ue_identity_5g_s_tmsi,
        0x8877665544332211
    );
}

// ---------------------------------------------------------------------------
// 7. Measurement Reporting
// ---------------------------------------------------------------------------

#[test]
fn test_rrc_measurement_reporting() {
    let report = MeasurementReport {
        meas_id: 1,
        serving_cell_results: MeasResultServingCell {
            rsrp_dbm: -85,
            rsrq_db: -12,
            sinr_db: 18,
        },
    };

    let msg = RrcMessage::MeasurementReport(report);
    let bytes = msg.to_bytes();
    assert_eq!(bytes[0], RRC_MSG_TYPE_MEAS_REPORT);

    let decoded = RrcMessage::from_bytes(&bytes).expect("MeasurementReport decode failed");
    match decoded {
        RrcMessage::MeasurementReport(rep) => {
            assert_eq!(rep.meas_id, 1);
            assert_eq!(rep.serving_cell_results.rsrp_dbm, -85);
            assert_eq!(rep.serving_cell_results.rsrq_db, -12);
            assert_eq!(rep.serving_cell_results.sinr_db, 18);
        }
        _ => panic!("Expected MeasurementReport"),
    }
}

// ---------------------------------------------------------------------------
// 8. RRC Container Serialization & Deserialization Fidelity
// ---------------------------------------------------------------------------

#[test]
fn test_rrc_container_roundtrip_all_messages() {
    // 1. RrcSetupRequest
    let msg1 = RrcMessage::SetupRequest(RrcSetupRequest {
        ue_identity: 0xFEED_FACE_CAFE_BABE,
        establishment_cause: RrcEstablishmentCause::Emergency,
    });
    let raw1 = msg1.to_bytes();
    assert_eq!(RrcMessage::from_bytes(&raw1), Some(msg1));

    // 2. RrcSetup
    let msg2 = RrcMessage::Setup(RrcSetup {
        rrc_transaction_identifier: 3,
        radio_bearer_config: RadioBearerConfig {
            srb_to_add_mod_list: vec![RrcSrbConfig {
                srb_id: 1,
                rlc_mode: RrcRlcMode::Acknowledged,
            }],
            drb_to_add_mod_list: vec![RrcDrbConfig {
                drb_id: 1,
                qfi_list: vec![9, 10],
                pdcp_sn_size_bits: 18,
                rlc_mode: RrcRlcMode::Acknowledged,
            }],
            drb_to_release_list: Vec::new(),
            security_config: None,
        },
        master_cell_group_allocated_crnti: 0x4002,
    });
    let raw2 = msg2.to_bytes();
    assert_eq!(RrcMessage::from_bytes(&raw2), Some(msg2));

    // 3. RrcSetupComplete
    let msg3 = RrcMessage::SetupComplete(RrcSetupComplete {
        rrc_transaction_identifier: 3,
        selected_plmn_id: test_plmn(),
        dedicated_nas_message: vec![0xAA, 0xBB, 0xCC, 0xDD],
    });
    let raw3 = msg3.to_bytes();
    assert_eq!(RrcMessage::from_bytes(&raw3), Some(msg3));

    // 4. RrcRelease with SuspendConfig
    let msg4 = RrcMessage::Release(RrcRelease {
        rrc_transaction_identifier: 4,
        release_cause: RrcReleaseCause::RrcSuspend,
        suspend_config: Some(SuspendConfig {
            full_i_rnti: 0x0000_0001_00A0_4001,
            short_i_rnti: 0x00A0_4001,
            ran_paging_cycle_rf: 64,
            t380_periodic_ran_update_mins: 120,
        }),
    });
    let raw4 = msg4.to_bytes();
    assert_eq!(RrcMessage::from_bytes(&raw4), Some(msg4));

    // 5. RrcResumeRequest
    let msg5 = RrcMessage::ResumeRequest(RrcResumeRequest {
        resume_identity_short_i_rnti: 0x00A0_4001,
        resume_cause: RrcResumeCause::MoData,
        short_mac_i: 0xABCD,
    });
    let raw5 = msg5.to_bytes();
    assert_eq!(RrcMessage::from_bytes(&raw5), Some(msg5));

    // 6. RrcReestablishmentRequest
    let msg6 = RrcMessage::ReestablishmentRequest(RrcReestablishmentRequest {
        crnti: 0x4001,
        phys_cell_id: 120,
        short_mac_i: 0x1234,
        reestablishment_cause: RrcReestablishmentCause::HandoverFailure,
    });
    let raw6 = msg6.to_bytes();
    assert_eq!(RrcMessage::from_bytes(&raw6), Some(msg6));
}
