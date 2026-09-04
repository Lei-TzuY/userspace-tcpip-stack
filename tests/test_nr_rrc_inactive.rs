//! Comprehensive Integration Tests for 3GPP Rel-17 5G NR RRC Inactive State & RNA Paging Engine.

use toy_tcpip::nr_rrc_inactive::*;

#[test]
fn test_nr_rrc_inactive_suspend_and_i_rnti() {
    let anchor_gnb_id: u32 = 0x0012_3456; // 24-bit gNodeB ID
    let ue_index: u16 = 0xABCD; // 16-bit UE Context Index

    let full_i_rnti = FullIRnti::new(anchor_gnb_id, ue_index);
    assert_eq!(full_i_rnti.anchor_gnb_id(), anchor_gnb_id);
    assert_eq!(full_i_rnti.ue_index(), ue_index);

    // Verify 24-bit Short I-RNTI derivation:
    // anchor_slice = (0x0012_3456 >> 8) & 0xFFFF = 0x1234
    // ue_slice = (0xABCD >> 8) & 0xFF = 0xAB
    // short = (0x1234 << 8) | 0xAB = 0x1234AB
    let short_i_rnti = full_i_rnti.to_short_i_rnti();
    assert_eq!(short_i_rnti.as_u32(), 0x0012_34AB);
    assert_eq!(short_i_rnti.anchor_slice(), 0x1234);

    let mut engine = NrRrcInactiveEngine::new(anchor_gnb_id);
    let rna = RanNotificationArea::CellList(vec![1001, 1002, 1003]);
    let k_gnb = [0x55u8; 32];
    let k_rrc_int = [0xAAu8; 16];

    let suspend_config = engine.suspend_ue_connection(
        "ue-inactive-01",
        ue_index,
        1001,
        15,
        rna.clone(),
        k_gnb,
        k_rrc_int,
        1,
        vec![1, 2],
        10,
        987654321,
        30,
    );

    assert_eq!(suspend_config.full_i_rnti, full_i_rnti);
    assert_eq!(suspend_config.short_i_rnti, short_i_rnti);
    assert_eq!(suspend_config.rna, rna);
    assert_eq!(suspend_config.t380_period_mins, 30);
    assert_eq!(suspend_config.next_hop_chaining_count, 1);

    // Verify anchor storage
    assert_eq!(engine.suspended_contexts.len(), 1);
    assert_eq!(engine.short_to_full_index.len(), 1);
    assert_eq!(
        engine.short_to_full_index.get(&short_i_rnti),
        Some(&full_i_rnti)
    );
}

#[test]
fn test_nr_rrc_inactive_rna_evaluation_and_periodic_update() {
    let mut engine = NrRrcInactiveEngine::new(100);
    let rna_cells = RanNotificationArea::CellList(vec![1001, 1002, 1003]);

    let config = InactiveSuspendConfig {
        full_i_rnti: FullIRnti::new(100, 1),
        short_i_rnti: FullIRnti::new(100, 1).to_short_i_rnti(),
        rna: rna_cells,
        t380_period_mins: 5,
        next_hop_chaining_count: 0,
    };

    let k_rrc_int = [0x77u8; 16];
    engine.ue_enter_inactive(config, k_rrc_int, 1001, 10);
    assert!(engine.ue_state_inactive);

    // 1. Mobility within RNA: moves from cell 1001 to 1002 -> no signaling required!
    let move1 = engine.ue_move_to_cell(1002, 20, 50, None);
    assert_eq!(move1, None);

    // 2. Mobility outside RNA: moves to cell 2001 -> triggers RNA Update!
    let move2 = engine.ue_move_to_cell(2001, 30, 50, None);
    assert_eq!(move2, Some(InactiveResumeCause::RnaUpdate));

    // 3. Test RAN Area Codes (RANAC) RNA
    let rna_ranac = RanNotificationArea::RanAreaCodes {
        tac: 500,
        ranac_list: vec![1, 2, 3],
    };
    assert!(rna_ranac.contains_cell(999, 500, Some(2)));
    assert!(!rna_ranac.contains_cell(999, 500, Some(4))); // RANAC 4 not in list
    assert!(!rna_ranac.contains_cell(999, 600, Some(2))); // TAC mismatch

    // 4. Periodic T380 timer evaluation
    engine.ue_t380_remaining_minutes = 3;
    assert_eq!(engine.ue_tick_minute(), None); // 2 min left
    assert_eq!(engine.ue_tick_minute(), None); // 1 min left
    // 3rd minute expires -> triggers periodic RNA update!
    assert_eq!(
        engine.ue_tick_minute(),
        Some(InactiveResumeCause::RnaUpdate)
    );
    // Timer automatically reloads
    assert_eq!(engine.ue_t380_remaining_minutes, 5);
}

#[test]
fn test_nr_rrc_inactive_resume_happy_path_same_gnb() {
    let anchor_gnb_id = 100;
    let mut engine = NrRrcInactiveEngine::new(anchor_gnb_id);

    let k_rrc_int = [0xABu8; 16];
    let k_gnb = [0xCDu8; 32];
    let cell_id = 1001;
    let pci = 12;

    let suspend_config = engine.suspend_ue_connection(
        "ue-local-resume",
        0x1234,
        cell_id,
        pci,
        RanNotificationArea::CellList(vec![cell_id]),
        k_gnb,
        k_rrc_int,
        2,
        vec![1, 2, 3],
        1,
        11223344,
        30,
    );

    // Client UE enters inactive state
    engine.ue_enter_inactive(suspend_config, k_rrc_int, cell_id, pci);

    // Client creates Msg3 RrcResumeRequest with cause MoData
    let resume_req = engine
        .ue_create_resume_request(InactiveResumeCause::MoData)
        .unwrap();

    assert_eq!(resume_req.resume_cause, InactiveResumeCause::MoData);
    assert_eq!(resume_req.source_pci, pci);
    assert_eq!(resume_req.target_cell_id, cell_id);

    // Anchor gNodeB handles resume request directly
    let resume_resp = engine.process_local_resume_request(&resume_req).unwrap();

    assert_eq!(resume_resp.allocated_c_rnti, 0x4000);
    assert_eq!(resume_resp.restored_drb_ids, vec![1, 2, 3]);
    assert_eq!(resume_resp.next_hop_chaining_count, 3); // incremented from 2
    assert_eq!(resume_resp.new_suspend_config, None); // Full resume: RRC_CONNECTED!

    // Context removed from suspended storage
    assert!(engine.suspended_contexts.is_empty());
    assert!(engine.short_to_full_index.is_empty());

    // Tamper test: corrupted ShortMAC-I must be rejected
    let mut bad_req = resume_req;
    bad_req.short_mac_i ^= 0xFFFF;
    assert!(engine.process_local_resume_request(&bad_req).is_err());
}

#[test]
fn test_nr_rrc_inactive_xn_context_retrieval_different_gnb() {
    let anchor_gnb_id = 100;
    let serving_gnb_id = 200;

    let mut anchor_engine = NrRrcInactiveEngine::new(anchor_gnb_id);

    let k_rrc_int = [0xEFu8; 16];
    let k_gnb = [0x99u8; 32];
    let anchor_cell_id = 1001;
    let anchor_pci = 10;
    let serving_cell_id = 2001;
    let serving_pci = 20;

    let suspend_config = anchor_engine.suspend_ue_connection(
        "ue-cross-gnb",
        0x5678,
        anchor_cell_id,
        anchor_pci,
        RanNotificationArea::CellList(vec![anchor_cell_id, serving_cell_id]),
        k_gnb,
        k_rrc_int,
        4,
        vec![1, 5],
        2,
        99887766,
        60,
    );

    // UE was suspended in anchor cell (PCI 10), then reselected serving cell (PCI 20) on gNodeB 200
    let mut ue_engine = NrRrcInactiveEngine::new(0);
    ue_engine.ue_enter_inactive(
        suspend_config.clone(),
        k_rrc_int,
        anchor_cell_id,
        anchor_pci,
    );
    ue_engine.ue_move_to_cell(serving_cell_id, serving_pci, 50, None);

    let resume_req = ue_engine
        .ue_create_resume_request(InactiveResumeCause::MoVoiceCall)
        .unwrap();

    assert_eq!(resume_req.source_pci, anchor_pci);
    assert_eq!(resume_req.target_cell_id, serving_cell_id);

    // Serving gNodeB 200 receives resume request and queries Anchor gNodeB 100 over Xn-C
    let xn_req = XnUeContextRetrieveRequest {
        target_gnb_id: serving_gnb_id,
        anchor_gnb_id,
        short_i_rnti: resume_req.short_i_rnti,
        resume_cause: resume_req.resume_cause,
        short_mac_i: resume_req.short_mac_i,
        target_cell_id: serving_cell_id,
        source_pci: resume_req.source_pci,
    };

    let xn_resp = anchor_engine
        .process_xn_retrieve_context(&xn_req)
        .expect("Xn context retrieval must succeed with valid ShortMAC-I");

    assert_eq!(xn_resp.ue_id, "ue-cross-gnb");
    assert_eq!(xn_resp.full_i_rnti, suspend_config.full_i_rnti);
    assert_eq!(xn_resp.k_gnb, k_gnb);
    assert_eq!(xn_resp.active_drb_ids, vec![1, 5]);
    assert_eq!(xn_resp.next_hop_chaining_count, 5); // NCC incremented from 4 to 5
    assert_eq!(xn_resp.pdu_session_id, 2);

    // Anchor storage is now cleared after successful context transfer
    assert!(anchor_engine.suspended_contexts.is_empty());
}

#[test]
fn test_nr_rrc_inactive_ran_paging_on_dl_data() {
    let anchor_gnb_id = 100;
    let mut anchor_engine = NrRrcInactiveEngine::new(anchor_gnb_id);

    let k_rrc_int = [0x11u8; 16];
    let k_gnb = [0x22u8; 32];
    let cell_id = 1001;
    let pci = 14;

    let suspend_config = anchor_engine.suspend_ue_connection(
        "ue-paging-test",
        0x0007,
        cell_id,
        pci,
        RanNotificationArea::CellList(vec![cell_id, 1002]),
        k_gnb,
        k_rrc_int,
        0,
        vec![1],
        1,
        123456,
        30,
    );

    // Downlink user-plane packet arrives at Anchor gNodeB while UE is inactive
    let paging_record = anchor_engine
        .trigger_ran_paging(suspend_config.full_i_rnti)
        .expect("Paging trigger must succeed for suspended UE");

    assert_eq!(paging_record.ue_identity, suspend_config.full_i_rnti);
    assert_eq!(paging_record.paging_priority, Some(1));
    assert_eq!(paging_record.paging_drx_slots, 128);

    // Paged UE responds with RRC Resume with MtAccess cause
    let mut ue_engine = NrRrcInactiveEngine::new(0);
    ue_engine.ue_enter_inactive(suspend_config, k_rrc_int, cell_id, pci);

    let resume_req = ue_engine
        .ue_create_resume_request(InactiveResumeCause::MtAccess)
        .unwrap();

    let resume_resp = anchor_engine
        .process_local_resume_request(&resume_req)
        .unwrap();

    assert_eq!(resume_resp.restored_drb_ids, vec![1]);
    assert!(anchor_engine.suspended_contexts.is_empty());
}
