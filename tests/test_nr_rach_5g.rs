//! Integration tests for 3GPP Rel-17 5G NR Random Access Channel (RACH) Procedure Engine.

use toy_tcpip::nr_rach_5g::{
    MacRarPayload, Msg2RarMessage, Msg4ContentionResolution, MsgBResponse, NrRachEngine,
    PrachOccasion, RachCause, RachConfig, RachFailureReason, RachState, RachType, bi_to_delay_ms,
};

#[test]
fn test_nr_rach_4step_cbra_happy_path() {
    let mut config = RachConfig::default();
    config.cb_preambles_per_ssb = 56;
    config.group_b_threshold_bytes = 56;

    let mut engine = NrRachEngine::new("ue-001", config);

    // Step 1: Msg1 Preamble Transmission
    // RO: symbol 0, slot 10, freq 1, NUL carrier 0
    let ro = PrachOccasion::new(0, 10, 1, 0);
    let expected_ra_rnti = 1 + 0 + 14 * 10 + 14 * 80 * 1 + 0; // 1261
    assert_eq!(ro.calculate_ra_rnti(), expected_ra_rnti);

    let msg1 = engine
        .initiate_4step_cbra(
            RachCause::InitialAccess,
            2,  // SSB index 2
            40, // Msg3 size 40 bytes (< 56 bytes -> Group A)
            75, // Pathloss 75 dB
            ro,
        )
        .expect("Msg1 initiation should succeed");

    assert_eq!(msg1.ra_rnti, expected_ra_rnti);
    assert_eq!(msg1.ssb_index, 2);
    assert_eq!(msg1.transmission_counter, 1);
    assert_eq!(engine.state, RachState::Msg1Transmitted);

    let target_rapid = msg1.preamble_index;

    // Step 2: Msg2 MAC RAR Reception
    let rar_payload = MacRarPayload {
        rapid: target_rapid,
        timing_advance: 128,
        ul_grant: 0x07FF_FFFF,
        tc_rnti: 0x4242,
    };
    let rar_msg = Msg2RarMessage {
        backoff_indicator: None,
        rar_payloads: vec![rar_payload.clone()],
    };

    let rx_rar = engine
        .handle_msg2_rar(&rar_msg)
        .expect("Msg2 RAR parsing should succeed")
        .expect("Target RAPID must match");

    assert_eq!(rx_rar, rar_payload);
    assert_eq!(engine.state, RachState::Msg2Received);

    // Step 3: Msg3 Scheduled Transmission on PUSCH
    // CCCH SDU carrying 48-bit identity (e.g. RRCSetupRequest)
    let ccch_sdu = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let msg3 = engine
        .transmit_msg3(&rx_rar, ccch_sdu.clone(), 15)
        .expect("Msg3 transmission should succeed");

    assert_eq!(msg3.tc_rnti, 0x4242);
    assert_eq!(msg3.payload, ccch_sdu);
    assert_eq!(engine.state, RachState::Msg3Transmitted);
    assert_eq!(engine.contention_timer_remaining, Some(64));

    // Step 4: Msg4 Contention Resolution
    let msg4 = Msg4ContentionResolution {
        contention_resolution_id: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
    };

    let resolved = engine
        .handle_msg4_contention_resolution(&msg4, rx_rar.timing_advance)
        .expect("Contention resolution should succeed");

    assert!(resolved);
    assert_eq!(
        engine.state,
        RachState::Completed {
            c_rnti: 0x4242,
            ta: 128,
        }
    );
    assert_eq!(engine.c_rnti, Some(0x4242));
    assert_eq!(engine.successful_ra_count, 1);
}

#[test]
fn test_nr_rach_power_ramping_and_backoff() {
    let mut config = RachConfig::default();
    config.preamble_trans_max = 3;
    config.power_ramping_step_db = 2;
    config.preamble_init_target_power_dbm = -108;
    config.ra_response_window_slots = 5;

    let mut engine = NrRachEngine::new("ue-002", config);
    let ro = PrachOccasion::new(0, 5, 0, 0);

    // Initial attempt: Tx power = -108 dBm
    let msg1_attempt1 = engine
        .initiate_4step_cbra(RachCause::InitialAccess, 0, 30, 80, ro)
        .unwrap();
    assert_eq!(msg1_attempt1.tx_power_dbm, -108);
    assert_eq!(msg1_attempt1.transmission_counter, 1);

    // Receive RAR with non-matching RAPID and Backoff Indicator = 2 (20ms)
    let rar_msg = Msg2RarMessage {
        backoff_indicator: Some(2),
        rar_payloads: vec![MacRarPayload {
            rapid: 63, // different preamble
            timing_advance: 0,
            ul_grant: 0,
            tc_rnti: 0x1111,
        }],
    };
    let match_res = engine.handle_msg2_rar(&rar_msg).unwrap();
    assert!(match_res.is_none());
    assert_eq!(bi_to_delay_ms(2), 20);

    // Advance 5 slots to expire RAR response window
    for _ in 0..4 {
        assert_eq!(engine.tick_slot(), None);
    }
    assert_eq!(engine.tick_slot(), Some(RachFailureReason::RarTimeout));

    // Power ramping for attempt 2: Tx power = -106 dBm
    let msg1_attempt2 = engine
        .initiate_4step_cbra(RachCause::InitialAccess, 0, 30, 80, ro)
        .unwrap();
    assert_eq!(msg1_attempt2.tx_power_dbm, -106);
    assert_eq!(msg1_attempt2.transmission_counter, 2);

    // Expire window for attempt 2
    for _ in 0..5 {
        engine.tick_slot();
    }

    // Power ramping for attempt 3: Tx power = -104 dBm (Max = 3)
    let msg1_attempt3 = engine
        .initiate_4step_cbra(RachCause::InitialAccess, 0, 30, 80, ro)
        .unwrap();
    assert_eq!(msg1_attempt3.tx_power_dbm, -104);
    assert_eq!(msg1_attempt3.transmission_counter, 3);

    // Expire window for attempt 3 -> exceeds preamble_trans_max!
    for _ in 0..4 {
        engine.tick_slot();
    }
    let fail_reason = engine.tick_slot();
    assert_eq!(fail_reason, Some(RachFailureReason::MaxPreambleReached));
    assert_eq!(
        engine.state,
        RachState::Failed(RachFailureReason::MaxPreambleReached)
    );
}

#[test]
fn test_nr_rach_contention_resolution_mismatch_and_retry() {
    let mut config = RachConfig::default();
    config.preamble_trans_max = 4;
    config.power_ramping_step_db = 2;

    let mut engine = NrRachEngine::new("ue-003", config);
    let ro = PrachOccasion::new(0, 0, 0, 0);

    let msg1 = engine
        .initiate_4step_cbra(RachCause::RrcReestablishment, 1, 30, 70, ro)
        .unwrap();

    let rar = MacRarPayload {
        rapid: msg1.preamble_index,
        timing_advance: 64,
        ul_grant: 0x0100,
        tc_rnti: 0x5555,
    };
    engine
        .handle_msg2_rar(&Msg2RarMessage {
            backoff_indicator: None,
            rar_payloads: vec![rar.clone()],
        })
        .unwrap();

    // Send Msg3 with our CCCH SDU
    let my_echo = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    engine.transmit_msg3(&rar, my_echo, 10).unwrap();

    // Collision: Msg4 arrives with another UE's contention resolution ID
    let collision_msg4 = Msg4ContentionResolution {
        contention_resolution_id: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
    };

    let result = engine.handle_msg4_contention_resolution(&collision_msg4, rar.timing_advance);
    assert_eq!(
        result.err(),
        Some(RachFailureReason::ContentionResolutionFailed)
    );

    // Preamble counter incremented and power ramped for retry
    assert_eq!(engine.preamble_trans_counter, 2);
    assert_eq!(engine.power_ramping_counter, 1);
    assert_eq!(engine.state, RachState::Idle);
}

#[test]
fn test_nr_rach_cfra_handover_and_bfr() {
    let config = RachConfig::default();
    let mut engine = NrRachEngine::new("ue-004", config);
    let ro = PrachOccasion::new(2, 4, 1, 0);

    // Dedicated preamble 60 assigned by target gNodeB for handover
    let dedicated_preamble = 60;
    let ssb_index = 3;

    let msg1 = engine.initiate_cfra(RachCause::Handover, dedicated_preamble, ssb_index, ro);

    assert_eq!(engine.rach_type, RachType::Cfra4Step);
    assert_eq!(msg1.preamble_index, dedicated_preamble);
    assert_eq!(engine.state, RachState::Msg1Transmitted);

    // Target gNodeB sends Msg2 RAR matching dedicated preamble
    let rar = MacRarPayload {
        rapid: dedicated_preamble,
        timing_advance: 256,
        ul_grant: 0x0200,
        tc_rnti: 0x7777,
    };

    let rx_rar = engine
        .handle_msg2_rar(&Msg2RarMessage {
            backoff_indicator: None,
            rar_payloads: vec![rar],
        })
        .unwrap()
        .unwrap();

    // CFRA completes immediately upon Msg2 without needing Msg3/Msg4!
    assert_eq!(
        engine.state,
        RachState::Completed {
            c_rnti: 0x7777,
            ta: 256,
        }
    );
    assert_eq!(engine.c_rnti, Some(0x7777));
    assert_eq!(engine.successful_ra_count, 1);
    assert_eq!(rx_rar.timing_advance, 256);
}

#[test]
fn test_nr_rach_2step_msga_msgb() {
    let config = RachConfig::default();
    let mut engine = NrRachEngine::new("ue-005", config);
    let ro = PrachOccasion::new(0, 1, 0, 0);

    let my_echo = [0x99, 0x88, 0x77, 0x66, 0x55, 0x44];
    let mut msg_a_payload = my_echo.to_vec();
    msg_a_payload.extend_from_slice(b"Extra Data");

    // 1. Initiate 2-Step RACH MsgA transmission
    let msga = engine.initiate_2step_msga(15, msg_a_payload, 1, ro);
    assert_eq!(msga.preamble_index, 15);
    assert_eq!(engine.state, RachState::Msg1Transmitted);

    // 2. SuccessRAR in MsgB
    let success_msgb = MsgBResponse::SuccessRar {
        c_rnti: 0x8888,
        timing_advance: 32,
        contention_resolution_id: my_echo,
    };

    let completed = engine
        .handle_msgb_response(&success_msgb, &my_echo)
        .unwrap();
    assert!(completed);
    assert_eq!(
        engine.state,
        RachState::Completed {
            c_rnti: 0x8888,
            ta: 32,
        }
    );

    // 3. FallbackRAR test
    let mut engine_fallback = NrRachEngine::new("ue-006", RachConfig::default());
    engine_fallback.initiate_2step_msga(16, my_echo.to_vec(), 1, ro);

    let fallback_msgb = MsgBResponse::FallbackRar {
        rapid: 16,
        timing_advance: 32,
        ul_grant: 0x1000,
        tc_rnti: 0x9999,
    };

    let fallback_res = engine_fallback
        .handle_msgb_response(&fallback_msgb, &my_echo)
        .unwrap();

    // Returns false indicating fallback to 4-step Msg3 transmission
    assert!(!fallback_res);
    assert_eq!(engine_fallback.rach_type, RachType::Cbra4Step);
    assert_eq!(engine_fallback.state, RachState::Msg2Received);
}
