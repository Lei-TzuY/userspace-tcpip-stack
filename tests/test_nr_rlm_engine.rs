//! Integration tests for 3GPP Rel-18/19 Radio Link Monitoring (RLM) & RLF Engine.

use toy_tcpip::nr_rlm_engine::{
    evaluate_l1_indications, L1RlmIndication, NrRlmEngine, RlfCause, RlmConfig, RlmRsMeasurement,
    RlmRsType, RlmState, RlmWirePdu, RLM_WIRE_MAGIC,
};

#[test]
fn test_l1_qout_and_qin_threshold_evaluation() {
    let mut cfg = RlmConfig::default();
    cfg.q_out_sinr_db = -3.0;
    cfg.q_in_sinr_db = 0.0;

    // 1. All measurements below Q_out => OutOfSync
    let oos_meas = vec![
        RlmRsMeasurement { rs: RlmRsType::Ssb { ssb_index: 0 }, sinr_db: -4.5 },
        RlmRsMeasurement { rs: RlmRsType::Ssb { ssb_index: 1 }, sinr_db: -6.0 },
    ];
    assert_eq!(evaluate_l1_indications(&oos_meas, &cfg).unwrap(), L1RlmIndication::OutOfSync);

    // 2. At least one measurement above Q_in => InSync
    let is_meas = vec![
        RlmRsMeasurement { rs: RlmRsType::Ssb { ssb_index: 0 }, sinr_db: -5.0 },
        RlmRsMeasurement { rs: RlmRsType::Ssb { ssb_index: 1 }, sinr_db: 1.5 },
    ];
    assert_eq!(evaluate_l1_indications(&is_meas, &cfg).unwrap(), L1RlmIndication::InSync);

    // 3. Between Q_out and Q_in => Indeterminate
    let indet_meas = vec![
        RlmRsMeasurement { rs: RlmRsType::Ssb { ssb_index: 0 }, sinr_db: -2.0 },
        RlmRsMeasurement { rs: RlmRsType::Ssb { ssb_index: 1 }, sinr_db: -1.0 },
    ];
    assert_eq!(evaluate_l1_indications(&indet_meas, &cfg).unwrap(), L1RlmIndication::Indeterminate);
}

#[test]
fn test_rlm_n310_consecutive_out_of_sync_starts_t310() {
    let mut cfg = RlmConfig::default();
    cfg.n310 = 5;
    cfg.t310_ms = 1000;

    let mut engine = NrRlmEngine::new(cfg).unwrap();
    assert_eq!(engine.state(), RlmState::NormalInSync);

    // Send 4 OutOfSync indications (below N310 threshold)
    for i in 1..=4 {
        engine.process_l1_indication(L1RlmIndication::OutOfSync);
        assert_eq!(engine.state(), RlmState::OutOfSyncCounting { count: i });
    }

    // 5th OutOfSync reaches N310 => T310 starts running
    engine.process_l1_indication(L1RlmIndication::OutOfSync);
    assert_eq!(engine.state(), RlmState::DegradedT310Running { remaining_ms: 1000 });
}

#[test]
fn test_rlm_t310_expiration_triggers_rlf() {
    let mut cfg = RlmConfig::default();
    cfg.n310 = 2;
    cfg.t310_ms = 1000;

    let mut engine = NrRlmEngine::new(cfg).unwrap();
    engine.process_l1_indication(L1RlmIndication::OutOfSync);
    engine.process_l1_indication(L1RlmIndication::OutOfSync);
    assert_eq!(engine.state(), RlmState::DegradedT310Running { remaining_ms: 1000 });

    // Advance 400 ms
    engine.advance_time_ms(400);
    assert_eq!(engine.state(), RlmState::DegradedT310Running { remaining_ms: 600 });

    // Advance remaining 600 ms => T310 expires
    engine.advance_time_ms(600);
    assert_eq!(
        engine.state(),
        RlmState::RadioLinkFailureDeclared { cause: RlfCause::T310Expiry }
    );
    assert_eq!(engine.total_rlf_count, 1);
}

#[test]
fn test_rlm_n311_consecutive_in_sync_recovers_link() {
    let mut cfg = RlmConfig::default();
    cfg.n310 = 1;
    cfg.n311 = 2;
    cfg.t310_ms = 1000;

    let mut engine = NrRlmEngine::new(cfg).unwrap();
    engine.process_l1_indication(L1RlmIndication::OutOfSync);
    assert_eq!(engine.state(), RlmState::DegradedT310Running { remaining_ms: 1000 });

    // 1st InSync: counter advances, T310 still active
    engine.process_l1_indication(L1RlmIndication::InSync);
    assert_eq!(engine.state(), RlmState::DegradedT310Running { remaining_ms: 1000 });
    assert_eq!(engine.is_counter, 1);

    // 2nd InSync: reaches N311 => Link recovered back to NormalInSync!
    engine.process_l1_indication(L1RlmIndication::InSync);
    assert_eq!(engine.state(), RlmState::NormalInSync);
    assert_eq!(engine.total_recovery_count, 1);
}

#[test]
fn test_rlm_t312_fast_early_recovery_acceleration() {
    let mut cfg = RlmConfig::default();
    cfg.n310 = 1;
    cfg.t310_ms = 1000;
    cfg.t312_ms = 100;

    let mut engine = NrRlmEngine::new(cfg).unwrap();
    engine.process_l1_indication(L1RlmIndication::OutOfSync);
    assert_eq!(engine.state(), RlmState::DegradedT310Running { remaining_ms: 1000 });

    // Measurement report triggered (e.g. Event A3 for handover attempt)
    engine.on_measurement_report_triggered();
    assert_eq!(
        engine.state(),
        RlmState::FastRecoveryT312Running {
            t310_remaining_ms: 1000,
            t312_remaining_ms: 100,
        }
    );

    // Advance 100 ms => T312 expires before T310, triggering fast RLF!
    engine.advance_time_ms(100);
    assert_eq!(
        engine.state(),
        RlmState::RadioLinkFailureDeclared { cause: RlfCause::T312Expiry }
    );
    assert_eq!(engine.total_rlf_count, 1);
}

#[test]
fn test_rlm_multi_trp_resilience_against_single_trp_blockage() {
    let mut cfg = RlmConfig::default();
    cfg.q_out_sinr_db = -3.0;
    cfg.q_in_sinr_db = 0.0;
    cfg.multi_trp_enabled = true;

    // TRP 0 is obstructed (-8.0 dB < Q_out), but TRP 1 has strong line-of-sight (+2.0 dB > Q_in)
    let mtrp_meas = vec![
        RlmRsMeasurement { rs: RlmRsType::Ssb { ssb_index: 0 }, sinr_db: -8.0 },
        RlmRsMeasurement { rs: RlmRsType::CsiRs { resource_id: 1 }, sinr_db: 2.0 },
    ];

    let ind = evaluate_l1_indications(&mtrp_meas, &cfg).unwrap();
    // Must NOT declare OutOfSync; TRP 1 maintains InSync
    assert_eq!(ind, L1RlmIndication::InSync);
}

#[test]
fn test_rlm_external_failure_triggers_rach_and_rlc() {
    let mut engine = NrRlmEngine::new(RlmConfig::default()).unwrap();

    // Trigger RACH problem
    engine.trigger_external_failure(RlfCause::RandomAccessProblem);
    assert_eq!(
        engine.state(),
        RlmState::RadioLinkFailureDeclared { cause: RlfCause::RandomAccessProblem }
    );

    // Start RRC connection re-establishment (T311)
    engine.start_reestablishment();
    assert_eq!(
        engine.state(),
        RlmState::ReEstablishingT311Running { remaining_ms: 3000 }
    );

    // Advance 3000 ms => T311 expires, fallback to Idle
    engine.advance_time_ms(3000);
    assert_eq!(engine.state(), RlmState::NormalInSync);
}

#[test]
fn test_binary_wire_codec_and_crc16_integrity() {
    let pdu = RlmWirePdu {
        magic: RLM_WIRE_MAGIC,
        timestamp_ms: 45000,
        state_tag: 2, // DegradedT310Running
        oos_count: 20,
        is_count: 0,
        rlf_count: 3,
        rlf_cause: 0, // T310
        payload: vec![0xDE, 0xAD, 0xC0, 0xDE],
        crc16: 0,
    };

    let serialized = pdu.serialize();
    assert_eq!(&serialized[..4], &[0x52, 0x4C, 0x4D, 0x46]); // "RLMF"

    // Successful deserialization
    let deserialized = RlmWirePdu::deserialize(&serialized).unwrap();
    assert_eq!(deserialized.timestamp_ms, 45000);
    assert_eq!(deserialized.state_tag, 2);
    assert_eq!(deserialized.oos_count, 20);
    assert_eq!(deserialized.payload, pdu.payload);

    // Tampered payload fails CRC
    let mut corrupted = serialized.clone();
    corrupted[22] ^= 0x01;
    assert!(RlmWirePdu::deserialize(&corrupted).is_err());
}
