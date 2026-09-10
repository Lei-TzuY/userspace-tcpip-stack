//! Integration tests for 3GPP Rel-18 Conditional PSCell Addition/Change (CPAC) Engine.

use toy_tcpip::nr_cpac_engine::{
    CellMeasurement, CpacCandidateConfig, CpacCandidateState, CpacEngine, CpacError,
    CpacProcedureType, CpacReleaseCause, CpacTriggerEvent, ScgServingCell, XnApCpacMessage,
    MAX_CPAC_CANDIDATES,
};

#[test]
fn test_cpac_candidate_management_and_limits() {
    let mut engine = CpacEngine::new(42);

    for i in 1..=MAX_CPAC_CANDIDATES as u8 {
        let cand = CpacCandidateConfig {
            candidate_id: i,
            pci: 200 + i as u16,
            arfcn: 630000,
            sn_id: 5,
            trigger_event: CpacTriggerEvent::default_a4(),
            dedicated_preamble_index: Some(i * 2),
            ssb_index: Some(0),
            scg_rrc_reconfig: vec![0xDE, 0xAD],
        };
        assert!(engine.add_candidate(cand).is_ok());
    }

    assert_eq!(engine.candidates.len(), 8);

    // Overflow check
    let cand_overflow = CpacCandidateConfig {
        candidate_id: 9,
        pci: 209,
        arfcn: 630000,
        sn_id: 5,
        trigger_event: CpacTriggerEvent::default_a4(),
        dedicated_preamble_index: None,
        ssb_index: None,
        scg_rrc_reconfig: vec![],
    };
    assert!(matches!(
        engine.add_candidate(cand_overflow),
        Err(CpacError::CandidateLimitExceeded(_))
    ));

    // Duplicate check
    let cand_dup = CpacCandidateConfig {
        candidate_id: 3,
        pci: 999,
        arfcn: 630000,
        sn_id: 5,
        trigger_event: CpacTriggerEvent::default_a4(),
        dedicated_preamble_index: None,
        ssb_index: None,
        scg_rrc_reconfig: vec![],
    };
    assert!(matches!(
        engine.add_candidate(cand_dup),
        Err(CpacError::DuplicateCandidateId(3))
    ));

    // Removal check
    assert!(engine.remove_candidate(2).is_ok());
    assert_eq!(engine.candidates.len(), 7);
    assert!(matches!(engine.remove_candidate(2), Err(CpacError::CandidateNotFound(2))));
}

#[test]
fn test_conditional_pscell_addition_event_a4_with_ttt() {
    let mut engine = CpacEngine::new(100);
    assert!(engine.active_pscell.is_none()); // No serving PSCell -> Addition procedure

    let cand1 = CpacCandidateConfig {
        candidate_id: 1,
        pci: 301,
        arfcn: 640000,
        sn_id: 10,
        trigger_event: CpacTriggerEvent::EventA4 {
            threshold_dbm: -100.0,
            hysteresis_db: 2.0,
            ttt_ms: 80,
        },
        dedicated_preamble_index: Some(15),
        ssb_index: Some(1),
        scg_rrc_reconfig: vec![0x01, 0x02, 0x03],
    };
    engine.add_candidate(cand1).unwrap();

    // 1. Measurement below entry condition (-100 + 2.0 = -98.0 dBm)
    let meas_low = vec![CellMeasurement {
        pci: 301,
        arfcn: 640000,
        rsrp_dbm: -99.0, // < -98.0
        rsrq_db: -10.0,
        sinr_db: 15.0,
    }];
    assert_eq!(engine.evaluate_measurements(&meas_low, 0), None);
    assert_eq!(engine.candidate_states.get(&1), Some(&CpacCandidateState::Configured));

    // 2. Measurement meets entry condition at t = 100 ms (-96.0 dBm >= -98.0 dBm)
    let meas_high = vec![CellMeasurement {
        pci: 301,
        arfcn: 640000,
        rsrp_dbm: -96.0,
        rsrq_db: -10.0,
        sinr_db: 18.0,
    }];
    assert_eq!(engine.evaluate_measurements(&meas_high, 100), None);
    assert_eq!(
        engine.candidate_states.get(&1),
        Some(&CpacCandidateState::ConditionMet { first_triggered_ms: 100 })
    );

    // 3. At t = 140 ms (elapsed 40 ms < TTT 80 ms): still pending
    assert_eq!(engine.evaluate_measurements(&meas_high, 140), None);

    // 4. At t = 180 ms (elapsed 80 ms >= TTT 80 ms): fires execution decision
    let decision = engine
        .evaluate_measurements(&meas_high, 180)
        .expect("CPAC execution triggered");

    assert_eq!(decision.candidate_id, 1);
    assert_eq!(decision.target_pci, 301);
    assert_eq!(decision.target_sn_id, 10);
    assert_eq!(decision.procedure_type, CpacProcedureType::ConditionalPscellAddition);
    assert_eq!(decision.dedicated_preamble_index, Some(15));
    assert_eq!(decision.scg_rrc_reconfig, vec![0x01, 0x02, 0x03]);
    assert_eq!(engine.candidate_states.get(&1), Some(&CpacCandidateState::Executing));
}

#[test]
fn test_conditional_pscell_change_event_a3_with_serving_cell() {
    let mut engine = CpacEngine::new(200);

    // Active serving PSCell on PCI 100
    engine.set_active_pscell(Some(ScgServingCell {
        pci: 100,
        arfcn: 630000,
        sn_id: 1,
    }));

    // Candidate on PCI 200 configured with Event A3 (Offset = 3.0 dB, Hyst = 2.0 dB, TTT = 60 ms)
    let cand = CpacCandidateConfig {
        candidate_id: 2,
        pci: 200,
        arfcn: 630000,
        sn_id: 2,
        trigger_event: CpacTriggerEvent::EventA3 {
            offset_db: 3.0,
            hysteresis_db: 2.0,
            ttt_ms: 60,
        },
        dedicated_preamble_index: Some(28),
        ssb_index: Some(0),
        scg_rrc_reconfig: vec![0xAA, 0xBB],
    };
    engine.add_candidate(cand).unwrap();

    // Serving PSCell RSRP = -95.0 dBm.
    // Condition requires Candidate RSRP >= -95.0 + 3.0 + 2.0 = -90.0 dBm.
    let meas1 = vec![
        CellMeasurement {
            pci: 100,
            arfcn: 630000,
            rsrp_dbm: -95.0,
            rsrq_db: -12.0,
            sinr_db: 10.0,
        },
        CellMeasurement {
            pci: 200,
            arfcn: 630000,
            rsrp_dbm: -92.0, // < -90.0 dBm -> condition not met
            rsrq_db: -10.0,
            sinr_db: 15.0,
        },
    ];
    assert_eq!(engine.evaluate_measurements(&meas1, 0), None);

    // Candidate improves to -88.0 dBm (>= -90.0 dBm)
    let meas2 = vec![
        CellMeasurement {
            pci: 100,
            arfcn: 630000,
            rsrp_dbm: -95.0,
            rsrq_db: -12.0,
            sinr_db: 10.0,
        },
        CellMeasurement {
            pci: 200,
            arfcn: 630000,
            rsrp_dbm: -88.0,
            rsrq_db: -9.0,
            sinr_db: 18.0,
        },
    ];
    assert_eq!(engine.evaluate_measurements(&meas2, 50), None); // Arm TTT
    assert_eq!(engine.evaluate_measurements(&meas2, 110).map(|d| d.procedure_type), Some(CpacProcedureType::ConditionalPscellChange));
}

#[test]
fn test_inter_node_xn_ap_cancellation_of_unselected_candidates() {
    let mut engine = CpacEngine::new(300);

    // Configure 3 candidates on different Secondary Nodes (SN 10, SN 20, SN 30)
    for i in 1..=3 {
        let cand = CpacCandidateConfig {
            candidate_id: i,
            pci: 500 + i as u16,
            arfcn: 640000,
            sn_id: i as u32 * 10,
            trigger_event: CpacTriggerEvent::default_a4(),
            dedicated_preamble_index: Some(i * 5),
            ssb_index: Some(0),
            scg_rrc_reconfig: vec![],
        };
        engine.add_candidate(cand).unwrap();
    }

    // Candidate 1 executes successfully
    let notifications = engine.handle_execution_success(1);

    // Must emit: 1 ExecutionNotification (to SN 10) + 2 CancelNotifications (to SN 20 and SN 30)
    assert_eq!(notifications.len(), 3);

    assert_eq!(
        notifications[0],
        XnApCpacMessage::CpacExecutionNotification {
            ue_id: 300,
            executed_pci: 501,
            target_sn_id: 10,
        }
    );

    assert_eq!(
        notifications[1],
        XnApCpacMessage::CpacCancelNotification {
            ue_id: 300,
            cancelled_pci: 502,
            target_sn_id: 20,
            cause: CpacReleaseCause::CpacExecutedOnOtherNode,
        }
    );

    assert_eq!(
        notifications[2],
        XnApCpacMessage::CpacCancelNotification {
            ue_id: 300,
            cancelled_pci: 503,
            target_sn_id: 30,
            cause: CpacReleaseCause::CpacExecutedOnOtherNode,
        }
    );

    // Verify candidate states
    assert_eq!(engine.candidate_states.get(&1), Some(&CpacCandidateState::Completed));
    assert_eq!(engine.candidate_states.get(&2), Some(&CpacCandidateState::Cancelled));
    assert_eq!(engine.candidate_states.get(&3), Some(&CpacCandidateState::Cancelled));
    assert_eq!(engine.stats_cancellations_sent, 2);
}

#[test]
fn test_scg_radio_link_failure_fast_cpac_fallback() {
    let mut engine = CpacEngine::new(400);

    let cand = CpacCandidateConfig {
        candidate_id: 1,
        pci: 601,
        arfcn: 630000,
        sn_id: 7,
        trigger_event: CpacTriggerEvent::default_a4(),
        dedicated_preamble_index: Some(12),
        ssb_index: Some(0),
        scg_rrc_reconfig: vec![0xCA, 0xFE],
    };
    engine.add_candidate(cand).unwrap();

    let measurements = vec![CellMeasurement {
        pci: 601,
        arfcn: 630000,
        rsrp_dbm: -96.0, // Healthy
        rsrq_db: -10.0,
        sinr_db: 15.0,
    }];

    // SCG RLF recovery immediately selects candidate 1 without waiting for TTT
    let decision = engine.handle_scg_failure(&measurements).expect("RLF fallback succeeds");
    assert_eq!(decision.candidate_id, 1);
    assert_eq!(decision.target_pci, 601);
    assert!(decision.reason.contains("SCG Radio Link Failure"));
}

#[test]
fn test_measurement_drop_resets_condition_met() {
    let mut engine = CpacEngine::new(500);
    let cand = CpacCandidateConfig {
        candidate_id: 1,
        pci: 701,
        arfcn: 630000,
        sn_id: 8,
        trigger_event: CpacTriggerEvent::EventA4 {
            threshold_dbm: -100.0,
            hysteresis_db: 0.0,
            ttt_ms: 100,
        },
        dedicated_preamble_index: None,
        ssb_index: None,
        scg_rrc_reconfig: vec![],
    };
    engine.add_candidate(cand).unwrap();

    // t=10: Condition met
    let m1 = vec![CellMeasurement {
        pci: 701,
        arfcn: 630000,
        rsrp_dbm: -95.0,
        rsrq_db: -10.0,
        sinr_db: 15.0,
    }];
    engine.evaluate_measurements(&m1, 10);
    assert!(matches!(engine.candidate_states.get(&1), Some(&CpacCandidateState::ConditionMet { .. })));

    // t=50: Signal fades below threshold (-105 < -100)
    let m2 = vec![CellMeasurement {
        pci: 701,
        arfcn: 630000,
        rsrp_dbm: -105.0,
        rsrq_db: -15.0,
        sinr_db: 5.0,
    }];
    engine.evaluate_measurements(&m2, 50);
    // Condition reset to Configured
    assert_eq!(engine.candidate_states.get(&1), Some(&CpacCandidateState::Configured));
}
