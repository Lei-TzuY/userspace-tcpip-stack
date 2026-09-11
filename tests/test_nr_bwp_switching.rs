//! Integration and unit tests for 3GPP Rel-18/19 5G-Advanced Dynamic Bandwidth Part (BWP)
//! Adaptation and Fast Switching Engine.

use toy_tcpip::nr_bwp_switching::*;

#[test]
fn test_riv_encoding_and_decoding_roundtrip() {
    let carrier_size = 273; // 100 MHz at 30 kHz SCS

    // Test cases: (start_prb, num_prbs)
    let test_cases = vec![
        (0, 1),
        (0, 24),
        (10, 50),
        (50, 100),
        (100, 150),
        (0, carrier_size),
        (200, 73),
    ];

    for (start, num) in test_cases {
        let riv = encode_riv(start, num, carrier_size);
        let (decoded_start, decoded_num) =
            decode_riv(riv, carrier_size).expect("RIV decoding should succeed");
        assert_eq!(
            (decoded_start, decoded_num),
            (start, num),
            "Failed roundtrip for start={}, num={}",
            start,
            num
        );
    }

    // Invalid RIV exceeding carrier size
    let invalid_riv = 273 * 274 + 500;
    assert!(decode_riv(invalid_riv, carrier_size).is_err());
}

#[test]
fn test_bwp_configuration_and_validation() {
    let mut engine = NrBwpEngine::new(273);

    // Initial BWP #0 (24 PRBs, 15 kHz SCS)
    let bwp0 = BandwidthPartConfig::new(
        0,
        SubcarrierSpacing::SCS15kHz,
        CyclicPrefix::Normal,
        0,
        24,
        BwpRole::Initial,
        273,
    );
    assert!(engine.add_bwp(bwp0).is_ok());

    // Default BWP #1 (51 PRBs, 30 kHz SCS)
    let bwp1 = BandwidthPartConfig::new(
        1,
        SubcarrierSpacing::SCS30kHz,
        CyclicPrefix::Normal,
        0,
        51,
        BwpRole::Default,
        273,
    );
    assert!(engine.add_bwp(bwp1).is_ok());

    // High-bandwidth BWP #2 (273 PRBs, 30 kHz SCS)
    let bwp2 = BandwidthPartConfig::new(
        2,
        SubcarrierSpacing::SCS30kHz,
        CyclicPrefix::Normal,
        0,
        273,
        BwpRole::GeneralActive,
        273,
    );
    assert!(engine.add_bwp(bwp2).is_ok());

    // Dormant BWP #3 (24 PRBs, 30 kHz SCS)
    let bwp3 = BandwidthPartConfig::new(
        3,
        SubcarrierSpacing::SCS30kHz,
        CyclicPrefix::Normal,
        0,
        24,
        BwpRole::Dormant,
        273,
    );
    assert!(engine.add_bwp(bwp3).is_ok());

    // 5th BWP exceeds 3GPP limit of 4 per cell
    let bwp4 = BandwidthPartConfig::new(
        4,
        SubcarrierSpacing::SCS30kHz,
        CyclicPrefix::Normal,
        0,
        50,
        BwpRole::GeneralActive,
        273,
    );
    assert_eq!(
        engine.add_bwp(bwp4),
        Err(BwpError::BwpCapacityExceeded {
            max: MAX_BWPS_PER_CELL,
            attempted: 5
        })
    );

    // BWP exceeding carrier PRB boundary
    let mut small_engine = NrBwpEngine::new(51);
    let overflow_bwp = BandwidthPartConfig::new(
        0,
        SubcarrierSpacing::SCS30kHz,
        CyclicPrefix::Normal,
        40,
        20,
        BwpRole::Initial,
        51,
    );
    assert!(small_engine.add_bwp(overflow_bwp).is_err());
}

#[test]
fn test_dci_triggered_bwp_switching_and_transition_delay() {
    let mut engine = NrBwpEngine::new(273);

    let bwp1 = BandwidthPartConfig::new(
        1,
        SubcarrierSpacing::SCS30kHz,
        CyclicPrefix::Normal,
        0,
        51,
        BwpRole::Default,
        273,
    );
    let bwp2 = BandwidthPartConfig::new(
        2,
        SubcarrierSpacing::SCS30kHz,
        CyclicPrefix::Normal,
        0,
        273,
        BwpRole::GeneralActive,
        273,
    );

    engine.add_bwp(bwp1).unwrap();
    engine.add_bwp(bwp2).unwrap();

    // Trigger DCI switch from default BWP #1 to wide BWP #2
    let delay_type = engine
        .trigger_switch(BwpSwitchingTrigger::DciIndicator {
            target_bwp_id: 2,
            dci_format: "1_1".into(),
        })
        .expect("Switch trigger should succeed");

    assert_eq!(delay_type, BwpSwitchingDelayType::Type1);
    // In transition: scheduling is gated
    assert!(!engine.can_schedule());
    assert_eq!(
        engine.state(),
        &BwpState::InTransition {
            target_bwp_id: 2,
            remaining_guard_slots: 1,
            delay_type: BwpSwitchingDelayType::Type1,
        }
    );

    // Advance 1 slot -> transition completes
    engine.step_slot();
    assert_eq!(engine.state(), &BwpState::Active);
    assert_eq!(engine.active_bwp_id(), 2);
    assert!(engine.can_schedule());

    let tel = engine.telemetry();
    assert_eq!(tel.total_bwp_switches, 1);
    assert_eq!(tel.dci_switches, 1);
    assert_eq!(tel.total_guard_slots_interrupted, 1);
}

#[test]
fn test_bwp_inactivity_timer_expiry_and_fallback() {
    let mut engine = NrBwpEngine::new(273);
    engine.set_inactivity_timer_ms(50);

    let bwp0 = BandwidthPartConfig::new(
        0,
        SubcarrierSpacing::SCS30kHz,
        CyclicPrefix::Normal,
        0,
        51,
        BwpRole::Default,
        273,
    );
    let bwp1 = BandwidthPartConfig::new(
        1,
        SubcarrierSpacing::SCS30kHz,
        CyclicPrefix::Normal,
        0,
        273,
        BwpRole::GeneralActive,
        273,
    );

    engine.add_bwp(bwp0).unwrap();
    engine.add_bwp(bwp1).unwrap();

    // Switch to wide BWP #1
    engine
        .trigger_switch(BwpSwitchingTrigger::DciIndicator {
            target_bwp_id: 1,
            dci_format: "1_1".into(),
        })
        .unwrap();
    engine.step_slot();
    assert_eq!(engine.active_bwp_id(), 1);

    // Step 30 ms -> timer still has 20 ms left
    engine.step_time_ms(30);
    assert_eq!(engine.active_bwp_id(), 1);

    // PDCCH received -> timer refreshed to 50 ms
    engine.on_pdcch_reception();

    // Advance 40 ms -> still active on BWP #1
    engine.step_time_ms(40);
    assert_eq!(engine.active_bwp_id(), 1);

    // Advance remaining 20 ms -> timer expires (60 ms total) -> triggers fallback to Default BWP #0
    engine.step_time_ms(20);
    assert_eq!(
        engine.state(),
        &BwpState::InTransition {
            target_bwp_id: 0,
            remaining_guard_slots: 1,
            delay_type: BwpSwitchingDelayType::Type1,
        }
    );

    engine.step_slot();
    assert_eq!(engine.active_bwp_id(), 0);
    assert_eq!(engine.telemetry().timer_fallback_switches, 1);
}

#[test]
fn test_scell_dormant_bwp_transition() {
    let mut engine = NrBwpEngine::new(273);

    let bwp0 = BandwidthPartConfig::new(
        0,
        SubcarrierSpacing::SCS30kHz,
        CyclicPrefix::Normal,
        0,
        51,
        BwpRole::Default,
        273,
    );
    let bwp1 = BandwidthPartConfig::new(
        1,
        SubcarrierSpacing::SCS30kHz,
        CyclicPrefix::Normal,
        0,
        24,
        BwpRole::Dormant,
        273,
    );

    engine.add_bwp(bwp0).unwrap();
    engine.add_bwp(bwp1).unwrap();

    // Trigger SCell dormancy
    engine
        .trigger_switch(BwpSwitchingTrigger::ScellDormancyIndication)
        .unwrap();
    engine.step_slot();

    assert_eq!(engine.active_bwp_id(), 1);
    // In Dormant BWP, UE does not monitor PDCCH; can_schedule is false
    assert!(!engine.can_schedule());
    // Dormant power is minimal (40 mW)
    assert_eq!(engine.evaluate_power_mw(), 40.0);
    assert_eq!(engine.telemetry().dormancy_switches, 1);
}

#[test]
fn test_rach_fallback_to_initial_bwp() {
    let mut engine = NrBwpEngine::new(273);

    let bwp0 = BandwidthPartConfig::new(
        0,
        SubcarrierSpacing::SCS15kHz,
        CyclicPrefix::Normal,
        0,
        24,
        BwpRole::Initial,
        273,
    );
    let bwp1 = BandwidthPartConfig::new(
        1,
        SubcarrierSpacing::SCS30kHz,
        CyclicPrefix::Normal,
        50,
        100,
        BwpRole::GeneralActive,
        273,
    );

    engine.add_bwp(bwp0).unwrap();
    engine.add_bwp(bwp1).unwrap();

    // Switch to BWP #1 (Type 2 delay due to SCS change 15 kHz -> 30 kHz)
    let delay_type = engine
        .trigger_switch(BwpSwitchingTrigger::DciIndicator {
            target_bwp_id: 1,
            dci_format: "0_1".into(),
        })
        .unwrap();
    assert_eq!(delay_type, BwpSwitchingDelayType::Type2);

    // Advance guard slots (4 slots at 30 kHz SCS)
    for _ in 0..4 {
        engine.step_slot();
    }
    assert_eq!(engine.active_bwp_id(), 1);

    // Random Access initiated on BWP #1 which lacks PRACH -> fallback to Initial BWP #0
    let delay_type = engine
        .trigger_switch(BwpSwitchingTrigger::RachFallback)
        .unwrap();
    assert_eq!(delay_type, BwpSwitchingDelayType::Type2);

    for _ in 0..2 {
        engine.step_slot();
    }
    assert_eq!(engine.active_bwp_id(), 0);
    assert_eq!(engine.telemetry().rach_fallback_switches, 1);
}

#[test]
fn test_power_saving_analytics() {
    let mut engine = NrBwpEngine::new(273);

    let bwp_wide = BandwidthPartConfig::new(
        1,
        SubcarrierSpacing::SCS30kHz,
        CyclicPrefix::Normal,
        0,
        273,
        BwpRole::GeneralActive,
        273,
    );
    let bwp_narrow = BandwidthPartConfig::new(
        2,
        SubcarrierSpacing::SCS30kHz,
        CyclicPrefix::Normal,
        0,
        51,
        BwpRole::Default,
        273,
    );

    engine.add_bwp(bwp_wide).unwrap();
    engine.add_bwp(bwp_narrow).unwrap();

    // Wide BWP (273 PRBs)
    engine
        .trigger_switch(BwpSwitchingTrigger::DciIndicator {
            target_bwp_id: 1,
            dci_format: "1_1".into(),
        })
        .unwrap();
    engine.step_slot();
    let power_wide = engine.evaluate_power_mw();
    assert!(power_wide > 500.0);

    // Narrow BWP (51 PRBs)
    engine
        .trigger_switch(BwpSwitchingTrigger::DciIndicator {
            target_bwp_id: 2,
            dci_format: "1_1".into(),
        })
        .unwrap();
    engine.step_slot();
    let power_narrow = engine.evaluate_power_mw();
    assert!(power_narrow < 200.0);

    // Power saving percentage > 60%
    let saving = (power_wide - power_narrow) / power_wide * 100.0;
    assert!(saving > 60.0, "Power saving was {}%", saving);
}

#[test]
fn test_binary_wire_codec_and_crc16() {
    let pdu = BwpSwitchingCommandPdu {
        cell_id: 1001,
        target_bwp_id: 2,
        transition_slots: 2,
        is_dormancy: false,
    };

    let wire = pdu.encode_wire();
    assert_eq!(&wire[0..4], &BWP_WIRE_MAGIC);

    let decoded = BwpSwitchingCommandPdu::decode_wire(&wire).expect("Decode must succeed");
    assert_eq!(decoded.cell_id, 1001);
    assert_eq!(decoded.target_bwp_id, 2);
    assert_eq!(decoded.transition_slots, 2);
    assert!(!decoded.is_dormancy);

    // Corrupt one byte to trigger CRC mismatch
    let mut corrupted = wire.clone();
    corrupted[6] ^= 0xFF;
    let err = BwpSwitchingCommandPdu::decode_wire(&corrupted).unwrap_err();
    match err {
        BwpError::ChecksumMismatch { .. } => {}
        other => panic!("Expected ChecksumMismatch, got {:?}", other),
    }

    // Test error display
    let err_str = format!("{}", err);
    assert!(err_str.contains("CRC-16 mismatch"));
}
