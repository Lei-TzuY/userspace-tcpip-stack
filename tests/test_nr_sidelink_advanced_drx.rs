//! Comprehensive integration tests for 3GPP Rel-18/19 Sidelink Advanced DRX
//! and Uu-PC5 Cross-Interface Energy Savings Engine.

use toy_tcpip::nr_sidelink_advanced_drx::{
    ArbitrationDecision, DfnSfnAligner, Fr2BeamDrxSweeper, InterfaceEvent, MultiRatDrxState,
    SidelinkAdvancedDrxEngine, SlDrxConfig, SlDrxError, SlWusCause, SlWusPacket,
    TransceiverHardwareArchitecture, UuDrxConfig,
};

#[test]
fn test_dfn_sfn_timing_alignment() {
    // 1. Set subframe offset to +25 subframes (2 frames + 5 subframes)
    let aligner = DfnSfnAligner::new(25);

    // SFN 10, subframe 0 -> 100 subframes + 25 = 125 subframes -> DFN 12, subframe 5
    let (dfn, dfn_subframe) = aligner.sfn_to_dfn(10, 0);
    assert_eq!(dfn, 12);
    assert_eq!(dfn_subframe, 5);

    // Round-trip back to SFN
    let (sfn, sfn_subframe) = aligner.dfn_to_sfn(12, 5);
    assert_eq!(sfn, 10);
    assert_eq!(sfn_subframe, 0);

    // 2. Test cycle wrap-around near 1024 frames (10240 subframes)
    // SFN 1023, subframe 8 -> 10238 subframes + 25 = 10263 -> wraps to 23 (DFN 2, subframe 3)
    let (wrap_dfn, wrap_subframe) = aligner.sfn_to_dfn(1023, 8);
    assert_eq!(wrap_dfn, 2);
    assert_eq!(wrap_subframe, 3);

    let (rev_sfn, rev_subframe) = aligner.dfn_to_sfn(2, 3);
    assert_eq!(rev_sfn, 1023);
    assert_eq!(rev_subframe, 8);
}

#[test]
fn test_unified_uu_pc5_active_time_harmonization() {
    let uu_cfg = UuDrxConfig {
        on_duration_ms: 10,
        inactivity_ms: 0,
        cycle_ms: 40,
        start_offset_ms: 0,
    };

    let sl_cfg = SlDrxConfig {
        sl_on_duration_ms: 10,
        sl_inactivity_ms: 0,
        sl_cycle_ms: 40,
        sl_start_offset_ms: 0,
        sl_wus_enabled: false,
        sl_wus_offset_ms: 2,
        sl_wus_duration_ms: 1,
    };

    // Aligned with offset 0: both Uu and PC5 share identical 40 ms cycle and onDuration [0..10)
    let mut engine = SidelinkAdvancedDrxEngine::new(
        TransceiverHardwareArchitecture::SingleTransceiver,
        0,
        uu_cfg,
        sl_cfg,
        0x1234,
    );

    // Step through 40 subframes (one full cycle)
    for subframe in 0..40 {
        let state = engine.step_subframe((subframe / 10) as u16, (subframe % 10) as u8);
        if subframe < 10 {
            // First 10 ms: Both are awake simultaneously in unified active time
            assert_eq!(state, MultiRatDrxState::UnifiedActiveBoth);
        } else {
            // Remaining 30 ms: Deep sleep for entire transceiver
            assert_eq!(state, MultiRatDrxState::DeepSleep);
        }
    }

    assert_eq!(engine.telemetry.unified_both_active_subframes, 10);
    assert_eq!(engine.telemetry.deep_sleep_subframes, 30);
    assert_eq!(engine.calculate_active_duty_cycle(), 0.25); // 10/40 = 25%
}

#[test]
fn test_cross_interface_conflict_arbitration() {
    let uu_cfg = UuDrxConfig {
        on_duration_ms: 10,
        inactivity_ms: 0,
        cycle_ms: 40,
        start_offset_ms: 0,
    };
    let sl_cfg = SlDrxConfig {
        sl_on_duration_ms: 10,
        sl_inactivity_ms: 0,
        sl_cycle_ms: 40,
        sl_start_offset_ms: 0,
        sl_wus_enabled: false,
        sl_wus_offset_ms: 2,
        sl_wus_duration_ms: 1,
    };

    // 1. Single Transceiver Mode
    let single_engine = SidelinkAdvancedDrxEngine::new(
        TransceiverHardwareArchitecture::SingleTransceiver,
        0,
        uu_cfg.clone(),
        sl_cfg.clone(),
        0x1234,
    );

    // PC5 Emergency ProSe (Tier 0) vs Uu URLLC HARQ (Tier 1) -> Grant PC5
    assert_eq!(
        single_engine.arbitrate_collision(
            InterfaceEvent::UuUrllcHarqPrach,
            InterfaceEvent::Pc5EmergencyProSe
        ),
        ArbitrationDecision::GrantPc5
    );

    // Uu URLLC (Tier 1) vs PC5 Safety Groupcast (Tier 3) -> Grant Uu
    assert_eq!(
        single_engine.arbitrate_collision(
            InterfaceEvent::UuUrllcHarqPrach,
            InterfaceEvent::Pc5SafetyGroupcast
        ),
        ArbitrationDecision::GrantUu
    );

    // Uu Paging (Tier 2) vs PC5 Non-safety (Tier 5) -> Grant Uu
    assert_eq!(
        single_engine.arbitrate_collision(
            InterfaceEvent::UuPagingBroadcast,
            InterfaceEvent::Pc5NonSafetyData
        ),
        ArbitrationDecision::GrantUu
    );

    // 2. Dual Transceiver Mode
    let dual_engine = SidelinkAdvancedDrxEngine::new(
        TransceiverHardwareArchitecture::DualTransceiver,
        0,
        uu_cfg,
        sl_cfg,
        0x1234,
    );

    assert_eq!(
        dual_engine.arbitrate_collision(
            InterfaceEvent::UuUrllcHarqPrach,
            InterfaceEvent::Pc5EmergencyProSe
        ),
        ArbitrationDecision::AllowBothConcurrent
    );
}

#[test]
fn test_on_demand_sl_wus_codec_and_crc() {
    // 1. Create SL-WUS packet targeting group hash 0xABCD with cause SafetyAlert
    let wus = SlWusPacket::new(0xABCD, SlWusCause::SafetyAlert);
    assert_eq!(wus.target_l2_id_hash, 0xABCD);
    assert_eq!(wus.cause, SlWusCause::SafetyAlert);

    // 2. Binary wire serialization (4 bytes)
    let wire_bytes = wus.serialize();
    assert_eq!(wire_bytes.len(), 4);
    assert_eq!(wire_bytes[0], 0xAB);
    assert_eq!(wire_bytes[1], 0xCD);
    assert_eq!(wire_bytes[2], 0x01);

    // 3. Binary parsing & CRC verification
    let parsed = SlWusPacket::parse(&wire_bytes).expect("Valid SL-WUS parse failed");
    assert_eq!(parsed.target_l2_id_hash, 0xABCD);
    assert_eq!(parsed.cause, SlWusCause::SafetyAlert);
    assert_eq!(parsed.crc8, wus.crc8);

    // 4. Corrupt CRC byte and verify error
    let mut corrupt_bytes = wire_bytes;
    corrupt_bytes[3] ^= 0xFF;
    let err = SlWusPacket::parse(&corrupt_bytes);
    assert!(matches!(err, Err(SlDrxError::CrcCheckFailed { .. })));
}

#[test]
fn test_sl_wus_sleep_skipping_optimization() {
    let uu_cfg = UuDrxConfig {
        on_duration_ms: 5,
        inactivity_ms: 0,
        cycle_ms: 50,
        start_offset_ms: 0,
    };
    let sl_cfg = SlDrxConfig {
        sl_on_duration_ms: 10,
        sl_inactivity_ms: 0,
        sl_cycle_ms: 50,
        sl_start_offset_ms: 0,
        sl_wus_enabled: true, // WUS active!
        sl_wus_offset_ms: 2,
        sl_wus_duration_ms: 1,
    };

    let mut engine = SidelinkAdvancedDrxEngine::new(
        TransceiverHardwareArchitecture::SingleTransceiver,
        0,
        uu_cfg,
        sl_cfg,
        0x9999, // Local UE hash
    );

    // Cycle 1: No SL-WUS received!
    // During nominal onDuration (subframes 0..10), PC5 must NOT wake up!
    for sf in 0..10 {
        let is_sl_active = engine.is_sl_active(0, sf);
        assert!(!is_sl_active, "PC5 should sleep when no WUS received");
        engine.step_subframe(0, sf);
    }
    // Complete cycle 1
    for sf in 10..50 {
        engine.step_subframe((sf / 10) as u16, (sf % 10) as u8);
    }
    assert_eq!(engine.telemetry.sl_wus_skips_count, 1);

    // Cycle 2: Matching SL-WUS received!
    let matching_wus = SlWusPacket::new(0x9999, SlWusCause::GroupcastData);
    engine.process_sl_wus_reception(&matching_wus);

    // Now PC5 should wake up for nominal onDuration (subframes 0..10)
    for sf in 0..10 {
        let is_sl_active = engine.is_sl_active(5, sf);
        assert!(is_sl_active, "PC5 must be active after matching WUS");
        engine.step_subframe(5, sf);
    }
}

#[test]
fn test_fr2_directional_beam_sweeping_in_drx() {
    let uu_cfg = UuDrxConfig {
        on_duration_ms: 8,
        inactivity_ms: 0,
        cycle_ms: 40,
        start_offset_ms: 0,
    };
    let sl_cfg = SlDrxConfig {
        sl_on_duration_ms: 8,
        sl_inactivity_ms: 0,
        sl_cycle_ms: 40,
        sl_start_offset_ms: 0,
        sl_wus_enabled: false,
        sl_wus_offset_ms: 2,
        sl_wus_duration_ms: 1,
    };

    let mut engine = SidelinkAdvancedDrxEngine::new(
        TransceiverHardwareArchitecture::SingleTransceiver,
        0,
        uu_cfg,
        sl_cfg,
        0x1234,
    );

    // 4 spatial beams, 2 subframes per beam -> 8 ms total sweep
    engine.set_beam_sweeper(Fr2BeamDrxSweeper::new(4, 2));

    // Subframe 0 and 1 -> Beam 0
    assert_eq!(engine.get_current_sl_beam(0, 0), Some(0));
    assert_eq!(engine.get_current_sl_beam(0, 1), Some(0));

    // Subframe 2 and 3 -> Beam 1
    assert_eq!(engine.get_current_sl_beam(0, 2), Some(1));
    assert_eq!(engine.get_current_sl_beam(0, 3), Some(1));

    // Subframe 4 and 5 -> Beam 2
    assert_eq!(engine.get_current_sl_beam(0, 4), Some(2));
    assert_eq!(engine.get_current_sl_beam(0, 5), Some(2));

    // Subframe 6 and 7 -> Beam 3
    assert_eq!(engine.get_current_sl_beam(0, 6), Some(3));
    assert_eq!(engine.get_current_sl_beam(0, 7), Some(3));

    // Subframe 8 -> Outside onDuration -> None
    assert_eq!(engine.get_current_sl_beam(0, 8), None);
}

#[test]
fn test_multi_rat_battery_energy_savings_model() {
    let uu_cfg = UuDrxConfig {
        on_duration_ms: 10,
        inactivity_ms: 0,
        cycle_ms: 100,
        start_offset_ms: 0,
    };
    let sl_cfg = SlDrxConfig {
        sl_on_duration_ms: 10,
        sl_inactivity_ms: 0,
        sl_cycle_ms: 100,
        sl_start_offset_ms: 0,
        sl_wus_enabled: false,
        sl_wus_offset_ms: 2,
        sl_wus_duration_ms: 1,
    };

    // Aligned DRX: 10 ms active out of 100 ms (10% duty cycle)
    let mut aligned_engine = SidelinkAdvancedDrxEngine::new(
        TransceiverHardwareArchitecture::SingleTransceiver,
        0,
        uu_cfg,
        sl_cfg,
        0x1234,
    );

    for sfn in 0..10 {
        for sf in 0..10 {
            aligned_engine.step_subframe(sfn, sf);
        }
    }

    let duty = aligned_engine.calculate_active_duty_cycle();
    assert!((duty - 0.10).abs() < 1e-4);

    // Average current with active 120 mA, sleep 0.05 mA:
    // I_avg = 0.10 * 120 + 0.90 * 0.05 = 12.0 + 0.045 = 12.045 mA
    let i_avg = aligned_engine.calculate_average_current_ma();
    assert!((i_avg - 12.045).abs() < 1e-3);

    // Battery lifetime with 1000 mAh battery: 1000 / 12.045 ~= 83.0 hours
    let hours = aligned_engine.calculate_battery_lifetime_hours();
    assert!((hours - 83.02).abs() < 0.5);
}
