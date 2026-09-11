//! Integration tests for 3GPP Rel-18/19 5G NR Multi-Panel Simultaneous Transmission (STxP) Engine.

use toy_tcpip::nr_multi_panel_stxp::*;

#[test]
fn test_multi_panel_initialization_and_states() {
    let mut engine = NrMultiPanelStxpEngine::new(23.0);
    assert_eq!(engine.p_cmax_total_dbm(), 23.0);

    let p0 = AntennaPanelConfig::new(0, 2, 0.0, 0.0);
    let p1 = AntennaPanelConfig::new(1, 2, 180.0, 0.0);
    let p2 = AntennaPanelConfig::new(2, 4, 90.0, 15.0);
    let p3 = AntennaPanelConfig::new(3, 4, 270.0, -15.0);

    assert!(engine.add_panel(p0).is_ok());
    assert!(engine.add_panel(p1).is_ok());
    assert!(engine.add_panel(p2).is_ok());
    assert!(engine.add_panel(p3).is_ok());

    // Duplicate panel ID should fail
    let dup = AntennaPanelConfig::new(1, 2, 0.0, 0.0);
    assert_eq!(engine.add_panel(dup), Err(StxpError::DuplicatePanelId(1)));

    // Capacity exceeded should fail
    let p4 = AntennaPanelConfig::new(4, 2, 0.0, 0.0);
    assert!(matches!(
        engine.add_panel(p4),
        Err(StxpError::PanelCapacityExceeded { max: 4, attempted: 5 })
    ));

    // Verify initial active state
    assert_eq!(engine.panel_state(0).unwrap(), PanelState::Active);
    assert_eq!(engine.panel_state(1).unwrap(), PanelState::Active);

    // State transitions
    assert!(engine.set_panel_state(2, PanelState::Standby).is_ok());
    assert_eq!(engine.panel_state(2).unwrap(), PanelState::Standby);
    assert!(!engine.panel_state(2).unwrap().is_available_for_tx());

    assert!(engine.set_panel_state(3, PanelState::ThermalShutdown).is_ok());
    assert_eq!(engine.panel_state(3).unwrap(), PanelState::ThermalShutdown);
    assert!(!engine.panel_state(3).unwrap().is_available_for_tx());

    // Non-existent panel
    assert_eq!(engine.panel_state(99), Err(StxpError::PanelNotFound(99)));
}

#[test]
fn test_independent_per_panel_power_control() {
    let mut engine = NrMultiPanelStxpEngine::new(23.0);
    let mut p0 = AntennaPanelConfig::new(0, 2, 0.0, 0.0);
    p0.p_o_pusch_dbm = -80.0;
    p0.alpha = 1.0;
    p0.p_cmax_p_dbm = 20.0;

    let mut p1 = AntennaPanelConfig::new(1, 2, 180.0, 0.0);
    p1.p_o_pusch_dbm = -70.0;
    p1.alpha = 0.8;
    p1.p_cmax_p_dbm = 18.0;

    engine.add_panel(p0).unwrap();
    engine.add_panel(p1).unwrap();

    // Request on Panel 0: PL = 90 dB, PRBs = 10, TPC = +1 dB
    let req0 = PanelTransmissionRequest {
        panel_id: 0,
        channel_type: UlChannelType::PuschData,
        pathloss_db: 90.0,
        allocated_prbs: 10,
        tpc_command_db: 1.0,
        delta_tf_db: 0.0,
    };
    // Expected P0: -80 + 10*log10(10) [= 10] + 1.0*90 + 0 + 1 = 21 dBm -> capped at P_CMAX,0 = 20 dBm
    let pwr0 = engine.calculate_panel_target_power(&req0).unwrap();
    assert!((pwr0 - 20.0).abs() < 1e-3);

    // Request on Panel 1: PL = 80 dB, PRBs = 1, TPC = -2 dB
    let req1 = PanelTransmissionRequest {
        panel_id: 1,
        channel_type: UlChannelType::PucchHarqAck,
        pathloss_db: 80.0,
        allocated_prbs: 1,
        tpc_command_db: -2.0,
        delta_tf_db: 0.0,
    };
    // Expected P1: -70 + 0 + 0.8*80 [= 64] + 0 - 2 = -8 dBm
    let pwr1 = engine.calculate_panel_target_power(&req1).unwrap();
    assert!((pwr1 - (-8.0)).abs() < 1e-3);
}

#[test]
fn test_cross_panel_total_power_scaling_and_priority_preservation() {
    // Total power cap 20 dBm = 100 mW
    let mut engine = NrMultiPanelStxpEngine::new(20.0);

    let mut p0 = AntennaPanelConfig::new(0, 2, 0.0, 0.0);
    p0.p_o_pusch_dbm = -60.0;
    p0.alpha = 1.0;
    p0.p_cmax_p_dbm = 20.0;

    let mut p1 = AntennaPanelConfig::new(1, 2, 180.0, 0.0);
    p1.p_o_pusch_dbm = -60.0;
    p1.alpha = 1.0;
    p1.p_cmax_p_dbm = 20.0;

    engine.add_panel(p0).unwrap();
    engine.add_panel(p1).unwrap();

    // Panel 0: High power PuschData (priority rank 4): requests 80 mW (~19 dBm)
    // Panel 1: Critical PucchHarqAck (priority rank 1): requests 60 mW (~17.8 dBm)
    // Sum requested = 140 mW > 100 mW P_CMAX,total!
    let req0 = PanelTransmissionRequest {
        panel_id: 0,
        channel_type: UlChannelType::PuschData,
        pathloss_db: 79.0, // target ~19 dBm (~80 mW)
        allocated_prbs: 1,
        tpc_command_db: 0.0,
        delta_tf_db: 0.0,
    };
    let req1 = PanelTransmissionRequest {
        panel_id: 1,
        channel_type: UlChannelType::PucchHarqAck,
        pathloss_db: 77.8, // target ~17.8 dBm (~60 mW)
        allocated_prbs: 1,
        tpc_command_db: 0.0,
        delta_tf_db: 0.0,
    };

    let result = engine.evaluate_stxp_slot(&[req0, req1], 100).unwrap();
    assert!(result.power_scaled);
    assert_eq!(result.tx_case, Some(StxpTransmissionCase::SimultaneousPuschPucch));

    // Total transmitted power should be bounded by 100 mW (20 dBm)
    assert!(result.total_transmitted_power_mw <= result.p_cmax_total_mw + 1e-4);

    let d_pucch = result.decisions.iter().find(|d| d.panel_id == 1).unwrap();
    let d_pusch = result.decisions.iter().find(|d| d.panel_id == 0).unwrap();

    // Priority 1 (PUCCH HARQ-ACK) should receive 100% of its requested power (scaling_factor = 1.0)
    assert!((d_pucch.scaling_factor - 1.0).abs() < 1e-4);
    assert!(d_pucch.allocated);

    // Priority 4 (PUSCH Data) should be scaled down to absorb remaining power budget
    assert!(d_pusch.scaling_factor < 1.0);
    assert!(d_pusch.scaling_factor > 0.0);
    assert!(d_pusch.allocated);
    assert!(d_pusch.scaled_power_dbm < d_pusch.requested_power_dbm);
}

#[test]
fn test_mpe_p_mpr_and_sar_protection() {
    let mut engine = NrMultiPanelStxpEngine::new(23.0);
    let mut p0 = AntennaPanelConfig::new(0, 2, 0.0, 0.0);
    p0.p_cmax_p_dbm = 20.0;
    p0.p_o_pusch_dbm = -60.0;
    p0.alpha = 1.0;

    engine.add_panel(p0).unwrap();

    // Baseline: no body proximity (10 cm away)
    let mpr0 = engine.update_proximity_sensor(0, 10.0, 0.1).unwrap();
    assert_eq!(mpr0, 0.0);
    assert_eq!(engine.panel_state(0).unwrap(), PanelState::Active);

    // Human finger/hand detected at 3.5 cm -> 3 dB P-MPR
    let mpr1 = engine.update_proximity_sensor(0, 3.5, 0.5).unwrap();
    assert_eq!(mpr1, 3.0);
    assert_eq!(engine.panel_state(0).unwrap(), PanelState::MpeThrottled);

    // Evaluate power with 3 dB P-MPR: power cap reduced from 20 dBm to 17 dBm
    let req = PanelTransmissionRequest {
        panel_id: 0,
        channel_type: UlChannelType::PuschData,
        pathloss_db: 85.0, // Requests 25 dBm, will cap at 17 dBm
        allocated_prbs: 1,
        tpc_command_db: 0.0,
        delta_tf_db: 0.0,
    };
    let target = engine.calculate_panel_target_power(&req).unwrap();
    assert!((target - 17.0).abs() < 1e-3);

    // Severe proximity at 1.0 cm -> 6 dB P-MPR
    let mpr2 = engine.update_proximity_sensor(0, 1.0, 1.8).unwrap();
    assert_eq!(mpr2, 6.0);
    let target2 = engine.calculate_panel_target_power(&req).unwrap();
    assert!((target2 - 14.0).abs() < 1e-3); // 20 - 6 = 14 dBm

    // Body moved away to 15.0 cm -> MPE cleared
    let mpr3 = engine.update_proximity_sensor(0, 15.0, 0.0).unwrap();
    assert_eq!(mpr3, 0.0);
    assert_eq!(engine.panel_state(0).unwrap(), PanelState::Active);
    let target3 = engine.calculate_panel_target_power(&req).unwrap();
    assert!((target3 - 20.0).abs() < 1e-3);
}

#[test]
fn test_inter_panel_isolation_enforcement() {
    let mut engine = NrMultiPanelStxpEngine::new(23.0);
    engine.add_panel(AntennaPanelConfig::new(0, 2, 0.0, 0.0)).unwrap();
    engine.add_panel(AntennaPanelConfig::new(1, 2, 180.0, 0.0)).unwrap();

    // Degrading isolation below 15 dB (e.g. damaged chassis / conductive casing)
    engine.set_inter_panel_isolation_db(10.0);

    let req0 = PanelTransmissionRequest {
        panel_id: 0,
        channel_type: UlChannelType::PuschData,
        pathloss_db: 70.0,
        allocated_prbs: 1,
        tpc_command_db: 0.0,
        delta_tf_db: 0.0,
    };
    let req1 = PanelTransmissionRequest {
        panel_id: 1,
        channel_type: UlChannelType::PuschData,
        pathloss_db: 70.0,
        allocated_prbs: 1,
        tpc_command_db: 0.0,
        delta_tf_db: 0.0,
    };

    // Attempting simultaneous transmission across panels with poor isolation should error
    let res = engine.evaluate_stxp_slot(&[req0.clone(), req1], 1);
    assert_eq!(
        res,
        Err(StxpError::IsolationTooLow {
            isolation_db: 10.0,
            required_db: 15.0
        })
    );

    // Single panel transmission on Panel 0 should still succeed despite isolation
    let res_single = engine.evaluate_stxp_slot(&[req0], 2);
    assert!(res_single.is_ok());
}

#[test]
fn test_mp_phr_binary_wire_codec_and_crc16() {
    let mut engine = NrMultiPanelStxpEngine::new(23.0);
    engine.add_panel(AntennaPanelConfig::new(0, 2, 0.0, 0.0)).unwrap();
    engine.add_panel(AntennaPanelConfig::new(1, 2, 180.0, 0.0)).unwrap();
    engine.update_proximity_sensor(1, 1.5, 1.2).unwrap(); // Trigger MPE on Panel 1

    let report = engine.generate_mp_phr_report(1001, 1726000000).unwrap();
    assert_eq!(report.ue_id, 1001);
    assert_eq!(report.timestamp_ms, 1726000000);
    assert_eq!(report.panels.len(), 2);
    assert!(!report.panels[0].mpe_applied);
    assert!(report.panels[1].mpe_applied);

    // Wire serialization
    let wire = report.encode_wire();
    assert!(wire.len() >= 20);

    // Wire deserialization
    let decoded = MpPhrReport::decode_wire(&wire).expect("decoding failed");
    assert_eq!(decoded.ue_id, report.ue_id);
    assert_eq!(decoded.timestamp_ms, report.timestamp_ms);
    assert_eq!(decoded.active_panels_bitmap, report.active_panels_bitmap);
    assert_eq!(decoded.panels.len(), report.panels.len());
    assert_eq!(decoded.panels[0].panel_id, 0);
    assert_eq!(decoded.panels[1].panel_id, 1);
    assert_eq!(decoded.panels[1].mpe_applied, true);

    // Corrupted payload CRC check
    let mut corrupted = wire.clone();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 0xFF;
    assert!(matches!(
        MpPhrReport::decode_wire(&corrupted),
        Err(StxpError::ChecksumMismatch { .. })
    ));
}

#[test]
fn test_stxp_telemetry_and_throughput_boost() {
    let mut engine = NrMultiPanelStxpEngine::new(23.0);
    engine.add_panel(AntennaPanelConfig::new(0, 2, 0.0, 0.0)).unwrap();
    engine.add_panel(AntennaPanelConfig::new(1, 2, 180.0, 0.0)).unwrap();

    let req0 = PanelTransmissionRequest {
        panel_id: 0,
        channel_type: UlChannelType::PuschData,
        pathloss_db: 60.0,
        allocated_prbs: 5,
        tpc_command_db: 0.0,
        delta_tf_db: 0.0,
    };
    let req1 = PanelTransmissionRequest {
        panel_id: 1,
        channel_type: UlChannelType::PuschData,
        pathloss_db: 60.0,
        allocated_prbs: 5,
        tpc_command_db: 0.0,
        delta_tf_db: 0.0,
    };

    // Slot 1: Single panel
    engine.evaluate_stxp_slot(&[req0.clone()], 1).unwrap();

    // Slot 2: Multi panel
    engine.evaluate_stxp_slot(&[req0.clone(), req1.clone()], 2).unwrap();

    // Slot 3: Multi panel
    engine.evaluate_stxp_slot(&[req0, req1], 3).unwrap();

    let tel = engine.telemetry();
    assert_eq!(tel.total_slots_scheduled, 3);
    assert_eq!(tel.single_panel_slots, 1);
    assert_eq!(tel.multi_panel_slots, 2);
    assert!((tel.stxp_utilization_percent() - 66.666).abs() < 0.1);
    assert!(tel.average_throughput_boost_ratio() > 1.5);
}

#[test]
fn test_error_display() {
    let e1 = StxpError::PanelNotFound(3);
    assert!(format!("{}", e1).contains("Panel ID 3 not found"));

    let e2 = StxpError::PanelCapacityExceeded { max: 4, attempted: 5 };
    assert!(format!("{}", e2).contains("capacity exceeded"));

    let e3 = StxpError::IsolationTooLow { isolation_db: 12.0, required_db: 15.0 };
    assert!(format!("{}", e3).contains("isolation 12.0 dB"));

    let e4 = StxpError::ChecksumMismatch { expected: 0x1234, calculated: 0x5678 };
    assert!(format!("{}", e4).contains("0x1234"));
}
