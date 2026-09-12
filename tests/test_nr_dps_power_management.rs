//! Comprehensive integration tests for 3GPP Rel-18/19 Dynamic Power Sharing (DPS)
//! and Dual-Connectivity Uplink Power Management Engine.

use toy_tcpip::nr_dps_power_management::{
    CellGroupType, DpsArbiter, DpsMode, MIN_POWER_DBM, PaArchitecture, PhrEntry, PhrType,
    PowerControlLoop, SarGovernor, TpcAccumulationMode, TransmissionRequest, UeCarrierConfig,
    UePowerClass, UplinkChannelType, dbm_to_mw, mw_to_dbm,
};

#[test]
fn test_ue_power_class_and_pcmax_calculation() {
    // 1. Verify standard UE power classes
    assert!((UePowerClass::Class1.nominal_max_power_dbm() - 31.0).abs() < 1e-4);
    assert!((UePowerClass::Class1.nominal_max_power_mw() - 1258.925).abs() < 0.1);

    assert!((UePowerClass::Class2.nominal_max_power_dbm() - 26.0).abs() < 1e-4);
    assert!((UePowerClass::Class2.nominal_max_power_mw() - 398.107).abs() < 0.1);

    assert!((UePowerClass::Class3.nominal_max_power_dbm() - 23.0).abs() < 1e-4);
    assert!((UePowerClass::Class3.nominal_max_power_mw() - 199.526).abs() < 0.1);

    assert!((UePowerClass::Class4.nominal_max_power_dbm() - 20.0).abs() < 1e-4);
    assert!((UePowerClass::Class4.nominal_max_power_mw() - 100.0).abs() < 0.1);
    assert!((mw_to_dbm(100.0) - 20.0).abs() < 1e-4);
    assert!((mw_to_dbm(dbm_to_mw(23.0)) - 23.0).abs() < 1e-4);

    // 2. Verify carrier PCMAX calculation under MPR/A-MPR bounds
    let carrier_cfg = UeCarrierConfig {
        carrier_id: 0,
        cell_group: CellGroupType::Mcg,
        carrier_frequency_hz: 3.5e9, // 3.5 GHz (Band n78)
        p_emax_dbm: 24.0,            // Network signaled limit
        mpr_db: 1.5,                 // 16-QAM MPR
        a_mpr_db: 0.5,               // Network signaling A-MPR
        p_mpr_db: 1.0,               // Proximity SAR backoff
        delta_tc_db: 0.0,
    };

    // For Class 3 (23 dBm nominal):
    // Total MPR = max(1.5 + 0.5, 1.0) = 2.0 dB
    // P_CMAX_L = min(24.0, 23.0 - 2.0) = 21.0 dBm
    // P_CMAX_H = min(24.0, 23.0) = 23.0 dBm
    // Configured PCMAX = min(21.0, 23.0) = 21.0 dBm
    let pcmax = carrier_cfg.compute_pcmax(UePowerClass::Class3);
    assert!(
        (pcmax - 21.0).abs() < 1e-4,
        "Expected PCMAX = 21.0 dBm, got {pcmax}"
    );
}

#[test]
fn test_semi_static_power_partitioning() {
    let carrier_mcg = UeCarrierConfig {
        carrier_id: 0,
        cell_group: CellGroupType::Mcg,
        carrier_frequency_hz: 1.8e9,
        p_emax_dbm: 23.0,
        mpr_db: 0.0,
        a_mpr_db: 0.0,
        p_mpr_db: 0.0,
        delta_tc_db: 0.0,
    };

    let carrier_scg = UeCarrierConfig {
        carrier_id: 1,
        cell_group: CellGroupType::Scg,
        carrier_frequency_hz: 3.5e9,
        p_emax_dbm: 23.0,
        mpr_db: 0.0,
        a_mpr_db: 0.0,
        p_mpr_db: 0.0,
        delta_tc_db: 0.0,
    };

    // Semi-static partition: 60% MCG (approx 119.7 mW / ~20.78 dBm), 40% SCG (approx 79.8 mW / ~19.02 dBm)
    let dps_mode = DpsMode::SemiStatic { mcg_ratio: 0.60 };
    let mut arbiter = DpsArbiter::new(
        UePowerClass::Class3,
        PaArchitecture::SinglePa,
        dps_mode,
        vec![carrier_mcg, carrier_scg],
        100.0,
    );

    // Both MCG and SCG request full 23 dBm (199.5 mW each)
    let reqs = vec![
        TransmissionRequest {
            carrier_id: 0,
            channel_type: UplinkChannelType::PuschDataOnly { mcs: 16 },
            requested_power_dbm: 23.0,
            symbol_start: 0,
            symbol_count: 14,
            prb_count: 50,
            timestamp_us: 10_000,
        },
        TransmissionRequest {
            carrier_id: 1,
            channel_type: UplinkChannelType::PuschDataOnly { mcs: 16 },
            requested_power_dbm: 23.0,
            symbol_start: 0,
            symbol_count: 14,
            prb_count: 50,
            timestamp_us: 10_000,
        },
    ];

    let result = arbiter
        .arbitrate(&reqs, 10_000, 500)
        .expect("Arbitration failed");
    assert!(result.power_curtailment_applied);
    assert_eq!(result.channels.len(), 2);

    let mcg_alloc = result.channels.iter().find(|c| c.carrier_id == 0).unwrap();
    let scg_alloc = result.channels.iter().find(|c| c.carrier_id == 1).unwrap();

    // Verify MCG received ~60% of total ~199.5 mW (~119.7 mW)
    let mcg_mw = dbm_to_mw(mcg_alloc.allocated_power_dbm);
    assert!((mcg_mw - 119.71).abs() < 1.0, "MCG alloc was {mcg_mw} mW");
    assert!((mcg_alloc.scaling_factor - 0.60).abs() < 0.05);

    // Verify SCG received ~40% of total ~199.5 mW (~79.8 mW)
    let scg_mw = dbm_to_mw(scg_alloc.allocated_power_dbm);
    assert!((scg_mw - 79.81).abs() < 1.0, "SCG alloc was {scg_mw} mW");
    assert!((scg_alloc.scaling_factor - 0.40).abs() < 0.05);
}

#[test]
fn test_dynamic_priority_arbitration_scaling() {
    let carriers = vec![
        UeCarrierConfig {
            carrier_id: 0,
            cell_group: CellGroupType::Mcg,
            carrier_frequency_hz: 2.1e9,
            p_emax_dbm: 23.0,
            mpr_db: 0.0,
            a_mpr_db: 0.0,
            p_mpr_db: 0.0,
            delta_tc_db: 0.0,
        },
        UeCarrierConfig {
            carrier_id: 1,
            cell_group: CellGroupType::Mcg,
            carrier_frequency_hz: 3.5e9,
            p_emax_dbm: 23.0,
            mpr_db: 0.0,
            a_mpr_db: 0.0,
            p_mpr_db: 0.0,
            delta_tc_db: 0.0,
        },
        UeCarrierConfig {
            carrier_id: 2,
            cell_group: CellGroupType::Scg,
            carrier_frequency_hz: 4.8e9,
            p_emax_dbm: 23.0,
            mpr_db: 0.0,
            a_mpr_db: 0.0,
            p_mpr_db: 0.0,
            delta_tc_db: 0.0,
        },
    ];

    let mut arbiter = DpsArbiter::new(
        UePowerClass::Class3, // 23 dBm = 199.526 mW
        PaArchitecture::SinglePa,
        DpsMode::DynamicPriority,
        carriers,
        100.0,
    );

    // Simultaneous requests:
    // 1. Carrier 0: PUCCH HARQ-ACK (Tier 2) requesting 20 dBm (100.0 mW)
    // 2. Carrier 1: PUSCH Data Only (Tier 5) requesting 23 dBm (199.526 mW)
    // 3. Carrier 2: SRS (Tier 6) requesting 17 dBm (50.118 mW)
    // Total requested power = 100.0 + 199.526 + 50.118 = ~349.64 mW > 199.526 mW ceiling
    let reqs = vec![
        TransmissionRequest {
            carrier_id: 0,
            channel_type: UplinkChannelType::PucchHarqAckSr {
                has_sr: true,
                has_bfr_sr: false,
            },
            requested_power_dbm: 20.0,
            symbol_start: 0,
            symbol_count: 14,
            prb_count: 1,
            timestamp_us: 5_000,
        },
        TransmissionRequest {
            carrier_id: 1,
            channel_type: UplinkChannelType::PuschDataOnly { mcs: 12 },
            requested_power_dbm: 23.0,
            symbol_start: 0,
            symbol_count: 14,
            prb_count: 50,
            timestamp_us: 5_000,
        },
        TransmissionRequest {
            carrier_id: 2,
            channel_type: UplinkChannelType::Srs {
                is_aperiodic: false,
            },
            requested_power_dbm: 17.0,
            symbol_start: 12,
            symbol_count: 2,
            prb_count: 48,
            timestamp_us: 5_000,
        },
    ];

    let result = arbiter
        .arbitrate(&reqs, 5_000, 500)
        .expect("Arbitration failed");
    assert!(result.power_curtailment_applied);

    let pucch_res = result.channels.iter().find(|c| c.carrier_id == 0).unwrap();
    let pusch_res = result.channels.iter().find(|c| c.carrier_id == 1).unwrap();
    let srs_res = result.channels.iter().find(|c| c.carrier_id == 2).unwrap();

    // Priority 2 (PUCCH) must get 100% allocation
    assert!(!pucch_res.is_dropped);
    assert!((pucch_res.scaling_factor - 1.0).abs() < 1e-4);
    assert!((pucch_res.allocated_power_dbm - 20.0).abs() < 1e-3);

    // Remaining power for Priority 5 (PUSCH): 199.526 - 100.0 = 99.526 mW (~19.98 dBm)
    // Beta = 99.526 / 199.526 = ~0.4988
    assert!(!pusch_res.is_dropped);
    let pusch_alloc_mw = dbm_to_mw(pusch_res.allocated_power_dbm);
    assert!(
        (pusch_alloc_mw - 99.526).abs() < 0.5,
        "PUSCH alloc was {pusch_alloc_mw} mW"
    );
    assert!((pusch_res.scaling_factor - 0.4988).abs() < 0.01);

    // Priority 6 (SRS) gets 0 power and is dropped
    assert!(srs_res.is_dropped);
    assert_eq!(srs_res.scaling_factor, 0.0);
    assert_eq!(srs_res.allocated_power_dbm, MIN_POWER_DBM);

    // Total allocated must strictly equal total ceiling (within numerical rounding)
    assert!((result.total_allocated_power_mw - result.power_ceiling_mw).abs() < 0.1);
}

#[test]
fn test_lookahead_enhanced_dps() {
    let carriers = vec![UeCarrierConfig {
        carrier_id: 0,
        cell_group: CellGroupType::Mcg,
        carrier_frequency_hz: 3.5e9,
        p_emax_dbm: 23.0,
        mpr_db: 0.0,
        a_mpr_db: 0.0,
        p_mpr_db: 0.0,
        delta_tc_db: 0.0,
    }];

    // Configure Rel-18 Lookahead with 0.50 smoothing factor
    let dps_mode = DpsMode::LookaheadEnhanced {
        lookahead_us: 500,
        smoothing_factor: 0.50,
    };

    let mut arbiter = DpsArbiter::new(
        UePowerClass::Class3,
        PaArchitecture::SinglePa,
        dps_mode,
        carriers,
        100.0,
    );

    // First epoch: high transmission (23 dBm = 199.5 mW)
    let req1 = vec![TransmissionRequest {
        carrier_id: 0,
        channel_type: UplinkChannelType::PuschDataOnly { mcs: 20 },
        requested_power_dbm: 23.0,
        symbol_start: 0,
        symbol_count: 14,
        prb_count: 100,
        timestamp_us: 1_000,
    }];
    let res1 = arbiter.arbitrate(&req1, 1_000, 500).unwrap();
    assert!((res1.total_allocated_power_mw - 199.526).abs() < 0.5);

    // Second epoch: small request (10 dBm = 10 mW)
    let req2 = vec![TransmissionRequest {
        carrier_id: 0,
        channel_type: UplinkChannelType::PuschDataOnly { mcs: 4 },
        requested_power_dbm: 10.0,
        symbol_start: 0,
        symbol_count: 14,
        prb_count: 10,
        timestamp_us: 1_500,
    }];
    let res2 = arbiter.arbitrate(&req2, 1_500, 500).unwrap();
    // In lookahead mode, small request within ceiling passes without curtailment
    assert!(!res2.power_curtailment_applied);
    assert!((res2.total_allocated_power_mw - 10.0).abs() < 0.1);
}

#[test]
fn test_sar_time_windowed_energy_budget_governor() {
    // 10-second sliding window with max 100 mW continuous power
    // Energy budget = 100 mW * 1e-3 W * 10s = 1.0 Joule
    let mut sar_gov = SarGovernor::new(10.0, 100.0);
    assert_eq!(sar_gov.max_energy_budget_joules, 1.0);
    assert_eq!(sar_gov.exposure_ratio(), 0.0);

    // Emit 200 mW for 2.5 seconds (2,500,000 us) at t = 0
    // Energy = 0.2 W * 2.5s = 0.5 Joules (50% of budget)
    sar_gov.record_emission(200.0, 2_500_000, 2_500_000);
    assert!((sar_gov.exposure_ratio() - 0.50).abs() < 1e-3);

    // Emit another 200 mW for 2.0 seconds at t = 3s
    // Energy = 0.2 W * 2.0s = 0.4 Joules (Total = 0.9 Joules, 90% of budget)
    sar_gov.record_emission(200.0, 2_000_000, 4_500_000);
    assert!((sar_gov.exposure_ratio() - 0.90).abs() < 1e-3);

    // At t = 5s, test allowed power for a 1.0s (1,000,000 us) slot:
    // Remaining budget = 1.0 - 0.9 = 0.1 Joules.
    // Allowed power for 1.0s = 0.1 J / 1.0s = 0.1 W = 100.0 mW
    let allowed_mw = sar_gov.get_allowed_power_mw(1_000_000, 5_000_000);
    assert!((allowed_mw - 100.0).abs() < 1.0);

    // Advance time past the 10-second window (e.g. t = 13.0s)
    // First emission (t = 2.5s) drops off the 10s window (13.0 - 10.0 = 3.0s > 2.5s)
    // Energy drops from 0.9 J by 0.5 J to 0.4 J (40% exposure)
    let _ = sar_gov.get_allowed_power_mw(1_000_000, 13_000_000);
    assert!((sar_gov.exposure_ratio() - 0.40).abs() < 1e-3);
}

#[test]
fn test_open_and_closed_loop_tpc_servo() {
    let mut loop_ctrl = PowerControlLoop::new(-90.0, 0.0, 0.8);
    assert_eq!(loop_ctrl.p_o_nominal_dbm, -90.0);
    assert_eq!(loop_ctrl.alpha, 0.8);

    // Update path loss: DL RS TxPower = 30 dBm, RSRP = -70 dBm -> PL = 100 dB
    loop_ctrl.update_path_loss(30.0, -70.0);
    assert_eq!(loop_ctrl.path_loss_db, 100.0);

    // PUSCH calculation:
    // 1 PRB: 10*log10(1) = 0 dB
    // Target = -90 + 0 + (0.8 * 100) + 0 + 0 = -10.0 dBm
    let power_1prb = loop_ctrl.compute_target_pusch_power(1, 23.0);
    assert!((power_1prb - (-10.0)).abs() < 1e-4);

    // 100 PRBs: 10*log10(100) = 20 dB
    // Target = -90 + 20 + 80 = +10.0 dBm
    let power_100prb = loop_ctrl.compute_target_pusch_power(100, 23.0);
    assert!((power_100prb - 10.0).abs() < 1e-4);

    // Apply TPC command: +3 dB accumulation
    loop_ctrl.apply_tpc_command(3.0, TpcAccumulationMode::Accumulation);
    assert_eq!(loop_ctrl.tpc_accumulator_db, 3.0);
    let power_with_tpc = loop_ctrl.compute_target_pusch_power(100, 23.0);
    assert!((power_with_tpc - 13.0).abs() < 1e-4);

    // Verify PCMAX clamping: if PCMAX = 12.0 dBm, result is clamped at 12.0 dBm
    let power_clamped = loop_ctrl.compute_target_pusch_power(100, 12.0);
    assert_eq!(power_clamped, 12.0);

    // Absolute TPC mode override
    loop_ctrl.apply_tpc_command(-4.0, TpcAccumulationMode::Absolute);
    assert_eq!(loop_ctrl.tpc_accumulator_db, -4.0);
}

#[test]
fn test_multiple_phr_mac_ce_serialization() {
    let entries = vec![
        // Primary cell (Carrier 0): Real transmission (V=0), PH = 10.5 dB, PCMAX = 23.0 dBm, no P-MPR
        PhrEntry {
            carrier_id: 0,
            phr_type: PhrType::Type1,
            ph_db: 10.5,
            pcmax_dbm: Some(23.0),
            is_virtual: false,
            p_mpr_applied: false,
        },
        // Secondary cell 1 (Carrier 2): Virtual transmission (V=1), PH = 22.0 dB, no PCMAX octet
        PhrEntry {
            carrier_id: 2,
            phr_type: PhrType::Type1,
            ph_db: 22.0,
            pcmax_dbm: None,
            is_virtual: true,
            p_mpr_applied: false,
        },
        // Secondary cell 2 (Carrier 3): Real transmission (V=0), PH = -4.0 dB, PCMAX = 21.0 dBm, P-MPR applied
        PhrEntry {
            carrier_id: 3,
            phr_type: PhrType::Type1,
            ph_db: -4.0,
            pcmax_dbm: Some(21.0),
            is_virtual: false,
            p_mpr_applied: true,
        },
    ];

    // Binary serialization
    let serialized = DpsArbiter::serialize_multiple_phr_mac_ce(&entries);
    assert!(!serialized.is_empty());

    // Check bitmap byte (Carrier 2 = bit 2, Carrier 3 = bit 3 -> 0x04 | 0x08 = 0x0C)
    assert_eq!(serialized[0], 0x0C);

    // Binary deserialization
    let parsed = DpsArbiter::parse_multiple_phr_mac_ce(&serialized).expect("Parsing failed");
    assert_eq!(parsed.len(), 3);

    // Validate Carrier 0
    assert_eq!(parsed[0].carrier_id, 0);
    assert!(!parsed[0].is_virtual);
    assert!(!parsed[0].p_mpr_applied);
    assert!((parsed[0].ph_db - 10.5).abs() < 1.0);
    assert_eq!(parsed[0].pcmax_dbm, Some(23.0));

    // Validate Carrier 2
    assert_eq!(parsed[1].carrier_id, 2);
    assert!(parsed[1].is_virtual);
    assert!(!parsed[1].p_mpr_applied);
    assert!((parsed[1].ph_db - 22.0).abs() < 1.0);
    assert_eq!(parsed[1].pcmax_dbm, None);

    // Validate Carrier 3
    assert_eq!(parsed[2].carrier_id, 3);
    assert!(!parsed[2].is_virtual);
    assert!(parsed[2].p_mpr_applied);
    assert!((parsed[2].ph_db - (-4.0)).abs() < 1.0);
    assert_eq!(parsed[2].pcmax_dbm, Some(21.0));
}
