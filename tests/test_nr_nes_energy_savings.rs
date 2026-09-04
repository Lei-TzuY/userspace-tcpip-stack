//! Integration tests for 3GPP Rel-18 5G-Advanced Network Energy Savings (NES).

use toy_tcpip::nr_nes_energy_savings::{
    BaseStationPowerModel, CellDtxDrxPattern, NES_DEFAULT_MAX_MIMO_ANTENNAS,
    NES_DEFAULT_MAX_SSB_BEAMS_FR1, NES_SYMBOLS_PER_SLOT, NesError, NesSleepLevel, NrNesEngine,
    SpatialMimoConfig, SsbAdaptationConfig,
};

#[test]
fn test_base_station_power_model_and_sleep_levels() {
    let model = BaseStationPowerModel::default();
    // Default: p_baseband = 180W, p_rf_static_per_antenna = 3.5W, p_tx_max_per_antenna = 0.625W, delta_slope = 3.8

    // 1. Static power with full 64 antennas: 180 + 3.5 * 64 = 404 W
    let p0_64 = model.calculate_static_power(64);
    assert!((p0_64 - 404.0).abs() < 1e-3);

    // Static power with muted 16 antennas: 180 + 3.5 * 16 = 236 W
    let p0_16 = model.calculate_static_power(16);
    assert!((p0_16 - 236.0).abs() < 1e-3);

    // 2. Active load-dependent power:
    // P_active(rho = 1.0, 64T) = 404 + 3.8 * (64 * 0.625) * 1.0 = 404 + 3.8 * 40 = 404 + 152 = 556 W
    let p_active_full = model.calculate_instantaneous_power(NesSleepLevel::Active, 64, 1.0);
    assert!((p_active_full - 556.0).abs() < 1e-3);

    // P_active(rho = 0.5, 64T) = 404 + 152 * 0.5 = 480 W
    let p_active_half = model.calculate_instantaneous_power(NesSleepLevel::Active, 64, 0.5);
    assert!((p_active_half - 480.0).abs() < 1e-3);

    // 3. Sleep power levels:
    // Level 1: Micro-sleep (50% of P0) = 0.50 * 404 = 202 W
    let p_micro = model.calculate_instantaneous_power(NesSleepLevel::Level1MicroSleep, 64, 0.0);
    assert!((p_micro - 202.0).abs() < 1e-3);

    // Level 2: Slot-level sleep (35% of P0) = 0.35 * 404 = 141.4 W
    let p_slot = model.calculate_instantaneous_power(NesSleepLevel::Level2SlotSleep, 64, 0.0);
    assert!((p_slot - 141.4).abs() < 1e-3);

    // Level 3: Light Dormancy (15% of P0) = 0.15 * 404 = 60.6 W
    let p_light = model.calculate_instantaneous_power(NesSleepLevel::Level3LightDormancy, 64, 0.0);
    assert!((p_light - 60.6).abs() < 1e-3);

    // Level 4: Deep Dormancy (5% of P0) = 0.05 * 404 = 20.2 W
    let p_deep = model.calculate_instantaneous_power(NesSleepLevel::Level4DeepDormancy, 64, 0.0);
    assert!((p_deep - 20.2).abs() < 1e-3);

    // 4. Wakeup latencies
    assert_eq!(NesSleepLevel::Active.wakeup_latency_ms(), 0.0);
    assert!(NesSleepLevel::Level1MicroSleep.wakeup_latency_ms() < 0.010);
    assert!(NesSleepLevel::Level2SlotSleep.wakeup_latency_ms() < 0.100);
    assert_eq!(NesSleepLevel::Level3LightDormancy.wakeup_latency_ms(), 2.5);
    assert_eq!(NesSleepLevel::Level4DeepDormancy.wakeup_latency_ms(), 100.0);
}

#[test]
fn test_dynamic_ssb_periodicity_and_spatial_beam_skipping() {
    // 1. Full broadcast: 8 beams active, 20ms periodicity
    let ssb_full = SsbAdaptationConfig::new(20, 8, 0xFF, false).expect("Valid config");
    assert_eq!(ssb_full.active_beam_count(), 8);
    assert!((ssb_full.calculate_ssb_overhead_fraction() - 1.0).abs() < 1e-6);

    // 2. Periodicity adaptation: scale to 80ms (4x reduction)
    let ssb_80ms = SsbAdaptationConfig::new(80, 8, 0xFF, false).expect("Valid config");
    assert_eq!(ssb_80ms.active_beam_count(), 8);
    assert!((ssb_80ms.calculate_ssb_overhead_fraction() - 0.25).abs() < 1e-6);

    // 3. Spatial beam skipping: only beams 0 and 1 active (mask = 0b0000_0011) at 20ms
    let ssb_skip = SsbAdaptationConfig::new(20, 8, 0x03, false).expect("Valid config");
    assert_eq!(ssb_skip.active_beam_count(), 2);
    // Overhead: (2 / 8) * (20 / 20) = 0.25
    assert!((ssb_skip.calculate_ssb_overhead_fraction() - 0.25).abs() < 1e-6);

    // 4. Combined beam skipping (2 beams) + 160ms periodicity
    let ssb_combined = SsbAdaptationConfig::new(160, 8, 0x03, false).expect("Valid config");
    // Overhead: (2 / 8) * (20 / 160) = 0.25 * 0.125 = 0.03125
    assert!((ssb_combined.calculate_ssb_overhead_fraction() - 0.03125).abs() < 1e-6);

    // 5. SSB-less SCell: 0% overhead
    let ssb_less = SsbAdaptationConfig::new(20, 8, 0xFF, true).expect("Valid config");
    assert_eq!(ssb_less.active_beam_count(), 0);
    assert_eq!(ssb_less.calculate_ssb_overhead_fraction(), 0.0);

    // 6. Invalid periodicity rejection
    let err_p = SsbAdaptationConfig::new(30, 8, 0xFF, false).unwrap_err();
    assert_eq!(err_p, NesError::InvalidSsbPeriodicity(30));
}

#[test]
fn test_spatial_mimo_antenna_branch_muting() {
    let mut mimo = SpatialMimoConfig::new(64, 64, 70, 25).expect("Valid config");
    assert_eq!(mimo.active_antennas, 64);

    // 1. Moderate load (50%) -> no change
    let (cnt1, changed1) = mimo.adapt_antenna_count(0.50);
    assert_eq!(cnt1, 64);
    assert!(!changed1);

    // 2. Low traffic load (15% <= 25%) -> Scale down to 32
    let (cnt2, changed2) = mimo.adapt_antenna_count(0.15);
    assert_eq!(cnt2, 32);
    assert!(changed2);

    // 3. Continuing low load (10% <= 25%) -> Scale down to 16
    let (cnt3, changed3) = mimo.adapt_antenna_count(0.10);
    assert_eq!(cnt3, 16);
    assert!(changed3);

    // Scale down further to 8 and 4
    let (cnt4, _) = mimo.adapt_antenna_count(0.05);
    assert_eq!(cnt4, 8);
    let (cnt5, _) = mimo.adapt_antenna_count(0.05);
    assert_eq!(cnt5, 4);

    // Clamping at lower bound 4 antennas
    let (cnt6, changed6) = mimo.adapt_antenna_count(0.01);
    assert_eq!(cnt6, 4);
    assert!(!changed6);

    // 4. Traffic surge (85% >= 70%) -> Scale up to 8 -> 16 -> 32 -> 64
    let (cnt7, changed7) = mimo.adapt_antenna_count(0.85);
    assert_eq!(cnt7, 8);
    assert!(changed7);

    mimo.adapt_antenna_count(0.90);
    assert_eq!(mimo.active_antennas, 16);
    mimo.adapt_antenna_count(0.90);
    assert_eq!(mimo.active_antennas, 32);
    mimo.adapt_antenna_count(0.90);
    assert_eq!(mimo.active_antennas, 64);

    // Clamping at upper bound 64 antennas
    let (cnt_max, changed_max) = mimo.adapt_antenna_count(0.95);
    assert_eq!(cnt_max, 64);
    assert!(!changed_max);
}

#[test]
fn test_cell_dtx_burst_scheduling_and_micro_sleep() {
    let mut engine = NrNesEngine::new(0.001); // 1 ms slot duration (15 kHz SCS)
    engine.dtx_pattern = CellDtxDrxPattern {
        on_duration_slots: 2,
        cycle_periodicity_slots: 10, // 2 ON, 8 SLEEP
        inactive_sleep_level: NesSleepLevel::Level2SlotSleep,
    };

    // Slot 0 (ON window): has data in 4 symbols (mask = 0b0000_0000_0000_1111)
    let (level0, energy0) = engine.tick_slot(0, 50, 100, 0x000F, 50_000);
    assert_eq!(level0, NesSleepLevel::Active);
    assert!(energy0 > 0.0);
    // Unallocated symbols in slot 0: 14 - 4 = 10 micro-sleep symbols
    assert_eq!(engine.metrics.micro_sleep_symbols_count, 10);
    assert_eq!(engine.metrics.slot_sleep_slots_count, 0);

    // Slot 1 (ON window): has data in all 14 symbols (mask = 0x3FFF)
    let (level1, energy1) = engine.tick_slot(1, 100, 100, 0x3FFF, 100_000);
    assert_eq!(level1, NesSleepLevel::Active);
    assert!(energy1 > energy0); // Higher load and no micro-sleep
    assert_eq!(engine.metrics.micro_sleep_symbols_count, 10); // Unchanged

    // Slot 2 (SLEEP window): should engage Level2SlotSleep
    let (level2, energy2) = engine.tick_slot(2, 0, 100, 0, 0);
    assert_eq!(level2, NesSleepLevel::Level2SlotSleep);
    assert!(energy2 < energy0); // Significantly lower power consumption in sleep
    assert_eq!(engine.metrics.slot_sleep_slots_count, 1);

    // Slots 3..9 (remaining 7 SLEEP slots)
    for s in 3..10 {
        let (lvl, _) = engine.tick_slot(s, 0, 100, 0, 0);
        assert_eq!(lvl, NesSleepLevel::Level2SlotSleep);
    }
    assert_eq!(engine.metrics.slot_sleep_slots_count, 8);
}

#[test]
fn test_energy_efficiency_kpi_and_saving_ratio() {
    let mut engine = NrNesEngine::new(0.001); // 1 ms slot
    engine.dtx_pattern = CellDtxDrxPattern {
        on_duration_slots: 2,
        cycle_periodicity_slots: 10,
        inactive_sleep_level: NesSleepLevel::Level2SlotSleep,
    };

    // Simulate 100 slots (10 complete DTX cycles)
    for slot in 0..100 {
        let is_on = engine.dtx_pattern.is_active_slot(slot);
        if is_on {
            // Active transmission with 50% load
            engine.tick_slot(slot, 50, 100, 0x00FF, 80_000);
        } else {
            // Inactive sleep
            engine.tick_slot(slot, 0, 100, 0, 0);
        }
    }

    assert!(engine.metrics.energy_consumed_joules > 0.0);
    assert!(engine.metrics.baseline_energy_joules > engine.metrics.energy_consumed_joules);
    assert_eq!(engine.metrics.data_bits_delivered, 20 * 80_000); // 20 active slots * 80,000 bits

    // Energy Saving Ratio should show substantial reduction (> 40%)
    let esr = engine.metrics.energy_saving_ratio();
    assert!(
        esr >= 0.40,
        "Expected energy saving ratio >= 40%, got {:.2}%",
        esr * 100.0
    );

    // Energy Efficiency KPI in bits/Joule
    let ee = engine.metrics.energy_efficiency_bits_per_joule();
    assert!(ee > 0.0);
    let expected_ee =
        (engine.metrics.data_bits_delivered as f64) / engine.metrics.energy_consumed_joules;
    assert!((ee - expected_ee).abs() < 1e-6);
}

#[test]
fn test_latency_budget_and_hysteresis_guards() {
    let mut engine = NrNesEngine::new(0.001);
    engine.min_dwell_slots = 10;
    engine.current_dwell_slots = 10; // Initially ready

    // 1. Transition to Light Dormancy (wake-up 2.5 ms) when max allowed latency is 5 ms -> Succeeds
    let state1 = engine
        .request_state_transition(NesSleepLevel::Level3LightDormancy, 5)
        .expect("Transition should succeed");
    assert_eq!(state1, NesSleepLevel::Level3LightDormancy);
    assert_eq!(engine.current_dwell_slots, 0);
    assert_eq!(engine.metrics.light_dormancy_periods_count, 1);

    // 2. Anti-flapping: Immediate transition attempt fails because dwell (0 < 10)
    let err_flapping = engine
        .request_state_transition(NesSleepLevel::Active, 10)
        .unwrap_err();
    match err_flapping {
        NesError::DwellTimeNotElapsed {
            current_dwell_slots,
            required_dwell_slots,
        } => {
            assert_eq!(current_dwell_slots, 0);
            assert_eq!(required_dwell_slots, 10);
        }
        _ => panic!("Expected DwellTimeNotElapsed"),
    }

    // Advance 10 slots to satisfy dwell time
    for s in 0..10 {
        engine.tick_slot(s, 0, 100, 0, 0);
    }
    assert!(engine.current_dwell_slots >= 10);

    // 3. Strict latency constraint: High priority URLLC traffic with max allowed latency 20 ms
    // Attempting to enter Deep Dormancy (wake-up 100 ms) -> Violates budget!
    let err_budget = engine
        .request_state_transition(NesSleepLevel::Level4DeepDormancy, 20)
        .unwrap_err();
    match err_budget {
        NesError::LatencyBudgetViolation {
            requested_sleep_ms,
            max_allowed_latency_ms,
        } => {
            assert_eq!(requested_sleep_ms, 100);
            assert_eq!(max_allowed_latency_ms, 20);
        }
        _ => panic!("Expected LatencyBudgetViolation"),
    }

    // 4. Relaxed latency constraint: IoT background traffic with max allowed latency 200 ms
    let state_deep = engine
        .request_state_transition(NesSleepLevel::Level4DeepDormancy, 200)
        .expect("Deep dormancy transition should succeed");
    assert_eq!(state_deep, NesSleepLevel::Level4DeepDormancy);
    assert_eq!(engine.metrics.deep_dormancy_periods_count, 1);
}

#[test]
fn test_error_formatting_and_display() {
    let err_ant = NesError::InvalidAntennaCount(12);
    assert!(format!("{}", err_ant).contains("must be one of [4, 8, 16, 32, 64]"));

    let err_load = NesError::InvalidLoadFactor("negative value".to_string());
    assert!(format!("{}", err_load).contains("negative value"));

    let err_cfg = NesError::InvalidConfiguration("invalid parameter".to_string());
    assert!(format!("{}", err_cfg).contains("NES configuration error"));

    // Verify constants
    assert_eq!(NES_SYMBOLS_PER_SLOT, 14);
    assert_eq!(NES_DEFAULT_MAX_MIMO_ANTENNAS, 64);
    assert_eq!(NES_DEFAULT_MAX_SSB_BEAMS_FR1, 8);
}
