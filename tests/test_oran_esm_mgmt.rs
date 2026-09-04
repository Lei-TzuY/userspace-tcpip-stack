//! Integration tests for O-RAN WG4 Open Fronthaul Energy Savings Management (ESM) Engine.

use toy_tcpip::oran_esm_mgmt::*;

#[test]
fn test_esm_modes_and_power_consumption_model() {
    let hw = OranRuHardwareProfile {
        digital_baseline_watts: 80.0,
        trx_baseline_watts: 1.5,
        total_installed_trx: 64,
        pa_efficiency: 0.50, // 50% PAE
        micro_sleep_quiescent_reduction: 0.50,
        deep_sleep_baseline_watts: 18.0,
        cooling_base_watts: 12.0,
    };

    let mut esm = OranEnergySavingsManager::new(hw);

    // Primary Carrier (C0: 64T64R, 5.0W RF per branch, 100% load)
    esm.add_carrier(CarrierOperationalStatus {
        carrier_id: 0,
        is_primary: true,
        is_active: true,
        active_trx_count: 64,
        max_trx_count: 64,
        prb_utilization_percent: 100.0,
        rf_power_per_branch_watts: 5.0,
    });

    // Secondary SCell Carrier (C1: 64T64R, 5.0W RF per branch, 100% load)
    esm.add_carrier(CarrierOperationalStatus {
        carrier_id: 1,
        is_primary: false,
        is_active: true,
        active_trx_count: 64,
        max_trx_count: 64,
        prb_utilization_percent: 100.0,
        rf_power_per_branch_watts: 5.0,
    });

    // 1. Baseline power:
    // Base: 80 (digital) + 12 (cooling) = 92W
    // TRX: 64 * 1.5 * 2 carriers = 192W
    // PA RF: 64 * 5.0 * 2 = 640W RF / 0.50 = 1280W PA
    // Total = 92 + 192 + 1280 = 1564W
    let baseline_power = esm.calculate_baseline_power_watts();
    assert!((baseline_power - 1564.0).abs() < 1e-3);

    // Initial instantaneous power with 0% idle ratio equals baseline
    let p_active = esm.calculate_instantaneous_power_watts(0.0);
    assert!((p_active - 1564.0).abs() < 1e-3);

    // 2. Tx Array Sleep: reduce both carriers to 32T32R
    esm.rpc_activate_energy_saving(EnergySavingMode::TxArraySleep, None, Some(32))
        .unwrap();
    assert_eq!(esm.state, EnergySavingState::Sleep);
    assert!(esm.active_modes.contains(&EnergySavingMode::TxArraySleep));

    // TRX: 32 * 1.5 * 2 = 96W
    // PA RF: 32 * 5.0 * 2 = 320W RF / 0.50 = 640W PA
    // Total = 92 + 96 + 640 = 828W
    let p_tx_sleep = esm.calculate_instantaneous_power_watts(0.0);
    assert!((p_tx_sleep - 828.0).abs() < 1e-3);

    // 3. Carrier Sleep: shut down secondary carrier C1 completely
    esm.rpc_activate_energy_saving(EnergySavingMode::CarrierSleep, Some(1), None)
        .unwrap();
    assert!(esm.active_modes.contains(&EnergySavingMode::CarrierSleep));

    // Only C0 active (32 TRX):
    // TRX: 32 * 1.5 = 48W
    // PA RF: 32 * 5.0 = 160W RF / 0.50 = 320W PA
    // Total = 92 + 48 + 320 = 460W
    let p_carrier_sleep = esm.calculate_instantaneous_power_watts(0.0);
    assert!((p_carrier_sleep - 460.0).abs() < 1e-3);

    // 4. Deep Sleep: hibernation
    esm.rpc_activate_energy_saving(EnergySavingMode::DeepSleep, None, None)
        .unwrap();
    assert_eq!(esm.state, EnergySavingState::DeepSleep);
    let p_deep_sleep = esm.calculate_instantaneous_power_watts(0.0);
    assert_eq!(p_deep_sleep, 18.0); // Only 18W!
}

#[test]
fn test_esm_rpc_lifecycle_and_transition_latencies() {
    let mut esm = OranEnergySavingsManager::new(OranRuHardwareProfile::default());

    esm.add_carrier(CarrierOperationalStatus {
        carrier_id: 0,
        is_primary: true,
        is_active: true,
        active_trx_count: 64,
        max_trx_count: 64,
        prb_utilization_percent: 50.0,
        rf_power_per_branch_watts: 4.0,
    });
    esm.add_carrier(CarrierOperationalStatus {
        carrier_id: 1,
        is_primary: false,
        is_active: true,
        active_trx_count: 64,
        max_trx_count: 64,
        prb_utilization_percent: 30.0,
        rf_power_per_branch_watts: 4.0,
    });

    // 1. Attempt to sleep primary carrier -> must error!
    let err_primary = esm.rpc_activate_energy_saving(EnergySavingMode::CarrierSleep, Some(0), None);
    assert!(err_primary.is_err());
    assert!(
        err_primary
            .unwrap_err()
            .contains("Cannot sleep primary coverage carrier")
    );

    // 2. Attempt invalid TRX count (e.g. 128 > 64) -> must error!
    let err_trx = esm.rpc_activate_energy_saving(EnergySavingMode::TxArraySleep, None, Some(128));
    assert!(err_trx.is_err());

    // 3. Deactivate Carrier Sleep successfully
    esm.rpc_activate_energy_saving(EnergySavingMode::CarrierSleep, Some(1), None)
        .unwrap();
    assert!(!esm.carriers.get(&1).unwrap().is_active);

    esm.rpc_deactivate_energy_saving(Some(EnergySavingMode::CarrierSleep))
        .unwrap();
    assert!(esm.carriers.get(&1).unwrap().is_active);
    assert_eq!(esm.state, EnergySavingState::Active);

    // 4. Test wakeup latency budget check
    esm.last_wakeup_latency_ms = 150;
    esm.max_acceptable_wakeup_latency_ms = 100;
    let err_latency = esm.rpc_deactivate_energy_saving(None);
    assert!(err_latency.is_err());
    assert!(err_latency.unwrap_err().contains("exceeded limit"));
}

#[test]
fn test_micro_sleep_slot_symbol_gating() {
    let mut esm = OranEnergySavingsManager::new(OranRuHardwareProfile::default());

    esm.add_carrier(CarrierOperationalStatus {
        carrier_id: 0,
        is_primary: true,
        is_active: true,
        active_trx_count: 64,
        max_trx_count: 64,
        prb_utilization_percent: 100.0,
        rf_power_per_branch_watts: 5.0,
    });

    // Activate Micro-Sleep
    esm.rpc_activate_energy_saving(EnergySavingMode::MicroSleep, None, None)
        .unwrap();

    // 1. Slot with 100% active DL (14 active symbols) -> 0% idle
    let full_dl_mask = [true; 14];
    let idle_ratio_0 = esm.micro_sleep.evaluate_slot_idle_ratio(&full_dl_mask);
    assert_eq!(idle_ratio_0, 0.0);
    let pwr_full = esm.calculate_instantaneous_power_watts(idle_ratio_0);

    // 2. Slot with 50% active DL (7 active symbols, 7 idle symbols) -> 50% idle
    let half_dl_mask = [
        true, true, true, true, true, true, true, false, false, false, false, false, false, false,
    ];
    let idle_ratio_half = esm.micro_sleep.evaluate_slot_idle_ratio(&half_dl_mask);
    assert_eq!(idle_ratio_half, 0.50);
    let pwr_half = esm.calculate_instantaneous_power_watts(idle_ratio_half);

    // Micro-sleep should reduce power during idle symbols
    assert!(pwr_half < pwr_full);

    // 3. Slot with 100% idle symbols (no DL scheduled) -> 100% idle
    let idle_mask = [false; 14];
    let idle_ratio_full = esm.micro_sleep.evaluate_slot_idle_ratio(&idle_mask);
    assert_eq!(idle_ratio_full, 1.0);
    let pwr_idle = esm.calculate_instantaneous_power_watts(idle_ratio_full);

    assert!(pwr_idle < pwr_half);
}

#[test]
fn test_carrier_sleep_schedule_and_traffic_watchdog() {
    let mut esm = OranEnergySavingsManager::new(OranRuHardwareProfile::default());

    esm.add_carrier(CarrierOperationalStatus {
        carrier_id: 0,
        is_primary: true,
        is_active: true,
        active_trx_count: 64,
        max_trx_count: 64,
        prb_utilization_percent: 30.0,
        rf_power_per_branch_watts: 4.0,
    });
    esm.add_carrier(CarrierOperationalStatus {
        carrier_id: 1,
        is_primary: false,
        is_active: true,
        active_trx_count: 64,
        max_trx_count: 64,
        prb_utilization_percent: 20.0,
        rf_power_per_branch_watts: 4.0,
    });

    // Schedule: Carrier Sleep between 02:00 (second 7200) and 06:00 (second 21600)
    let schedule = CarrierSleepSchedule {
        schedule_id: 1,
        start_second_of_day: 7200,
        duration_seconds: 14400,
        target_carrier_ids: vec![1],
        emergency_wake_prb_threshold: 75.0, // if C0 load > 75%, wake up!
    };
    esm.add_schedule(schedule);

    // Second 7199 (01:59:59): Before window
    esm.tick_seconds(1, 7199, 0.0);
    assert!(esm.carriers.get(&1).unwrap().is_active);

    // Second 7200 (02:00:00): Window starts -> Carrier 1 enters Carrier Sleep
    esm.tick_seconds(1, 7200, 0.0);
    assert!(!esm.carriers.get(&1).unwrap().is_active);
    assert_eq!(esm.state, EnergySavingState::Sleep);

    // Sudden traffic surge on primary carrier (PRB load rises to 85% > 75%)
    esm.carriers.get_mut(&0).unwrap().prb_utilization_percent = 85.0;

    // Next tick: Emergency guardrail triggers immediate wakeup of Carrier 1!
    esm.tick_seconds(1, 7210, 0.0);
    assert!(esm.carriers.get(&1).unwrap().is_active);
    assert_eq!(esm.state, EnergySavingState::Active);
}

#[test]
fn test_esm_xml_json_serialization_and_notifications() {
    let mut esm = OranEnergySavingsManager::new(OranRuHardwareProfile::default());

    esm.add_carrier(CarrierOperationalStatus {
        carrier_id: 0,
        is_primary: true,
        is_active: true,
        active_trx_count: 64,
        max_trx_count: 64,
        prb_utilization_percent: 100.0,
        rf_power_per_branch_watts: 5.0,
    });
    esm.add_carrier(CarrierOperationalStatus {
        carrier_id: 1,
        is_primary: false,
        is_active: true,
        active_trx_count: 64,
        max_trx_count: 64,
        prb_utilization_percent: 100.0,
        rf_power_per_branch_watts: 5.0,
    });

    // Run for 3600 seconds (1 hour) in Active state
    esm.tick_seconds(3600, 3600, 0.0);

    // Engage Carrier Sleep on Carrier 1
    esm.rpc_activate_energy_saving(EnergySavingMode::CarrierSleep, Some(1), None)
        .unwrap();

    // Run for another 3600 seconds in Sleep state
    esm.tick_seconds(3600, 7200, 0.0);

    let report = esm.generate_report();
    assert!(report.cumulative_energy_saved_kwh > 0.0);
    assert!(report.power_savings_percent > 20.0);
    assert!(report.cumulative_cost_saved_usd > 0.0);
    assert!(report.estimated_co2_saved_kg > 0.0);

    // Test XML serialization
    let xml = esm.serialize_status_xml();
    assert!(xml.contains("<energy-saving-status"));
    assert!(xml.contains("<state>SLEEP</state>"));
    assert!(xml.contains("<active-mode>CARRIER_SLEEP</active-mode>"));
    assert!(xml.contains("<power-savings-percent>"));

    // Test JSON serialization
    let json = esm.serialize_status_json();
    assert!(json.contains("\"o-ran-energy-saving:energy-saving-status\""));
    assert!(json.contains("\"state\":\"SLEEP\""));
    assert!(json.contains("\"CARRIER_SLEEP\""));
    assert!(json.contains("\"cumulative-energy-saved-kwh\""));
}
