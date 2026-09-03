//! Integration tests for 3GPP TS 38.300 / TS 38.306 / TS 38.331 5G NR RedCap (Reduced Capability).

use toy_tcpip::redcap_5g::*;

// ---------------------------------------------------------------------------
// 1. RedCap Smartwatch Attachment and Initial BWP Allocation Happy Path
// ---------------------------------------------------------------------------

#[test]
fn test_redcap_smartwatch_attachment_and_initial_bwp_allocation_happy_path() {
    let mut redcap = RedCapEngine::new("gnb-shibuya-01");

    // Configure Cell 1: 100 MHz wideband carrier with 20 MHz RedCap Initial BWP
    redcap.configure_cell(1001, 100, true, true, 20, 0).unwrap();

    let smartwatch_cap = RedCapCapability {
        device_type: RedCapDeviceType::Wearable,
        max_bandwidth_mhz: 20,
        num_rx_antennas: 1, // 1 Rx antenna for compact wearable form factor
        duplex_mode: RedCapDuplexMode::HalfDuplexFdd,
        max_dl_modulation: RedCapModulation::Qam64,
        supports_edrx: true,
        supports_rrm_relaxation: true,
    };

    let ue_ctx = redcap
        .handle_random_access(1001, "ue-smartwatch-apple-01", smartwatch_cap)
        .unwrap();

    assert_eq!(ue_ctx.assigned_bwp_mhz, 20); // Confined to 20 MHz
    assert_eq!(ue_ctx.assigned_bwp_start_rb, 0);
    assert!(ue_ctx.is_connected);
    assert_eq!(ue_ctx.cell_id, 1001);
}

// ---------------------------------------------------------------------------
// 2. Cell-Level Access Barring
// ---------------------------------------------------------------------------

#[test]
fn test_redcap_cell_access_barring() {
    let mut redcap = RedCapEngine::new("gnb-shinjuku-02");

    // Cell 2 has redcap_allowed = false (eMBB-only cell)
    redcap
        .configure_cell(2001, 100, false, false, 20, 10)
        .unwrap();

    let sensor_cap = RedCapCapability {
        device_type: RedCapDeviceType::IndustrialSensor,
        max_bandwidth_mhz: 20,
        num_rx_antennas: 2,
        duplex_mode: RedCapDuplexMode::Tdd,
        max_dl_modulation: RedCapModulation::Qam64,
        supports_edrx: true,
        supports_rrm_relaxation: true,
    };

    let err = redcap.handle_random_access(2001, "ue-industrial-sensor-01", sensor_cap);
    assert_eq!(err, Err(RedCapError::RedCapAccessBarred { cell_id: 2001 }));
}

// ---------------------------------------------------------------------------
// 3. Power Saving: eDRX and RRM Measurement Relaxation
// ---------------------------------------------------------------------------

#[test]
fn test_redcap_power_saving_edrx_and_rrm_relaxation() {
    let mut redcap = RedCapEngine::new("gnb-factory-03");

    redcap.configure_cell(3001, 50, true, true, 10, 0).unwrap();

    let sensor_cap = RedCapCapability {
        device_type: RedCapDeviceType::IndustrialSensor,
        max_bandwidth_mhz: 10,
        num_rx_antennas: 1,
        duplex_mode: RedCapDuplexMode::HalfDuplexFdd,
        max_dl_modulation: RedCapModulation::Qam64,
        supports_edrx: true,
        supports_rrm_relaxation: true,
    };

    let ue_id = "ue-vibration-sensor-agv";
    redcap
        .handle_random_access(3001, ue_id, sensor_cap)
        .unwrap();

    // Enable 60-second eDRX cycle and stationary RRM relaxation
    redcap
        .configure_power_saving(ue_id, Some(60), true)
        .expect("Power saving configuration failed");

    let ue = redcap.connected_ues.get(ue_id).unwrap();
    assert_eq!(ue.edrx_cycle_s, Some(60));
    assert!(ue.rrm_relaxed);
}

// ---------------------------------------------------------------------------
// 4. Excessive Bandwidth Requested Rejection
// ---------------------------------------------------------------------------

#[test]
fn test_redcap_excessive_bandwidth_rejection() {
    let mut redcap = RedCapEngine::new("gnb-cctv-04");

    redcap.configure_cell(4001, 100, true, true, 20, 0).unwrap();

    // Device falsely claims RedCap but requests 50 MHz (> 20 MHz FR1 limit)
    let invalid_cap = RedCapCapability {
        device_type: RedCapDeviceType::SurveillanceVideo,
        max_bandwidth_mhz: 50,
        num_rx_antennas: 2,
        duplex_mode: RedCapDuplexMode::FullDuplexFdd,
        max_dl_modulation: RedCapModulation::Qam256,
        supports_edrx: false,
        supports_rrm_relaxation: false,
    };

    let err = redcap.handle_random_access(4001, "ue-cctv-4k", invalid_cap);
    assert_eq!(
        err,
        Err(RedCapError::ExcessiveBandwidthRequested { max_mhz: 50 })
    );
}

// ---------------------------------------------------------------------------
// 5. Error Handling: Invalid Initial BWP, Unknown Cell, and Disconnect
// ---------------------------------------------------------------------------

#[test]
fn test_redcap_disconnect_and_cell_errors() {
    let mut redcap = RedCapEngine::new("gnb-err-05");

    // Invalid Initial BWP (> 20 MHz)
    let err_bwp = redcap.configure_cell(5001, 100, true, true, 40, 0);
    assert_eq!(err_bwp, Err(RedCapError::InvalidInitialBwp { bwp_mhz: 40 }));

    // Valid cell
    redcap.configure_cell(5001, 100, true, true, 20, 0).unwrap();

    let cap = RedCapCapability {
        device_type: RedCapDeviceType::Wearable,
        max_bandwidth_mhz: 20,
        num_rx_antennas: 1,
        duplex_mode: RedCapDuplexMode::HalfDuplexFdd,
        max_dl_modulation: RedCapModulation::Qam64,
        supports_edrx: true,
        supports_rrm_relaxation: false,
    };

    // Unknown cell access
    let err_cell = redcap.handle_random_access(9999, "ue-test", cap.clone());
    assert_eq!(err_cell, Err(RedCapError::CellNotFound { cell_id: 9999 }));

    // Successful connect then disconnect
    redcap.handle_random_access(5001, "ue-temp", cap).unwrap();
    assert!(redcap.connected_ues.contains_key("ue-temp"));

    redcap.disconnect_ue("ue-temp").unwrap();
    assert!(!redcap.connected_ues.contains_key("ue-temp"));

    // Disconnect again returns UeNotFound
    let err_disc = redcap.disconnect_ue("ue-temp");
    assert_eq!(
        err_disc,
        Err(RedCapError::UeNotFound {
            ue_id: "ue-temp".to_string()
        })
    );
}
