use toy_tcpip::ptp_phy_asymmetry::{PortPhyCalibration, PtpFourTimestamps, PtpPhyAsymmetryEngine};

#[test]
fn test_ptp_phy_asymmetry_subnanosecond_compensation() {
    let engine = PtpPhyAsymmetryEngine::new();

    let master_phy = PortPhyCalibration::new("GM-Port1", 15.25, 11.75, 0.50); // Tx=15.25, Rx=11.75, Cable=0.5 -> 3.5 + 0.5 = 4.0 ns
    let slave_phy = PortPhyCalibration::new("BC-Port1", 14.00, 14.00, 0.00);

    let ts = PtpFourTimestamps {
        t1_sync_tx_ns: 5000.0,
        t2_sync_rx_ns: 5120.0, // t2 - t1 = 120 ns
        t3_delay_req_tx_ns: 10000.0,
        t4_delay_resp_rx_ns: 10080.0, // t4 - t3 = 80 ns
    };

    let result = engine.calculate_calibrated_sync(&master_phy, &slave_phy, ts);

    assert_eq!(result.raw_mean_path_delay_ns, 100.0);
    assert_eq!(result.raw_offset_from_master_ns, 20.0);

    // Total asymmetry = 4.0 ns
    assert_eq!(result.calibrated_mean_path_delay_ns, 98.0);
    assert_eq!(result.calibrated_offset_from_master_ns, 20.0);
    assert_eq!(result.scaled_correction_field, (4.0 * 65536.0) as i64);
}
