//! Integration tests for IEEE 1588-2019 / IEEE 802.1AS High-Accuracy PTP Profile.

use toy_tcpip::ptp_high_accuracy::{
    HighAccuracyPortCalibration, HighAccuracyPtpEngine, HighPrecisionTimestamp,
    PTP_TLV_HIGH_ACCURACY_DELAY_ASYM, PtpDelayAsymmetryTlv,
};

#[test]
fn test_ptp_high_accuracy_tlv_constants_and_roundtrip() {
    assert_eq!(PTP_TLV_HIGH_ACCURACY_DELAY_ASYM, 0x2001);

    let tlv = PtpDelayAsymmetryTlv::from_picoseconds(-5_400); // -5.4 ns asymmetry
    let raw = tlv.serialize();
    assert_eq!(raw.len(), 12);

    let parsed = PtpDelayAsymmetryTlv::parse(&raw).unwrap();
    assert_eq!(parsed.to_picoseconds(), -5_400);
}

#[test]
fn test_ptp_high_accuracy_sub_nanosecond_convergence() {
    let cal = HighAccuracyPortCalibration {
        port_id: 2,
        tx_phy_latency_ps: 1_250, // 1.25 ns
        rx_phy_latency_ps: 1_850, // 1.85 ns
        fiber_asymmetry_ps: 800,  // 0.80 ns
        is_calibrated: true,
    };

    let engine = HighAccuracyPtpEngine::new(cal);

    let t1 = HighPrecisionTimestamp::new(50, 0);
    let t2 = HighPrecisionTimestamp::new(50, 20_000_000_000); // 20 ns apparent delay
    let t3 = HighPrecisionTimestamp::new(50, 100_000_000_000);
    let t4 = HighPrecisionTimestamp::new(50, 120_000_000_000);

    let res = engine.compute_offset_and_delay(t1, t2, t3, t4, 150, 0);
    assert!(res.mean_path_delay_ps > 0);
    assert_eq!(res.total_asymmetry_correction_ps, 800);
}
