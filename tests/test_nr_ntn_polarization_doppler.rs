//! Integration tests for 3GPP Rel-17 NTN Polarization & Doppler Tracking Engine.

use toy_tcpip::nr_ntn_polarization_doppler::*;

#[test]
fn test_circular_polarization_axial_ratio_and_xpd() {
    // Ideal circular polarization: AR = 1.0 -> XPD = 100 dB
    let ideal = PolarizationTracker::new(PolarizationSense::Rhcp, 1.0).unwrap();
    assert_eq!(ideal.cross_polarization_discrimination_db(), 100.0);

    // Near-ideal: AR = 1.1 -> XPD = 20 * log10(2.1 / 0.1) = 20 * log10(21) ≈ 26.444 dB
    let p_1_1 = PolarizationTracker::new(PolarizationSense::Rhcp, 1.1).unwrap();
    let xpd_1_1 = p_1_1.cross_polarization_discrimination_db();
    assert!((xpd_1_1 - 26.444).abs() < 0.01);

    // AR = 1.5 -> XPD = 20 * log10(2.5 / 0.5) = 20 * log10(5) ≈ 13.979 dB
    let p_1_5 = PolarizationTracker::new(PolarizationSense::Rhcp, 1.5).unwrap();
    let xpd_1_5 = p_1_5.cross_polarization_discrimination_db();
    assert!((xpd_1_5 - 13.979).abs() < 0.01);

    // Degraded: AR = 2.0 -> XPD = 20 * log10(3.0 / 1.0) ≈ 9.542 dB
    let p_2_0 = PolarizationTracker::new(PolarizationSense::Rhcp, 2.0).unwrap();
    let xpd_2_0 = p_2_0.cross_polarization_discrimination_db();
    assert!((xpd_2_0 - 9.542).abs() < 0.01);

    // Invalid AR < 1.0
    let err = PolarizationTracker::new(PolarizationSense::Rhcp, 0.95);
    assert_eq!(err, Err(NtnPolarizationError::InvalidAxialRatio(0.95)));
}

#[test]
fn test_polarization_mismatch_loss() {
    let tx_rhcp = PolarizationTracker::new(PolarizationSense::Rhcp, 1.0).unwrap();
    let rx_rhcp = PolarizationTracker::new(PolarizationSense::Rhcp, 1.0).unwrap();
    let rx_lhcp = PolarizationTracker::new(PolarizationSense::Lhcp, 1.0).unwrap();

    // Co-polarized (RHCP to RHCP): 0 dB loss
    let loss_co = rx_rhcp.polarization_mismatch_loss_db(&tx_rhcp);
    assert!(loss_co.abs() < 1e-4);

    // Cross-polarized (RHCP to LHCP): 100 dB isolation
    let loss_cross = rx_lhcp.polarization_mismatch_loss_db(&tx_rhcp);
    assert_eq!(loss_cross, 100.0);

    // Imperfect antennas: AR = 1.2
    let tx_imp = PolarizationTracker::new(PolarizationSense::Rhcp, 1.2).unwrap();
    let rx_imp = PolarizationTracker::new(PolarizationSense::Rhcp, 1.2).unwrap();
    let loss_imp = rx_imp.polarization_mismatch_loss_db(&tx_imp);
    // Co-polarization loss should be negligible (< 0.1 dB)
    assert!(loss_imp < 0.1);
}

#[test]
fn test_leo_orbital_kinematics_and_doppler_limits() {
    // 600 km LEO, S-band (2.0 GHz)
    let leo_s = SatelliteKinematics::new(600_000.0, 2.0e9).unwrap();

    // Orbital speed: v = sqrt(GM / (R_E + 600km)) ≈ 7561.7 m/s
    assert!((leo_s.orbital_velocity_m_s - 7561.7).abs() < 2.0);

    // Zenith (ground track x = 0): radial velocity = 0, Doppler = 0
    let (v_r_zenith, dop_zenith) = leo_s.doppler_at_ground_distance(0.0);
    assert!(v_r_zenith.abs() < 1e-4);
    assert!(dop_zenith.abs() < 1e-4);

    // Approaching at ground distance x = -1000 km
    let (v_r_app, dop_app) = leo_s.doppler_at_ground_distance(-1_000_000.0);
    assert!(v_r_app < 0.0);
    assert!(dop_app > 0.0); // Blue-shifted (positive Doppler)
    // S-band maximum Doppler is bounded within 50 kHz
    assert!(dop_app < 50_000.0);

    // 600 km LEO, Ka-band (20.0 GHz) -> 10x higher Doppler
    let leo_ka = SatelliteKinematics::new(600_000.0, 20.0e9).unwrap();
    let (_, dop_ka_app) = leo_ka.doppler_at_ground_distance(-1_000_000.0);
    assert!((dop_ka_app - 10.0 * dop_app).abs() < 1e-2);
}

#[test]
fn test_zenith_pass_maximum_doppler_drift_rate() {
    // 600 km LEO, S-band (2.0 GHz)
    let leo_s = SatelliteKinematics::new(600_000.0, 2.0e9).unwrap();

    // Maximum drift rate at closest approach / zenith:
    // f_dot_max = -(f_c / c) * (v_orb^2 / h)
    // ≈ -(2e9 / 2.9979e8) * (7561.7^2 / 600000) ≈ -6.671 * 95.30 ≈ -635.7 Hz/s
    let drift_rate = leo_s.max_doppler_drift_rate_hz_s();
    assert!(drift_rate < 0.0);
    assert!((drift_rate - (-635.7)).abs() < 2.0);

    // Ka-band (20 GHz) drift rate is 10x higher: ~ -6.35 kHz/s
    let leo_ka = SatelliteKinematics::new(600_000.0, 20.0e9).unwrap();
    let drift_ka = leo_ka.max_doppler_drift_rate_hz_s();
    assert!((drift_ka - (-6357.0)).abs() < 20.0);
}

#[test]
fn test_doppler_fll_servo_tracking_and_precompensation() {
    let mut servo = DopplerFllServo::new(0.4, 0.08);

    // Simulate linear chirp: f(t) = 10,000 Hz - 200 Hz/s * t
    let f0 = 10_000.0;
    let chirp_rate = -200.0;

    let dt = 0.01; // 10 ms update rate (typical NTN slot/subframe rate)
    for step in 1..=200 {
        let t = (step as f64) * dt;
        let true_freq = f0 + chirp_rate * t;
        servo.update(true_freq, t);
    }

    // After 2 seconds of tracking (200 steps), servo should converge tightly
    let t_final = 2.0;
    let true_final_freq = f0 + chirp_rate * t_final;
    let freq_error = (servo.estimated_doppler_hz - true_final_freq).abs();
    assert!(
        freq_error < 5.0,
        "Frequency error {} Hz should be < 5 Hz",
        freq_error
    );

    let drift_error = (servo.estimated_drift_rate_hz_s - chirp_rate).abs();
    assert!(
        drift_error < 10.0,
        "Drift error {} Hz/s should be < 10 Hz/s",
        drift_error
    );

    // Autonomous uplink pre-compensation with 20 ms RTT (10 ms one-way delay)
    let rtt = 0.020;
    let precomp = servo.compute_uplink_precompensation(rtt);
    // Target at satellite receiver in 10 ms is true_final_freq + chirp_rate * 0.01
    let target_sat_freq = true_final_freq + chirp_rate * 0.01;
    assert!((precomp - (-target_sat_freq)).abs() < 10.0);
}

#[test]
fn test_subcarrier_orthogonality_residual_margin() {
    let mut metrics = NtnDopplerMetrics {
        subcarrier_spacing_hz: 15_000.0, // 15 kHz SCS (Normal CP)
        residual_doppler_error_hz: 50.0,
        residual_scs_ratio: 50.0 / 15_000.0, // 0.33% <= 1.0%
        ..Default::default()
    };

    // 0.33% is well within 1.0% limit -> OK
    assert!(metrics.check_subcarrier_orthogonality().is_ok());

    // Excessive residual Doppler: 300 Hz (2.0% > 1.0%)
    metrics.residual_doppler_error_hz = 300.0;
    metrics.residual_scs_ratio = 300.0 / 15_000.0; // 2.0%
    let err = metrics.check_subcarrier_orthogonality();
    assert!(matches!(
        err,
        Err(NtnPolarizationError::SubcarrierOrthogonalityLost { .. })
    ));
}

#[test]
fn test_error_formatting_and_display() {
    let err_ar = NtnPolarizationError::InvalidAxialRatio(0.8);
    assert!(err_ar.to_string().contains("Invalid axial ratio"));

    let err_alt = NtnPolarizationError::InvalidAltitude(-100.0);
    assert!(
        err_alt
            .to_string()
            .contains("Invalid satellite orbital altitude")
    );

    let err_fc = NtnPolarizationError::InvalidCarrierFrequency(0.0);
    assert!(err_fc.to_string().contains("Invalid carrier frequency"));

    let err_scs = NtnPolarizationError::InvalidSubcarrierSpacing(-15.0);
    assert!(err_scs.to_string().contains("Invalid subcarrier spacing"));

    let err_orth = NtnPolarizationError::SubcarrierOrthogonalityLost {
        residual_hz: 250.0,
        scs_hz: 15_000.0,
        ratio: 0.0166,
    };
    assert!(
        err_orth
            .to_string()
            .contains("Residual Doppler 250.0 Hz exceeds")
    );
}
