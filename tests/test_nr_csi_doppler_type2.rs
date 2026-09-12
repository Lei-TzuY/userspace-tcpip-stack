//! Integration tests for 3GPP Rel-18 5G-Advanced Enhanced Type II CSI Codebook with Doppler / Delay Compression.

use toy_tcpip::nr_csi_doppler_type2::{
    AntennaArrayLayout, Complex64, DopplerType2Config, DopplerType2Engine, DopplerType2Error,
    MAX_CSI_PORTS,
};

#[test]
fn test_complex_number_operations() {
    let a = Complex64::new(1.0, 2.0);
    let b = Complex64::new(3.0, -4.0);

    let sum = a.add(b);
    assert_eq!(sum, Complex64::new(4.0, -2.0));

    let diff = a.sub(b);
    assert_eq!(diff, Complex64::new(-2.0, 6.0));

    let prod = a.mul(b);
    // (1 + 2j)(3 - 4j) = 3 - 4j + 6j + 8 = 11 + 2j
    assert_eq!(prod, Complex64::new(11.0, 2.0));

    let scaled = a.scale(2.5);
    assert_eq!(scaled, Complex64::new(2.5, 5.0));

    // Polar construction
    let polar = Complex64::from_polar(2.0, std::f64::consts::PI / 2.0);
    assert!(polar.re.abs() < 1e-10);
    assert!((polar.im - 2.0).abs() < 1e-10);
}

#[test]
fn test_antenna_layout_and_config_initialization() {
    let layout = AntennaArrayLayout::new(4, 2, 4, 4);
    assert_eq!(layout.total_ports(), 16);
    assert!(layout.total_ports() <= MAX_CSI_PORTS);

    let cfg = DopplerType2Config {
        layout,
        num_subbands: 8,
        num_time_slots: 8,
        num_spatial_beams: 2,
        num_delay_basis: 4,
        num_doppler_basis: 2,
        max_non_zero_coeffs: 16,
    };

    let engine = DopplerType2Engine::new(cfg).expect("Engine initializes cleanly");
    assert_eq!(engine.spatial_bases.len(), 2);
    assert_eq!(engine.delay_bases.len(), 4);
    assert_eq!(engine.doppler_bases.len(), 2);
}

#[test]
fn test_spatial_delay_doppler_basis_orthogonality() {
    let cfg = DopplerType2Config::new_default();
    let engine = DopplerType2Engine::new(cfg).unwrap();

    // 1. Verify delay basis orthogonality: <f_i, f_j> = delta_{i, j}
    for i in 0..engine.delay_bases.len() {
        for j in 0..engine.delay_bases.len() {
            let mut dot = Complex64::ZERO;
            for (a, b) in engine.delay_bases[i]
                .iter()
                .zip(engine.delay_bases[j].iter())
            {
                dot = dot.add(a.conj().mul(*b));
            }
            if i == j {
                assert!((dot.norm() - 1.0).abs() < 1e-5);
            } else {
                assert!(dot.norm() < 1e-5);
            }
        }
    }

    // 2. Verify Doppler basis orthogonality: <d_i, d_j> = delta_{i, j}
    for i in 0..engine.doppler_bases.len() {
        for j in 0..engine.doppler_bases.len() {
            let mut dot = Complex64::ZERO;
            for (a, b) in engine.doppler_bases[i]
                .iter()
                .zip(engine.doppler_bases[j].iter())
            {
                dot = dot.add(a.conj().mul(*b));
            }
            if i == j {
                assert!((dot.norm() - 1.0).abs() < 1e-5);
            } else {
                assert!(dot.norm() < 1e-5);
            }
        }
    }
}

#[test]
fn test_channel_compression_and_reconstruction() {
    let cfg = DopplerType2Config {
        layout: AntennaArrayLayout::new(2, 2, 4, 4), // 8 ports
        num_subbands: 4,
        num_time_slots: 4,
        num_spatial_beams: 2,
        num_delay_basis: 2,
        num_doppler_basis: 2,
        max_non_zero_coeffs: 8,
    };
    let engine = DopplerType2Engine::new(cfg.clone()).unwrap();

    let nt = cfg.num_time_slots;
    let n3 = cfg.num_subbands;
    let ports = cfg.layout.total_ports();

    // Generate a synthetic single-path Doppler-delay channel:
    // H(t, f, port) = e^{j 2pi * 1 * t / nt} * e^{-j 2pi * 1 * f / n3} * spatial_beam[0]
    let mut channel = vec![vec![vec![Complex64::ZERO; ports]; n3]; nt];
    for t in 0..nt {
        let doppler_term =
            Complex64::from_polar(1.0, 2.0 * std::f64::consts::PI * (t as f64) / (nt as f64));
        for f in 0..n3 {
            let delay_term =
                Complex64::from_polar(1.0, -2.0 * std::f64::consts::PI * (f as f64) / (n3 as f64));
            for p in 0..ports {
                let half_p = p % 4;
                let spatial_term = engine.spatial_bases[0][half_p];
                channel[t][f][p] = doppler_term.mul(delay_term).mul(spatial_term);
            }
        }
    }

    // Compress channel
    let report = engine
        .compress_channel(&channel)
        .expect("Compression succeeds");
    assert!(!report.coefficients.is_empty());
    assert!(report.max_amplitude > 0.0);

    // Reconstruct channel at slot t=0, subband f=0
    let h_hat = engine.reconstruct_channel_vector(&report, 0, 0);
    let h_true = &channel[0][0];

    let gcs = DopplerType2Engine::evaluate_gcs(h_true, &h_hat);
    let nmse_db = DopplerType2Engine::evaluate_nmse_db(h_true, &h_hat);

    // Reconstructed channel must have high similarity (GCS > 0.90)
    assert!(gcs > 0.90, "Expected GCS > 0.90, got {:.4}", gcs);
    assert!(
        nmse_db < -5.0,
        "Expected NMSE < -5 dB, got {:.2} dB",
        nmse_db
    );
}

#[test]
fn test_future_slot_extrapolation_mitigating_channel_aging() {
    let cfg = DopplerType2Config {
        layout: AntennaArrayLayout::new(2, 2, 4, 4), // 8 ports
        num_subbands: 4,
        num_time_slots: 4,
        num_spatial_beams: 2,
        num_delay_basis: 2,
        num_doppler_basis: 2,
        max_non_zero_coeffs: 8,
    };
    let engine = DopplerType2Engine::new(cfg.clone()).unwrap();

    let nt = cfg.num_time_slots;
    let n3 = cfg.num_subbands;
    let ports = cfg.layout.total_ports();

    // Multipath channel with 2 spatial paths and differential Doppler:
    // Path 1: Beam 0 with static Doppler (k = 0)
    // Path 2: Beam 1 with rotating Doppler (k = 1)
    let mut channel = vec![vec![vec![Complex64::ZERO; ports]; n3]; nt];
    for t in 0..nt {
        let doppler_term =
            Complex64::from_polar(1.0, 2.0 * std::f64::consts::PI * (t as f64) / (nt as f64));
        for f in 0..n3 {
            for p in 0..ports {
                let half_p = p % 4;
                let path1 = engine.spatial_bases[0][half_p];
                let path2 = doppler_term.mul(engine.spatial_bases[1][half_p]);
                channel[t][f][p] = path1.add(path2);
            }
        }
    }

    let report = engine.compress_channel(&channel).unwrap();

    // Now evaluate at FUTURE slot t = 2 where Path 2 has inverted phase (-1)
    let t_future = 2;
    let f_target = 0;

    let doppler_future = Complex64::from_polar(
        1.0,
        2.0 * std::f64::consts::PI * (t_future as f64) / (nt as f64),
    );
    let mut h_true_future = vec![Complex64::ZERO; ports];
    for p in 0..ports {
        let half_p = p % 4;
        let path1 = engine.spatial_bases[0][half_p];
        let path2 = doppler_future.mul(engine.spatial_bases[1][half_p]);
        h_true_future[p] = path1.add(path2);
    }

    // 1. Rel-18 Doppler-extrapolated prediction
    let h_predicted = engine.reconstruct_channel_vector(&report, t_future, f_target);
    let gcs_predicted = DopplerType2Engine::evaluate_gcs(&h_true_future, &h_predicted);

    // 2. Legacy static prediction (uncompensated: uses slot 0 CSI without Doppler rotation)
    let h_legacy_static = engine.reconstruct_channel_vector(&report, 0, f_target);
    let gcs_legacy = DopplerType2Engine::evaluate_gcs(&h_true_future, &h_legacy_static);

    // Doppler-predicted CSI should maintain high correlation (>0.90), whereas aged legacy GCS drops (<0.50)
    assert!(
        gcs_predicted > 0.90,
        "Expected predicted GCS > 0.90, got {:.4}",
        gcs_predicted
    );
    assert!(
        gcs_predicted > gcs_legacy + 0.3,
        "Predicted GCS ({:.4}) must substantially outperform aged legacy GCS ({:.4})",
        gcs_predicted,
        gcs_legacy
    );
}

#[test]
fn test_dimension_and_boundary_error_handling() {
    let cfg = DopplerType2Config::new_default();
    let engine = DopplerType2Engine::new(cfg).unwrap();

    // 1. Empty/truncated channel tensor returns DimensionMismatch
    let truncated_channel: Vec<Vec<Vec<Complex64>>> = vec![];
    let err = engine.compress_channel(&truncated_channel);
    assert!(matches!(
        err,
        Err(DopplerType2Error::DimensionMismatch { .. })
    ));

    // 2. All zero channel returns ZeroEnergyChannel
    let zero_channel = vec![vec![vec![Complex64::ZERO; 16]; 8]; 8];
    let err_zero = engine.compress_channel(&zero_channel);
    assert_eq!(err_zero, Err(DopplerType2Error::ZeroEnergyChannel));

    // 3. Error display format
    let display_err = format!("{}", DopplerType2Error::ZeroEnergyChannel);
    assert!(display_err.contains("zero energy"));
}
