//! Integration tests for O-RAN WG4 Open Fronthaul Massive MIMO Beamforming Engine.

use std::f64::consts::PI;
use toy_tcpip::oran_beamforming::{
    AntennaArrayConfig, AntennaPolarization, ArrayTopology, ComplexNumber, MuMimoPrecoder,
    OranBeamformingEngine, SpatialAngle, compute_steering_vector,
};
use toy_tcpip::oran_cplane_ext::{BfwCompressionMethod, SectionExtension1, SectionExtension2};

#[test]
fn test_steering_vector_generation_and_spatial_phase() {
    let array_cfg = AntennaArrayConfig {
        topology: ArrayTopology::UniformLinearArray {
            num_elements: 8,
            element_spacing_wavelength: 0.5,
        },
        polarization: AntennaPolarization::SinglePol,
        carrier_frequency_hz: 3.5e9,
        max_tx_power_dbm: 40.0,
    };

    assert_eq!(array_cfg.total_transceivers(), 8);

    // 1. Broadside (azimuth = 0°, elevation = 0°): All elements in phase
    let broadside = SpatialAngle::new(0.0, 0.0);
    let v_broadside = compute_steering_vector(&array_cfg, &broadside);
    assert_eq!(v_broadside.len(), 8);
    for w in &v_broadside {
        assert!((w.re - 1.0).abs() < 1e-6);
        assert!(w.im.abs() < 1e-6);
    }

    // 2. Off-boresight at 30°: delta_psi = 2 * pi * d * sin(30°) = pi * 0.5 = pi / 2
    let angle_30 = SpatialAngle::new(30.0, 0.0);
    let v_30 = compute_steering_vector(&array_cfg, &angle_30);
    assert_eq!(v_30.len(), 8);

    for (m, w) in v_30.iter().enumerate() {
        let expected_phase = (m as f64) * (PI / 2.0);
        let expected_re = expected_phase.cos();
        let expected_im = expected_phase.sin();
        assert!(
            (w.re - expected_re).abs() < 1e-5,
            "Element {} re mismatch: got {}, expected {}",
            m,
            w.re,
            expected_re
        );
        assert!(
            (w.im - expected_im).abs() < 1e-5,
            "Element {} im mismatch: got {}, expected {}",
            m,
            w.im,
            expected_im
        );
    }
}

#[test]
fn test_grid_of_beams_codebook_generation_and_nearest_search() {
    let array_cfg = AntennaArrayConfig::default_64t64r(3.5e9);
    assert_eq!(array_cfg.total_transceivers(), 64);

    let engine = OranBeamformingEngine::new(array_cfg);
    // 8 azimuth x 4 elevation = 32 beams
    assert_eq!(engine.codebook.beams.len(), 32);

    for beam in &engine.codebook.beams {
        assert_eq!(beam.weights.len(), 64);
        let pwr = beam.total_power();
        assert!(
            (pwr - 1.0).abs() < 1e-5,
            "Beam {} power was {}, expected 1.0",
            beam.beam_id,
            pwr
        );
    }

    // Find nearest beam for target angle (15.0°, 0.0°)
    let target = SpatialAngle::new(15.0, 0.0);
    let nearest = engine.codebook.find_nearest_beam(&target);
    assert!(nearest.is_some());
    let beam = nearest.unwrap();
    assert_eq!(beam.weights.len(), 64);
}

#[test]
fn test_multi_user_mimo_zero_forcing_precoding() {
    // 32-transceiver Massive MIMO array serving 4 distinct UEs
    let array_cfg = AntennaArrayConfig::default_32t32r(3.5e9);
    assert_eq!(array_cfg.total_transceivers(), 32);

    let ue_angles = vec![
        SpatialAngle::new(-45.0, 0.0),
        SpatialAngle::new(-15.0, 0.0),
        SpatialAngle::new(15.0, 0.0),
        SpatialAngle::new(45.0, 0.0),
    ];

    let mut h_matrix: Vec<Vec<ComplexNumber>> = Vec::new();
    for angle in &ue_angles {
        let channel_row = compute_steering_vector(&array_cfg, angle);
        h_matrix.push(channel_row);
    }

    // Zero-Forcing precoding (alpha = 0.0)
    let result = MuMimoPrecoder::compute_precoding(&h_matrix, 0.0);
    assert!(result.is_ok(), "Precoding computation failed");
    let res = result.unwrap();

    assert_eq!(res.user_weights.len(), 4);
    assert_eq!(res.user_sir_db.len(), 4);

    // Each user should experience high Signal-to-Interference Ratio (> 25 dB)
    for (u, &sir) in res.user_sir_db.iter().enumerate() {
        assert!(
            sir > 25.0,
            "User {} SIR was {:.2} dB, expected > 25.0 dB",
            u,
            sir
        );
    }

    // Verify off-diagonal interference terms are suppressed
    for i in 0..4 {
        for j in 0..4 {
            let eff = res.effective_channel[i][j].norm();
            if i == j {
                assert!(eff > 0.1, "Desired channel for user {} was too weak", i);
            } else {
                assert!(
                    eff < 1e-4,
                    "Interference from user {} to user {} not nulled: {}",
                    j,
                    i,
                    eff
                );
            }
        }
    }
}

#[test]
fn test_regularized_zf_mmse_stability() {
    let array_cfg = AntennaArrayConfig::default_32t32r(3.5e9);

    // Two closely spaced UEs (correlated channel)
    let ue_angles = vec![
        SpatialAngle::new(10.0, 0.0),
        SpatialAngle::new(10.5, 0.0), // Very close, ill-conditioned Gram matrix
    ];

    let mut h_matrix = Vec::new();
    for angle in &ue_angles {
        h_matrix.push(compute_steering_vector(&array_cfg, angle));
    }

    // Regularized ZF / MMSE with alpha = 0.05
    let res = MuMimoPrecoder::compute_precoding(&h_matrix, 0.05);
    assert!(res.is_ok());
    let precoding = res.unwrap();
    assert_eq!(precoding.user_weights.len(), 2);
    for beam in &precoding.user_weights {
        assert_eq!(beam.weights.len(), 32);
        assert!((beam.total_power() - 1.0).abs() < 1e-5);
    }
}

#[test]
fn test_power_normalization_and_bfp_quantization() {
    let array_cfg = AntennaArrayConfig::default_32t32r(3.5e9);
    let mut engine = OranBeamformingEngine::new(array_cfg);

    let angle = SpatialAngle::new(25.0, -5.0);
    let weights = compute_steering_vector(&engine.array_config, &angle);
    let mut beam = toy_tcpip::oran_beamforming::BeamWeightVector {
        beam_id: 7,
        weights,
    };
    beam.normalize_unit_power();

    // Check PA power balance across antennas
    let papr = engine.evaluate_pa_power_balance(&beam);
    assert!((papr - 1.0).abs() < 0.1, "PAPR was {}, expected ~1.0", papr);

    // Quantize to BFP
    let bundle_bfp = beam.quantize(BfwCompressionMethod::BlockFloatingPoint, 16);
    assert_eq!(bundle_bfp.weights.len(), 32);

    // Quantize to 8-bit uncompressed
    let bundle_8bit = beam.quantize(BfwCompressionMethod::Uncompressed, 8);
    assert_eq!(bundle_8bit.weights.len(), 32);
    for w in &bundle_8bit.weights {
        assert!(w.re >= -128 && w.re <= 127);
        assert!(w.im >= -128 && w.im <= 127);
    }
}

#[test]
fn test_end_to_end_section_ext2_to_ext1_conversion() {
    let array_cfg = AntennaArrayConfig::default_64t64r(3.5e9);
    let mut engine = OranBeamformingEngine::new(array_cfg);

    // Incoming Section Extension 2 (Beam Attributes)
    let ext2 = SectionExtension2::new(101, 32.5, -8.0);

    // Convert to Section Extension 1 (BFW Weights)
    let ext1 = engine.convert_ext2_to_ext1(&ext2, BfwCompressionMethod::Uncompressed, 16);
    assert_eq!(ext1.bfw_iq_width, 16);
    assert_eq!(ext1.bundles.len(), 1);
    assert_eq!(ext1.bundles[0].weights.len(), 64);

    // Serialize to wire bytes
    let wire_bytes = ext1.serialize();
    assert!(!wire_bytes.is_empty());
    assert_eq!(
        wire_bytes[0],
        toy_tcpip::oran_cplane_ext::ORAN_EXT_BEAMFORMING_WEIGHTS
    );

    // Parse back from wire bytes with 64 antennas
    let parsed_ext1 =
        SectionExtension1::parse(&wire_bytes, 64).expect("Failed to parse SectionExtension1");
    assert_eq!(parsed_ext1.bundles.len(), 1);
    assert_eq!(parsed_ext1.bundles[0].weights.len(), 64);

    // Verify telemetry
    assert_eq!(engine.telemetry.total_beams_generated, 1);
    assert_eq!(engine.telemetry.total_ext2_attributes_mapped, 1);
    assert_eq!(engine.telemetry.total_cplane_ext1_packets, 1);
}
