//! Integration tests for 3GPP Rel-18/19 5G NR Positioning Integrity & RAIM/FDE Engine.

use toy_tcpip::nr_positioning_integrity::*;

#[test]
fn test_4x4_matrix_inversion() {
    let eye = [
        [1.0, 0.0, 0.0, 0.0],
        [0.0, 1.0, 0.0, 0.0],
        [0.0, 0.0, 1.0, 0.0],
        [0.0, 0.0, 0.0, 1.0],
    ];
    let inv = invert_4x4_matrix(&eye).expect("inversion failed");
    assert_eq!(inv, eye);

    let diag = [
        [2.0, 0.0, 0.0, 0.0],
        [0.0, 4.0, 0.0, 0.0],
        [0.0, 0.0, 5.0, 0.0],
        [0.0, 0.0, 0.0, 10.0],
    ];
    let inv_diag = invert_4x4_matrix(&diag).expect("diag inv failed");
    assert!((inv_diag[0][0] - 0.5).abs() < 1e-6);
    assert!((inv_diag[1][1] - 0.25).abs() < 1e-6);
    assert!((inv_diag[2][2] - 0.20).abs() < 1e-6);
    assert!((inv_diag[3][3] - 0.10).abs() < 1e-6);

    // Singular matrix check
    let singular = [
        [1.0, 2.0, 3.0, 4.0],
        [2.0, 4.0, 6.0, 8.0], // Dependent row
        [0.0, 0.0, 1.0, 0.0],
        [0.0, 0.0, 0.0, 1.0],
    ];
    assert_eq!(
        invert_4x4_matrix(&singular),
        Err(IntegrityError::SingularGeometryMatrix)
    );
}

#[test]
fn test_chi_square_threshold_monotonicity() {
    let t1 = chi_square_threshold_pfa_1e5(1);
    let t2 = chi_square_threshold_pfa_1e5(2);
    let t3 = chi_square_threshold_pfa_1e5(3);
    let t4 = chi_square_threshold_pfa_1e5(4);
    assert!(t1 < t2);
    assert!(t2 < t3);
    assert!(t3 < t4);
}

#[test]
fn test_crc16_and_report_wire_codec() {
    let report = PositioningIntegrityReport {
        ue_id: 12345,
        epoch_ms: 100_000,
        hpl_m: 0.85,
        vpl_m: 1.42,
        hal_m: 1.50,
        val_m: 3.00,
        safety_status: IntegritySafetyStatus::Safe,
        excluded_trps: vec![101, 102],
    };

    let wire = report.encode_wire();
    // Magic 'P', 'I', 'N', 0x12
    assert_eq!(wire[0], 0x50);
    assert_eq!(wire[1], 0x49);
    assert_eq!(wire[2], 0x4E);
    assert_eq!(wire[3], 0x12);

    let decoded = PositioningIntegrityReport::decode_wire(&wire).expect("report decode failed");
    assert_eq!(decoded.ue_id, 12345);
    assert_eq!(decoded.epoch_ms, 100_000);
    assert!((decoded.hpl_m - 0.85).abs() < 1e-4);
    assert!((decoded.vpl_m - 1.42).abs() < 1e-4);
    assert_eq!(decoded.safety_status, IntegritySafetyStatus::Safe);
    assert_eq!(decoded.excluded_trps, vec![101, 102]);

    // Corrupt CRC
    let mut bad_wire = wire.clone();
    let l = bad_wire.len() - 1;
    bad_wire[l] ^= 0xFF;
    assert!(matches!(
        PositioningIntegrityReport::decode_wire(&bad_wire),
        Err(IntegrityError::ChecksumMismatch { .. })
    ));

    // Corrupt Magic
    let mut bad_magic = wire.clone();
    bad_magic[0] = 0x00;
    let new_crc = compute_crc16(&bad_magic[..bad_magic.len() - 2]);
    let len = bad_magic.len();
    bad_magic[len - 2..len].copy_from_slice(&new_crc.to_be_bytes());
    assert!(matches!(
        PositioningIntegrityReport::decode_wire(&bad_magic),
        Err(IntegrityError::DeserializationError(msg)) if msg.contains("magic")
    ));

    // Truncated buffer
    assert!(PositioningIntegrityReport::decode_wire(&[0x50, 0x49, 0x4E]).is_err());
}

#[test]
fn test_positioning_and_protection_level_nominal_case() {
    let mut engine = NrPositioningIntegrityEngine::new(DEFAULT_HAL_METERS, DEFAULT_VAL_METERS);

    // True UE position: (10.0, 20.0, 5.0), clock bias = 15.0 m
    let ue_true: [f64; 4] = [10.0, 20.0, 5.0, 15.0];

    // 6 Anchor TRPs around the area
    let trp_coords = [
        (1, 100.0, 0.0, 20.0),
        (2, -100.0, 0.0, 25.0),
        (3, 0.0, 100.0, 30.0),
        (4, 0.0, -100.0, 15.0),
        (5, 50.0, 50.0, 10.0),
        (6, -50.0, -50.0, 22.0),
    ];

    let mut anchors = Vec::new();
    for &(id, x, y, z) in &trp_coords {
        let dx = ue_true[0] - x;
        let dy = ue_true[1] - y;
        let dz = ue_true[2] - z;
        let true_range = (dx * dx + dy * dy + dz * dz).sqrt();
        let pr = true_range + ue_true[3]; // nominal zero-noise
        anchors.push(TrpRangingMeasurement {
            trp_id: id,
            x_m: x,
            y_m: y,
            z_m: z,
            pseudorange_m: pr,
            sigma_m: 0.3, // 30 cm PRS standard deviation
        });
    }

    let result = engine
        .evaluate_integrity(&anchors, [0.0, 0.0, 0.0, 0.0])
        .expect("integrity evaluation failed");

    assert!(!result.fault_detected);
    assert!(result.excluded_trp_ids.is_empty());
    assert_eq!(result.safety_status, IntegritySafetyStatus::Safe);

    // Position accuracy check
    assert!((result.estimated_position[0] - ue_true[0]).abs() < 0.1);
    assert!((result.estimated_position[1] - ue_true[1]).abs() < 0.1);
    assert!((result.estimated_position[2] - ue_true[2]).abs() < 0.1);

    // Protection levels should be strictly bounded
    assert!(result.hpl_m < result.hal_m);
    assert!(result.vpl_m < result.val_m);
    assert!(result.hpl_m > 0.0);
    assert!(result.vpl_m > 0.0);

    let tel = engine.telemetry();
    assert_eq!(tel.total_epochs_evaluated, 1);
    assert_eq!(tel.safe_epochs, 1);
    assert_eq!(tel.faults_detected, 0);
    assert_eq!(tel.integrity_availability_percent(), 100.0);
}

#[test]
fn test_fault_detection_and_exclusion_single_outlier() {
    let mut engine = NrPositioningIntegrityEngine::new(DEFAULT_HAL_METERS, DEFAULT_VAL_METERS);
    let ue_true: [f64; 4] = [10.0, 20.0, 5.0, 15.0];

    let trp_coords = [
        (101, 100.0, 0.0, 20.0),
        (102, -100.0, 0.0, 25.0),
        (103, 0.0, 100.0, 30.0), // Fault will be injected here!
        (104, 0.0, -100.0, 15.0),
        (105, 50.0, 50.0, 10.0),
        (106, -50.0, -50.0, 22.0),
    ];

    let mut anchors = Vec::new();
    for &(id, x, y, z) in &trp_coords {
        let dx = ue_true[0] - x;
        let dy = ue_true[1] - y;
        let dz = ue_true[2] - z;
        let true_range = (dx * dx + dy * dy + dz * dz).sqrt();
        let mut pr = true_range + ue_true[3];
        if id == 103 {
            pr += 20.0; // 20-meter multipath / clock jump anomaly!
        }
        anchors.push(TrpRangingMeasurement {
            trp_id: id,
            x_m: x,
            y_m: y,
            z_m: z,
            pseudorange_m: pr,
            sigma_m: 0.3,
        });
    }

    let result = engine
        .evaluate_integrity(&anchors, [0.0, 0.0, 0.0, 0.0])
        .expect("evaluation failed");

    // FDE must detect the fault and identify TRP 103 as the outlier!
    assert!(result.fault_detected);
    assert_eq!(result.excluded_trp_ids, vec![103]);

    // Position after exclusion should still be accurate within sub-meter error
    assert!((result.estimated_position[0] - ue_true[0]).abs() < 0.2);
    assert!((result.estimated_position[1] - ue_true[1]).abs() < 0.2);

    let tel = engine.telemetry();
    assert_eq!(tel.faults_detected, 1);
    assert_eq!(tel.faults_excluded_successfully, 1);
}

#[test]
fn test_unsafe_alarm_when_protection_level_exceeds_hal() {
    // Set a very strict HAL of 0.2 meters, with loose measurement sigma 2.0 meters
    let mut engine = NrPositioningIntegrityEngine::new(0.2, 0.5);

    let trp_coords = [
        (1, 100.0, 0.0, 20.0),
        (2, -100.0, 0.0, 25.0),
        (3, 0.0, 100.0, 30.0),
        (4, 0.0, -100.0, 15.0),
        (5, 50.0, 50.0, 10.0),
        (6, -50.0, -50.0, 22.0),
    ];

    let ue_true: [f64; 4] = [10.0, 20.0, 5.0, 15.0];
    let mut anchors = Vec::new();
    for &(id, x, y, z) in &trp_coords {
        let dx = ue_true[0] - x;
        let dy = ue_true[1] - y;
        let dz = ue_true[2] - z;
        let true_range = (dx * dx + dy * dy + dz * dz).sqrt();
        anchors.push(TrpRangingMeasurement {
            trp_id: id,
            x_m: x,
            y_m: y,
            z_m: z,
            pseudorange_m: true_range + ue_true[3],
            sigma_m: 2.0, // High noise -> large HPL
        });
    }

    let result = engine
        .evaluate_integrity(&anchors, [0.0, 0.0, 0.0, 0.0])
        .expect("eval failed");

    // HPL should exceed 0.2 meters, triggering Unsafe alarm
    assert!(result.hpl_m > 0.2);
    assert_eq!(result.safety_status, IntegritySafetyStatus::Unsafe);
    assert_eq!(engine.telemetry().unsafe_epochs, 1);
}

#[test]
fn test_insufficient_anchors_error() {
    let mut engine = NrPositioningIntegrityEngine::new(DEFAULT_HAL_METERS, DEFAULT_VAL_METERS);
    let anchors = vec![
        TrpRangingMeasurement {
            trp_id: 1,
            x_m: 0.0,
            y_m: 0.0,
            z_m: 0.0,
            pseudorange_m: 10.0,
            sigma_m: 1.0,
        },
        TrpRangingMeasurement {
            trp_id: 2,
            x_m: 1.0,
            y_m: 0.0,
            z_m: 0.0,
            pseudorange_m: 10.0,
            sigma_m: 1.0,
        },
    ];
    let res = engine.evaluate_integrity(&anchors, [0.0; 4]);
    assert!(matches!(
        res,
        Err(IntegrityError::InsufficientAnchors {
            available: 2,
            required: 4
        })
    ));
}

#[test]
fn test_error_display() {
    let err1 = IntegrityError::InsufficientAnchors {
        available: 3,
        required: 4,
    };
    assert!(format!("{}", err1).contains("insufficient"));

    let err2 = IntegrityError::SingularGeometryMatrix;
    assert!(format!("{}", err2).contains("collinear"));
}
