//! Integration tests for 3GPP TS 29.572 / TS 23.273 / TS 38.305 5G Location Management Function (LMF) Engine.

use toy_tcpip::lmf_5g::*;

// ---------------------------------------------------------------------------
// 1. Multi-RTT Trilateration High-Precision Positioning Happy Path
// ---------------------------------------------------------------------------

#[test]
fn test_lmf_multi_rtt_high_precision_positioning() {
    let mut lmf = LmfEngine::new("lmf-core-001");
    let supi = "imsi-208950000000001";

    let measurements = vec![
        GnbMeasurement {
            gnb_id: 1,
            cell_id: 101,
            gnb_latitude: 35.6890,
            gnb_longitude: 139.6910,
            timing_advance_ns: Some(300),
            rx_tx_diff_ns: Some(400),
            aoa_azimuth_deg: None,
            rsrp_dbm: Some(-75),
        },
        GnbMeasurement {
            gnb_id: 2,
            cell_id: 102,
            gnb_latitude: 35.6900,
            gnb_longitude: 139.6910,
            timing_advance_ns: Some(300),
            rx_tx_diff_ns: Some(400),
            aoa_azimuth_deg: None,
            rsrp_dbm: Some(-78),
        },
        GnbMeasurement {
            gnb_id: 3,
            cell_id: 103,
            gnb_latitude: 35.6895,
            gnb_longitude: 139.6925,
            timing_advance_ns: Some(300),
            rx_tx_diff_ns: Some(400),
            aoa_azimuth_deg: None,
            rsrp_dbm: Some(-80),
        },
    ];

    let req = DetermineLocationRequest {
        supi: supi.to_string(),
        client_type: LcsClientType::EmergencyServices,
        requested_qos: Some(LocationQos {
            horizontal_accuracy_m: 3.0,
            vertical_accuracy_m: Some(5.0),
            max_response_time_ms: 1000,
        }),
        measurements,
        timestamp_epoch_s: 1700000000,
    };

    let resp = lmf
        .determine_location(&req)
        .expect("Positioning calculation failed");
    assert_eq!(resp.method_used, PositioningMethod::MultiRtt);
    assert!(resp.qos_satisfied);
    assert!(resp.position.uncertainty_horizontal_m <= 3.0);
    assert_eq!(resp.position.confidence_percent, 95);
    assert!(resp.position.latitude > 35.688 && resp.position.latitude < 35.691);
    assert!(resp.position.longitude > 139.690 && resp.position.longitude < 139.693);
}

// ---------------------------------------------------------------------------
// 2. UL-AoA (Angle of Arrival) + Timing Advance Solver
// ---------------------------------------------------------------------------

#[test]
fn test_lmf_ul_aoa_and_timing_advance_positioning() {
    let mut lmf = LmfEngine::new("lmf-core-002");
    let supi = "imsi-208950000000002";

    let gnb_lat = 35.6895;
    let gnb_lon = 139.6917;

    // 1 gNodeB reporting 45 degree azimuth and 667 ns TA (~100m)
    let measurements = vec![GnbMeasurement {
        gnb_id: 10,
        cell_id: 201,
        gnb_latitude: gnb_lat,
        gnb_longitude: gnb_lon,
        timing_advance_ns: Some(667), // ~100 meters
        rx_tx_diff_ns: None,
        aoa_azimuth_deg: Some(45.0), // North-East
        rsrp_dbm: Some(-70),
    }];

    let req = DetermineLocationRequest {
        supi: supi.to_string(),
        client_type: LcsClientType::Commercial,
        requested_qos: Some(LocationQos {
            horizontal_accuracy_m: 10.0,
            vertical_accuracy_m: None,
            max_response_time_ms: 2000,
        }),
        measurements,
        timestamp_epoch_s: 1700000000,
    };

    let resp = lmf.determine_location(&req).unwrap();
    assert_eq!(resp.method_used, PositioningMethod::UlAoA);
    assert!(resp.qos_satisfied);

    // Projected coordinate should be North-East of gNodeB
    assert!(resp.position.latitude > gnb_lat);
    assert!(resp.position.longitude > gnb_lon);
}

// ---------------------------------------------------------------------------
// 3. E-CID & Cell-ID Fallback Positioning
// ---------------------------------------------------------------------------

#[test]
fn test_lmf_enhanced_cell_id_and_cell_id_fallback() {
    let mut lmf = LmfEngine::new("lmf-core-003");

    // E-CID with Timing Advance only
    let ecid_meas = vec![GnbMeasurement {
        gnb_id: 20,
        cell_id: 301,
        gnb_latitude: 40.7128,
        gnb_longitude: -74.0060,
        timing_advance_ns: Some(1000), // ~150 meters
        rx_tx_diff_ns: None,
        aoa_azimuth_deg: None,
        rsrp_dbm: Some(-85),
    }];

    let req_ecid = DetermineLocationRequest {
        supi: "imsi-208950000000003".to_string(),
        client_type: LcsClientType::ValueAdded,
        requested_qos: None,
        measurements: ecid_meas,
        timestamp_epoch_s: 1700000000,
    };
    let resp_ecid = lmf.determine_location(&req_ecid).unwrap();
    assert_eq!(resp_ecid.method_used, PositioningMethod::EnhancedCellId);

    // Fallback to basic Cell ID (no TA, no AoA, no Multi-RTT)
    let cid_meas = vec![GnbMeasurement {
        gnb_id: 20,
        cell_id: 302,
        gnb_latitude: 40.7128,
        gnb_longitude: -74.0060,
        timing_advance_ns: None,
        rx_tx_diff_ns: None,
        aoa_azimuth_deg: None,
        rsrp_dbm: Some(-95),
    }];

    let req_cid = DetermineLocationRequest {
        supi: "imsi-208950000000004".to_string(),
        client_type: LcsClientType::ValueAdded,
        requested_qos: None,
        measurements: cid_meas,
        timestamp_epoch_s: 1700000000,
    };
    let resp_cid = lmf.determine_location(&req_cid).unwrap();
    assert_eq!(resp_cid.method_used, PositioningMethod::CellId);
    assert_eq!(resp_cid.position.uncertainty_horizontal_m, 250.0);
}

// ---------------------------------------------------------------------------
// 4. Velocity & Bearing Motion Tracking
// ---------------------------------------------------------------------------

#[test]
fn test_lmf_velocity_and_bearing_motion_tracking() {
    let mut lmf = LmfEngine::new("lmf-core-004");
    let supi = "imsi-208950000000005";

    // Fix 1 at t = 1000s
    let req1 = DetermineLocationRequest {
        supi: supi.to_string(),
        client_type: LcsClientType::Commercial,
        requested_qos: None,
        measurements: vec![GnbMeasurement {
            gnb_id: 1,
            cell_id: 1,
            gnb_latitude: 35.6895,
            gnb_longitude: 139.6917,
            timing_advance_ns: None,
            rx_tx_diff_ns: None,
            aoa_azimuth_deg: None,
            rsrp_dbm: None,
        }],
        timestamp_epoch_s: 1000,
    };
    let resp1 = lmf.determine_location(&req1).unwrap();
    assert!(resp1.velocity.is_none()); // First fix has no velocity

    // Fix 2 at t = 1010s (10 seconds later, moved slightly North-East)
    let req2 = DetermineLocationRequest {
        supi: supi.to_string(),
        client_type: LcsClientType::Commercial,
        requested_qos: None,
        measurements: vec![GnbMeasurement {
            gnb_id: 1,
            cell_id: 1,
            gnb_latitude: 35.6905,   // ~111 meters North
            gnb_longitude: 139.6927, // ~90 meters East
            timing_advance_ns: None,
            rx_tx_diff_ns: None,
            aoa_azimuth_deg: None,
            rsrp_dbm: None,
        }],
        timestamp_epoch_s: 1010,
    };
    let resp2 = lmf.determine_location(&req2).unwrap();
    assert!(resp2.velocity.is_some());

    let vel = resp2.velocity.unwrap();
    assert!(vel.horizontal_speed_mps > 10.0 && vel.horizontal_speed_mps < 20.0); // ~14 m/s (50 km/h)
    assert!(vel.bearing_degrees > 20.0 && vel.bearing_degrees < 60.0); // North-East heading (~35-45 deg)
}

// ---------------------------------------------------------------------------
// 5. QoS Tolerance Failure Detection
// ---------------------------------------------------------------------------

#[test]
fn test_lmf_qos_tolerance_failure() {
    let mut lmf = LmfEngine::new("lmf-core-005");

    let req = DetermineLocationRequest {
        supi: "imsi-208950000000006".to_string(),
        client_type: LcsClientType::Commercial,
        requested_qos: Some(LocationQos {
            horizontal_accuracy_m: 0.5, // Strict sub-meter requirement
            vertical_accuracy_m: None,
            max_response_time_ms: 500,
        }),
        measurements: vec![GnbMeasurement {
            gnb_id: 1,
            cell_id: 1,
            gnb_latitude: 35.6895,
            gnb_longitude: 139.6917,
            timing_advance_ns: None,
            rx_tx_diff_ns: None,
            aoa_azimuth_deg: None,
            rsrp_dbm: None,
        }],
        timestamp_epoch_s: 1700000000,
    };

    let resp = lmf.determine_location(&req).unwrap();
    assert!(!resp.qos_satisfied); // Cell ID accuracy (250m) does not satisfy 0.5m target
}
