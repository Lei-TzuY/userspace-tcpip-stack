//! Comprehensive integration tests for 3GPP Rel-18/19 SON, ANR, MDT & MRO Engine.

use toy_tcpip::nr_son_anr_mdt::{
    CoverageAnomaly, GnssLocation, MdtMeasurementLog, MroFailureType, Ncgi, NeighborRelationEntry,
    SensorMeasurements, SonAnrMdtEngine, SonError,
};

// ---------------------------------------------------------------------------
// Test 1: ANR Neighbor Addition, Validation & Self-Collision Detection
// ---------------------------------------------------------------------------
#[test]
fn test_anr_neighbor_addition_and_validation() {
    let s_ncgi = Ncgi::new(310, 410, 0x123456789).expect("Valid serving NCGI");
    let mut engine = SonAnrMdtEngine::new(100, s_ncgi, 12345, 630000).expect("Valid engine");
    assert_eq!(engine.serving_pci(), 100);

    // 1. Valid neighbor addition (PCI 101)
    let n_ncgi1 = Ncgi::new(310, 410, 0x987654321).unwrap();
    let entry1 = NeighborRelationEntry::new(101, n_ncgi1, 12345, 630000).unwrap();
    assert!(engine.add_neighbor(entry1).is_ok());
    assert_eq!(engine.telemetry().total_nrt_entries, 1);

    // 2. Invalid PCI (> 1007)
    assert!(NeighborRelationEntry::new(1008, Ncgi::new(310, 410, 1).unwrap(), 1, 1).is_err());

    // 3. Self-PCI conflict: Neighbor with same PCI as serving cell (100)
    let self_pci_entry =
        NeighborRelationEntry::new(100, Ncgi::new(310, 410, 0xABCDEF).unwrap(), 12345, 630000)
            .unwrap();
    let err = engine.add_neighbor(self_pci_entry);
    assert!(matches!(err, Err(SonError::PciCollisionDetected { .. })));
    assert_eq!(engine.telemetry().pci_collisions_detected, 1);
}

// ---------------------------------------------------------------------------
// Test 2: PCI Confusion Detection in ANR
// ---------------------------------------------------------------------------
#[test]
fn test_pci_confusion_detection() {
    let s_ncgi = Ncgi::new(310, 410, 100).unwrap();
    let mut engine = SonAnrMdtEngine::new(50, s_ncgi, 1, 1000).unwrap();

    // Add neighbor 1 with PCI 200, NCGI A
    let ncgi_a = Ncgi::new(310, 410, 2001).unwrap();
    let entry_a = NeighborRelationEntry::new(200, ncgi_a.clone(), 1, 1000).unwrap();
    engine.add_neighbor(entry_a).unwrap();

    // Attempt to add duplicate neighbor with same PCI 200 but different NCGI B -> Confusion!
    let ncgi_b = Ncgi::new(310, 410, 2002).unwrap();
    let entry_b = NeighborRelationEntry::new(200, ncgi_b, 1, 1000).unwrap();
    let err = engine.add_neighbor(entry_b);
    assert!(matches!(err, Err(SonError::PciConfusionDetected { .. })));
    assert_eq!(engine.telemetry().pci_confusions_detected, 1);
}

// ---------------------------------------------------------------------------
// Test 3: Autonomous UE-Assisted CGI Acquisition via Measurement Gap
// ---------------------------------------------------------------------------
#[test]
fn test_autonomous_ue_assisted_cgi_acquisition() {
    let s_ncgi = Ncgi::new(460, 0, 10).unwrap();
    let mut engine = SonAnrMdtEngine::new(1, s_ncgi, 100, 500000).unwrap();

    // UE detects unknown PCI 450 in measurement gap, reads SIB1
    let resolved_ncgi = Ncgi::new(460, 0, 0x555555555).unwrap();
    let resolved_tac = 8888;
    let arfcn = 500000;

    engine
        .resolve_neighbor_cgi_via_ue_gap(450, resolved_ncgi.clone(), resolved_tac, arfcn)
        .expect("Resolve neighbor CGI");

    assert_eq!(engine.telemetry().autonomous_cgi_resolutions, 1);
    let neighbor = engine.get_neighbor(450).expect("Neighbor found in NRT");
    assert_eq!(neighbor.pci, 450);
    assert_eq!(neighbor.ncgi, resolved_ncgi);
    assert_eq!(neighbor.tac, 8888);
}

// ---------------------------------------------------------------------------
// Test 4: Immediate MDT Reporting & CCO Coverage Anomaly Detection
// ---------------------------------------------------------------------------
#[test]
fn test_mdt_immediate_reporting_and_anomaly_detection() {
    let s_ncgi = Ncgi::new(310, 260, 1).unwrap();
    let mut engine = SonAnrMdtEngine::new(10, s_ncgi, 1, 1000).unwrap();

    // 1. Coverage Hole: Both RSRP <= -115 dBm and SINR <= -3 dB
    let hole_log = MdtMeasurementLog {
        timestamp_ms: 1000,
        serving_pci: 10,
        serving_rsrp_dbm: -120.0,
        serving_rsrq_db: -18.0,
        serving_sinr_db: -6.0,
        neighbor_rsrp: vec![(11, -122.0)],
        location: None,
        sensors: None,
    };
    let anomaly1 = engine.ingest_immediate_mdt_report(hole_log);
    assert!(matches!(
        anomaly1,
        Some(CoverageAnomaly::CoverageHole { .. })
    ));
    assert_eq!(engine.telemetry().coverage_holes_detected, 1);

    // 2. Weak Coverage: RSRP <= -105 dBm but SINR > -3 dB
    let weak_log = MdtMeasurementLog {
        timestamp_ms: 2000,
        serving_pci: 10,
        serving_rsrp_dbm: -110.0,
        serving_rsrq_db: -12.0,
        serving_sinr_db: 5.0,
        neighbor_rsrp: vec![],
        location: None,
        sensors: None,
    };
    let anomaly2 = engine.ingest_immediate_mdt_report(weak_log);
    assert!(matches!(
        anomaly2,
        Some(CoverageAnomaly::WeakCoverage { .. })
    ));

    // 3. Pilot Pollution: Serving = -80.0 dBm with 3 competing neighbors within 3 dB
    let pollution_log = MdtMeasurementLog {
        timestamp_ms: 3000,
        serving_pci: 10,
        serving_rsrp_dbm: -80.0,
        serving_rsrq_db: -10.0,
        serving_sinr_db: 2.0,
        neighbor_rsrp: vec![(11, -81.0), (12, -82.0), (13, -80.5)],
        location: None,
        sensors: None,
    };
    let anomaly3 = engine.ingest_immediate_mdt_report(pollution_log);
    assert!(matches!(
        anomaly3,
        Some(CoverageAnomaly::PilotPollution { .. })
    ));
    assert_eq!(engine.telemetry().pilot_pollutions_detected, 1);
}

// ---------------------------------------------------------------------------
// Test 5: Logged MDT Batch Retrieval with Sensor & GNSS Location
// ---------------------------------------------------------------------------
#[test]
fn test_logged_mdt_batch_ingestion_and_sensors() {
    let s_ncgi = Ncgi::new(310, 410, 100).unwrap();
    let mut engine = SonAnrMdtEngine::new(10, s_ncgi, 1, 1000).unwrap();

    let loc = GnssLocation {
        latitude: 37.7749,
        longitude: -122.4194,
        altitude_meters: 15.2,
        horizontal_accuracy_meters: 2.5,
    };

    let sensors = SensorMeasurements {
        barometric_pressure_hpa: Some(1013.25),
        ble_beacons: vec![("00:11:22:33:44:55".into(), -65)],
        wlan_aps: vec![("Office-WiFi".into(), -55)],
    };

    let log = MdtMeasurementLog {
        timestamp_ms: 50_000,
        serving_pci: 10,
        serving_rsrp_dbm: -88.0,
        serving_rsrq_db: -9.0,
        serving_sinr_db: 15.0,
        neighbor_rsrp: vec![(20, -95.0)],
        location: Some(loc),
        sensors: Some(sensors),
    };

    let anomalies = engine
        .ingest_logged_mdt_batch(vec![log])
        .expect("Ingest logged MDT batch");

    assert!(anomalies.is_empty()); // Good signal, no anomaly
    assert_eq!(engine.telemetry().logged_mdt_batches_retrieved, 1);
}

// ---------------------------------------------------------------------------
// Test 6: Mobility Robustness Optimization (MRO) Failure Analysis & CIO Tuning
// ---------------------------------------------------------------------------
#[test]
fn test_mro_failure_classification_and_cio_tuning() {
    let s_ncgi = Ncgi::new(310, 410, 100).unwrap();
    let mut engine = SonAnrMdtEngine::new(10, s_ncgi, 1, 1000).unwrap();

    // Register neighbor cells 20 and 30
    let n20 = NeighborRelationEntry::new(20, Ncgi::new(310, 410, 20).unwrap(), 1, 1000).unwrap();
    let n30 = NeighborRelationEntry::new(30, Ncgi::new(310, 410, 30).unwrap(), 1, 1000).unwrap();
    engine.add_neighbor(n20).unwrap();
    engine.add_neighbor(n30).unwrap();

    // 1. Too Early Handover to Cell 20 -> Penalizes Cell 20 CIO by -0.5 dB (-1 step)
    let early_ho = MroFailureType::TooEarlyHandover {
        source_pci: 10,
        target_pci: 20,
        time_since_ho_ms: 300,
    };
    let new_cio_20 = engine.analyze_mro_failure(early_ho).unwrap();
    assert_eq!(new_cio_20, -1);
    assert_eq!(engine.get_neighbor(20).unwrap().cio_half_db, -1);
    assert_eq!(engine.telemetry().too_early_ho_count, 1);

    // 2. Too Late Handover to Cell 30 -> Boosts Cell 30 CIO by +0.5 dB (+1 step)
    let late_ho = MroFailureType::TooLateHandover {
        source_pci: 10,
        target_pci: 30,
    };
    let new_cio_30 = engine.analyze_mro_failure(late_ho).unwrap();
    assert_eq!(new_cio_30, 1);
    assert_eq!(engine.get_neighbor(30).unwrap().cio_half_db, 1);
    assert_eq!(engine.telemetry().too_late_ho_count, 1);

    // 3. Handover to Wrong Cell: Sent to Cell 20, re-established in Cell 30
    let wrong_cell = MroFailureType::HandoverToWrongCell {
        source_pci: 10,
        attempted_target_pci: 20,
        actual_reestablishment_pci: 30,
    };
    engine.analyze_mro_failure(wrong_cell).unwrap();
    assert_eq!(engine.telemetry().wrong_cell_ho_count, 1);
    // Cell 20 penalized by -2 steps (-1.0 dB) -> -1 - 2 = -3
    assert_eq!(engine.get_neighbor(20).unwrap().cio_half_db, -3);
    // Cell 30 boosted by +1 step (+0.5 dB) -> 1 + 1 = 2
    assert_eq!(engine.get_neighbor(30).unwrap().cio_half_db, 2);
}

// ---------------------------------------------------------------------------
// Test 7: Neighbor Removal & Policy Flag Protection (noRemove)
// ---------------------------------------------------------------------------
#[test]
fn test_neighbor_removal_and_protection() {
    let s_ncgi = Ncgi::new(310, 410, 1).unwrap();
    let mut engine = SonAnrMdtEngine::new(10, s_ncgi, 1, 1000).unwrap();

    // 1. Add neighbor with no_remove = true
    let mut protected =
        NeighborRelationEntry::new(100, Ncgi::new(310, 410, 100).unwrap(), 1, 1000).unwrap();
    protected.no_remove = true;
    engine.add_neighbor(protected).unwrap();

    // Attempting removal must return Ok(false)
    let removed = engine.remove_neighbor(100).expect("Remove check");
    assert_eq!(removed, false);
    assert!(engine.get_neighbor(100).is_some());

    // 2. Add unprotected neighbor (no_remove = false)
    let unprotected =
        NeighborRelationEntry::new(200, Ncgi::new(310, 410, 200).unwrap(), 1, 1000).unwrap();
    engine.add_neighbor(unprotected).unwrap();

    let removed2 = engine.remove_neighbor(200).expect("Remove check");
    assert_eq!(removed2, true);
    assert!(engine.get_neighbor(200).is_none());
}
