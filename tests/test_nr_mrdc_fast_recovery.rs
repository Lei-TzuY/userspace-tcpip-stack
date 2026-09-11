//! Integration tests for 3GPP Rel-18/19 MR-DC Fast MCG/SCG Recovery Engine.

use toy_tcpip::nr_mrdc_fast_recovery::*;

#[test]
fn test_crc16_integrity() {
    let test_bytes = b"3GPP-TS-38.331-Rel18-FastRecovery";
    let crc = compute_crc16(test_bytes);
    assert_ne!(crc, 0);

    // Deterministic check
    let crc2 = compute_crc16(test_bytes);
    assert_eq!(crc, crc2);

    // Modified data produces different CRC
    let mut modified = test_bytes.to_vec();
    modified[0] ^= 0x01;
    let crc_mod = compute_crc16(&modified);
    assert_ne!(crc, crc_mod);
}

#[test]
fn test_failure_causes_from_u8() {
    assert_eq!(McgFailureCause::from_u8(1).unwrap(), McgFailureCause::T310Expiry);
    assert_eq!(McgFailureCause::from_u8(2).unwrap(), McgFailureCause::RandomAccessProblem);
    assert_eq!(McgFailureCause::from_u8(3).unwrap(), McgFailureCause::RlcMaxNumRetx);
    assert_eq!(McgFailureCause::from_u8(4).unwrap(), McgFailureCause::SynchReconfigFailureMcg);
    assert_eq!(McgFailureCause::from_u8(5).unwrap(), McgFailureCause::ScgLbtFailure);
    assert_eq!(McgFailureCause::from_u8(6).unwrap(), McgFailureCause::BeamFailureRecoveryFailure);
    assert_eq!(McgFailureCause::from_u8(7).unwrap(), McgFailureCause::T312Expiry);
    assert!(McgFailureCause::from_u8(0).is_err());
    assert!(McgFailureCause::from_u8(8).is_err());

    assert_eq!(ScgFailureCause::from_u8(1).unwrap(), ScgFailureCause::T310Expiry);
    assert_eq!(ScgFailureCause::from_u8(2).unwrap(), ScgFailureCause::SynchReconfigFailureScg);
    assert_eq!(ScgFailureCause::from_u8(3).unwrap(), ScgFailureCause::RandomAccessProblem);
    assert_eq!(ScgFailureCause::from_u8(4).unwrap(), ScgFailureCause::RlcMaxNumRetx);
    assert_eq!(ScgFailureCause::from_u8(5).unwrap(), ScgFailureCause::ScgChangeFailure);
    assert_eq!(ScgFailureCause::from_u8(6).unwrap(), ScgFailureCause::ScgLbtFailure);
    assert_eq!(ScgFailureCause::from_u8(7).unwrap(), ScgFailureCause::BeamFailureRecoveryFailure);
    assert!(ScgFailureCause::from_u8(0).is_err());
    assert!(ScgFailureCause::from_u8(99).is_err());
}

#[test]
fn test_mcg_failure_information_codec_and_crc() {
    let serving_meas = vec![CellMeasurementResult {
        pci: 42,
        rsrp_dbm: -105.5,
        rsrq_db: -14.0,
        sinr_db: -3.5,
    }];
    let neighbor_meas = vec![
        CellMeasurementResult {
            pci: 43,
            rsrp_dbm: -88.0,
            rsrq_db: -9.5,
            sinr_db: 12.0,
        },
        CellMeasurementResult {
            pci: 44,
            rsrp_dbm: -92.5,
            rsrq_db: -11.0,
            sinr_db: 8.5,
        },
    ];

    let info = McgFailureInformation {
        failure_cause: McgFailureCause::T310Expiry,
        failed_pcell_pci: 42,
        serving_measurements: serving_meas,
        neighbor_measurements: neighbor_meas,
    };

    let wire = info.encode_wire();
    assert!(wire.len() > 10);
    // Magic header 'M', 'F', 0x12
    assert_eq!(wire[0], 0x4D);
    assert_eq!(wire[1], 0x46);
    assert_eq!(wire[2], 0x12);
    assert_eq!(wire[3], 1); // McgFailureCause::T310Expiry

    // Decode successfully
    let decoded = McgFailureInformation::decode_wire(&wire).expect("decoding failed");
    assert_eq!(decoded.failure_cause, info.failure_cause);
    assert_eq!(decoded.failed_pcell_pci, info.failed_pcell_pci);
    assert_eq!(decoded.serving_measurements.len(), 1);
    assert_eq!(decoded.neighbor_measurements.len(), 2);
    assert_eq!(decoded.neighbor_measurements[0].pci, 43);
    assert!((decoded.neighbor_measurements[0].sinr_db - 12.0).abs() < 1e-4);

    // Corrupt CRC
    let mut corrupted_crc = wire.clone();
    let last = corrupted_crc.len() - 1;
    corrupted_crc[last] ^= 0xFF;
    match McgFailureInformation::decode_wire(&corrupted_crc) {
        Err(MrdcRecoveryError::ChecksumMismatch { .. }) => {}
        other => panic!("Expected ChecksumMismatch, got {:?}", other),
    }

    // Corrupt Magic
    let mut corrupted_magic = wire.clone();
    corrupted_magic[0] = 0x00;
    // Update CRC so checksum passes but magic fails
    let new_crc = compute_crc16(&corrupted_magic[..corrupted_magic.len() - 2]);
    let len = corrupted_magic.len();
    corrupted_magic[len - 2..len].copy_from_slice(&new_crc.to_be_bytes());
    match McgFailureInformation::decode_wire(&corrupted_magic) {
        Err(MrdcRecoveryError::DeserializationError(msg)) => {
            assert!(msg.contains("magic"));
        }
        other => panic!("Expected DeserializationError, got {:?}", other),
    }

    // Truncated buffer
    assert!(McgFailureInformation::decode_wire(&[0x4D, 0x46]).is_err());
}

#[test]
fn test_scg_failure_information_codec_and_crc() {
    let meas = vec![CellMeasurementResult {
        pci: 201,
        rsrp_dbm: -95.0,
        rsrq_db: -10.0,
        sinr_db: 5.0,
    }];

    let info = ScgFailureInformation {
        failure_cause: ScgFailureCause::BeamFailureRecoveryFailure,
        failed_pscell_pci: 201,
        measurements: meas,
    };

    let wire = info.encode_wire();
    // Magic 'S', 'F', 0x12
    assert_eq!(wire[0], 0x53);
    assert_eq!(wire[1], 0x46);
    assert_eq!(wire[2], 0x12);

    let decoded = ScgFailureInformation::decode_wire(&wire).expect("scg decode failed");
    assert_eq!(decoded.failure_cause, ScgFailureCause::BeamFailureRecoveryFailure);
    assert_eq!(decoded.failed_pscell_pci, 201);
    assert_eq!(decoded.measurements.len(), 1);
    assert_eq!(decoded.measurements[0].pci, 201);

    // Corrupt CRC
    let mut bad_wire = wire.clone();
    let l = bad_wire.len() - 1;
    bad_wire[l] ^= 0xAA;
    assert!(matches!(
        ScgFailureInformation::decode_wire(&bad_wire),
        Err(MrdcRecoveryError::ChecksumMismatch { .. })
    ));

    // Truncated
    assert!(ScgFailureInformation::decode_wire(&[0x53, 0x46, 0x12]).is_err());
}

#[test]
fn test_fast_mcg_recovery_trigger_and_completion() {
    let mut engine = MrdcFastRecoveryEngine::new(1001, 10, 20);
    assert_eq!(engine.ue_id(), 1001);
    assert_eq!(engine.pcell_pci(), 10);
    assert_eq!(engine.pscell_pci(), 20);
    assert_eq!(engine.mcg_status(), CellGroupStatus::NormalActive);
    assert_eq!(engine.scg_status(), CellGroupStatus::NormalActive);

    // Trigger Fast MCG Recovery
    let info = engine
        .trigger_fast_mcg_recovery(McgFailureCause::T310Expiry, vec![], vec![])
        .expect("Trigger MCG recovery failed");

    assert_eq!(info.failed_pcell_pci, 10);
    assert_eq!(engine.mcg_status(), CellGroupStatus::Recovering);

    // Advance 8 ms (sub-15ms fast recovery procedure over SCG leg)
    let expiry = engine.advance_time_ms(8);
    assert!(expiry.is_none());
    assert_eq!(engine.current_time_ms(), 8);

    // Complete recovery with handover/reconfig to PCell 15
    let duration = engine.complete_mcg_recovery(15).expect("complete recovery failed");
    assert_eq!(duration, 8);
    assert_eq!(engine.pcell_pci(), 15);
    assert_eq!(engine.mcg_status(), CellGroupStatus::NormalActive);

    // Check telemetry
    let tel = engine.telemetry();
    assert_eq!(tel.mcg_failures_detected, 1);
    assert_eq!(tel.mcg_fast_recoveries_succeeded, 1);
    assert_eq!(tel.mcg_recovery_timeouts_t316, 0);
    assert_eq!(tel.total_recovery_duration_ms, 8);
    assert_eq!(tel.max_recovery_duration_ms, 8);
    assert!((tel.mcg_recovery_success_rate() - 100.0).abs() < 1e-4);
    assert!((tel.average_recovery_duration_ms() - 8.0).abs() < 1e-4);
}

#[test]
fn test_fast_scg_recovery_trigger_and_completion() {
    let mut engine = MrdcFastRecoveryEngine::new(1002, 10, 20);

    let scg_info = engine
        .trigger_fast_scg_recovery(ScgFailureCause::SynchReconfigFailureScg, vec![])
        .expect("trigger SCG recovery failed");

    assert_eq!(scg_info.failed_pscell_pci, 20);
    assert_eq!(engine.scg_status(), CellGroupStatus::Suspended);

    // Complete SCG recovery with updated PSCell 25
    engine.complete_scg_recovery(25);
    assert_eq!(engine.pscell_pci(), 25);
    assert_eq!(engine.scg_status(), CellGroupStatus::NormalActive);

    let tel = engine.telemetry();
    assert_eq!(tel.scg_failures_detected, 1);
    assert_eq!(tel.scg_fast_recoveries_succeeded, 1);
}

#[test]
fn test_t316_expiry_legacy_rrc_reestablishment_fallback() {
    let mut engine = MrdcFastRecoveryEngine::new(1003, 10, 20);

    engine
        .trigger_fast_mcg_recovery(McgFailureCause::RandomAccessProblem, vec![], vec![])
        .unwrap();

    // Advance 100 ms (T316 is 200 ms, not expired yet)
    let ret1 = engine.advance_time_ms(100);
    assert!(ret1.is_none());
    assert_eq!(engine.mcg_status(), CellGroupStatus::Recovering);

    // Advance another 101 ms (Total 201 ms > 200 ms T316)
    let ret2 = engine.advance_time_ms(101);
    assert!(matches!(
        ret2,
        Some(MrdcRecoveryError::RecoveryTimerExpired(name)) if name == "T316"
    ));
    assert_eq!(engine.mcg_status(), CellGroupStatus::LegacyRrcReestablishment);

    let tel = engine.telemetry();
    assert_eq!(tel.mcg_failures_detected, 1);
    assert_eq!(tel.mcg_fast_recoveries_succeeded, 0);
    assert_eq!(tel.mcg_recovery_timeouts_t316, 1);
    assert_eq!(tel.mcg_recovery_success_rate(), 0.0);
}

#[test]
fn test_scg_unavailable_mcg_recovery_rejection() {
    let mut engine = MrdcFastRecoveryEngine::new(1004, 10, 20);

    // Suspend SCG first
    engine
        .trigger_fast_scg_recovery(ScgFailureCause::T310Expiry, vec![])
        .unwrap();
    assert_eq!(engine.scg_status(), CellGroupStatus::Suspended);

    // Now attempt MCG recovery via the suspended SCG
    let res = engine.trigger_fast_mcg_recovery(McgFailureCause::T310Expiry, vec![], vec![]);
    assert_eq!(res, Err(MrdcRecoveryError::ScgNotAvailableForRecovery));
}

#[test]
fn test_double_mcg_recovery_attempt() {
    let mut engine = MrdcFastRecoveryEngine::new(1005, 10, 20);
    engine
        .trigger_fast_mcg_recovery(McgFailureCause::T310Expiry, vec![], vec![])
        .unwrap();

    // Attempt second recovery while first is still pending
    let res = engine.trigger_fast_mcg_recovery(McgFailureCause::RlcMaxNumRetx, vec![], vec![]);
    assert_eq!(res, Err(MrdcRecoveryError::RecoveryAlreadyInProgress));
}

#[test]
fn test_complete_mcg_recovery_when_not_recovering() {
    let mut engine = MrdcFastRecoveryEngine::new(1006, 10, 20);
    let res = engine.complete_mcg_recovery(99);
    assert!(matches!(res, Err(MrdcRecoveryError::InvalidCellGroup(_))));
}

#[test]
fn test_scg_recovery_when_mcg_not_active() {
    let mut engine = MrdcFastRecoveryEngine::new(1007, 10, 20);
    engine
        .trigger_fast_mcg_recovery(McgFailureCause::T310Expiry, vec![], vec![])
        .unwrap();

    // MCG is now Recovering, not NormalActive
    let res = engine.trigger_fast_scg_recovery(ScgFailureCause::T310Expiry, vec![]);
    assert_eq!(res, Err(MrdcRecoveryError::McgNotAvailableForRecovery));
}

#[test]
fn test_error_display() {
    let err1 = MrdcRecoveryError::ScgNotAvailableForRecovery;
    assert!(format!("{}", err1).contains("SCG leg not available"));

    let err2 = MrdcRecoveryError::ChecksumMismatch {
        expected: 0x1234,
        calculated: 0x5678,
    };
    assert!(format!("{}", err2).contains("0x1234"));
}
