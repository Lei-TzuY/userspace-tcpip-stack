//! Integration Tests for 3GPP Rel-18 Ambient IoT (Zero-Energy Devices) Air Interface Engine.

use toy_tcpip::nr_ambient_iot::*;

#[test]
fn test_rf_energy_harvesting_and_wake_up_sensitivity() {
    let fc = 900.0e6; // 900 MHz Sub-1GHz ISM / 5G Band n8
    let tx_power_dbm = 30.0; // 1 Watt EIRP

    let engine = AmbientIotEngine::new(
        fc,
        tx_power_dbm,
        TopologyMode::Monostatic {
            gnb_pos: [0.0, 0.0, 5.0],
            carrier_leakage_cancellation_db: 95.0,
        },
        LineCoding::Fm0,
        BackscatterModulation::Ook,
    )
    .expect("Failed to initialize Ambient IoT engine");

    // Class 1 tag (sensitivity -20 dBm) and Class 2 tag (sensitivity -28 dBm) at 5 meters
    let tag_near_c1 = AmbientTag::new(0x1001, AmbientDeviceClass::Class1Passive, [5.0, 0.0, 1.0]);
    let tag_near_c2 = AmbientTag::new(0x1002, AmbientDeviceClass::Class2Assisted, [5.0, 0.0, 1.0]);

    let budget_c1 = engine.compute_link_budget(&tag_near_c1);
    let budget_c2 = engine.compute_link_budget(&tag_near_c2);

    // At 5m, incident power is approx -12 to -15 dBm > -20 dBm
    assert!(budget_c1.incident_power_tag_dbm > -20.0);
    assert!(
        budget_c1.is_tag_energized,
        "Class 1 tag should be energized at 5m"
    );
    assert!(
        budget_c2.is_tag_energized,
        "Class 2 tag should be energized at 5m"
    );
    assert!(
        budget_c1.harvested_power_tag_uw > 5.0,
        "Harvested power should be > 5 uW"
    );

    // Move tag to 35 meters:
    // Incident power drops below -20 dBm (Class 1 fails), but remains above -28 dBm (Class 2 works)
    let tag_far_c1 = AmbientTag::new(0x2001, AmbientDeviceClass::Class1Passive, [35.0, 0.0, 1.0]);
    let tag_far_c2 = AmbientTag::new(0x2002, AmbientDeviceClass::Class2Assisted, [35.0, 0.0, 1.0]);

    let budget_far_c1 = engine.compute_link_budget(&tag_far_c1);
    let budget_far_c2 = engine.compute_link_budget(&tag_far_c2);

    assert!(
        budget_far_c1.incident_power_tag_dbm < -20.0
            && budget_far_c1.incident_power_tag_dbm > -28.0,
        "Incident power at 35m should be between -28 and -20 dBm, got {:.2} dBm",
        budget_far_c1.incident_power_tag_dbm
    );
    assert!(
        !budget_far_c1.is_tag_energized,
        "Class 1 tag should NOT wake up below -20 dBm"
    );
    assert!(
        budget_far_c2.is_tag_energized,
        "Class 2 tag should wake up with -28 dBm sensitivity"
    );
}

#[test]
fn test_bistatic_vs_monostatic_radar_cross_section_link_budget() {
    let fc = 900.0e6;

    // 1. Monostatic Mode (Emitter and Reader collocated)
    let engine_mono = AmbientIotEngine::new(
        fc,
        30.0,
        TopologyMode::Monostatic {
            gnb_pos: [0.0, 0.0, 5.0],
            carrier_leakage_cancellation_db: 95.0,
        },
        LineCoding::Miller4,
        BackscatterModulation::Ask,
    )
    .unwrap();

    let tag = AmbientTag::new(0x3001, AmbientDeviceClass::Class1Passive, [8.0, 0.0, 1.0]);
    let budget_mono = engine_mono.compute_link_budget(&tag);

    // Differential RCS sigma = (lambda^2 / 4pi) * G_tag^2
    assert!(budget_mono.rcs_m2 > 0.01 && budget_mono.rcs_m2 < 0.1);

    // Carrier leakage with 95 dB cancellation: 30 dBm - 95 dB = -65 dBm
    assert_eq!(budget_mono.residual_carrier_leakage_dbm, -65.0);

    // With 95 dB cancellation, SNR should be positive (> 0 dB)
    assert!(
        budget_mono.snr_db > 0.0,
        "SNR should be positive at 8m with 95 dB SIC, got {:.2} dB",
        budget_mono.snr_db
    );

    // 2. Bistatic Mode: Carrier Emitter at [0, 0, 5], Reader at [10, 0, 1]
    let engine_bi = AmbientIotEngine::new(
        fc,
        30.0,
        TopologyMode::Bistatic {
            emitter_pos: [0.0, 0.0, 5.0],
            reader_pos: [10.0, 0.0, 1.0],
        },
        LineCoding::Miller4,
        BackscatterModulation::Ask,
    )
    .unwrap();

    let budget_bi = engine_bi.compute_link_budget(&tag);
    // In bistatic mode, zero carrier leakage direct into reader
    assert!(
        budget_bi.received_power_reader_dbm > -90.0 && budget_bi.received_power_reader_dbm < -30.0,
        "Received power should be reasonable, got {:.2} dBm",
        budget_bi.received_power_reader_dbm
    );
}

#[test]
fn test_line_coding_fm0_and_miller() {
    let bits = vec![false, true, false, false, true]; // 0, 1, 0, 0, 1

    // 1. FM0 encoding: 2 symbols per bit
    let fm0_symbols = encode_line_code(&bits, LineCoding::Fm0);
    assert_eq!(fm0_symbols.len(), bits.len() * 2);

    // 2. Miller-2 encoding: 2 symbols per bit
    let m2_symbols = encode_line_code(&bits, LineCoding::Miller2);
    assert_eq!(m2_symbols.len(), bits.len() * 2);

    // 3. Miller-4 encoding: 4 symbols per bit
    let m4_symbols = encode_line_code(&bits, LineCoding::Miller4);
    assert_eq!(m4_symbols.len(), bits.len() * 4);

    // 4. Miller-8 encoding: 8 symbols per bit
    let m8_symbols = encode_line_code(&bits, LineCoding::Miller8);
    assert_eq!(m8_symbols.len(), bits.len() * 8);
}

#[test]
fn test_crc16_ccitt_generation_and_detection() {
    let payload = b"3GPP_Rel18_AmbientIoT";
    let crc = compute_crc16(payload);
    assert_ne!(crc, 0);

    // Corrupted payload
    let mut corrupted = payload.to_vec();
    corrupted[0] ^= 0x01; // flip 1 bit
    let crc_corrupted = compute_crc16(&corrupted);
    assert_ne!(crc, crc_corrupted, "CRC must detect bit flip");
}

#[test]
fn test_dynamic_q_algorithm_collision_resolution_and_inventory() {
    let mut engine = AmbientIotEngine::new(
        900.0e6,
        30.0,
        TopologyMode::Monostatic {
            gnb_pos: [0.0, 0.0, 5.0],
            carrier_leakage_cancellation_db: 95.0,
        },
        LineCoding::Miller2,
        BackscatterModulation::Ook,
    )
    .unwrap();

    // Add 4 tags at 5m
    for i in 1..=4 {
        let tag = AmbientTag::new(
            0xA000 + i as u64,
            AmbientDeviceClass::Class1Passive,
            [5.0, (i as f64 - 2.5) * 1.0, 1.0],
        );
        engine.add_tag(tag);
    }

    // Run inventory rounds until all tags are read
    let mut total_inventoried = Vec::new();
    for _round in 1..=10 {
        let read_tags = engine.run_inventory_round();
        total_inventoried.extend(read_tags);
        if total_inventoried.len() == 4 {
            break;
        }
    }

    // All 4 tags must have been inventoried
    assert_eq!(
        total_inventoried.len(),
        4,
        "All 4 tags should be inventoried"
    );
    for tag in &engine.tags {
        assert!(
            tag.is_inventoried,
            "Tag {:#X} should be marked inventoried",
            tag.tag_id
        );
    }

    // Verify Q algorithm step adjustments
    let mut q = QAlgorithm::new(4.0);
    assert_eq!(q.slot_count(), 16);

    q.feedback_collision();
    assert_eq!(q.q_float, 4.8);

    q.feedback_empty();
    assert_eq!(q.q_float, 4.6);

    q.feedback_success();
    assert_eq!(q.q_float, 4.5);
}

#[test]
fn test_device_class_behavior_and_storage() {
    let mut tag_c2 = AmbientTag::new(0x5001, AmbientDeviceClass::Class2Assisted, [10.0, 0.0, 1.0]);

    // Simulate energy harvesting accumulation over time:
    // 10 microwatts * 100 ms = 1 microjoule
    tag_c2.stored_energy_uj += 10.0 * 0.1;
    assert_eq!(tag_c2.stored_energy_uj, 1.0);

    // Consume energy for sensing (0.4 uJ)
    tag_c2.stored_energy_uj -= 0.4;
    assert!((tag_c2.stored_energy_uj - 0.6).abs() < 1e-6);
}

#[test]
fn test_error_handling_and_parameter_validation() {
    // 0 Hz carrier frequency should error
    let err_fc = AmbientIotEngine::new(
        0.0,
        30.0,
        TopologyMode::Monostatic {
            gnb_pos: [0.0, 0.0, 0.0],
            carrier_leakage_cancellation_db: 90.0,
        },
        LineCoding::Fm0,
        BackscatterModulation::Ook,
    );
    assert!(matches!(
        err_fc,
        Err(AmbientIotError::InvalidConfiguration(_))
    ));

    // Error formatting display checks
    let err_power = AmbientIotError::InsufficientHarvestedPower {
        incident_dbm: -25.0,
        threshold_dbm: -20.0,
    };
    assert!(
        err_power
            .to_string()
            .contains("Incident RF power -25.0 dBm")
    );

    let err_crc = AmbientIotError::CrcMismatch {
        computed: 0x1234,
        received: 0x5678,
    };
    assert!(err_crc.to_string().contains("CRC-16 mismatch"));
}
