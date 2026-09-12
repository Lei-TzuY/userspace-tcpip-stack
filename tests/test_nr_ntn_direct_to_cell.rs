//! Integration tests for 3GPP Rel-18/19 NTN Direct-to-Cell (D2C) and Satellite-to-Handheld Engine.

use toy_tcpip::nr_ntn_direct_to_cell::*;

#[test]
fn test_band_properties() {
    let band_s = D2cBand::BandS2GHz;
    assert_eq!(band_s.carrier_frequency_hz(), 2.0e9);
    assert!((band_s.wavelength_meters() - 0.149896).abs() < 1e-4);

    let band_sub = D2cBand::BandSubGHz750;
    assert_eq!(band_sub.carrier_frequency_hz(), 750.0e6);
    assert!((band_sub.wavelength_meters() - 0.399723).abs() < 1e-4);

    let band_mid = D2cBand::BandMidGHz1900;
    assert_eq!(band_mid.carrier_frequency_hz(), 1.9e9);
}

#[test]
fn test_d2c_service_types_from_u8() {
    assert_eq!(
        D2cServiceType::from_u8(1).unwrap(),
        D2cServiceType::EmergencySos
    );
    assert_eq!(
        D2cServiceType::from_u8(2).unwrap(),
        D2cServiceType::TwoWaySms
    );
    assert_eq!(
        D2cServiceType::from_u8(3).unwrap(),
        D2cServiceType::NarrowbandVoNr
    );
    assert_eq!(
        D2cServiceType::from_u8(4).unwrap(),
        D2cServiceType::LocationBeacon
    );
    assert!(D2cServiceType::from_u8(0).is_err());
    assert!(D2cServiceType::from_u8(5).is_err());

    assert_eq!(D2cServiceType::EmergencySos.min_required_snr_db(), -6.0);
    assert_eq!(D2cServiceType::TwoWaySms.min_required_snr_db(), -3.0);
}

#[test]
fn test_crc16_integrity() {
    let msg = b"3GPP-TR-38.882-DirectToCell-Rel19";
    let crc1 = compute_crc16(msg);
    let crc2 = compute_crc16(msg);
    assert_eq!(crc1, crc2);
    assert_ne!(crc1, 0);

    let mut corrupted = msg.to_vec();
    corrupted[0] ^= 0x01;
    let crc_bad = compute_crc16(&corrupted);
    assert_ne!(crc1, crc_bad);
}

#[test]
fn test_packet_wire_codec_emergency_sos() {
    let lat = 37.7749;
    let lon = -122.4194;
    let pkt = D2cPacket::new_emergency_sos(101, 8888, lat, lon, 1000);
    assert_eq!(pkt.service_type, D2cServiceType::EmergencySos);
    assert_eq!(pkt.priority, 1);
    assert_eq!(pkt.sender_ue_id, 8888);

    let wire = pkt.encode_wire();
    // Magic check 'D', '2', 'C', 0x13
    assert_eq!(wire[0], 0x44);
    assert_eq!(wire[1], 0x32);
    assert_eq!(wire[2], 0x43);
    assert_eq!(wire[3], 0x13);

    let decoded = D2cPacket::decode_wire(&wire).expect("decoding failed");
    assert_eq!(decoded.message_id, 101);
    assert_eq!(decoded.service_type, D2cServiceType::EmergencySos);
    assert_eq!(decoded.priority, 1);
    assert_eq!(decoded.sender_ue_id, 8888);
    assert_eq!(decoded.timestamp_ms, 1000);

    // Verify reconstructed coordinates
    let lat_bits = u64::from_be_bytes(decoded.payload[0..8].try_into().unwrap());
    let lon_bits = u64::from_be_bytes(decoded.payload[8..16].try_into().unwrap());
    assert!((f64::from_bits(lat_bits) - lat).abs() < 1e-6);
    assert!((f64::from_bits(lon_bits) - lon).abs() < 1e-6);

    // Corrupt CRC
    let mut bad_crc = wire.clone();
    let last = bad_crc.len() - 1;
    bad_crc[last] ^= 0xFF;
    assert!(matches!(
        D2cPacket::decode_wire(&bad_crc),
        Err(D2cError::ChecksumMismatch { .. })
    ));

    // Corrupt Magic
    let mut bad_magic = wire.clone();
    bad_magic[0] = 0x00;
    let new_crc = compute_crc16(&bad_magic[..bad_magic.len() - 2]);
    let len = bad_magic.len();
    bad_magic[len - 2..len].copy_from_slice(&new_crc.to_be_bytes());
    assert!(matches!(
        D2cPacket::decode_wire(&bad_magic),
        Err(D2cError::DeserializationError(msg)) if msg.contains("magic")
    ));

    // Truncated buffer
    assert!(D2cPacket::decode_wire(&wire[..10]).is_err());
}

#[test]
fn test_two_way_sms_wire_codec() {
    let text = "Direct-to-Cell SOS Received. Rescue team dispatched.";
    let pkt = D2cPacket {
        message_id: 202,
        service_type: D2cServiceType::TwoWaySms,
        priority: 2,
        sender_ue_id: 9999,
        payload: text.as_bytes().to_vec(),
        timestamp_ms: 2500,
    };

    let wire = pkt.encode_wire();
    let decoded = D2cPacket::decode_wire(&wire).expect("sms decode failed");
    assert_eq!(decoded.message_id, 202);
    assert_eq!(decoded.service_type, D2cServiceType::TwoWaySms);
    let decoded_text = String::from_utf8(decoded.payload).expect("utf8 decode failed");
    assert_eq!(decoded_text, text);
}

#[test]
fn test_spherical_geometry_zenith() {
    let engine = NtnDirectToCellEngine::new(
        D2cBand::BandS2GHz,
        PhasedArrayConfig::default(),
        SatelliteOrbitState {
            altitude_km: 550.0,
            velocity_km_s: 7.6,
            sub_satellite_lat: 40.0,
            sub_satellite_lon: -105.0,
        },
        HandheldLocation {
            latitude_deg: 40.0,
            longitude_deg: -105.0,
            altitude_m: 0.0,
            body_loss_db: 3.0,
            foliage_loss_db: 0.0,
        },
    );

    // Sub-satellite point and handheld are identical -> zenith
    assert_eq!(engine.angular_separation_rad(), 0.0);
    assert!((engine.calculate_elevation_deg() - 90.0).abs() < 1e-4);
    assert!((engine.calculate_slant_range_km() - 550.0).abs() < 1e-4);
}

#[test]
fn test_link_budget_evaluation_zenith() {
    let mut engine = NtnDirectToCellEngine::new(
        D2cBand::BandS2GHz,
        PhasedArrayConfig::default(),
        SatelliteOrbitState {
            altitude_km: 550.0,
            velocity_km_s: 7.6,
            sub_satellite_lat: 37.7749,
            sub_satellite_lon: -122.4194,
        },
        HandheldLocation::default(),
    );

    let budget = engine.evaluate_link_budget().expect("link budget failed");
    assert!((budget.elevation_deg - 90.0).abs() < 1e-4);
    assert!((budget.slant_range_km - 550.0).abs() < 1e-4);

    // Free space path loss at 550 km and 2 GHz should be ~ 153.3 dB
    assert!((budget.fspl_db - 153.28).abs() < 0.5);

    // Downlink SNR should be high with 58 dBW satellite EIRP
    assert!(budget.dl_snr_db > 20.0);
    assert_eq!(budget.max_supported_mcs, 24); // 256QAM supported

    // Uplink SNR with 1024-element phased array
    assert!(budget.ul_snr_db > 10.0);
    assert_eq!(budget.required_repetition_factor, 1);

    // Sidelobe EPFD compliance (< -120 dBW/m2/MHz)
    assert!(budget.epfd_compliant);
    assert!(budget.epfd_dbw_m2_mhz <= -120.0);

    // Telemetry check
    let tel = engine.telemetry();
    assert_eq!(tel.link_budget_evaluations, 1);
    assert_eq!(tel.epfd_checks_performed, 1);
    assert_eq!(tel.epfd_violations_detected, 0);
    assert!(tel.average_dl_snr_db() > 20.0);
}

#[test]
fn test_link_budget_elevation_mask_rejection() {
    let mut engine = NtnDirectToCellEngine::new(
        D2cBand::BandS2GHz,
        PhasedArrayConfig::default(),
        SatelliteOrbitState {
            altitude_km: 550.0,
            velocity_km_s: 7.6,
            sub_satellite_lat: 10.0, // Far away
            sub_satellite_lon: -122.4194,
        },
        HandheldLocation::default(),
    );

    let res = engine.evaluate_link_budget();
    assert!(matches!(res, Err(D2cError::ElevationBelowMask { .. })));
}

#[test]
fn test_emergency_sos_and_sms_flows() {
    let mut engine = NtnDirectToCellEngine::new(
        D2cBand::BandS2GHz,
        PhasedArrayConfig::default(),
        SatelliteOrbitState::default(),
        HandheldLocation::default(),
    );

    assert_eq!(engine.handheld_state(), HandheldD2cState::IdleSearch);

    // Perform initial access
    let init_budget = engine
        .perform_initial_access()
        .expect("initial access failed");
    assert!(init_budget.epfd_compliant);
    assert_eq!(engine.handheld_state(), HandheldD2cState::ConnectedDirect);

    // Dispatch Emergency SOS
    let sos_pkt = engine
        .send_emergency_sos(1, 1001)
        .expect("send emergency SOS failed");
    assert_eq!(sos_pkt.service_type, D2cServiceType::EmergencySos);
    assert_eq!(
        engine.handheld_state(),
        HandheldD2cState::EmergencySosActive
    );

    // Dispatch Two-Way SMS
    let sms_pkt = engine
        .send_two_way_sms(2, 1001, "Need immediate medical help at coordinates")
        .expect("send sms failed");
    assert_eq!(sms_pkt.service_type, D2cServiceType::TwoWaySms);

    let tel = engine.telemetry();
    assert_eq!(tel.sos_packets_dispatched, 1);
    assert_eq!(tel.packets_transmitted, 2);
    assert_eq!(tel.packets_received_ok, 2);
    assert_eq!(tel.packet_delivery_rate(), 100.0);
}

#[test]
fn test_repetition_servo_with_severe_attenuation() {
    let mut loc = HandheldLocation::default();
    loc.body_loss_db = 6.0;
    loc.foliage_loss_db = 22.0; // 28 dB total clutter loss under dense forest canopy!

    let mut engine = NtnDirectToCellEngine::new(
        D2cBand::BandS2GHz,
        PhasedArrayConfig::default(),
        SatelliteOrbitState::default(),
        loc,
    );

    let budget = engine.evaluate_link_budget().expect("budget failed");
    // With 21 dB extra attenuation, uplink SNR should drop, triggering higher repetition factor
    assert!(budget.required_repetition_factor >= 4);
}

#[test]
fn test_handover_evaluation() {
    let mut engine = NtnDirectToCellEngine::new(
        D2cBand::BandS2GHz,
        PhasedArrayConfig::default(),
        SatelliteOrbitState {
            altitude_km: 550.0,
            velocity_km_s: 7.6,
            sub_satellite_lat: 37.7749 + 11.5, // Near the 15° elevation boundary
            sub_satellite_lon: -122.4194,
        },
        HandheldLocation::default(),
    );

    let next_sat = SatelliteOrbitState {
        altitude_km: 550.0,
        velocity_km_s: 7.6,
        sub_satellite_lat: 37.7749, // Directly overhead
        sub_satellite_lon: -122.4194,
    };

    let handed_over = engine.evaluate_handover(Some(next_sat));
    assert!(handed_over);
    assert_eq!(engine.handheld_state(), HandheldD2cState::ConnectedDirect);
    assert_eq!(engine.telemetry().beam_handovers_completed, 1);

    // Advance time
    engine.advance_time_ms(10_000);
    assert_eq!(engine.telemetry().beam_handovers_completed, 1);
}

#[test]
fn test_error_display() {
    let err1 = D2cError::ElevationBelowMask {
        elevation_deg: 10.5,
        min_deg: 15.0,
    };
    assert!(format!("{}", err1).contains("10.5"));

    let err2 = D2cError::EpfdViolation {
        epfd_dbw: -115.0,
        limit_dbw: -120.0,
    };
    assert!(format!("{}", err2).contains("-115.00"));

    let err3 = D2cError::ChecksumMismatch {
        expected: 0xAAAA,
        calculated: 0xBBBB,
    };
    assert!(format!("{}", err3).contains("0xAAAA"));
}
