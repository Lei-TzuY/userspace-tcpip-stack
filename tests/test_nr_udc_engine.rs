//! Integration tests for 3GPP Rel-17 5G NR Uplink Data Compression (UDC) in PDCP Engine
//!
//! Conforms to 3GPP TS 38.323 §5.14, §6.2.3, §6.3.8, and TS 38.331.

use toy_tcpip::nr_udc_engine::{
    UdcBufferSize, UdcConfig, UdcEngine, UdcFeedbackPdu, UdcHeader, compute_udc_crc4,
};

#[test]
fn test_udc_header_codec_and_crc4() {
    // 1. UDC Header Bit Packing
    // FU = 1 (bit 7), FR = 0 (bit 6), Checksum = 0x0B (bits 5..2: 1011_00)
    let header = UdcHeader::new(true, false, 0x0B);
    let wire_byte = header.serialize();
    assert_eq!(wire_byte, 0xAC); // 1010_1100

    let parsed = UdcHeader::parse(wire_byte);
    assert_eq!(parsed.fu, true);
    assert_eq!(parsed.fr, false);
    assert_eq!(parsed.checksum, 0x0B);

    // 2. Field Reset (FR = 1) Header
    let header_reset = UdcHeader::new(false, true, 0x07);
    let wire_reset = header_reset.serialize();
    assert_eq!(wire_reset, 0x5C); // 0101_1100
    let parsed_reset = UdcHeader::parse(wire_reset);
    assert_eq!(parsed_reset.fu, false);
    assert_eq!(parsed_reset.fr, true);
    assert_eq!(parsed_reset.checksum, 0x07);

    // 3. 4-bit CRC Calculation
    let payload_1 = b"GET /api/v1/telemetry HTTP/1.1\r\nHost: example.org\r\n";
    let payload_2 = b"POST /api/v1/telemetry HTTP/1.1\r\nHost: example.org\r\n";
    let crc_1 = compute_udc_crc4(payload_1);
    let crc_2 = compute_udc_crc4(payload_2);
    assert!(crc_1 <= 15);
    assert!(crc_2 <= 15);
    assert_ne!(
        crc_1, crc_2,
        "Different payloads should produce distinct CRC4"
    );
}

#[test]
fn test_udc_compression_and_decompression_fidelity() {
    let config = UdcConfig {
        buffer_size: UdcBufferSize::Buf4096,
        min_compression_len: 16,
        predefined_dictionary: None,
    };
    let mut engine = UdcEngine::new(config);

    // Realistic repetitive structured uplink payload (e.g. IoT JSON sensor report)
    let packet_template = r#"{"device_id":"ORU-NODE-8877","sensor":"temp","reading":24.5,"unit":"C","status":"HEALTHY","firmware":"v2.1.0"}"#;
    let sdu_1 = packet_template.as_bytes();

    // 1. First packet: dictionary initially empty, populates dictionary
    let pdu_1 = engine.compress_uplink(sdu_1);
    assert_eq!(
        pdu_1[0] & 0x80,
        0x00,
        "First packet uncompressed (dictionary empty)"
    );
    let decomp_1 = engine
        .decompress_uplink(&pdu_1)
        .expect("Decompression must succeed");
    assert_eq!(decomp_1, sdu_1);

    // 2. Second packet with identical structure (only reading changes)
    let sdu_2 = r#"{"device_id":"ORU-NODE-8877","sensor":"temp","reading":25.1,"unit":"C","status":"HEALTHY","firmware":"v2.1.0"}"#.as_bytes();
    let pdu_2 = engine.compress_uplink(sdu_2);
    let header_2 = UdcHeader::parse(pdu_2[0]);
    assert!(
        header_2.fu,
        "Second packet must be compressed using sliding dictionary"
    );
    assert!(
        pdu_2.len() < sdu_2.len(),
        "Compressed PDU must be smaller than SDU"
    );

    let decomp_2 = engine
        .decompress_uplink(&pdu_2)
        .expect("Decompression must succeed");
    assert_eq!(decomp_2, sdu_2);

    // 3. Third packet: repeated patterns
    let sdu_3 = r#"{"device_id":"ORU-NODE-8877","sensor":"temp","reading":25.8,"unit":"C","status":"HEALTHY","firmware":"v2.1.0"}"#.as_bytes();
    let pdu_3 = engine.compress_uplink(sdu_3);
    let decomp_3 = engine
        .decompress_uplink(&pdu_3)
        .expect("Decompression must succeed");
    assert_eq!(decomp_3, sdu_3);
}

#[test]
fn test_udc_sliding_window_buffer_management() {
    // Small 2048-byte buffer to test wrap-around
    let config = UdcConfig {
        buffer_size: UdcBufferSize::Buf2048,
        min_compression_len: 16,
        predefined_dictionary: None,
    };
    let mut engine = UdcEngine::new(config);

    // Stream 20 packets of 200 bytes each (total 4000 bytes > 2048 bytes buffer capacity)
    for i in 0..20 {
        let text = format!(
            "Timestamp: 170000{:04}, SensorReadingIndex: {:05}, Status: Operational, AlertCode: NONE, Mode: CONTINUOUS_TRANSMISSION",
            i, i
        );
        let sdu = text.into_bytes();

        let pdu = engine.compress_uplink(&sdu);
        let decomp = engine
            .decompress_uplink(&pdu)
            .expect("Decompression must succeed across wrap-around");
        assert_eq!(decomp, sdu);
    }
}

#[test]
fn test_udc_desync_detection_and_feedback_reset() {
    let config = UdcConfig {
        buffer_size: UdcBufferSize::Buf2048,
        min_compression_len: 16,
        predefined_dictionary: None,
    };
    let mut engine = UdcEngine::new(config);

    // Warm up dictionary with initial packets
    let initial_data = b"CommonPrefixForSensors_Version_1_0_0_SystemReady_NormalStatus";
    let pdu1 = engine.compress_uplink(initial_data);
    let _ = engine.decompress_uplink(&pdu1).unwrap();

    let sdu2 = b"CommonPrefixForSensors_Version_1_0_0_SystemReady_TemperatureReading_24C";
    let pdu2 = engine.compress_uplink(sdu2);

    // 1. Simulate transmission corruption (bit-flip in payload)
    let mut corrupted_pdu2 = pdu2.clone();
    if corrupted_pdu2.len() > 3 {
        corrupted_pdu2[2] ^= 0xFF; // Flip bits
    }

    // Decompressor must detect CRC mismatch and declare desynchronization
    let result = engine.decompress_uplink(&corrupted_pdu2);
    assert!(result.is_err());
    assert!(engine.decompressor.is_desynchronized);

    // 2. Subsequent packets while desynchronized must be rejected
    let sdu3 = b"CommonPrefixForSensors_Version_1_0_0_SystemReady_PressureReading_1013hPa";
    let pdu3 = engine.compress_uplink(sdu3);
    assert!(engine.decompress_uplink(&pdu3).is_err());

    // 3. Decompressor generates UDC Feedback Control PDU (FE = 1)
    let feedback = engine.decompressor.generate_reset_feedback();
    assert!(feedback.fe);

    let feedback_bytes = feedback.serialize();
    let parsed_feedback = UdcFeedbackPdu::parse(&feedback_bytes).expect("Valid feedback parsing");
    assert!(parsed_feedback.fe);

    // 4. Transmitter handles feedback -> triggers reset
    engine.handle_feedback(&parsed_feedback);

    // 5. Next packet transmitted has FR = 1 (Field Reset)
    let sdu4 = b"CommonPrefixForSensors_Version_1_0_0_SystemReady_ResetRecoveryPacket";
    let pdu4 = engine.compress_uplink(sdu4);
    let header4 = UdcHeader::parse(pdu4[0]);
    assert!(header4.fr, "Transmitter must set FR=1 after reset trigger");

    // 6. Decompressor handles FR=1, clears desync, and successfully decompresses
    let decomp4 = engine
        .decompress_uplink(&pdu4)
        .expect("Decompression must recover upon FR=1");
    assert_eq!(decomp4, sdu4);
    assert!(!engine.decompressor.is_desynchronized);
}

#[test]
fn test_udc_compression_ratio_and_bandwidth_savings() {
    let config = UdcConfig {
        buffer_size: UdcBufferSize::Buf4096,
        min_compression_len: 16,
        predefined_dictionary: None,
    };
    let mut engine = UdcEngine::new(config);

    // 1. Incompressible random noise: should be sent uncompressed with FU=0
    let noise: Vec<u8> = (0..100).map(|i| ((i * 37 + 13) % 256) as u8).collect();
    let noise_pdu = engine.compress_uplink(&noise);
    let noise_header = UdcHeader::parse(noise_pdu[0]);
    assert_eq!(noise_header.fu, false); // Avoid expanding random noise
    assert_eq!(noise_pdu.len(), noise.len() + 1);

    // 2. Highly repetitive structured telemetry
    let repeated_log = "ERROR [2026-09-04 15:00:00.123] [Subsystem-Radio-PHY] Carrier frequency drift detected on Port 0. Action: AFC tuning applied.\n";
    for _ in 0..10 {
        let pdu = engine.compress_uplink(repeated_log.as_bytes());
        let _ = engine.decompress_uplink(&pdu).unwrap();
    }

    let ratio = engine.compressor.compression_ratio();
    assert!(
        ratio < 0.60,
        "UDC on repetitive text should achieve compression ratio < 0.60 (got {:.2})",
        ratio
    );
}
