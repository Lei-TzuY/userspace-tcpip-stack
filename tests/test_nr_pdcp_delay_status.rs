//! Integration tests for 3GPP Rel-18/19 PDCP Data Volume and Delay Status Reporting.
//!
//! Validates:
//! - SDU enqueue, sequence numbering, and FIFO transmission
//! - TS 38.323 §5.2.1 discardTimer autonomous purging and cumulative metrics
//! - Excess Delay tracking (packet count and aggregated byte volume)
//! - Imminent Discard predictive horizon triggering
//! - HOL delay threshold and buffer volume event triggers
//! - Periodic reporting cadence
//! - 3GPP TS 38.323 §6.2.3.6 Control PDU binary serialization & parsing
//! - Binary wire framing (`NrPdcpDelayWirePdu`) with CRC-16 CCITT integrity

use toy_tcpip::nr_pdcp_delay_status::{
    NrPdcpDelayWirePdu, PdcpDelayReportConfig, PdcpDelayStatusEngine,
    PdcpDelayStatusError, ReportTriggerReason, PDCP_DELAY_CONTROL_PDU_SIZE,
    PDU_TYPE_DATA_VOLUME_AND_DELAY_STATUS,
};

#[test]
fn test_pdcp_sdu_enqueue_and_fifo_transmit() {
    let config = PdcpDelayReportConfig {
        drb_id: 2,
        discard_timer_us: None, // No discard for this test
        excess_delay_threshold_us: 10_000,
        report_interval_us: None,
        hol_delay_threshold_us: None,
        volume_threshold_bytes: None,
        imminent_discard_window_us: 2_000,
        max_buffer_capacity: 10,
    };

    let mut engine = PdcpDelayStatusEngine::new(config);

    // Enqueue 3 SDUs
    let sn0 = engine.enqueue_sdu(1000, 1).unwrap();
    let sn1 = engine.enqueue_sdu(1500, 1).unwrap();
    let sn2 = engine.enqueue_sdu(800, 2).unwrap();

    assert_eq!(sn0, 0);
    assert_eq!(sn1, 1);
    assert_eq!(sn2, 2);

    // Poll status report
    let rep = engine.poll_report();
    assert_eq!(rep.drb_id, 2);
    assert_eq!(rep.total_pending_sdus, 3);
    assert_eq!(rep.total_buffered_bytes, 3300);

    // Dequeue in FIFO order
    let p0 = engine.transmit_sdu().unwrap();
    assert_eq!(p0.sn, 0);
    assert_eq!(p0.size_bytes, 1000);

    let p1 = engine.transmit_sdu().unwrap();
    assert_eq!(p1.sn, 1);

    let p2 = engine.transmit_sdu().unwrap();
    assert_eq!(p2.sn, 2);

    assert!(engine.transmit_sdu().is_none());
}

#[test]
fn test_pdcp_discard_timer_autonomous_purge() {
    let config = PdcpDelayReportConfig {
        drb_id: 1,
        discard_timer_us: Some(15_000), // 15 ms discard timer (XR video)
        excess_delay_threshold_us: 10_000,
        report_interval_us: None,
        hol_delay_threshold_us: None,
        volume_threshold_bytes: None,
        imminent_discard_window_us: 3_000,
        max_buffer_capacity: 100,
    };

    let mut engine = PdcpDelayStatusEngine::new(config);

    // Enqueue SDU 0 at t = 0
    engine.enqueue_sdu(1200, 1).unwrap();

    // Advance time to t = 5 ms (5,000 us)
    engine.advance_time(5_000);
    // Enqueue SDU 1 at t = 5 ms
    engine.enqueue_sdu(1400, 1).unwrap();

    // Advance time to t = 16 ms (16,000 us)
    // SDU 0 age = 16 ms > 15 ms -> discarded!
    // SDU 1 age = 16 - 5 = 11 ms < 15 ms -> retained!
    engine.advance_time(16_000);

    let rep = engine.poll_report();
    assert_eq!(rep.cumulative_discarded_sdus, 1);
    assert_eq!(rep.total_pending_sdus, 1);
    assert_eq!(rep.total_buffered_bytes, 1400);
    assert_eq!(rep.hol_delay_us, 11_000); // Oldest remaining SDU is SDU 1 with 11 ms delay
}

#[test]
fn test_excess_delay_volume_and_count_accounting() {
    let config = PdcpDelayReportConfig {
        drb_id: 3,
        discard_timer_us: Some(30_000),
        excess_delay_threshold_us: 10_000, // 10 ms excess delay threshold
        report_interval_us: None,
        hol_delay_threshold_us: None,
        volume_threshold_bytes: None,
        imminent_discard_window_us: 2_000,
        max_buffer_capacity: 100,
    };

    let mut engine = PdcpDelayStatusEngine::new(config);

    // Enqueue SDU 0 at t = 0 ms (1000 bytes)
    engine.enqueue_sdu(1000, 1).unwrap();

    // Advance to t = 4 ms and enqueue SDU 1 (2000 bytes)
    engine.advance_time(4_000);
    engine.enqueue_sdu(2000, 1).unwrap();

    // Advance to t = 8 ms and enqueue SDU 2 (3000 bytes)
    engine.advance_time(8_000);
    engine.enqueue_sdu(3000, 1).unwrap();

    // Advance to t = 12 ms:
    // SDU 0: age 12 ms >= 10 ms -> Excess Delay!
    // SDU 1: age 8 ms < 10 ms -> Not excess
    // SDU 2: age 4 ms < 10 ms -> Not excess
    engine.advance_time(12_000);

    let rep = engine.poll_report();
    assert_eq!(rep.excess_delay_count, 1);
    assert_eq!(rep.excess_delay_bytes, 1000);
    assert_eq!(rep.total_buffered_bytes, 6000);

    // Advance to t = 15 ms:
    // SDU 0: age 15 ms -> Excess
    // SDU 1: age 11 ms -> Excess
    // SDU 2: age 7 ms -> Not excess
    engine.advance_time(15_000);

    let rep2 = engine.poll_report();
    assert_eq!(rep2.excess_delay_count, 2);
    assert_eq!(rep2.excess_delay_bytes, 3000); // 1000 + 2000
}

#[test]
fn test_imminent_discard_alert_trigger() {
    let config = PdcpDelayReportConfig {
        drb_id: 1,
        discard_timer_us: Some(15_000),      // 15 ms
        excess_delay_threshold_us: 10_000,
        report_interval_us: None,            // No periodic
        hol_delay_threshold_us: None,
        volume_threshold_bytes: None,
        imminent_discard_window_us: 2_000,   // SDUs expiring within 2 ms (age >= 13 ms)
        max_buffer_capacity: 100,
    };

    let mut engine = PdcpDelayStatusEngine::new(config);
    engine.enqueue_sdu(1400, 1).unwrap();

    // Advance to t = 10 ms: age = 10 ms, remaining = 5 ms > 2 ms -> no alert
    let rep10 = engine.advance_time(10_000);
    assert!(rep10.is_none());

    // Advance to t = 13.5 ms: age = 13.5 ms, remaining = 1.5 ms <= 2 ms -> Imminent Discard Trigger!
    let rep13 = engine.advance_time(13_500);
    assert!(rep13.is_some());
    let rep = rep13.unwrap();
    assert_eq!(rep.trigger, ReportTriggerReason::ImminentDiscardAlert);
    assert_eq!(rep.imminent_discard_count, 1);
    assert_eq!(rep.imminent_discard_bytes, 1400);
}

#[test]
fn test_hol_delay_threshold_trigger() {
    let config = PdcpDelayReportConfig {
        drb_id: 1,
        discard_timer_us: None,
        excess_delay_threshold_us: 20_000,
        report_interval_us: None,
        hol_delay_threshold_us: Some(6_000), // 6 ms HOL threshold
        volume_threshold_bytes: None,
        imminent_discard_window_us: 1_000,
        max_buffer_capacity: 50,
    };

    let mut engine = PdcpDelayStatusEngine::new(config);
    engine.enqueue_sdu(500, 1).unwrap();

    // Advance to t = 4 ms -> no report
    assert!(engine.advance_time(4_000).is_none());

    // Advance to t = 6.2 ms -> HOL delay = 6.2 ms >= 6 ms -> HolDelayThresholdExceeded trigger!
    let rep = engine.advance_time(6_200).expect("Should trigger HOL report");
    assert_eq!(rep.trigger, ReportTriggerReason::HolDelayThresholdExceeded);
    assert_eq!(rep.hol_delay_us, 6_200);
}

#[test]
fn test_buffer_volume_threshold_trigger() {
    let config = PdcpDelayReportConfig {
        drb_id: 2,
        discard_timer_us: None,
        excess_delay_threshold_us: 50_000,
        report_interval_us: None,
        hol_delay_threshold_us: None,
        volume_threshold_bytes: Some(5_000), // 5 KB threshold
        imminent_discard_window_us: 1_000,
        max_buffer_capacity: 50,
    };

    let mut engine = PdcpDelayStatusEngine::new(config);

    // Enqueue 4 KB -> total 4 KB < 5 KB -> no report
    engine.enqueue_sdu(4_000, 1).unwrap();
    assert!(engine.evaluate_triggers().is_none());

    // Enqueue 2 KB -> total 6 KB >= 5 KB -> VolumeThresholdExceeded trigger!
    engine.enqueue_sdu(2_000, 1).unwrap();
    let rep = engine.evaluate_triggers().expect("Should trigger volume report");
    assert_eq!(rep.trigger, ReportTriggerReason::VolumeThresholdExceeded);
    assert_eq!(rep.total_buffered_bytes, 6_000);
}

#[test]
fn test_periodic_reporting_cadence() {
    let config = PdcpDelayReportConfig {
        drb_id: 1,
        discard_timer_us: None,
        excess_delay_threshold_us: 20_000,
        report_interval_us: Some(10_000), // 10 ms periodic interval
        hol_delay_threshold_us: None,
        volume_threshold_bytes: None,
        imminent_discard_window_us: 1_000,
        max_buffer_capacity: 100,
    };

    let mut engine = PdcpDelayStatusEngine::new(config);
    engine.enqueue_sdu(800, 1).unwrap();

    // Advance to 5 ms -> interval not reached
    assert!(engine.advance_time(5_000).is_none());

    // Advance to 10 ms -> Periodic trigger!
    let rep10 = engine.advance_time(10_000).expect("Periodic trigger at 10 ms");
    assert_eq!(rep10.trigger, ReportTriggerReason::Periodic);

    // Advance to 15 ms -> interval not reached
    assert!(engine.advance_time(15_000).is_none());

    // Advance to 20 ms -> Periodic trigger!
    let rep20 = engine.advance_time(20_000).expect("Periodic trigger at 20 ms");
    assert_eq!(rep20.trigger, ReportTriggerReason::Periodic);
}

#[test]
fn test_ts38323_control_pdu_encode_decode_roundtrip() {
    let report = toy_tcpip::nr_pdcp_delay_status::PdcpDelayStatusReport {
        drb_id: 5,
        trigger: ReportTriggerReason::HolDelayThresholdExceeded,
        hol_delay_us: 12_400, // 12.4 ms -> 124 units of 100 us
        total_buffered_bytes: 48_500,
        total_pending_sdus: 32,
        excess_delay_bytes: 15_000,
        excess_delay_count: 10,
        imminent_discard_bytes: 4_200,
        imminent_discard_count: 3,
        cumulative_discarded_sdus: 7,
        report_timestamp_us: 100_000,
    };

    let pdu_bytes = PdcpDelayStatusEngine::encode_control_pdu(&report);
    assert_eq!(pdu_bytes.len(), PDCP_DELAY_CONTROL_PDU_SIZE);

    // Check Header Byte 0: D/C=0 (bit 7), PDU Type = 010 (bits 6-4)
    let dc_bit = (pdu_bytes[0] >> 7) & 0x01;
    let pdu_type = (pdu_bytes[0] >> 4) & 0x07;
    assert_eq!(dc_bit, 0);
    assert_eq!(pdu_type, PDU_TYPE_DATA_VOLUME_AND_DELAY_STATUS);

    // Decode Control PDU
    let decoded = PdcpDelayStatusEngine::decode_control_pdu(&pdu_bytes).unwrap();
    assert_eq!(decoded.drb_id, 5);
    assert_eq!(decoded.trigger, ReportTriggerReason::HolDelayThresholdExceeded);
    assert_eq!(decoded.hol_delay_us, 12_400);
    assert_eq!(decoded.total_buffered_bytes, 48_500);
    assert_eq!(decoded.total_pending_sdus, 32);
    assert_eq!(decoded.excess_delay_bytes, 15_000);
    assert_eq!(decoded.excess_delay_count, 10);
    assert_eq!(decoded.imminent_discard_bytes, 4_200);
    assert_eq!(decoded.imminent_discard_count, 3);
}

#[test]
fn test_wire_pdu_framing_and_crc16() {
    let wire = NrPdcpDelayWirePdu {
        sfn: 102,
        slot: 14,
        drb_id: 3,
        trigger_code: ReportTriggerReason::Periodic.to_code(),
        hol_delay_units: 75, // 7.5 ms
        total_volume_bytes: 32_000,
        pending_sdus: 20,
        excess_volume_bytes: 8_000,
        discarded_sdus: 2,
    };

    let raw = wire.to_wire_bytes();
    assert_eq!(raw.len(), toy_tcpip::nr_pdcp_delay_status::PDCP_DELAY_WIRE_PDU_SIZE);

    let parsed = NrPdcpDelayWirePdu::from_wire_bytes(&raw).unwrap();
    assert_eq!(parsed, wire);

    // Test CRC-16 corruption detection
    let mut corrupted = raw.clone();
    corrupted[10] ^= 0xFF; // Corrupt HOL delay
    let err = NrPdcpDelayWirePdu::from_wire_bytes(&corrupted).unwrap_err();
    match err {
        PdcpDelayStatusError::WireCrcMismatch { .. } => (),
        other => panic!("Expected WireCrcMismatch, got {:?}", other),
    }

    // Test Invalid Magic
    let mut bad_magic = raw.clone();
    bad_magic[0] = 0x00;
    let err2 = NrPdcpDelayWirePdu::from_wire_bytes(&bad_magic).unwrap_err();
    match err2 {
        PdcpDelayStatusError::InvalidWireMagic(_) => (),
        other => panic!("Expected InvalidWireMagic, got {:?}", other),
    }
}
