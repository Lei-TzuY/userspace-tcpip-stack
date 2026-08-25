use toy_tcpip::gtpu_telemetry::{GtpuTelemetryEngine, PDU_SESSION_TYPE_UL, PduSessionTelemetry};

#[test]
fn test_gtpu_pdu_session_container_telemetry_codec() {
    let tel = PduSessionTelemetry::new(PDU_SESSION_TYPE_UL, 9, true, Some(450));
    let wire = tel.serialize();

    let parsed = PduSessionTelemetry::parse(&wire).expect("parse PDU session container");
    assert_eq!(parsed.pdu_type, PDU_SESSION_TYPE_UL);
    assert_eq!(parsed.qfi, 9);
    assert_eq!(parsed.rqi, true);
    assert_eq!(parsed.delay_result_us, Some(450));
}

#[test]
fn test_gtpu_telemetry_engine_encapsulate_and_decapsulate() {
    let mut engine = GtpuTelemetryEngine::new();
    let teid = 0x20004001;
    let qfi = 5;
    let delay_us = Some(120);
    let payload = b"5G-RAN-User-Traffic";

    let pkt = engine.encapsulate(teid, qfi, false, delay_us, payload);
    let wire = pkt.serialize();

    let decapsulated = engine.decapsulate(&wire).expect("decapsulate packet");
    assert_eq!(decapsulated.teid, teid);
    assert_eq!(decapsulated.telemetry.qfi, qfi);
    assert_eq!(decapsulated.telemetry.rqi, false);
    assert_eq!(decapsulated.telemetry.delay_result_us, delay_us);
    assert_eq!(decapsulated.payload, payload);

    assert_eq!(engine.encapsulated_count, 1);
    assert_eq!(engine.decapsulated_count, 1);
    assert_eq!(engine.total_delay_us_accumulated, 240);
}
