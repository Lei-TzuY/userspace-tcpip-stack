use toy_tcpip::ptp_telecom_tc::TelecomPeerTransparentClockEngine;

#[test]
fn test_ptp_telecom_p2p_transparent_clock_correction() {
    let mut tc = TelecomPeerTransparentClockEngine::new();

    // Port 1 link delay measurement:
    // t1 = 1000ns, t2 = 1200ns, t3 = 2000ns, t4 = 2400ns
    // Peer Delay = ((2400 - 1000) - (2000 - 1200)) / 2 = (1400 - 800) / 2 = 300ns
    let delay = tc.compute_peer_delay(1000, 1200, 2000, 2400);
    assert_eq!(delay, 300);

    tc.set_port_peer_delay(1, delay);

    // Event packet residence correction:
    // Ingress Port 1 at Tin = 5000ns, Egress Port 2 at Tout = 5600ns (Residence Time = 600ns)
    // Initial correction = 50ns
    // Expected correction = 50 + 600 (residence) + 300 (peer delay) = 950ns
    let updated_corr = tc.correct_event_packet(1, 5000, 5600, 50);
    assert_eq!(updated_corr, 950);
    assert_eq!(tc.corrections_performed, 1);
    assert_eq!(tc.accumulated_correction_ns, 900);
}

#[test]
fn test_ptp_telecom_e2e_transparent_clock_mode() {
    use toy_tcpip::ptp_telecom_tc::TelecomTcMode;

    let mut tc = TelecomPeerTransparentClockEngine::new().with_mode(TelecomTcMode::EndToEnd);
    tc.set_port_peer_delay(1, 400); // Should be ignored in E2E mode

    // Residence time = 500ns (5500 - 5000)
    // In E2E TC, only residence time is added to correctionField (no peer link delay)
    let updated = tc.correct_event_packet(1, 5000, 5500, 100);
    assert_eq!(updated, 600); // 100 + 500
}

#[test]
fn test_ptp_telecom_sub_nanosecond_scaled_correction_and_asymmetry() {
    use toy_tcpip::ptp_telecom_tc::{PTP_SUB_NS_SCALE, TelecomPeerTransparentClockEngine};

    assert_eq!(PTP_SUB_NS_SCALE, 65536);
    let mut tc = TelecomPeerTransparentClockEngine::new();
    tc.set_port_peer_delay(1, 200); // 200 ns peer delay
    tc.set_port_asymmetry(1, 15); // +15 ns fiber asymmetry

    // Initial correction = 10.5 ns = 10.5 * 65536 = 688128 scaled units
    let initial_scaled = TelecomPeerTransparentClockEngine::to_scaled_nanoseconds(10.5);
    assert_eq!(initial_scaled, 688128);

    // Residence time = 400 ns (1400 - 1000)
    // Delta = 400 (residence) + 200 (peer delay) + 15 (asymmetry) = 615 ns
    // Delta scaled = 615 * 65536 = 40304640 units
    let result_scaled = tc.correct_event_packet_scaled(1, 1000, 1400, initial_scaled);
    assert_eq!(result_scaled, 688128 + 40304640);

    let result_ns = TelecomPeerTransparentClockEngine::from_scaled_nanoseconds(result_scaled);
    assert!((result_ns - 625.5).abs() < 1e-6);
}

#[test]
fn test_ptp_telecom_header_in_place_correction() {
    use toy_tcpip::ptp::{PTP_MSG_SYNC, PtpHeader};

    let mut tc = TelecomPeerTransparentClockEngine::new();
    tc.set_port_peer_delay(2, 150);

    let mut hdr = PtpHeader {
        message_type: PTP_MSG_SYNC,
        version: 2,
        message_length: 44,
        domain_number: 24, // Telecom profile domain
        flags: 0x0200,     // Two-step
        correction_field: 0,
        clock_identity: [1; 8],
        source_port_id: 1,
        sequence_id: 101,
        control_field: 0,
        log_message_interval: -4,
    };

    // Transit: ingress Port 2 at 10_000 ns, egress at 10_350 ns (residence = 350 ns)
    // Delta = 350 + 150 = 500 ns = 500 * 65536 = 32768000 scaled units
    tc.correct_ptp_header(&mut hdr, 2, 10_000, 10_350);
    assert_eq!(hdr.correction_field, 500 * 65536);
}

#[test]
fn test_ptp_telecom_peer_delay_with_neighbor_rate_ratio() {
    let tc = TelecomPeerTransparentClockEngine::new();

    // Round-trip = 1400ns, peer turnaround = 800ns
    // When neighbor clock runs 100ppm faster (ratio = 1.0001):
    // Turnaround adjusted = 800 * 1.0001 = 800.08ns
    // Peer delay = (1400 - 800.08) / 2 = 299.96 -> rounds to 300ns
    let delay = tc.compute_peer_delay_with_ratio(1000, 1200, 2000, 2400, 1.0001);
    assert_eq!(delay, 300);

    // Extreme frequency offset ratio 1.05 (turnaround = 840ns)
    // Delay = (1400 - 840) / 2 = 280ns
    let delay_skewed = tc.compute_peer_delay_with_ratio(1000, 1200, 2000, 2400, 1.05);
    assert_eq!(delay_skewed, 280);
}
