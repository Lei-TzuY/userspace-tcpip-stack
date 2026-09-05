use toy_tcpip::ptp_tc::{HopMeasurement, PtpTcError, TransparentClockEngine, TransparentClockMode};

#[test]
fn test_ptp_tc_e2e_residence_time_accumulation() {
    let mut tc = TransparentClockEngine::new(TransparentClockMode::EndToEnd);
    let hop1 = HopMeasurement {
        ingress_timestamp_ns: 1000,
        egress_timestamp_ns: 1250,
    };
    let hop2 = HopMeasurement {
        ingress_timestamp_ns: 5000,
        egress_timestamp_ns: 5180,
    };

    let corr1 = tc.update_correction_field(0, &hop1).unwrap();
    assert_eq!(corr1, 250);

    let corr2 = tc.update_correction_field(corr1, &hop2).unwrap();
    assert_eq!(corr2, 430);

    assert_eq!(tc.corrected_packets_count, 2);
    assert_eq!(tc.total_residence_time_ns, 430);
}

#[test]
fn test_ptp_tc_p2p_peer_delay_and_scaled_ns() {
    let mut tc = TransparentClockEngine::new(TransparentClockMode::PeerToPeer);
    let pdelay = tc.calculate_peer_delay(100, 200, 250, 450).unwrap();
    assert_eq!(pdelay, 150);

    let hop = HopMeasurement {
        ingress_timestamp_ns: 10_000,
        egress_timestamp_ns: 10_100,
    };

    let updated = tc.update_correction_field(20, &hop).unwrap();
    assert_eq!(updated, 270);

    let scaled = TransparentClockEngine::to_scaled_nanoseconds(updated).unwrap();
    assert_eq!(TransparentClockEngine::from_scaled_nanoseconds(scaled), 270);
}

#[test]
fn test_ptp_tc_rejects_peer_turnaround_larger_than_round_trip() {
    let mut tc = TransparentClockEngine::new(TransparentClockMode::PeerToPeer);
    assert_eq!(
        tc.calculate_peer_delay(100, 200, 600, 450),
        Err(PtpTcError::InvalidPeerDelayTimestamps)
    );
    assert_eq!(tc.peer_delay_ns, 0);
}

#[test]
fn test_ptp_tc_rejects_total_residence_overflow_without_partial_mutation() {
    let mut tc = TransparentClockEngine::new(TransparentClockMode::EndToEnd);
    tc.total_residence_time_ns = u64::MAX;
    tc.corrected_packets_count = 7;
    let hop = HopMeasurement {
        ingress_timestamp_ns: 10,
        egress_timestamp_ns: 11,
    };

    assert_eq!(
        tc.update_correction_field(0, &hop),
        Err(PtpTcError::ArithmeticOverflow)
    );
    assert_eq!(tc.total_residence_time_ns, u64::MAX);
    assert_eq!(tc.corrected_packets_count, 7);
}
