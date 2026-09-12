//! Comprehensive Integration Tests for 3GPP Rel-18/19 L4S DualQ Coupled AQM.
//!
//! Validates:
//! - IP ECN codepoint parsing and classification (RFC 9331)
//! - Queue separation into Low-Latency (L) and Classic (C) queues
//! - L4S ramp marking under varied queuing delay
//! - PI2 Active Queue Management and coupled quadratic probability calculation (RFC 9332)
//! - Classic ECN marking vs. Not-ECT congestion dropping
//! - Deficit Round Robin (DRR) inter-queue scheduling and starvation prevention
//! - Buffer overflow protection and capacity limiting
//! - TS 26.114 RAN Congestion Notification feedback generation
//! - Binary wire PDU framing and CRC-16 CCITT integrity validation

use toy_tcpip::nr_l4s_dualq::{
    compute_crc16, DualQConfig, DualQCoupledAqm, IpEcnField, L4sError, L4sPacket, L4sPacketAction,
    NrL4sWirePdu, RanCongestionLevel, L4S_WIRE_MAGIC, L4S_WIRE_PDU_SIZE,
};

#[test]
fn test_ecn_codepoint_parsing_and_properties() {
    assert_eq!(IpEcnField::from_bits(0b00).unwrap(), IpEcnField::NotEct);
    assert_eq!(IpEcnField::from_bits(0b01).unwrap(), IpEcnField::Ect1);
    assert_eq!(IpEcnField::from_bits(0b10).unwrap(), IpEcnField::Ect0);
    assert_eq!(IpEcnField::from_bits(0b11).unwrap(), IpEcnField::Ce);

    // Masking higher bits
    assert_eq!(IpEcnField::from_bits(0b111101).unwrap(), IpEcnField::Ect1);

    let ect1 = IpEcnField::Ect1;
    assert!(ect1.is_l4s_traffic());
    assert!(ect1.is_ecn_capable());

    let not_ect = IpEcnField::NotEct;
    assert!(!not_ect.is_l4s_traffic());
    assert!(!not_ect.is_ecn_capable());

    let ect0 = IpEcnField::Ect0;
    assert!(!ect0.is_l4s_traffic());
    assert!(ect0.is_ecn_capable());

    let ce = IpEcnField::Ce;
    assert!(ce.is_l4s_traffic());
    assert!(ce.is_ecn_capable());
}

#[test]
fn test_l4s_and_classic_queue_classification() {
    let config = DualQConfig::default();
    let mut aqm = DualQCoupledAqm::new(config);

    // Enqueue 2 L4S packets
    let p1 = L4sPacket::new(1, 10, 1000, IpEcnField::Ect1, 100).unwrap();
    let p2 = L4sPacket::new(2, 10, 500, IpEcnField::Ect1, 150).unwrap();
    aqm.enqueue(p1).unwrap();
    aqm.enqueue(p2).unwrap();

    // Enqueue 2 Classic packets (one Not-ECT, one ECT(0))
    let p3 = L4sPacket::new(3, 20, 1200, IpEcnField::NotEct, 120).unwrap();
    let p4 = L4sPacket::new(4, 20, 800, IpEcnField::Ect0, 180).unwrap();
    aqm.enqueue(p3).unwrap();
    aqm.enqueue(p4).unwrap();

    assert_eq!(aqm.l4s_packet_count(), 2);
    assert_eq!(aqm.l4s_queue_bytes(), 1500);

    assert_eq!(aqm.classic_packet_count(), 2);
    assert_eq!(aqm.classic_queue_bytes(), 2000);

    assert_eq!(aqm.stats().total_l4s_enqueued, 2);
    assert_eq!(aqm.stats().total_classic_enqueued, 2);
}

#[test]
fn test_l4s_ramp_marking_low_latency() {
    let mut config = DualQConfig::default();
    config.l_min_us = 500;
    config.l_max_us = 1500;
    let mut aqm = DualQCoupledAqm::new(config);

    // Case 1: Low queuing delay (200 us < l_min_us) -> forward unchanged
    let p1 = L4sPacket::new(1, 1, 800, IpEcnField::Ect1, 1000).unwrap();
    aqm.enqueue(p1).unwrap();
    aqm.advance_time(1200).unwrap(); // sojourn = 200 us

    let (out_pkt, action) = aqm.dequeue().expect("Should dequeue packet");
    assert_eq!(action, L4sPacketAction::ForwardUnchanged);
    assert_eq!(out_pkt.ecn, IpEcnField::Ect1);

    // Case 2: High queuing delay (2000 us > l_max_us) -> 100% mark CE
    let p2 = L4sPacket::new(2, 1, 800, IpEcnField::Ect1, 2000).unwrap();
    aqm.enqueue(p2).unwrap();
    aqm.advance_time(4500).unwrap(); // sojourn = 2500 us > l_max_us

    let (out_pkt2, action2) = aqm.dequeue().expect("Should dequeue packet");
    assert_eq!(action2, L4sPacketAction::MarkCe);
    assert_eq!(out_pkt2.ecn, IpEcnField::Ce);
    assert_eq!(aqm.stats().total_l4s_marked_ce, 1);
}

#[test]
fn test_classic_pi2_controller_and_coupling() {
    let mut config = DualQConfig::default();
    config.target_latency_classic_us = 10_000; // 10 ms target
    config.update_interval_us = 16_000;        // 16 ms update interval
    config.pi2_alpha = 0.2;
    config.pi2_beta = 0.05;
    config.coupling_factor_k = 2.0;

    let mut aqm = DualQCoupledAqm::new(config);

    // Insert packet into Classic queue with arrival time 0
    let p = L4sPacket::new(1, 5, 1000, IpEcnField::Ect0, 0).unwrap();
    aqm.enqueue(p).unwrap();

    // Advance time beyond target latency (30 ms >> 10 ms) across multiple updates
    aqm.advance_time(16_000).unwrap();
    let p_c_step1 = aqm.classic_probability();
    assert!(p_c_step1 > 0.0, "p_C should become positive due to delay > target");

    let p_l_step1 = aqm.coupled_l4s_probability();
    // Coupled formula: p_L = min(1.0, 2.0 * (p_C)^2)
    let expected_p_l = (2.0 * p_c_step1 * p_c_step1).min(1.0);
    assert!((p_l_step1 - expected_p_l).abs() < 1e-6);

    // Advance again at 32 ms with sustained delay
    aqm.advance_time(32_000).unwrap();
    let p_c_step2 = aqm.classic_probability();
    assert!(p_c_step2 > p_c_step1, "p_C should ramp up under sustained congestion");
}

#[test]
fn test_classic_ecn_marking_vs_not_ect_drop() {
    let config = DualQConfig::default();
    let mut aqm = DualQCoupledAqm::new(config);

    // Explicitly set 100% drop/marking probability
    aqm.set_probabilities(1.0, 1.0);

    // Enqueue an ECT(0) packet and a Not-ECT packet into Classic queue
    let p_ect0 = L4sPacket::new(10, 2, 1000, IpEcnField::Ect0, 0).unwrap();
    let p_not_ect = L4sPacket::new(11, 2, 1000, IpEcnField::NotEct, 0).unwrap();
    aqm.enqueue(p_ect0).unwrap();
    aqm.enqueue(p_not_ect).unwrap();

    // Dequeue ECT(0) -> with prob=1.0, ECN-capable packet MUST be marked CE, NOT dropped!
    let (pkt_ce, action_ce) = aqm.dequeue().expect("Should dequeue ECT(0) packet");
    assert_eq!(pkt_ce.id, 10);
    assert_eq!(action_ce, L4sPacketAction::MarkCe);
    assert_eq!(pkt_ce.ecn, IpEcnField::Ce);
    assert_eq!(aqm.stats().total_classic_marked_ce, 1);

    // Dequeue Not-ECT -> with prob=1.0, non-ECN packet MUST be dropped!
    let (pkt_drop, action_drop) = aqm.dequeue().expect("Should dequeue Not-ECT packet");
    assert_eq!(pkt_drop.id, 11);
    assert_eq!(action_drop, L4sPacketAction::Drop);
    assert_eq!(pkt_drop.ecn, IpEcnField::NotEct);
    assert_eq!(aqm.stats().total_classic_dropped, 1);
}

#[test]
fn test_deficit_round_robin_fair_scheduling() {
    let mut config = DualQConfig::default();
    config.classic_weight = 1;
    config.l4s_weight = 2;
    let mut aqm = DualQCoupledAqm::new(config);

    // Populate both queues
    for i in 1..=6 {
        aqm.enqueue(L4sPacket::new(i, 1, 1000, IpEcnField::Ect1, 0).unwrap()).unwrap();
        aqm.enqueue(L4sPacket::new(100 + i, 2, 1000, IpEcnField::NotEct, 0).unwrap()).unwrap();
    }

    let mut l4s_served = 0;
    let mut classic_served = 0;

    while let Some((pkt, _)) = aqm.dequeue() {
        if pkt.id < 100 {
            l4s_served += 1;
        } else {
            classic_served += 1;
        }
    }

    assert_eq!(l4s_served, 6);
    assert_eq!(classic_served, 6);
    assert_eq!(aqm.classic_queue_bytes(), 0);
    assert_eq!(aqm.l4s_queue_bytes(), 0);
}

#[test]
fn test_buffer_overflow_protection() {
    let mut config = DualQConfig::default();
    config.max_buffer_bytes_l4s = 2000;
    config.max_buffer_bytes_classic = 3000;

    let mut aqm = DualQCoupledAqm::new(config);

    // Enqueue 1500 bytes into L4S queue (ok)
    aqm.enqueue(L4sPacket::new(1, 1, 1500, IpEcnField::Ect1, 0).unwrap()).unwrap();

    // Next 1000 bytes would exceed 2000 bytes limit -> overflow error!
    let err = aqm.enqueue(L4sPacket::new(2, 1, 1000, IpEcnField::Ect1, 0).unwrap()).unwrap_err();
    assert!(matches!(err, L4sError::BufferOverflow { queue: "L4S", capacity_bytes: 2000 }));
    assert_eq!(aqm.stats().total_l4s_dropped, 1);

    // Same for classic queue
    aqm.enqueue(L4sPacket::new(3, 1, 2500, IpEcnField::NotEct, 0).unwrap()).unwrap();
    let err_c = aqm.enqueue(L4sPacket::new(4, 1, 1000, IpEcnField::NotEct, 0).unwrap()).unwrap_err();
    assert!(matches!(err_c, L4sError::BufferOverflow { queue: "Classic", capacity_bytes: 3000 }));
    assert_eq!(aqm.stats().total_classic_dropped, 1);
}

#[test]
fn test_ran_feedback_reporting() {
    let config = DualQConfig::default();
    let mut aqm = DualQCoupledAqm::new(config);

    // Initial state: no congestion
    let report = aqm.generate_ran_feedback();
    assert_eq!(report.congestion_level, RanCongestionLevel::None);
    assert!(report.bitrate_adjustment_factor > 0.0);

    // Advance time forward
    aqm.advance_time(100_000).unwrap();

    // Advance time backwards should return InvalidTimeSequence error
    let err_back = aqm.advance_time(50_000).unwrap_err();
    assert!(matches!(err_back, L4sError::InvalidTimeSequence { current_us: 100_000, advance_to_us: 50_000 }));
}

#[test]
fn test_wire_pdu_serialization_deserialization_and_crc() {
    // Verify CRC computation directly
    let test_bytes = b"3GPP_REL18_L4S_DUALQ";
    let crc = compute_crc16(test_bytes);
    assert_ne!(crc, 0);

    let pdu = NrL4sWirePdu {
        sfn: 512,
        slot: 19,
        qfi: 9,
        l4s_bytes: 14500,
        classic_bytes: 65200,
        l4s_qdelay_us: 650,
        classic_qdelay_us: 14200,
        prob_classic_scaled: 1540,
        prob_l4s_scaled: 475,
    };

    let wire_bytes = pdu.to_wire_bytes();
    assert_eq!(wire_bytes.len(), L4S_WIRE_PDU_SIZE);
    assert_eq!(&wire_bytes[0..4], &L4S_WIRE_MAGIC);

    // Decode roundtrip
    let decoded = NrL4sWirePdu::from_wire_bytes(&wire_bytes).expect("Should decode successfully");
    assert_eq!(pdu, decoded);

    // Corrupt byte and assert CRC mismatch
    let mut corrupted = wire_bytes;
    corrupted[10] ^= 0xFF;
    let err = NrL4sWirePdu::from_wire_bytes(&corrupted).unwrap_err();
    assert!(matches!(err, L4sError::WireCrcMismatch { .. }));

    // Test buffer too small
    let too_short = [0u8; 10];
    let err_short = NrL4sWirePdu::from_wire_bytes(&too_short).unwrap_err();
    assert!(matches!(err_short, L4sError::WireBufferTooSmall { .. }));
}
