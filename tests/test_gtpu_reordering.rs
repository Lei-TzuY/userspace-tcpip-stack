use toy_tcpip::gtpu_reordering::{GtpuReorderingEngine, seq_gt, seq_lt};

#[test]
fn test_gtpu_sequence_modular_arithmetic() {
    assert!(seq_lt(10, 11));
    assert!(seq_gt(11, 10));

    // RFC 1982 wrap-around: 65535 is before 0
    assert!(seq_lt(65535, 0));
    assert!(seq_gt(0, 65535));
    assert!(seq_lt(65534, 1));
}

#[test]
fn test_gtpu_reordering_deep_shuffled_burst() {
    let mut engine = GtpuReorderingEngine::new(0xABCDEF, 100, 32);

    // Arrives: 102, 104, 101, 103, 100
    let d1 = engine.ingest_packet(102, b"102".to_vec());
    assert_eq!(d1.len(), 0);

    let d2 = engine.ingest_packet(104, b"104".to_vec());
    assert_eq!(d2.len(), 0);

    let d3 = engine.ingest_packet(101, b"101".to_vec());
    assert_eq!(d3.len(), 0);

    let d4 = engine.ingest_packet(103, b"103".to_vec());
    assert_eq!(d4.len(), 0);

    // 100 arrives -> Triggers cascade: 100, 101, 102, 103, 104 in perfect sequential order!
    let d5 = engine.ingest_packet(100, b"100".to_vec());
    assert_eq!(d5.len(), 5);
    for (i, p) in d5.iter().enumerate() {
        assert_eq!(p.sequence_number, (100 + i) as u16);
    }
    assert_eq!(engine.next_expected_seq, 105);
    assert_eq!(engine.buffer.len(), 0);
    assert_eq!(engine.total_reordered, 4);
    assert_eq!(engine.total_in_order, 1);
}
