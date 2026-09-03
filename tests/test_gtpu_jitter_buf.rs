use toy_tcpip::gtpu_jitter_buf::{GtpuJitterBufEngine, JitterBufferAction};

#[test]
fn test_gtpu_jitter_buf_lifecycle() {
    let mut jbuf = GtpuJitterBufEngine::new(0x8899, 10, 2_000, 40_000);
    jbuf.update_rtt(16_000, 2_000); // Target delay: 16000/2 + 4*2000 = 16000 µs (16 ms)

    assert_eq!(jbuf.target_hold_delay_us(), 16_000);

    // 1. In-order packet 10
    let a10 = jbuf.push_packet(10, vec![10], 1000);
    if let JitterBufferAction::ReleaseInOrder(pkts) = a10 {
        assert_eq!(pkts.len(), 1);
        assert_eq!(pkts[0].seq_num, 10);
    } else {
        panic!("Expected in-order release");
    }

    // 2. Out-of-order packet 12 arrives (packet 11 delayed)
    let a12 = jbuf.push_packet(12, vec![12], 1010);
    assert_eq!(
        a12,
        JitterBufferAction::Queued {
            current_buffered: 1,
            expected_seq: 11,
        }
    );

    // 3. Packet 11 arrives -> contiguous release of [11, 12]
    let a11 = jbuf.push_packet(11, vec![11], 1020);
    if let JitterBufferAction::ReleaseInOrder(pkts) = a11 {
        assert_eq!(pkts.len(), 2);
        assert_eq!(pkts[0].seq_num, 11);
        assert_eq!(pkts[1].seq_num, 12);
    } else {
        panic!("Expected contiguous drain");
    }
    assert_eq!(jbuf.expected_seq, 13);

    // 4. Duplicate packet 10 arrived late -> DropDuplicate
    assert_eq!(
        jbuf.push_packet(10, vec![10], 1050),
        JitterBufferAction::DropDuplicate
    );

    // 5. Packet 15 arrives at t=2000 (packets 13, 14 lost)
    let a15 = jbuf.push_packet(15, vec![15], 2000);
    assert_eq!(
        a15,
        JitterBufferAction::Queued {
            current_buffered: 1,
            expected_seq: 13,
        }
    );

    // 6. At t=20000 (elapsed 18000 µs >= 16000 µs target hold delay) -> Flush expired skips gap [13, 14]
    let flushed = jbuf.flush_expired(20_000);
    assert_eq!(flushed.len(), 1);
    assert_eq!(flushed[0].seq_num, 15);
    assert_eq!(jbuf.expected_seq, 16);
}
