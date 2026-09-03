use toy_tcpip::gtpu_sliding_window_ack::{
    GtpuSlidingWindowAckEngine, SackBlock, SlidingWindowAckVerdict,
};

#[test]
fn test_gtpu_sliding_window_ack_integration() {
    let mut engine = GtpuSlidingWindowAckEngine::new(0xABCD1234, 32);

    // 1. In-order packet 1 -> Cumulative ACK = 1
    let v1 = engine.ingest_packet(1);
    assert_eq!(
        v1,
        SlidingWindowAckVerdict::PacketAckedInOrder {
            teid: 0xABCD1234,
            seq_number: 1,
            cumulative_ack: 1,
        }
    );

    // 2. Out-of-order packet 3 -> SACK block [3..=3], Cumulative ACK stays 1
    let v3 = engine.ingest_packet(3);
    assert_eq!(
        v3,
        SlidingWindowAckVerdict::OutOfOrderSackGenerated {
            teid: 0xABCD1234,
            received_seq: 3,
            cumulative_ack: 1,
            sack_blocks: vec![SackBlock {
                start_seq: 3,
                end_seq: 3
            }],
        }
    );

    // 3. Out-of-order packet 4 -> SACK block consolidated [3..=4]
    let v4 = engine.ingest_packet(4);
    assert_eq!(
        v4,
        SlidingWindowAckVerdict::OutOfOrderSackGenerated {
            teid: 0xABCD1234,
            received_seq: 4,
            cumulative_ack: 1,
            sack_blocks: vec![SackBlock {
                start_seq: 3,
                end_seq: 4
            }],
        }
    );

    // 4. Out-of-order packet 6 -> Two SACK blocks: [3..=4], [6..=6]
    let v6 = engine.ingest_packet(6);
    assert_eq!(
        v6,
        SlidingWindowAckVerdict::OutOfOrderSackGenerated {
            teid: 0xABCD1234,
            received_seq: 6,
            cumulative_ack: 1,
            sack_blocks: vec![
                SackBlock {
                    start_seq: 3,
                    end_seq: 4
                },
                SackBlock {
                    start_seq: 6,
                    end_seq: 6
                },
            ],
        }
    );

    // 5. Duplicate packet 3 -> Ignored
    let v3_dup = engine.ingest_packet(3);
    assert_eq!(
        v3_dup,
        SlidingWindowAckVerdict::DuplicatePacketIgnored {
            teid: 0xABCD1234,
            seq_number: 3,
            cumulative_ack: 1,
        }
    );

    // 6. Ingest missing packet 2 -> Fills hole [1..=4]! Cumulative ACK jumps to 4, SACK blocks reduced to [6..=6]
    let v2 = engine.ingest_packet(2);
    assert_eq!(
        v2,
        SlidingWindowAckVerdict::PacketAckedInOrder {
            teid: 0xABCD1234,
            seq_number: 2,
            cumulative_ack: 4,
        }
    );

    // Check Wire Report
    let report = engine.generate_ack_report(1_000_000);
    assert_eq!(report.cumulative_ack, 4);
    assert_eq!(
        report.sack_blocks,
        vec![SackBlock {
            start_seq: 6,
            end_seq: 6
        }]
    );
}
