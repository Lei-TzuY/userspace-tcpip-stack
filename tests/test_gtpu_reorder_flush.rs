//! Integration tests for 3GPP TS 29.281 / TS 38.415 5G GTP-U Sequence Reordering Buffer & Early Flush Engine.

use toy_tcpip::gtpu_reorder_flush::{GtpuReorderFlushEngine, GtpuReorderFlushVerdict};

#[test]
fn test_gtpu_reorder_flush_integration() {
    let mut engine = GtpuReorderFlushEngine::new(32, 20_000, 1);

    // Send packets 1, 3, 4, 5
    let v1 = engine.ingest_packet(1, 1000, 100);
    assert!(matches!(
        v1,
        GtpuReorderFlushVerdict::InOrderPacketEmitted { seq_number: 1, .. }
    ));

    let v3 = engine.ingest_packet(3, 1000, 200);
    assert!(matches!(
        v3,
        GtpuReorderFlushVerdict::PacketBuffered {
            seq_number: 3,
            buffer_depth: 1,
            ..
        }
    ));

    let v4 = engine.ingest_packet(4, 1000, 300);
    assert!(matches!(
        v4,
        GtpuReorderFlushVerdict::PacketBuffered {
            seq_number: 4,
            buffer_depth: 2,
            ..
        }
    ));

    let v5 = engine.ingest_packet(5, 1000, 400);
    assert!(matches!(
        v5,
        GtpuReorderFlushVerdict::PacketBuffered {
            seq_number: 5,
            buffer_depth: 3,
            ..
        }
    ));

    // Timeout check after 25,000 us -> should skip missing seq 2 and flush 3, 4, 5
    let v_timeout = engine.check_timeouts(25_200);
    match v_timeout {
        GtpuReorderFlushVerdict::GapSkippedEarlyFlush {
            skipped_seq_count,
            new_expected_seq,
            flushed_packets,
        } => {
            assert_eq!(skipped_seq_count, 1); // seq 2 was skipped
            assert_eq!(new_expected_seq, 6);
            assert_eq!(flushed_packets.len(), 3);
        }
        _ => panic!("Expected GapSkippedEarlyFlush on timeout"),
    }
    assert_eq!(engine.buffer.len(), 0);
}
