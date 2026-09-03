use toy_tcpip::tsn_cqf_frame_reassembly::{
    FrameReassemblyVerdict, TsnCqfFrameReassemblyEngine, TsnFragment,
};

#[test]
fn test_tsn_cqf_frame_reassembly_integration() {
    let mut engine = TsnCqfFrameReassemblyEngine::new(125_000, 250_000, 2000);

    // 1. Ingest fragment 0 (out of 3)
    let f0 = TsnFragment {
        stream_id: 42,
        frame_id: 1001,
        fragment_seq: 0,
        is_last: false,
        payload_bytes: 400,
        timestamp_ns: 50_000,
        crc_valid: true,
    };
    let v0 = engine.ingest_fragment(f0);
    assert_eq!(
        v0,
        FrameReassemblyVerdict::FragmentBuffered {
            stream_id: 42,
            frame_id: 1001,
            fragment_seq: 0,
            accumulated_bytes: 400,
        }
    );

    // 2. Ingest corrupted fragment 1 -> CrcErrorDropped & buffer evicted
    let f1_bad = TsnFragment {
        stream_id: 42,
        frame_id: 1001,
        fragment_seq: 1,
        is_last: false,
        payload_bytes: 400,
        timestamp_ns: 60_000,
        crc_valid: false,
    };
    let v1_bad = engine.ingest_fragment(f1_bad);
    assert_eq!(
        v1_bad,
        FrameReassemblyVerdict::CrcErrorDropped {
            stream_id: 42,
            frame_id: 1001,
            fragment_seq: 1,
        }
    );
    assert!(engine.buffers.is_empty());

    // 3. New frame reassembly full sequence
    let f_start = TsnFragment {
        stream_id: 42,
        frame_id: 1002,
        fragment_seq: 0,
        is_last: false,
        payload_bytes: 600,
        timestamp_ns: 100_000,
        crc_valid: true,
    };
    let f_end = TsnFragment {
        stream_id: 42,
        frame_id: 1002,
        fragment_seq: 1,
        is_last: true,
        payload_bytes: 400,
        timestamp_ns: 120_000,
        crc_valid: true,
    };

    engine.ingest_fragment(f_start);
    let v_fin = engine.ingest_fragment(f_end);
    assert_eq!(
        v_fin,
        FrameReassemblyVerdict::FrameReassembledAndScheduled {
            stream_id: 42,
            frame_id: 1002,
            total_bytes: 1000,
            target_cycle: 1,
        }
    );

    // 4. Timeout sweep check
    let f_stale = TsnFragment {
        stream_id: 99,
        frame_id: 2001,
        fragment_seq: 0,
        is_last: false,
        payload_bytes: 300,
        timestamp_ns: 200_000,
        crc_valid: true,
    };
    engine.ingest_fragment(f_stale);
    assert_eq!(engine.buffers.len(), 1);

    let swept = engine.sweep_timeouts(500_000);
    assert_eq!(swept.len(), 1);
    assert!(matches!(
        swept[0],
        FrameReassemblyVerdict::TimeoutFlushed {
            stream_id: 99,
            frame_id: 2001,
            dropped_bytes: 300
        }
    ));
    assert!(engine.buffers.is_empty());
}
