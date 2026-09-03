use toy_tcpip::tsn_cqf_ring_align::{RingAlignVerdict, TsnCqfRingAlignEngine, TsnRingId};

#[test]
fn test_tsn_cqf_ring_align_lifecycle() {
    // Ring 0 (3 hops = 3 cycles), Ring 1 (6 hops = 6 cycles)
    let mut engine = TsnCqfRingAlignEngine::new(100_000, 3, 6);

    assert_eq!(engine.max_ring_delay(), 6);

    // 1. Origin Tx at cycle 20
    // Shorter Ring 0 frame arrives at cycle 23 (20 + 3) -> Held for alignment
    let v1 = engine.ingest_frame(TsnRingId::Ring0, 5, 200, 20, 23, 1000);
    assert_eq!(
        v1,
        RingAlignVerdict::HoldForAlignment {
            stream_id: 5,
            seq_num: 200,
            release_cycle: 26, // 20 + 6
        }
    );
    assert_eq!(engine.held_frames.len(), 1);

    // 2. Longer Ring 1 frame arrives at cycle 26 (20 + 6) -> Paired & Ready for FRER
    let v2 = engine.ingest_frame(TsnRingId::Ring1, 5, 200, 20, 26, 1000);
    assert_eq!(
        v2,
        RingAlignVerdict::AlignedPairReady {
            stream_id: 5,
            seq_num: 200,
            release_cycle: 26,
            paired_ring: TsnRingId::Ring0,
        }
    );
    assert_eq!(engine.held_frames.len(), 0);
    assert_eq!(engine.total_aligned_pairs, 1);

    // 3. Stale duplicate drop
    let v3 = engine.ingest_frame(TsnRingId::Ring0, 5, 200, 20, 27, 1000);
    assert_eq!(
        v3,
        RingAlignVerdict::StaleDuplicateDrop {
            stream_id: 5,
            seq_num: 200,
            ring_id: TsnRingId::Ring0,
        }
    );
}
