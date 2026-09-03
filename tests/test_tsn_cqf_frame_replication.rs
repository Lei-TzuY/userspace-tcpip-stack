// tests/test_tsn_cqf_frame_replication.rs

use toy_tcpip::tsn_cqf_frame_replication::{
    ETHERTYPE_R_TAG, FrerEliminationVerdict, R_TAG_HEADER_LEN, RTagHeader, ReplicationPath,
    TsnCqfFrameReplicationEngine,
};

#[test]
fn test_tsn_cqf_frame_replication_lifecycle() {
    let mut engine = TsnCqfFrameReplicationEngine::new(100_000);
    let stream_id = 5001;
    engine.register_stream(stream_id);

    // 1. Replicate 3 packets on ingress
    let (rtag1, p_a1, p_b1) = engine.replicate_frame(stream_id, 0x0800).unwrap();
    let (rtag2, p_a2, p_b2) = engine.replicate_frame(stream_id, 0x0800).unwrap();
    let (rtag3, p_a3, p_b3) = engine.replicate_frame(stream_id, 0x0800).unwrap();

    assert_eq!(rtag1.sequence_number, 1);
    assert_eq!(rtag2.sequence_number, 2);
    assert_eq!(rtag3.sequence_number, 3);
    assert_eq!(p_a1, ReplicationPath::PathA);
    assert_eq!(p_b1, ReplicationPath::PathB);
    assert_eq!(p_a2, ReplicationPath::PathA);
    assert_eq!(p_b2, ReplicationPath::PathB);
    assert_eq!(p_a3, ReplicationPath::PathA);
    assert_eq!(p_b3, ReplicationPath::PathB);

    assert_eq!(engine.total_replicated_frames, 6);

    // 2. Out-of-order & inter-path egress arrivals:
    // Packet 2 arrives first on Path B -> Delivered
    let v2_b = engine.process_egress_frame(stream_id, 2, 20, ReplicationPath::PathB);
    assert_eq!(
        v2_b,
        FrerEliminationVerdict::Delivered {
            stream_id,
            sequence_number: 2,
            arrival_cycle: 20,
            source_path: ReplicationPath::PathB,
        }
    );

    // Packet 1 arrives on Path A -> Delivered (hole filled within history window)
    let v1_a = engine.process_egress_frame(stream_id, 1, 20, ReplicationPath::PathA);
    assert_eq!(
        v1_a,
        FrerEliminationVerdict::Delivered {
            stream_id,
            sequence_number: 1,
            arrival_cycle: 20,
            source_path: ReplicationPath::PathA,
        }
    );

    // Packet 2 duplicate arrives on Path A -> EliminatedDuplicate
    let v2_a = engine.process_egress_frame(stream_id, 2, 21, ReplicationPath::PathA);
    assert_eq!(
        v2_a,
        FrerEliminationVerdict::EliminatedDuplicate {
            stream_id,
            sequence_number: 2,
            arrival_cycle: 21,
            source_path: ReplicationPath::PathA,
        }
    );

    // Packet 3 arrives on Path A -> Delivered
    let v3_a = engine.process_egress_frame(stream_id, 3, 21, ReplicationPath::PathA);
    assert_eq!(
        v3_a,
        FrerEliminationVerdict::Delivered {
            stream_id,
            sequence_number: 3,
            arrival_cycle: 21,
            source_path: ReplicationPath::PathA,
        }
    );

    // Packet 3 duplicate arrives on Path B -> EliminatedDuplicate
    let v3_b = engine.process_egress_frame(stream_id, 3, 22, ReplicationPath::PathB);
    assert_eq!(
        v3_b,
        FrerEliminationVerdict::EliminatedDuplicate {
            stream_id,
            sequence_number: 3,
            arrival_cycle: 22,
            source_path: ReplicationPath::PathB,
        }
    );

    // Packet 1 duplicate arrives late on Path B -> EliminatedDuplicate
    let v1_b = engine.process_egress_frame(stream_id, 1, 22, ReplicationPath::PathB);
    assert_eq!(
        v1_b,
        FrerEliminationVerdict::EliminatedDuplicate {
            stream_id,
            sequence_number: 1,
            arrival_cycle: 22,
            source_path: ReplicationPath::PathB,
        }
    );

    assert_eq!(engine.total_delivered_frames, 3);
    assert_eq!(engine.total_eliminated_duplicates, 3);
}

#[test]
fn test_rtag_constants_and_serialization() {
    assert_eq!(ETHERTYPE_R_TAG, 0xF1C1);
    assert_eq!(R_TAG_HEADER_LEN, 6);

    let rtag = RTagHeader::new(1024, 0x88F7);
    let raw = rtag.serialize();
    let parsed = RTagHeader::parse(&raw).unwrap();
    assert_eq!(parsed.sequence_number, 1024);
    assert_eq!(parsed.encapsulated_ethertype, 0x88F7);
}
