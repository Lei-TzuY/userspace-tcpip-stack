//! Integration tests for DetNet MPLS PREOF & Control Word Sub-Layer (RFC 8964 / RFC 8938).

use toy_tcpip::detnet_mpls_cw::{
    DetNetMplsControlWord, DetNetMplsEngine, DetNetMplsProfile, DetNetMplsResult,
};

#[test]
fn test_detnet_mpls_cw_structure_and_nibble() {
    let dcw = DetNetMplsControlWord::new(65535);
    let bytes = dcw.serialize();
    assert_eq!(bytes[0] >> 4, 0); // Nibble 0
    assert_eq!(bytes[2], 0xFF);
    assert_eq!(bytes[3], 0xFF);

    let parsed = DetNetMplsControlWord::parse(&bytes).unwrap();
    assert_eq!(parsed.sequence_number, 65535);

    // Corrupted nibble (e.g. IPv4 0x4) -> rejected
    let mut corrupt = bytes;
    corrupt[0] = 0x40;
    assert!(DetNetMplsControlWord::parse(&corrupt).is_none());
}

#[test]
fn test_detnet_mpls_dual_path_failover_and_elimination() {
    let mut engine = DetNetMplsEngine::new();

    let profile = DetNetMplsProfile {
        flow_id: 100,
        s_label: 5000,
        f_labels: vec![101, 102], // Two disjoint paths
    };
    engine.register_profile(profile);

    let telemetry_packet = b"SmartGridSyncSignal_PhaseA";

    // 1. Ingress Replicate
    let result = engine.ingress_replicate(100, telemetry_packet);
    let frames = match result {
        DetNetMplsResult::ReplicatedPaths {
            s_label,
            seq,
            frames,
        } => {
            assert_eq!(s_label, 5000);
            assert_eq!(seq, 0);
            assert_eq!(frames.len(), 2);
            frames
        }
        other => panic!("Expected ReplicatedPaths, got {:?}", other),
    };

    // 2. Primary arrives
    let primary_pdu = &frames[0].1[4..];
    let res1 = engine.egress_eliminate(primary_pdu);
    match res1 {
        DetNetMplsResult::AcceptedUnique {
            s_label,
            seq,
            payload,
        } => {
            assert_eq!(s_label, 5000);
            assert_eq!(seq, 0);
            assert_eq!(payload, telemetry_packet);
        }
        other => panic!("Expected AcceptedUnique, got {:?}", other),
    }

    // 3. Backup arrives (duplicate)
    let backup_pdu = &frames[1].1[4..];
    let res2 = engine.egress_eliminate(backup_pdu);
    match res2 {
        DetNetMplsResult::DuplicateDropped { s_label, seq } => {
            assert_eq!(s_label, 5000);
            assert_eq!(seq, 0);
        }
        other => panic!("Expected DuplicateDropped, got {:?}", other),
    }
}
