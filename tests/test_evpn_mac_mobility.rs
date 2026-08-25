use toy_tcpip::evpn_mac_mobility::{
    EvpnMacMobilityEngine, MacMobilityExtComm,
    EXT_COMM_TYPE_MAC_MOBILITY, EXT_COMM_SUBTYPE_MAC_MOBILITY,
};

#[test]
fn test_mac_mobility_ext_comm_codec_roundtrip() {
    let comm = MacMobilityExtComm {
        sticky: true,
        sequence_number: 1234,
    };
    let wire = comm.serialize();
    assert_eq!(wire.len(), 8);
    assert_eq!(wire[0], EXT_COMM_TYPE_MAC_MOBILITY);
    assert_eq!(wire[1], EXT_COMM_SUBTYPE_MAC_MOBILITY);
    assert_eq!(wire[2] & 0x01, 1); // sticky

    let parsed = MacMobilityExtComm::parse(&wire).unwrap();
    assert_eq!(parsed.sticky, true);
    assert_eq!(parsed.sequence_number, 1234);
}

#[test]
fn test_mac_mobility_move_sequence_increment() {
    let mut engine = EvpnMacMobilityEngine::new(5);
    let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let vtep1 = [10, 0, 0, 1];
    let vtep2 = [10, 0, 0, 2];
    let vtep3 = [10, 0, 0, 3];

    // Initial learn → seq 0, no move
    let (comm, moved) = engine.learn_mac(1000, mac, vtep1, false);
    assert!(!moved);
    assert_eq!(comm.sequence_number, 0);

    // Same VTEP refresh → no move
    let (comm, moved) = engine.learn_mac(1000, mac, vtep1, false);
    assert!(!moved);
    assert_eq!(comm.sequence_number, 0);

    // Move to vtep2 → seq 1
    let (comm, moved) = engine.learn_mac(1000, mac, vtep2, false);
    assert!(moved);
    assert_eq!(comm.sequence_number, 1);

    // Move to vtep3 → seq 2
    let (comm, moved) = engine.learn_mac(1000, mac, vtep3, false);
    assert!(moved);
    assert_eq!(comm.sequence_number, 2);
}

#[test]
fn test_sticky_mac_prevents_non_sticky_override() {
    let mut engine = EvpnMacMobilityEngine::new(10);
    let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    let vtep1 = [10, 0, 0, 1];
    let vtep2 = [10, 0, 0, 2];

    // Learn as sticky on vtep1
    engine.learn_mac(2000, mac, vtep1, true);

    // Non-sticky attempt from vtep2 → rejected
    let (_, moved) = engine.learn_mac(2000, mac, vtep2, false);
    assert!(!moved);
    let entry = engine.entries.iter().find(|e| e.mac == mac).unwrap();
    assert_eq!(entry.vtep_ip, vtep1);
    assert!(entry.sticky);
}

#[test]
fn test_duplicate_detection_fires_at_threshold() {
    let mut engine = EvpnMacMobilityEngine::new(3);
    let mac = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
    let va = [10, 0, 0, 1];
    let vb = [10, 0, 0, 2];

    engine.learn_mac(100, mac, va, false); // initial
    assert_eq!(engine.duplicate_count(), 0);

    engine.learn_mac(100, mac, vb, false); // move 1
    assert_eq!(engine.duplicate_count(), 0);

    engine.learn_mac(100, mac, va, false); // move 2
    assert_eq!(engine.duplicate_count(), 0);

    engine.learn_mac(100, mac, vb, false); // move 3 → threshold
    assert_eq!(engine.duplicate_count(), 1);
}

#[test]
fn test_remote_advertisement_higher_seq_wins() {
    let mut engine = EvpnMacMobilityEngine::new(10);
    let mac = [0xDE, 0xAD, 0x00, 0x00, 0x00, 0x01];
    let local_vtep = [10, 0, 0, 1];
    let remote_vtep = [10, 0, 0, 99];

    // Local learn at seq 0
    engine.learn_mac(500, mac, local_vtep, false);

    // Remote advertisement with higher seq → remote wins
    let remote_comm = MacMobilityExtComm {
        sticky: false,
        sequence_number: 10,
    };
    let updated = engine.process_remote_advertisement(500, mac, remote_vtep, &remote_comm);
    assert!(updated);

    let entry = engine.entries.iter().find(|e| e.mac == mac).unwrap();
    assert_eq!(entry.vtep_ip, remote_vtep);
    assert_eq!(entry.sequence_number, 10);

    // Remote with lower seq → local wins (not updated)
    let old_comm = MacMobilityExtComm {
        sticky: false,
        sequence_number: 5,
    };
    let updated = engine.process_remote_advertisement(500, mac, local_vtep, &old_comm);
    assert!(!updated);
    let entry = engine.entries.iter().find(|e| e.mac == mac).unwrap();
    assert_eq!(entry.vtep_ip, remote_vtep); // still remote
}
