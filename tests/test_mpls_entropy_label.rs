//! Integration tests for MPLS Entropy Label (RFC 6790 / RFC 6391)

use toy_tcpip::mpls_entropy_label::{
    EcmpNextHop, EntropyLabelError, MplsEntropyLabelEngine, MplsLabelEntry, MplsLabelStack,
    DEFAULT_HASH_SEED, ENTROPY_LABEL_MIN, MPLS_LABEL_ELI,
};

#[test]
fn test_mpls_label_stack_entry_encoding() {
    let entry = MplsLabelEntry::new(1048575, 7, true, 255);
    assert_eq!(entry.label, 1048575);
    assert_eq!(entry.tc, 7);
    assert!(entry.bos);
    assert_eq!(entry.ttl, 255);

    let bytes = entry.to_bytes();
    let decoded = MplsLabelEntry::from_bytes(&bytes);
    assert_eq!(entry, decoded);

    let eli = MplsLabelEntry::eli(64);
    assert!(eli.is_eli());
    assert_eq!(eli.label, MPLS_LABEL_ELI);
    assert_eq!(eli.tc, 0);
    assert!(!eli.bos);
    assert_eq!(eli.ttl, 64);
}

#[test]
fn test_mpls_label_stack_eli_el_lifecycle() {
    let mut stack = MplsLabelStack::new();

    // Push bottom label (VPN / service label)
    stack.push(MplsLabelEntry::new(2001, 0, true, 64));
    // Push transport label
    stack.push(MplsLabelEntry::new(16050, 0, false, 64));

    assert_eq!(stack.depth(), 2);
    assert!(!stack.has_entropy_label());
    assert_eq!(stack.find_eli(), None);

    // Insert ELI/EL between transport label and service label (position 1)
    let entropy_val = 54321u32;
    stack.insert_entropy_label(1, entropy_val, 64);

    assert_eq!(stack.depth(), 4);
    assert!(stack.has_entropy_label());
    assert_eq!(stack.find_eli(), Some(1));
    assert_eq!(stack.entropy_label_value(), Some(entropy_val));

    // Verify BoS flags: only the deepest label (entry 3) should have BoS = true
    assert!(!stack.entries[0].bos); // Transport
    assert!(!stack.entries[1].bos); // ELI
    assert!(!stack.entries[2].bos); // EL
    assert!(stack.entries[3].bos);  // VPN label

    // Serialize and deserialize stack
    let wire_bytes = stack.to_bytes();
    assert_eq!(wire_bytes.len(), 16); // 4 labels * 4 bytes

    let parsed_stack = MplsLabelStack::from_bytes(&wire_bytes).expect("Valid stack");
    assert_eq!(parsed_stack.depth(), 4);
    assert_eq!(parsed_stack.entropy_label_value(), Some(entropy_val));

    // Strip ELI/EL at egress LSR
    let mut engine = MplsEntropyLabelEngine::new(DEFAULT_HASH_SEED);
    let stripped = engine.strip_entropy_at_egress(&mut stack).expect("Strip success");
    assert_eq!(stripped, entropy_val);
    assert_eq!(stack.depth(), 2);
    assert!(!stack.has_entropy_label());
    assert!(stack.entries.last().unwrap().bos);
    assert_eq!(engine.stats_el_stripped, 1);
}

#[test]
fn test_mpls_entropy_hash_consistency_and_bounds() {
    let engine = MplsEntropyLabelEngine::new(DEFAULT_HASH_SEED);

    let flow1 = b"10.0.1.10:5001->10.0.2.20:80/TCP";
    let flow2 = b"10.0.1.10:5002->10.0.2.20:80/TCP";

    let hash1 = engine.compute_entropy_hash(flow1);
    let hash2 = engine.compute_entropy_hash(flow2);

    // Deterministic
    assert_eq!(hash1, engine.compute_entropy_hash(flow1));
    // Different 5-tuples produce different hashes
    assert_ne!(hash1, hash2);

    // Bounded between ENTROPY_LABEL_MIN and 20-bit max
    assert!(hash1 >= ENTROPY_LABEL_MIN);
    assert!(hash1 <= 0xFFFFF);
    assert!(hash2 >= ENTROPY_LABEL_MIN);
    assert!(hash2 <= 0xFFFFF);
}

#[test]
fn test_mpls_entropy_ecmp_forwarding_and_load_balance() {
    let mut engine = MplsEntropyLabelEngine::new(DEFAULT_HASH_SEED);

    let top_label = 16001u32;
    let next_hops = vec![
        EcmpNextHop {
            id: 1,
            interface: "ge-0/0/0".to_string(),
            address: "192.0.2.1".to_string(),
            weight: 1,
        },
        EcmpNextHop {
            id: 2,
            interface: "ge-0/0/1".to_string(),
            address: "192.0.2.2".to_string(),
            weight: 1,
        },
        EcmpNextHop {
            id: 3,
            interface: "ge-0/0/2".to_string(),
            address: "192.0.2.3".to_string(),
            weight: 1,
        },
    ];
    engine.add_ecmp_group(top_label, next_hops);

    // Verify deterministic selection across different entropy labels
    let mut counts = [0usize; 3];
    for flow_id in 0..60 {
        let flow_key = format!("Flow-Key-ID-{}", flow_id);
        let mut stack = MplsLabelStack::new();
        stack.push(MplsLabelEntry::new(100, 0, true, 64)); // Service
        stack.push(MplsLabelEntry::new(top_label, 0, false, 64)); // Transport

        let el_val = engine.insert_entropy_at_ingress(&mut stack, flow_key.as_bytes(), 1, 64);
        assert!(el_val >= ENTROPY_LABEL_MIN);

        let selection = engine.select_ecmp_path(top_label, &stack).expect("ECMP selected");
        assert_eq!(selection.total_paths, 3);
        assert_eq!(selection.entropy_value, el_val);
        counts[selection.bucket_index] += 1;
    }

    // All 3 paths should receive a portion of flows
    for (i, count) in counts.iter().enumerate() {
        assert!(*count > 5, "Path {} should receive traffic, got {}", i + 1, count);
    }
}

#[test]
fn test_mpls_entropy_error_handling() {
    let mut engine = MplsEntropyLabelEngine::new(DEFAULT_HASH_SEED);

    // 1. Stack without entropy label
    let mut stack = MplsLabelStack::new();
    stack.push(MplsLabelEntry::new(100, 0, true, 64));
    let err = engine.select_ecmp_path(100, &stack).unwrap_err();
    assert_eq!(err, EntropyLabelError::NoNextHops);

    engine.add_ecmp_group(100, vec![EcmpNextHop {
        id: 1,
        interface: "eth0".to_string(),
        address: "10.0.0.1".to_string(),
        weight: 1,
    }]);

    let err2 = engine.select_ecmp_path(100, &stack).unwrap_err();
    assert_eq!(err2, EntropyLabelError::NoEntropyLabel);

    // 2. Invalid stack byte length
    let bad_bytes = vec![0u8; 5];
    let err3 = MplsLabelStack::from_bytes(&bad_bytes).unwrap_err();
    assert_eq!(err3, EntropyLabelError::InvalidStackLength(5));
}
