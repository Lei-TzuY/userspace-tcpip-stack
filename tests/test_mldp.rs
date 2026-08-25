use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::mldp::{MldpEngine, MldpFecElement, MldpFecType, MLDP_OPAQUE_TYPE_GENERIC_LSP_ID};

#[test]
fn test_mldp_fec_element_codec() {
    let root = Ipv4Address::new(192, 168, 1, 1);
    let fec = MldpFecElement::new_p2mp_generic(root, 5001);

    assert_eq!(fec.fec_type, MldpFecType::P2mp);
    assert_eq!(fec.root_node, root);
    assert_eq!(fec.opaque_type, MLDP_OPAQUE_TYPE_GENERIC_LSP_ID);
    assert_eq!(fec.generic_lsp_id(), Some(5001));

    let wire = fec.encode();
    assert_eq!(wire.len(), 1 + 1 + 4 + 1 + 1 + 4);

    let (decoded, consumed) = MldpFecElement::decode(&wire).expect("decode mLDP FEC");
    assert_eq!(consumed, wire.len());
    assert_eq!(decoded, fec);
}

#[test]
fn test_mldp_multicast_tree_branch_replication() {
    let local_ip = Ipv4Address::new(10, 0, 0, 2);
    let mut engine = MldpEngine::new(local_ip);

    let root = Ipv4Address::new(10, 0, 0, 1);
    let fec = MldpFecElement::new_p2mp_generic(root, 7788);

    // Set upstream parent
    engine.set_upstream_parent(fec.clone(), root, 100);
    assert_eq!(engine.upstream_bindings.len(), 1);

    // Add 3 downstream branches
    engine.add_downstream_branch(&fec, 1, 201);
    engine.add_downstream_branch(&fec, 2, 202);
    engine.add_downstream_branch(&fec, 3, 203);

    let payload = b"IP Multicast Video Packet";
    let replicated = engine.replicate_multicast(&fec, payload);

    assert_eq!(replicated.len(), 3);
    assert_eq!(replicated[0].0, 1);
    assert_eq!(replicated[0].1, 201);
    assert_eq!(replicated[1].0, 2);
    assert_eq!(replicated[1].1, 202);
    assert_eq!(replicated[2].0, 3);
    assert_eq!(replicated[2].1, 203);

    // Verify MPLS label in replicated packet wire
    assert_eq!(replicated[0].2.len(), 4 + payload.len());

    // Prune branch 2
    assert!(engine.remove_downstream_branch(&fec, 2, 202));
    let after_prune = engine.replicate_multicast(&fec, payload);
    assert_eq!(after_prune.len(), 2);
}
