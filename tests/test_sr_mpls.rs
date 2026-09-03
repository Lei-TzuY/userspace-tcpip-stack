//! Integration tests for Segment Routing over MPLS (SR-MPLS) Data Plane & TI-LFA Engine (RFC 8660, RFC 8667).

use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::sr_mpls::{SrAction, SrMplsEngine, Srgb, Srlb, TiLfaEngine};

#[test]
fn test_sr_mpls_srgb_mapping_and_node_sid_forwarding() {
    let srgb = Srgb::new(16000, 8000);
    let srlb = Srlb::new(15000, 1000);
    let mut engine = SrMplsEngine::new(srgb, srlb);

    let pe1 = Ipv4Address([10, 0, 0, 1]);
    let p1 = Ipv4Address([10, 0, 0, 2]);
    let pe2 = Ipv4Address([10, 0, 0, 3]);

    engine.register_node_sid(pe1, 1); // 16001
    engine.register_node_sid(p1, 2); // 16002
    engine.register_node_sid(pe2, 3); // 16003

    assert_eq!(engine.resolve_node_sid(pe2), Some(16003));

    // Ingress PE1 encapsulates customer IP packet with SR-MPLS path [P1 (16002), PE2 (16003)]
    let ip_payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let path = vec![16002, 16003];
    let sr_packet = engine.push_label_stack(ip_payload, &path, 64);
    assert_eq!(sr_packet.len(), 8 + ip_payload.len());

    // Transit P1 receives packet with top label 16002 -> pops it
    let (action_p1, p1_out) = engine.process_incoming_mpls(&sr_packet).unwrap();
    assert_eq!(action_p1, SrAction::Pop);
    assert_eq!(p1_out.len(), 4 + ip_payload.len());

    // Egress PE2 receives packet with top label 16003 (Bottom of stack) -> forwards payload
    let (action_pe2, pe2_out) = engine.process_incoming_mpls(&p1_out).unwrap();
    assert_eq!(action_pe2, SrAction::ForwardPayload);
    assert_eq!(pe2_out, ip_payload);
}

#[test]
fn test_sr_mpls_binding_sid_expansion() {
    let mut engine = SrMplsEngine::new(Srgb::default(), Srlb::default());
    let bsid = 15050;
    let te_path = vec![16002, 16004, 16008];

    engine.register_binding_sid(bsid, te_path.clone());

    let customer_pkt = b"VPN-CUSTOMER-PAYLOAD";
    let bsid_packet = engine.push_label_stack(customer_pkt, &[bsid], 64);

    let (action, expanded_pkt) = engine.process_incoming_mpls(&bsid_packet).unwrap();
    assert_eq!(action, SrAction::Push(te_path));
    assert_eq!(expanded_pkt.len(), 3 * 4 + customer_pkt.len());
}

#[test]
fn test_ti_lfa_protection_stack_construction() {
    let p_node_label = Some(16004);
    let adj_label = Some(15001);
    let dest_label = 16008;

    let backup_path = TiLfaEngine::compute_repair_stack(p_node_label, adj_label, dest_label);
    assert_eq!(backup_path, vec![16004, 15001, 16008]);
}
