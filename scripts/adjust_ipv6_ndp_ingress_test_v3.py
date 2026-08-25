from pathlib import Path

p = Path('tests/test_ipv6_ndp_ingress_validation.rs')
text = p.read_text()
text = text.replace(
    'fn router_rejects_offlink_na_before_neighbor_cache_learning() {',
    'fn router_rejects_offlink_na_and_unexpected_valid_na_does_not_create_cache() {',
    1,
)
old = '''    let valid_ip = Ipv6Packet::serialize(neighbor_ip, router_ip, NEXT_HEADER_ICMPV6, 255, &na);\n    let valid_frame = EthernetFrame::serialize(router_mac, neighbor_mac, ETHERTYPE_IPV6, &valid_ip);\n    assert!(\n        router\n            .process_incoming_frame("lan", &valid_frame)\n            .is_empty()\n    );\n    assert_eq!(\n        router.ndp_tables.get("eth0").unwrap().lookup(&neighbor_ip),\n        Some(neighbor_mac)\n    );\n'''
new = '''    let valid_ip = Ipv6Packet::serialize(neighbor_ip, router_ip, NEXT_HEADER_ICMPV6, 255, &na);\n    let valid_frame = EthernetFrame::serialize(router_mac, neighbor_mac, ETHERTYPE_IPV6, &valid_ip);\n    assert!(\n        router\n            .process_incoming_frame("lan", &valid_frame)\n            .is_empty()\n    );\n    // RFC 4861 section 7.2.5 / NUD: a valid NA is not permission to create\n    // Neighbor Cache state from nothing. There is no cached or INCOMPLETE\n    // resolution entry in this test, so the mapping remains absent.\n    assert_eq!(\n        router.ndp_tables.get("eth0").unwrap().lookup(&neighbor_ip),\n        None\n    );\n'''
if old not in text:
    raise SystemExit('stale NA expectation anchor not found')
p.write_text(text.replace(old, new, 1))
