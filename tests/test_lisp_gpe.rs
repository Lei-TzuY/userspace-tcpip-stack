use toy_tcpip::Ipv4Address;
use toy_tcpip::lisp_gpe::{
    LISP_GPE_FLAG_I, LISP_GPE_FLAG_P, LISP_GPE_FLAG_V, LISP_GPE_UDP_PORT, LispGpeEngine,
    LispGpeHeader, LispGpeMapping, LispGpeNextProto, LispGpePacket,
};

#[test]
fn test_lisp_gpe_constants_and_ports() {
    assert_eq!(LISP_GPE_UDP_PORT, 4341);
    assert_eq!(LISP_GPE_FLAG_P, 0x04);
    assert_eq!(LISP_GPE_FLAG_I, 0x08);
    assert_eq!(LISP_GPE_FLAG_V, 0x10);

    let hdr = LispGpeHeader::new(400, LispGpeNextProto::Nsh);
    let bytes = hdr.serialize();
    let parsed = LispGpeHeader::parse(&bytes).unwrap();
    assert_eq!(parsed.instance_id, 400);
    assert_eq!(parsed.next_protocol, LispGpeNextProto::Nsh);
}

#[test]
fn test_lisp_gpe_multi_tenant_encapsulation_and_decapsulation() {
    let mut engine = LispGpeEngine::new();

    // Mapping for Tenant VNI 1000
    engine.add_mapping(
        1000,
        b"10.10.1.1".to_vec(),
        LispGpeMapping {
            instance_id: 1000,
            rloc_underlay_ip: Ipv4Address::new(192, 168, 1, 50),
            next_protocol: LispGpeNextProto::Ipv4,
        },
    );

    // Encapsulate an IPv4 packet inside LISP-GPE
    let payload = b"Hello LISP-GPE Multi-Tenant Overlay";
    let packet = engine.encapsulate(1000, LispGpeNextProto::Ipv4, payload);

    let raw = packet.serialize();
    assert_eq!(raw.len(), 8 + payload.len());

    let parsed = LispGpePacket::parse(&raw).expect("Valid LISP-GPE packet");
    assert_eq!(parsed.header.instance_id, 1000);
    assert_eq!(parsed.header.next_protocol, LispGpeNextProto::Ipv4);

    let (iid, proto, dec_data) = engine.decapsulate(&parsed);
    assert_eq!(iid, 1000);
    assert_eq!(proto, LispGpeNextProto::Ipv4);
    assert_eq!(dec_data, payload);
}

#[test]
fn test_lisp_gpe_l2_ethernet_encap() {
    let engine = LispGpeEngine::new();

    let eth_frame = vec![
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Dst MAC
        0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, // Src MAC
        0x08, 0x00, // EtherType IPv4
        0x45, 0x00, 0x00, 0x14, // IPv4 header stub
    ];

    let packet = engine.encapsulate(2000, LispGpeNextProto::Ethernet, &eth_frame);
    let ser = packet.serialize();

    let parsed = LispGpePacket::parse(&ser).unwrap();
    assert_eq!(parsed.header.instance_id, 2000);
    assert_eq!(parsed.header.next_protocol, LispGpeNextProto::Ethernet);
    assert_eq!(parsed.payload, eth_frame);
}
