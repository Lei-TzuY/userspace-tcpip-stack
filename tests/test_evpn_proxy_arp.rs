use toy_tcpip::arp::{
    ArpOpcode, ArpPacket, ARP_HLEN_ETHERNET, ARP_HTYPE_ETHERNET, ARP_PLEN_IPV4, ARP_PTYPE_IPV4,
};
use toy_tcpip::ethernet::MacAddress;
use toy_tcpip::evpn_proxy_arp::{ArpSuppressionAction, EvpnProxyArpEngine};
use toy_tcpip::ipv4::Ipv4Address;

#[test]
fn test_evpn_proxy_arp_suppression_and_synthesized_reply() {
    let mut engine = EvpnProxyArpEngine::new();
    let vni = 200;

    let target_ip = Ipv4Address::new(10, 20, 0, 15);
    let target_mac = MacAddress([0x52, 0x54, 0x00, 0xAA, 0xBB, 0xCC]);

    // 1. Learn remote host from BGP EVPN Route Type 2
    engine.learn_from_evpn_route_type2(vni, target_ip, target_mac);
    assert_eq!(engine.lookup(vni, target_ip), Some(target_mac));

    // 2. Incoming ARP Request from a local tenant VM
    let sender_ip = Ipv4Address::new(10, 20, 0, 10);
    let sender_mac = MacAddress([0x52, 0x54, 0x00, 0x11, 0x22, 0x33]);

    let req = ArpPacket {
        htype: ARP_HTYPE_ETHERNET,
        ptype: ARP_PTYPE_IPV4,
        hlen: ARP_HLEN_ETHERNET,
        plen: ARP_PLEN_IPV4,
        opcode: ArpOpcode::Request,
        sender_mac,
        sender_ip: sender_ip.0,
        target_mac: MacAddress::BROADCAST,
        target_ip: target_ip.0,
    };

    let action = engine.process_local_arp(vni, &req);
    match action {
        ArpSuppressionAction::SynthesizedReply(reply) => {
            assert_eq!(reply.opcode, ArpOpcode::Reply);
            assert_eq!(reply.sender_ip, target_ip.0);
            assert_eq!(reply.sender_mac, target_mac);
            assert_eq!(reply.target_ip, sender_ip.0);
            assert_eq!(reply.target_mac, sender_mac);
        }
        other => panic!("Expected SynthesizedReply, got {:?}", other),
    }

    assert_eq!(engine.suppressed_requests_count, 1);
    assert_eq!(engine.flooded_requests_count, 0);

    // 3. ARP Request for unknown host (cache miss)
    let unknown_req = ArpPacket {
        htype: ARP_HTYPE_ETHERNET,
        ptype: ARP_PTYPE_IPV4,
        hlen: ARP_HLEN_ETHERNET,
        plen: ARP_PLEN_IPV4,
        opcode: ArpOpcode::Request,
        sender_mac,
        sender_ip: sender_ip.0,
        target_mac: MacAddress::BROADCAST,
        target_ip: [10, 20, 0, 99],
    };
    let miss_action = engine.process_local_arp(vni, &unknown_req);
    assert_eq!(miss_action, ArpSuppressionAction::Flood);
    assert_eq!(engine.flooded_requests_count, 1);
}

#[test]
fn test_distributed_anycast_gateway_response() {
    let mut engine = EvpnProxyArpEngine::new();
    let vni = 300;
    let gw_ip = Ipv4Address::new(172, 16, 1, 1);
    let gw_mac = MacAddress([0x00, 0x00, 0x5E, 0x00, 0x01, 0x01]);

    engine.add_anycast_gateway(vni, gw_ip, gw_mac);

    let vm_ip = Ipv4Address::new(172, 16, 1, 50);
    let vm_mac = MacAddress([0x52, 0x54, 0x00, 0x50, 0x50, 0x50]);

    let req = ArpPacket {
        htype: ARP_HTYPE_ETHERNET,
        ptype: ARP_PTYPE_IPV4,
        hlen: ARP_HLEN_ETHERNET,
        plen: ARP_PLEN_IPV4,
        opcode: ArpOpcode::Request,
        sender_mac: vm_mac,
        sender_ip: vm_ip.0,
        target_mac: MacAddress::BROADCAST,
        target_ip: gw_ip.0,
    };

    let action = engine.process_local_arp(vni, &req);
    if let ArpSuppressionAction::SynthesizedReply(reply) = action {
        assert_eq!(reply.sender_ip, gw_ip.0);
        assert_eq!(reply.sender_mac, gw_mac);
        assert_eq!(reply.target_ip, vm_ip.0);
        assert_eq!(reply.target_mac, vm_mac);
    } else {
        panic!("Expected Anycast Gateway synthesized reply");
    }
}
