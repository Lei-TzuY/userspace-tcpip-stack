use std::str::FromStr;

use toy_tcpip::icmpv6::{
    ICMPV6_TYPE_NEIGHBOR_ADVERT, ICMPV6_TYPE_NEIGHBOR_SOLICIT, ICMPV6_TYPE_ROUTER_ADVERT,
    ICMPV6_TYPE_ROUTER_SOLICIT, Icmpv6Packet, NDP_OPT_SRC_LINK_LAYER_ADDR,
    NDP_OPT_TARGET_LINK_LAYER_ADDR,
};
use toy_tcpip::ipv6::Ipv6Address;

fn ip6(text: &str) -> Ipv6Address {
    Ipv6Address::from_str(text).unwrap()
}

fn option(option_type: u8, units: u8) -> Vec<u8> {
    let mut bytes = vec![option_type, units];
    bytes.resize(units as usize * 8, 0x5a);
    bytes
}

#[test]
fn neighbor_solicitation_rejects_non_ethernet_slla_length() {
    let source = ip6("2001:db8:1::2");
    let target = ip6("2001:db8:1::1");
    let destination = target.solicited_node_multicast();
    let mut payload = vec![0; 4];
    payload.extend_from_slice(&target.0);
    payload.extend_from_slice(&option(NDP_OPT_SRC_LINK_LAYER_ADDR, 2));
    let packet = Icmpv6Packet {
        msg_type: ICMPV6_TYPE_NEIGHBOR_SOLICIT,
        code: 0,
        checksum: 0,
        payload: &payload,
    };

    assert_eq!(
        packet.validated_neighbor_solicitation_target(source, destination, 255),
        None
    );
}

#[test]
fn neighbor_advertisement_rejects_non_ethernet_tlla_length() {
    let target = ip6("2001:db8:1::2");
    let destination = ip6("2001:db8:1::1");
    let mut payload = vec![0; 4];
    payload.extend_from_slice(&target.0);
    payload.extend_from_slice(&option(NDP_OPT_TARGET_LINK_LAYER_ADDR, 2));
    let packet = Icmpv6Packet {
        msg_type: ICMPV6_TYPE_NEIGHBOR_ADVERT,
        code: 0,
        checksum: 0,
        payload: &payload,
    };

    assert_eq!(
        packet.validated_neighbor_advertisement_target(destination, 255),
        None
    );
}

#[test]
fn router_discovery_rejects_non_ethernet_slla_lengths() {
    let source = ip6("fe80::2");

    let mut rs_payload = vec![0; 4];
    rs_payload.extend_from_slice(&option(NDP_OPT_SRC_LINK_LAYER_ADDR, 2));
    let rs = Icmpv6Packet {
        msg_type: ICMPV6_TYPE_ROUTER_SOLICIT,
        code: 0,
        checksum: 0,
        payload: &rs_payload,
    };
    assert!(!rs.is_valid_router_solicitation(source, 255));

    let mut ra_payload = vec![0; 12];
    ra_payload.extend_from_slice(&option(NDP_OPT_SRC_LINK_LAYER_ADDR, 2));
    let ra = Icmpv6Packet {
        msg_type: ICMPV6_TYPE_ROUTER_ADVERT,
        code: 0,
        checksum: 0,
        payload: &ra_payload,
    };
    assert!(ra.validated_router_advertisement(source, 255).is_none());
}

#[test]
fn irrelevant_link_layer_option_keeps_rfc4861_ignore_semantics() {
    let source = ip6("2001:db8:1::2");
    let target = ip6("2001:db8:1::1");
    let destination = target.solicited_node_multicast();
    let mut payload = vec![0; 4];
    payload.extend_from_slice(&target.0);
    // TLLA is not defined for NS. RFC 4861 says such an option is ignored,
    // so its Ethernet-specific content must not invalidate an otherwise valid NS.
    payload.extend_from_slice(&option(NDP_OPT_TARGET_LINK_LAYER_ADDR, 2));
    let packet = Icmpv6Packet {
        msg_type: ICMPV6_TYPE_NEIGHBOR_SOLICIT,
        code: 0,
        checksum: 0,
        payload: &payload,
    };

    assert_eq!(
        packet.validated_neighbor_solicitation_target(source, destination, 255),
        Some(target)
    );
}
