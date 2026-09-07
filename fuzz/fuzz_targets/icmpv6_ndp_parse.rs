#![no_main]

use libfuzzer_sys::fuzz_target;
use toy_tcpip::icmpv6::{
    Icmpv6Packet, ICMPV6_TYPE_NEIGHBOR_ADVERT, ICMPV6_TYPE_NEIGHBOR_SOLICIT,
    ICMPV6_TYPE_REDIRECT, ICMPV6_TYPE_ROUTER_ADVERT, ICMPV6_TYPE_ROUTER_SOLICIT,
};
use toy_tcpip::ipv6::Ipv6Address;

fuzz_target!(|data: &[u8]| {
    if data.len() < 33 {
        return;
    }

    let mut src = [0u8; 16];
    src.copy_from_slice(&data[..16]);
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&data[16..32]);
    let src = Ipv6Address(src);
    let dst = Ipv6Address(dst);
    let hop_limit = data[32];
    let wire = &data[33..];

    // Always exercise checksum verification as well as unchecked structural parsing.
    let _ = Icmpv6Packet::parse(src, dst, wire, true);

    let Ok(packet) = Icmpv6Packet::parse(src, dst, wire, false) else {
        assert!(wire.len() < 4);
        return;
    };

    assert!(wire.len() >= 4);
    assert_eq!(packet.msg_type, wire[0]);
    assert_eq!(packet.code, wire[1]);
    assert_eq!(packet.checksum, u16::from_be_bytes([wire[2], wire[3]]));
    assert_eq!(packet.payload, &wire[4..]);

    // Drive all NDP ingress validators with arbitrary option lists. These paths
    // must fail closed on malformed/truncated options without panicking.
    match packet.msg_type {
        ICMPV6_TYPE_NEIGHBOR_SOLICIT => {
            let _ = packet.validated_neighbor_solicitation_target(src, dst, hop_limit);
        }
        ICMPV6_TYPE_NEIGHBOR_ADVERT => {
            let _ = packet.validated_neighbor_advertisement_target(dst, hop_limit);
        }
        ICMPV6_TYPE_REDIRECT => {
            let _ = packet.validated_redirect(src, dst, hop_limit);
        }
        ICMPV6_TYPE_ROUTER_SOLICIT => {
            let _ = packet.is_valid_router_solicitation(src, hop_limit);
        }
        ICMPV6_TYPE_ROUTER_ADVERT => {
            let _ = packet.validated_router_advertisement(src, hop_limit);
        }
        _ => {}
    }
});
