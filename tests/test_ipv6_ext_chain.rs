use std::str::FromStr;
use toy_tcpip::ipv6::{Ipv6Address, Ipv6Header, Ipv6Packet};
use toy_tcpip::ipv6_ext::{
    IPV6_EXT_DEST_OPTIONS, IPV6_EXT_FRAGMENT, IPV6_EXT_HOP_BY_HOP, IPV6_EXT_NO_NEXT_HEADER,
    Ipv6ExtError, Ipv6ExtensionChain, Ipv6ExtensionHeader, Ipv6Option, MAX_EXTENSION_HEADERS,
    compute_flow_label,
};

#[test]
fn test_ipv6_hop_by_hop_and_destination_options_roundtrip() {
    let mut chain = Ipv6ExtensionChain::new(17); // UDP

    // Hop-by-Hop with Router Alert (RFC 2711) and Jumbo Payload (RFC 2675)
    let hbh = Ipv6ExtensionHeader::HopByHop {
        options: vec![
            Ipv6Option::RouterAlert(0x0000), // MLD
            Ipv6Option::JumboPayload(131072),
        ],
    };

    // Destination Options with Pad1 and PadN
    let dst_opts = Ipv6ExtensionHeader::DestinationOptions {
        options: vec![
            Ipv6Option::Pad1,
            Ipv6Option::PadN(vec![0xAA, 0xBB, 0xCC]),
            Ipv6Option::Generic {
                opt_type: 0x1E, // Experimental
                data: vec![1, 2, 3, 4],
            },
        ],
    };

    chain.push(hbh);
    chain.push(dst_opts);

    let (serialized_exts, first_nh) = chain.serialize();
    assert_eq!(first_nh, IPV6_EXT_HOP_BY_HOP);
    assert_eq!(
        serialized_exts.len() % 8,
        0,
        "Extension chain must align to 8 octets"
    );

    // Prepend IPv6 fixed header
    let src = Ipv6Address::from_str("2001:db8:1::1").unwrap();
    let dst = Ipv6Address::from_str("2001:db8:2::2").unwrap();
    let flow_label = compute_flow_label(src, dst, 17, 5000, 53, 0xdeadbeef);

    let ipv6_hdr = Ipv6Header {
        version: 6,
        traffic_class: 0,
        flow_label,
        payload_length: serialized_exts.len() as u16 + 8, // Ext headers + 8-byte dummy UDP
        next_header: first_nh,
        hop_limit: 64,
        src_ip: src,
        dst_ip: dst,
    };

    let mut full_packet = ipv6_hdr.serialize();
    full_packet.extend_from_slice(&serialized_exts);
    full_packet.extend_from_slice(&[0x13, 0x88, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00]); // UDP dummy

    let parsed_ip = Ipv6Packet::parse(&full_packet).unwrap();
    assert_eq!(parsed_ip.header.next_header, IPV6_EXT_HOP_BY_HOP);
    assert_eq!(parsed_ip.header.flow_label, flow_label);

    // Parse extension chain from IPv6 payload
    let (parsed_chain, consumed) =
        Ipv6ExtensionChain::parse(parsed_ip.header.next_header, parsed_ip.payload).unwrap();

    assert_eq!(consumed, serialized_exts.len());
    assert_eq!(parsed_chain.final_next_header, 17); // UDP
    assert_eq!(parsed_chain.headers.len(), 2);

    let remaining_l4 = &parsed_ip.payload[consumed..];
    assert_eq!(remaining_l4.len(), 8);
    assert_eq!(u16::from_be_bytes([remaining_l4[0], remaining_l4[1]]), 5000); // Src Port
}

#[test]
fn test_ipv6_fragment_extension_header() {
    let frag = Ipv6ExtensionHeader::Fragment {
        fragment_offset: 185, // 185 * 8 = 1480 bytes offset
        more_fragments: false,
        identification: 0x12345678,
    };

    let mut chain = Ipv6ExtensionChain::new(6); // TCP
    chain.push(frag);

    let (raw, first_nh) = chain.serialize();
    assert_eq!(first_nh, IPV6_EXT_FRAGMENT);
    assert_eq!(raw.len(), 8);

    let (parsed, consumed) = Ipv6ExtensionChain::parse(first_nh, &raw).unwrap();
    assert_eq!(consumed, 8);
    assert_eq!(parsed.final_next_header, 6);
    assert_eq!(
        parsed.headers[0],
        Ipv6ExtensionHeader::Fragment {
            fragment_offset: 185,
            more_fragments: false,
            identification: 0x12345678
        }
    );
}

#[test]
fn test_ipv6_no_next_header_termination() {
    let mut chain = Ipv6ExtensionChain::new(IPV6_EXT_NO_NEXT_HEADER);
    chain.push(Ipv6ExtensionHeader::HopByHop {
        options: vec![Ipv6Option::RouterAlert(5)],
    });

    let (raw, first_nh) = chain.serialize();
    let (parsed, consumed) = Ipv6ExtensionChain::parse(first_nh, &raw).unwrap();
    assert_eq!(consumed, raw.len());
    assert_eq!(parsed.final_next_header, IPV6_EXT_NO_NEXT_HEADER);
}

/// Builds a raw chain of `count` minimal 8-octet Destination Options headers terminating
/// in `final_nh`. This is the shape a resource-exhaustion probe takes: every header is as
/// small as the format allows, so the payload buys the attacker as many as possible.
fn minimal_dest_opt_chain(count: usize, final_nh: u8) -> Vec<u8> {
    let mut raw = Vec::with_capacity(count * 8);
    for i in 0..count {
        let next = if i + 1 == count {
            final_nh
        } else {
            IPV6_EXT_DEST_OPTIONS
        };
        raw.push(next); // Next Header
        raw.push(0); // Hdr Ext Len: 0 => 8 octets total
        raw.extend_from_slice(&[1, 4, 0, 0, 0, 0]); // PadN filling the rest
    }
    raw
}

/// A chain right at the cap still parses, so the bound never rejects a legitimate packet.
#[test]
fn test_ipv6_extension_chain_at_the_cap_is_accepted() {
    let raw = minimal_dest_opt_chain(MAX_EXTENSION_HEADERS, 17);
    let (parsed, consumed) =
        Ipv6ExtensionChain::parse(IPV6_EXT_DEST_OPTIONS, &raw).expect("chain at the cap parses");

    assert_eq!(parsed.headers.len(), MAX_EXTENSION_HEADERS);
    assert_eq!(consumed, raw.len());
    assert_eq!(parsed.final_next_header, 17);
}

/// One header past the cap is rejected instead of allocating an entry for every 8 octets
/// of attacker-controlled payload.
#[test]
fn test_ipv6_extension_chain_beyond_the_cap_is_rejected() {
    let raw = minimal_dest_opt_chain(MAX_EXTENSION_HEADERS + 1, 17);
    let err = Ipv6ExtensionChain::parse(IPV6_EXT_DEST_OPTIONS, &raw)
        .expect_err("chain past the cap must be refused");

    assert!(
        matches!(err, Ipv6ExtError::ChainTooLong(_)),
        "expected ChainTooLong, got {:?}",
        err
    );
}

/// A full 64 KiB payload of minimal headers is refused outright rather than turning into
/// thousands of heap allocations.
#[test]
fn test_ipv6_extension_chain_flood_is_bounded() {
    let raw = minimal_dest_opt_chain(8192, 17);
    let err = Ipv6ExtensionChain::parse(IPV6_EXT_DEST_OPTIONS, &raw)
        .expect_err("a header flood must be refused");

    assert!(matches!(err, Ipv6ExtError::ChainTooLong(_)));
}

/// RFC 8200 section 4.1: Hop-by-Hop must immediately follow the IPv6 header. One hidden
/// behind another extension header is malformed -- accepting it would let a sender slip
/// hop-by-hop options past forwarding nodes.
#[test]
fn test_ipv6_hop_by_hop_must_come_first() {
    // Destination Options, then Hop-by-Hop, then UDP.
    let mut raw = vec![IPV6_EXT_HOP_BY_HOP, 0, 1, 4, 0, 0, 0, 0];
    raw.extend_from_slice(&[17, 0, 1, 4, 0, 0, 0, 0]);

    let err = Ipv6ExtensionChain::parse(IPV6_EXT_DEST_OPTIONS, &raw)
        .expect_err("a misplaced Hop-by-Hop must be refused");

    assert!(
        matches!(err, Ipv6ExtError::MisplacedHopByHop),
        "expected MisplacedHopByHop, got {:?}",
        err
    );
}

/// The same two headers in the RFC 8200 order parse normally, confirming the rule keys on
/// position rather than on the presence of a Hop-by-Hop header at all.
#[test]
fn test_ipv6_hop_by_hop_first_is_accepted() {
    let mut raw = vec![IPV6_EXT_DEST_OPTIONS, 0, 1, 4, 0, 0, 0, 0];
    raw.extend_from_slice(&[17, 0, 1, 4, 0, 0, 0, 0]);

    let (parsed, consumed) =
        Ipv6ExtensionChain::parse(IPV6_EXT_HOP_BY_HOP, &raw).expect("correct order parses");

    assert_eq!(parsed.headers.len(), 2);
    assert_eq!(consumed, 16);
    assert_eq!(parsed.final_next_header, 17);
}
