from pathlib import Path

lab = Path("src/lab.rs")
text = lab.read_text()
old_import = "use crate::ipv6::{Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6};"
new_import = "use crate::ipv6::{\n    Ipv6Address, Ipv6Packet, NEXT_HEADER_DEST_OPTS, NEXT_HEADER_FRAGMENT, NEXT_HEADER_HOP_BY_HOP,\n    NEXT_HEADER_ICMPV6, NEXT_HEADER_ROUTING,\n};"
if old_import not in text:
    raise SystemExit("expected ipv6 import not found")
text = text.replace(old_import, new_import, 1)

start_marker = "/// RFC 4443 section 2.4(e) suppression rules shared by router-generated\n"
end_marker = "impl LabRouter {\n"
start = text.index(start_marker)
end = text.index(end_marker, start)
replacement = r'''const NEXT_HEADER_AUTHENTICATION: u8 = 51;

/// Walks the IPv6 extension-header chain far enough to determine whether the
/// invoking packet carries an ICMPv6 error message. `None` means the chain is
/// truncated or a non-initial fragment prevents safe inspection; callers must
/// conservatively suppress a generated error in that case.
fn invoking_contains_icmpv6_error(invoking: &Ipv6Packet<'_>) -> Option<bool> {
    let mut next_header = invoking.header.next_header;
    let mut payload = invoking.payload;

    loop {
        match next_header {
            NEXT_HEADER_ICMPV6 => return payload.first().map(|msg_type| *msg_type < 128),
            NEXT_HEADER_HOP_BY_HOP | NEXT_HEADER_ROUTING | NEXT_HEADER_DEST_OPTS => {
                if payload.len() < 2 {
                    return None;
                }
                let header_len = (usize::from(payload[1]) + 1).checked_mul(8)?;
                if payload.len() < header_len {
                    return None;
                }
                next_header = payload[0];
                payload = &payload[header_len..];
            }
            NEXT_HEADER_FRAGMENT => {
                if payload.len() < 8 {
                    return None;
                }
                next_header = payload[0];
                let fragment_field = u16::from_be_bytes([payload[2], payload[3]]);
                let fragment_offset = fragment_field >> 3;
                if fragment_offset != 0 {
                    return match next_header {
                        NEXT_HEADER_ICMPV6
                        | NEXT_HEADER_HOP_BY_HOP
                        | NEXT_HEADER_ROUTING
                        | NEXT_HEADER_FRAGMENT
                        | NEXT_HEADER_DEST_OPTS
                        | NEXT_HEADER_AUTHENTICATION => None,
                        _ => Some(false),
                    };
                }
                payload = &payload[8..];
            }
            NEXT_HEADER_AUTHENTICATION => {
                if payload.len() < 2 {
                    return None;
                }
                let header_len = (usize::from(payload[1]) + 2).checked_mul(4)?;
                if payload.len() < header_len {
                    return None;
                }
                next_header = payload[0];
                payload = &payload[header_len..];
            }
            _ => return Some(false),
        }
    }
}

/// RFC 4443 section 2.4(e) suppression rules shared by router-generated
/// ICMPv6 errors. The simulator cannot identify anycast sources, but it can
/// reject the explicitly non-unique unspecified and multicast source forms.
///
/// Packet Too Big (and Parameter Problem Code 2, if added later) are the only
/// error classes allowed in response to IPv6/link-layer multicast traffic, so
/// callers opt into that exception explicitly.
fn should_send_icmpv6_error(
    invoking: &Ipv6Packet<'_>,
    link_destination: MacAddress,
    allow_multicast_exception: bool,
) -> bool {
    if invoking.header.src_ip.is_unspecified() || invoking.header.src_ip.is_multicast() {
        return false;
    }

    // RFC 4443 section 2.4(e): never send an ICMPv6 error in response to an
    // ICMPv6 error. Walk extension headers rather than assuming ICMPv6 is the
    // base header's immediate Next Header. If a malformed chain or a non-first
    // fragment prevents a safe determination, fail closed and suppress.
    if invoking_contains_icmpv6_error(invoking) != Some(false) {
        return false;
    }

    allow_multicast_exception
        || (!invoking.header.dst_ip.is_multicast() && link_destination.is_unicast())
}

'''
text = text[:start] + replacement + text[end:]
lab.write_text(text)

test = Path("tests/test_ipv6_icmp_error_suppression.rs")
t = test.read_text()
old_test_import = "use toy_tcpip::ipv6::{Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6};"
new_test_import = "use toy_tcpip::ipv6::{\n    Ipv6Address, Ipv6Packet, NEXT_HEADER_DEST_OPTS, NEXT_HEADER_FRAGMENT,\n    NEXT_HEADER_HOP_BY_HOP, NEXT_HEADER_ICMPV6,\n};"
if old_test_import not in t:
    raise SystemExit("expected test ipv6 import not found")
t = t.replace(old_test_import, new_test_import, 1)

append = r'''

fn extension_header(next_header: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![next_header, 0, 0, 0, 0, 0, 0, 0];
    out.extend_from_slice(body);
    out
}

#[test]
fn time_exceeded_is_suppressed_for_icmpv6_error_behind_extension_headers() {
    let mut router = make_router();
    let source = ip6("2001:db8:1::2");
    let destination = ip6("2001:db8:2::2");
    let inner = Ipv6Packet::serialize(destination, source, 17, 64, b"quoted");
    let error = Icmpv6Packet::build_destination_unreachable(source, destination, 0, &inner);
    let destination_options = extension_header(NEXT_HEADER_ICMPV6, &error);
    let hop_by_hop = extension_header(NEXT_HEADER_DEST_OPTS, &destination_options);
    let raw = frame(
        source,
        destination,
        NEXT_HEADER_HOP_BY_HOP,
        1,
        &hop_by_hop,
        mac(0x10),
    );

    assert!(router.process_incoming_frame("lan1", &raw).is_empty());
}

#[test]
fn time_exceeded_is_suppressed_for_first_fragment_of_icmpv6_error() {
    let mut router = make_router();
    let source = ip6("2001:db8:1::2");
    let destination = ip6("2001:db8:2::2");
    let inner = Ipv6Packet::serialize(destination, source, 17, 64, b"quoted");
    let error = Icmpv6Packet::build_destination_unreachable(source, destination, 0, &inner);
    let mut fragment = vec![NEXT_HEADER_ICMPV6, 0, 0, 0, 0, 0, 0, 1];
    fragment.extend_from_slice(&error);
    let raw = frame(
        source,
        destination,
        NEXT_HEADER_FRAGMENT,
        1,
        &fragment,
        mac(0x10),
    );

    assert!(router.process_incoming_frame("lan1", &raw).is_empty());
}

#[test]
fn time_exceeded_fails_closed_for_non_initial_icmpv6_fragment() {
    let mut router = make_router();
    let source = ip6("2001:db8:1::2");
    let destination = ip6("2001:db8:2::2");
    // Fragment offset 1 means the ICMPv6 type byte is not present in this fragment.
    // The Fragment header still identifies ICMPv6 as the fragmentable protocol, so
    // RFC 4443 error-to-error safety requires conservative suppression.
    let fragment = [NEXT_HEADER_ICMPV6, 0, 0, 8, 0, 0, 0, 1, 0xaa, 0xbb, 0xcc, 0xdd];
    let raw = frame(
        source,
        destination,
        NEXT_HEADER_FRAGMENT,
        1,
        &fragment,
        mac(0x10),
    );

    assert!(router.process_incoming_frame("lan1", &raw).is_empty());
}

#[test]
fn time_exceeded_still_works_for_udp_behind_extension_header() {
    let mut router = make_router();
    let source = ip6("2001:db8:1::2");
    let destination = ip6("2001:db8:2::2");
    let hop_by_hop = extension_header(17, b"udp-payload");
    let raw = frame(
        source,
        destination,
        NEXT_HEADER_HOP_BY_HOP,
        1,
        &hop_by_hop,
        mac(0x10),
    );

    let out = router.process_incoming_frame("lan1", &raw);
    assert_eq!(out.len(), 1);
    let eth = EthernetFrame::parse(&out[0].1).unwrap();
    let ip = Ipv6Packet::parse(eth.payload).unwrap();
    let icmp = Icmpv6Packet::parse(ip.header.src_ip, ip.header.dst_ip, ip.payload, true).unwrap();
    assert_eq!(icmp.msg_type, ICMPV6_TYPE_TIME_EXCEEDED);
}
'''
t += append
test.write_text(t)
