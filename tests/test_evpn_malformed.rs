//! Adversarial MP-BGP and EVPN input.
//!
//! Everything here is what a hostile or broken neighbour can put on the wire
//! once a session is up. The bar is the same as for the IPv4 suite: no length
//! field is trusted before it is checked, the process never panics, the control
//! plane tables stay bounded, and nothing enters the EVPN RIB or programs a
//! tunnel that should not.
//!
//! EVPN widens the attack surface in a specific way. The MP attributes nest a
//! second length-delimited structure inside a path attribute, and the EVPN NLRI
//! nests a third inside that, so there are three separate places a length can
//! claim more than is present - and the interesting ones are the fields *in the
//! middle*, where a lie shifts every offset after it rather than simply running
//! off the end.

mod common;

use common::bgp_lab::{RawBgpPeer, ip};
use toy_tcpip::bgp::{
    AsPath, BGP_ATTR_FLAG_OPTIONAL, BGP_ATTR_FLAG_TRANSITIVE, BgpOrigin, BgpPathAttributes, BgpPdu,
    BgpUpdateMessage,
};
use toy_tcpip::bgp_caps::{AfiSafi, BGP_OPT_PARAM_CAPABILITY, BgpCapabilitySet};
use toy_tcpip::bgp_evpn::{
    MAX_EVPN_NLRI_PER_UPDATE, MAX_EVPN_ROUTES, RouteTarget, decode_evpn_nlri_list,
    encode_evpn_nlri_list,
};
use toy_tcpip::bgp_mp::{
    BGP_ATTR_MP_REACH_NLRI, BGP_ATTR_MP_UNREACH_NLRI, MpReachNlri, MpUnreachNlri,
};
use toy_tcpip::bgp_router::BgpState;
use toy_tcpip::ethernet::MacAddress;
use toy_tcpip::evpn::{EvpnNlri, RouteDistinguisher};
use toy_tcpip::evpn_vtep::MAX_LOCAL_MACS_PER_INSTANCE;
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::lab::evpn_rt;

const AS1: u32 = 65001;
const AS2: u32 = 65002;
const VNI: u32 = 5001;
const VTEP1: Ipv4Address = Ipv4Address([10, 0, 0, 1]);
const VTEP2: Ipv4Address = Ipv4Address([10, 0, 0, 2]);

fn mac(last: u8) -> MacAddress {
    MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, last])
}

fn rd() -> RouteDistinguisher {
    RouteDistinguisher::new(VTEP2, VNI as u16)
}

/// A leaf under test: a VTEP with one instance, and a raw peer already in
/// ESTABLISHED with EVPN negotiated.
fn victim() -> RawBgpPeer {
    let mut peer = RawBgpPeer::connect_configured(AS1, AS2, ip(9, 9, 9, 9), |r| {
        r.add_interface(
            "eth1",
            MacAddress([0x02, 0, 0, 0, 0xBB, 0x02]),
            ip(192, 168, 10, 1),
            24,
            "tenant",
        );
        r.enable_vtep(VTEP1, "eth0");
        r.add_evpn_instance(
            VNI,
            RouteDistinguisher::new(VTEP1, VNI as u16),
            &[evpn_rt(65001, VNI)],
            &[evpn_rt(65001, VNI)],
        );
        r.attach_evpn_access_port(VNI, "eth1");
    });
    peer.establish();
    assert_eq!(peer.state(), BgpState::Established);
    peer
}

/// Wraps a raw MP_REACH_NLRI attribute value in an UPDATE the framer accepts, so
/// the router has to parse the value itself rather than being handed a struct.
fn update_with_raw_attribute(type_code: u8, flags: u8, value: &[u8]) -> Vec<u8> {
    let mut attrs = Vec::new();
    // ORIGIN and AS_PATH, which an MP_REACH UPDATE is required to carry.
    attrs.extend_from_slice(&[BGP_ATTR_FLAG_TRANSITIVE, 1, 1, 0]);
    let path = AsPath::sequence(vec![AS2]).encode_width(true);
    attrs.extend_from_slice(&[BGP_ATTR_FLAG_TRANSITIVE, 2, path.len() as u8]);
    attrs.extend_from_slice(&path);
    attrs.push(flags);
    attrs.push(type_code);
    attrs.push(value.len() as u8);
    attrs.extend_from_slice(value);

    let mut body = Vec::new();
    body.extend_from_slice(&0u16.to_be_bytes()); // no withdrawn routes
    body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    body.extend_from_slice(&attrs);

    let mut frame = Vec::new();
    frame.extend_from_slice(&toy_tcpip::bgp::BGP_MARKER);
    frame.extend_from_slice(&((19 + body.len()) as u16).to_be_bytes());
    frame.push(toy_tcpip::bgp::BGP_MSG_UPDATE);
    frame.extend_from_slice(&body);
    frame
}

/// The state that must be untouched after a malformed message.
fn assert_nothing_leaked(peer: &mut RawBgpPeer) {
    let bgp = peer.victim_bgp();
    assert_eq!(
        bgp.evpn_adj_rib_in.total_routes(),
        0,
        "a malformed UPDATE put a route in the EVPN Adj-RIB-In"
    );
    let vtep = peer.lab.router("victim").unwrap().vtep().unwrap();
    assert_eq!(
        vtep.remote_mac_count(),
        0,
        "a malformed UPDATE programmed a remote MAC"
    );
}

// ============================================================================
// Capability parsing
// ============================================================================

#[test]
fn test_a_malformed_capability_block_never_panics_and_never_negotiates() {
    // Each of these is a different lie about a length, fed to the OPEN parser
    // through the real socket.
    let cases: Vec<Vec<u8>> = vec![
        vec![BGP_OPT_PARAM_CAPABILITY],       // parameter header cut short
        vec![BGP_OPT_PARAM_CAPABILITY, 200],  // parameter longer than the OPEN
        vec![BGP_OPT_PARAM_CAPABILITY, 2, 1], // capability header cut short
        vec![BGP_OPT_PARAM_CAPABILITY, 2, 1, 250], // capability longer than the block
        vec![BGP_OPT_PARAM_CAPABILITY, 3, 65, 1, 7], // AS4 with a one-byte value
        vec![BGP_OPT_PARAM_CAPABILITY, 4, 1, 2, 0, 1], // Multiprotocol with two bytes
        vec![BGP_OPT_PARAM_CAPABILITY, 0],    // empty capability block
        vec![BGP_OPT_PARAM_CAPABILITY, 2, 2, 4, 0, 0, 0, 0], // Route Refresh with a value
    ];

    for raw in cases {
        // The decoder itself must return, not panic, whatever the bytes say.
        let _ = BgpCapabilitySet::parse_opt_params(&raw);

        let mut peer = RawBgpPeer::connect(AS1, AS2, ip(9, 9, 9, 9));
        let mut open = toy_tcpip::bgp::BgpOpenMessage::new(AS2, 9, ip(5, 5, 5, 5));
        open.opt_params = raw.clone();
        peer.write(&BgpPdu::Open(open).serialize());

        // Either the OPEN was refused or it was read; what must never happen is
        // a session that believes it negotiated something it could not parse.
        if peer.state() == BgpState::Established {
            let negotiated = &peer.victim_bgp().peers()[0].negotiated;
            assert!(
                !negotiated.supports_evpn(),
                "EVPN was negotiated from a capability block that does not parse: {:?}",
                raw
            );
        }
    }
}

#[test]
fn test_a_capability_length_that_overruns_is_refused_by_the_decoder() {
    assert!(BgpCapabilitySet::parse_opt_params(&[BGP_OPT_PARAM_CAPABILITY, 2, 1, 250]).is_err());
    assert!(BgpCapabilitySet::parse_opt_params(&[BGP_OPT_PARAM_CAPABILITY, 200]).is_err());
    assert!(BgpCapabilitySet::parse_opt_params(&[BGP_OPT_PARAM_CAPABILITY]).is_err());
}

// ============================================================================
// MP attribute lengths
// ============================================================================

#[test]
fn test_a_lying_mp_reach_length_is_refused_rather_than_indexed() {
    // The next-hop length is the dangerous one: it sits before the reserved
    // octet and the NLRI, so a lie there moves everything after it.
    let cases: Vec<Vec<u8>> = vec![
        vec![],                               // empty
        vec![0, 25],                          // AFI only
        vec![0, 25, 70],                      // no next-hop length
        vec![0, 25, 70, 4],                   // next hop claimed, none present
        vec![0, 25, 70, 4, 10, 0, 0, 1],      // next hop present, no reserved octet
        vec![0, 25, 70, 200, 10, 0, 0, 1, 0], // next hop far longer than the value
        vec![0, 25, 70, 255, 0],              // maximal next-hop claim
    ];
    for raw in &cases {
        assert!(
            MpReachNlri::parse_value(raw).is_err(),
            "MP_REACH value {:?} was accepted",
            raw
        );
    }

    // And through the real session, which also exercises the attribute framing.
    for raw in &cases {
        let mut peer = victim();
        peer.write(&update_with_raw_attribute(
            BGP_ATTR_MP_REACH_NLRI,
            BGP_ATTR_FLAG_OPTIONAL,
            raw,
        ));
        assert_nothing_leaked(&mut peer);
    }
}

#[test]
fn test_a_lying_mp_unreach_length_is_refused() {
    for raw in [vec![], vec![0u8], vec![0, 25]] {
        assert!(MpUnreachNlri::parse_value(&raw).is_err());
        let mut peer = victim();
        peer.write(&update_with_raw_attribute(
            BGP_ATTR_MP_UNREACH_NLRI,
            BGP_ATTR_FLAG_OPTIONAL,
            &raw,
        ));
        assert_nothing_leaked(&mut peer);
    }
}

#[test]
fn test_an_mp_attribute_with_the_wrong_flags_is_refused() {
    // RFC 4760 makes both attributes optional non-transitive. One marked
    // well-known would have to be understood by every receiver, which is exactly
    // the claim a speaker must not be able to make about a family we may not
    // implement.
    let mp = MpReachNlri::with_ipv4_next_hop(AfiSafi::L2VPN_EVPN, VTEP2, Vec::new());
    let mut peer = victim();
    peer.write(&update_with_raw_attribute(
        BGP_ATTR_MP_REACH_NLRI,
        BGP_ATTR_FLAG_TRANSITIVE,
        &mp.encode_value(),
    ));
    assert_ne!(peer.state(), BgpState::Established);
}

#[test]
fn test_an_unnegotiated_afi_safi_is_ignored_without_disturbing_the_session() {
    let mut peer = victim();
    let mp = MpReachNlri::new(AfiSafi::new(2, 1), vec![0u8; 16], vec![0xAA, 0xBB]);
    peer.write(&update_with_raw_attribute(
        BGP_ATTR_MP_REACH_NLRI,
        BGP_ATTR_FLAG_OPTIONAL,
        &mp.encode_value(),
    ));

    // IPv6-Unicast is implemented, but this test peer did not negotiate AFI 2 /
    // SAFI 1 in OPEN. The optional MP attribute must therefore not be consumed as
    // usable routing information or reset the otherwise healthy session.
    assert_eq!(peer.state(), BgpState::Established);
    assert_nothing_leaked(&mut peer);
}

// ============================================================================
// EVPN NLRI structure
// ============================================================================

#[test]
fn test_every_truncation_of_a_valid_nlri_list_is_refused_or_empty() {
    // The exhaustive form of the bounds check: take a route that decodes, cut it
    // at every possible point, and require that none of the prefixes panics.
    let full = encode_evpn_nlri_list(&[
        EvpnNlri::build_mac_ip(rd(), mac(1), Some(ip(192, 168, 10, 11)), VNI),
        EvpnNlri::build_inclusive_multicast(rd(), VTEP2),
    ]);
    for n in 0..full.len() {
        let _ = decode_evpn_nlri_list(&full[..n]);
    }
    // The complete list still decodes, so the loop above was not vacuous.
    assert_eq!(decode_evpn_nlri_list(&full).unwrap().len(), 2);
}

#[test]
fn test_a_lying_nlri_length_field_is_refused() {
    assert!(decode_evpn_nlri_list(&[2, 200, 0, 0]).is_err());
    assert!(decode_evpn_nlri_list(&[2]).is_err());
    assert!(
        decode_evpn_nlri_list(&[2, 0]).is_err(),
        "a zero-length body"
    );
    assert!(decode_evpn_nlri_list(&[3, 255]).is_err());
}

#[test]
fn test_a_mac_length_other_than_48_bits_is_refused() {
    // Body: RD(8) ESI(10) EthTag(4) MacLen(1) MAC(6) IpLen(1) Label(3).
    // Claiming any other MAC length shifts every field after it, so reading the
    // route as if it had said 48 would decode a MAC that was never sent.
    for bad_len in [0u8, 32, 47, 49, 64, 255] {
        let mut body = vec![0u8; 33];
        body[22] = bad_len;
        let mut nlri = vec![2u8, body.len() as u8];
        nlri.extend_from_slice(&body);
        assert!(
            EvpnNlri::parse(&nlri).is_err(),
            "a MAC length of {} bits was accepted",
            bad_len
        );
    }
    // 48 is accepted, so the loop above rejects the length and not the shape.
    let mut body = vec![0u8; 33];
    body[22] = 48;
    body[29] = 0;
    let mut nlri = vec![2u8, body.len() as u8];
    nlri.extend_from_slice(&body);
    assert!(EvpnNlri::parse(&nlri).is_ok());
}

#[test]
fn test_an_ip_length_that_does_not_fit_the_body_is_refused() {
    // The bug this pins: a route claiming a 32-bit host IP inside a body with no
    // room for one used to be read anyway, indexing past the end.
    for body_len in 33..37 {
        let mut body = vec![0u8; body_len];
        body[22] = 48; // MAC length
        body[29] = 32; // claims an IPv4 host address
        let mut nlri = vec![2u8, body.len() as u8];
        nlri.extend_from_slice(&body);
        assert!(
            EvpnNlri::parse(&nlri).is_err(),
            "a {}-byte body claiming a 32-bit IP was accepted",
            body_len
        );
    }
    // 37 bytes is exactly enough, and decodes.
    let mut body = vec![0u8; 37];
    body[22] = 48;
    body[29] = 32;
    let mut nlri = vec![2u8, body.len() as u8];
    nlri.extend_from_slice(&body);
    assert!(EvpnNlri::parse(&nlri).is_ok());

    // An IP length that is neither 0, 32 nor 128 is a lie about the layout.
    for bad in [1u8, 31, 33, 64, 127, 129, 255] {
        let mut body = vec![0u8; 64];
        body[22] = 48;
        body[29] = bad;
        let mut nlri = vec![2u8, body.len() as u8];
        nlri.extend_from_slice(&body);
        assert!(
            EvpnNlri::parse(&nlri).is_err(),
            "an IP length of {} bits was accepted",
            bad
        );
    }
}

#[test]
fn test_a_type_3_route_with_a_bad_ip_length_is_refused() {
    for bad in [0u8, 1, 31, 33, 128, 255] {
        let mut body = vec![0u8; 17];
        body[12] = bad;
        let mut nlri = vec![3u8, body.len() as u8];
        nlri.extend_from_slice(&body);
        assert!(
            EvpnNlri::parse(&nlri).is_err(),
            "a Type 3 IP length of {} bits was accepted",
            bad
        );
    }
}

#[test]
fn test_an_unknown_evpn_route_type_is_skipped_not_fatal() {
    // Types 1, 4 and 5 exist in RFC 7432 and this speaker does not implement
    // them. Refusing the whole UPDATE would drop the Type 2 routes beside them.
    let mut raw = Vec::new();
    for route_type in [1u8, 4, 5, 99] {
        raw.push(route_type);
        raw.push(4);
        raw.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
    }
    raw.extend_from_slice(&EvpnNlri::build_mac_ip(rd(), mac(7), None, VNI).serialize());

    let decoded = decode_evpn_nlri_list(&raw).unwrap();
    assert_eq!(decoded.len(), 1);
    assert_eq!(
        match &decoded[0] {
            EvpnNlri::MacIpAdv(m) => m.mac,
            _ => panic!("wrong route type survived"),
        },
        mac(7)
    );
}

// ============================================================================
// Extended communities and Route Targets
// ============================================================================

#[test]
fn test_an_extended_communities_length_that_is_not_a_multiple_of_eight_is_refused() {
    let mut peer = victim();
    let mut attrs = Vec::new();
    attrs.extend_from_slice(&[BGP_ATTR_FLAG_TRANSITIVE, 1, 1, 0]);
    let path = AsPath::sequence(vec![AS2]).encode_width(true);
    attrs.extend_from_slice(&[BGP_ATTR_FLAG_TRANSITIVE, 2, path.len() as u8]);
    attrs.extend_from_slice(&path);
    // Seven bytes: a truncated community whose Route Target cannot be trusted.
    attrs.extend_from_slice(&[
        BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANSITIVE,
        16,
        7,
        0,
        2,
        0xFD,
        0xE9,
        0,
        0,
        0x13,
    ]);

    let mut body = Vec::new();
    body.extend_from_slice(&0u16.to_be_bytes());
    body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    body.extend_from_slice(&attrs);
    let mut frame = Vec::new();
    frame.extend_from_slice(&toy_tcpip::bgp::BGP_MARKER);
    frame.extend_from_slice(&((19 + body.len()) as u16).to_be_bytes());
    frame.push(toy_tcpip::bgp::BGP_MSG_UPDATE);
    frame.extend_from_slice(&body);

    peer.write(&frame);
    assert_nothing_leaked(&mut peer);
}

#[test]
fn test_a_community_that_is_not_a_route_target_is_not_read_as_one() {
    use toy_tcpip::bgp_ext_comm::BgpExtendedCommunity;

    // Only the RT subtype counts. A Color or Tunnel Encapsulation community with
    // bytes that happen to look like an RT must not admit a route.
    for other in [
        BgpExtendedCommunity::Color {
            flags: 0,
            color: 5001,
        },
        BgpExtendedCommunity::TunnelEncapsulation { tunnel_type: 8 },
        BgpExtendedCommunity::RouteOrigin2Octet {
            asn: 65001,
            value: 5001,
        },
        BgpExtendedCommunity::MacMobility {
            sticky: false,
            sequence: 5001,
        },
    ] {
        assert_eq!(RouteTarget::from_bytes(&other.serialize()), None);
    }
    // The real thing still decodes.
    let rt = RouteTarget::as2(65001, VNI);
    assert_eq!(RouteTarget::from_bytes(&rt.to_bytes()), Some(rt));
}

#[test]
fn test_an_evpn_route_with_no_route_target_at_all_is_not_imported() {
    let mut peer = victim();
    let nlri = encode_evpn_nlri_list(&[EvpnNlri::build_mac_ip(rd(), mac(1), None, VNI)]);
    let mut attrs =
        BgpPathAttributes::new(BgpOrigin::Igp, AsPath::sequence(vec![AS2]), ip(0, 0, 0, 0));
    attrs.mp_reach = Some(MpReachNlri::with_ipv4_next_hop(
        AfiSafi::L2VPN_EVPN,
        VTEP2,
        nlri,
    ));
    // No extended communities at all.
    peer.write_pdu(BgpPdu::Update(BgpUpdateMessage::mp_announce(attrs)));

    assert_eq!(peer.state(), BgpState::Established);
    assert_nothing_leaked(&mut peer);
    assert!(peer.victim_bgp().peers()[0].counters.evpn_rt_rejected > 0);
}

// ============================================================================
// Next hop
// ============================================================================

#[test]
fn test_an_unusable_evpn_next_hop_is_refused() {
    // A VTEP address that cannot be sent to would program a tunnel that can
    // never come up, and the failure would be silent.
    for bad in [
        Ipv4Address::new(0, 0, 0, 0),
        Ipv4Address::new(127, 0, 0, 1),
        Ipv4Address::new(224, 0, 0, 5),
        Ipv4Address::new(255, 255, 255, 255),
    ] {
        let mut peer = victim();
        let nlri = encode_evpn_nlri_list(&[EvpnNlri::build_mac_ip(rd(), mac(1), None, VNI)]);
        let mut attrs =
            BgpPathAttributes::new(BgpOrigin::Igp, AsPath::sequence(vec![AS2]), ip(0, 0, 0, 0));
        attrs.mp_reach = Some(MpReachNlri::with_ipv4_next_hop(
            AfiSafi::L2VPN_EVPN,
            bad,
            nlri,
        ));
        attrs.ext_communities = vec![RouteTarget::as2(65001, VNI).to_bytes()];
        peer.write_pdu(BgpPdu::Update(BgpUpdateMessage::mp_announce(attrs)));

        assert_ne!(
            peer.state(),
            BgpState::Established,
            "an EVPN next hop of {} was accepted",
            bad
        );
        assert_nothing_leaked(&mut peer);
    }
}

#[test]
fn test_an_evpn_next_hop_that_is_not_four_bytes_is_refused() {
    let mut peer = victim();
    let nlri = encode_evpn_nlri_list(&[EvpnNlri::build_mac_ip(rd(), mac(1), None, VNI)]);
    // A 16-byte next hop names an IPv6 VTEP this underlay cannot reach.
    let mp = MpReachNlri::new(AfiSafi::L2VPN_EVPN, vec![0x20; 16], nlri);
    peer.write(&update_with_raw_attribute(
        BGP_ATTR_MP_REACH_NLRI,
        BGP_ATTR_FLAG_OPTIONAL,
        &mp.encode_value(),
    ));
    assert_ne!(peer.state(), BgpState::Established);
    assert_nothing_leaked(&mut peer);
}

// ============================================================================
// Bounds
// ============================================================================

#[test]
fn test_the_evpn_adj_rib_in_is_bounded() {
    let mut peer = victim();
    let rt = RouteTarget::as2(65001, VNI).to_bytes();

    // Advertise more routes than the cap allows - 5120 against a cap of 4096 -
    // in batches the framer will accept, and require the session to be cut
    // rather than the table to grow.
    let mut sent = 0usize;
    let mut cut = false;
    'outer: for batch in 0..80u32 {
        let routes: Vec<EvpnNlri> = (0..64u32)
            .map(|i| {
                let n = batch * 64 + i;
                EvpnNlri::build_mac_ip(
                    rd(),
                    MacAddress([
                        0x02,
                        (n >> 24) as u8,
                        (n >> 16) as u8,
                        (n >> 8) as u8,
                        n as u8,
                        1,
                    ]),
                    None,
                    VNI,
                )
            })
            .collect();
        let mut attrs =
            BgpPathAttributes::new(BgpOrigin::Igp, AsPath::sequence(vec![AS2]), ip(0, 0, 0, 0));
        attrs.mp_reach = Some(MpReachNlri::with_ipv4_next_hop(
            AfiSafi::L2VPN_EVPN,
            VTEP2,
            encode_evpn_nlri_list(&routes),
        ));
        attrs.ext_communities = vec![rt];
        peer.write_pdu(BgpPdu::Update(BgpUpdateMessage::mp_announce(attrs)));
        sent += routes.len();

        if peer.state() != BgpState::Established {
            cut = true;
            break 'outer;
        }
        assert!(
            peer.victim_bgp().evpn_adj_rib_in.total_routes() <= MAX_EVPN_ROUTES,
            "the EVPN Adj-RIB-In grew past its cap after {} routes",
            sent
        );
    }

    assert!(
        sent > MAX_EVPN_ROUTES,
        "the test stopped before the cap could be reached, so it proves nothing"
    );
    assert!(
        cut,
        "a peer advertised {} EVPN routes against a cap of {} and kept its session",
        sent, MAX_EVPN_ROUTES
    );
    let note = peer
        .notification()
        .expect("no NOTIFICATION when the EVPN route limit was blown");
    assert_eq!(note.error_code, 6); // Cease
    assert_eq!(note.error_subcode, 1); // Maximum Number of Prefixes Reached

    // Tearing the session down took the routes with it, so a peer cannot leave
    // a full table behind by overrunning the cap.
    assert_eq!(peer.victim_bgp().evpn_adj_rib_in.total_routes(), 0);
    assert_eq!(
        peer.lab
            .router("victim")
            .unwrap()
            .vtep()
            .unwrap()
            .remote_mac_count(),
        0
    );
}

#[test]
fn test_one_update_cannot_carry_unbounded_nlri() {
    // A pathological NLRI list is refused by count, not merely by message size.
    let one = EvpnNlri::build_mac_ip(rd(), mac(1), None, VNI).serialize();
    let mut raw = Vec::new();
    for _ in 0..(MAX_EVPN_NLRI_PER_UPDATE + 10) {
        raw.extend_from_slice(&one);
    }
    assert!(decode_evpn_nlri_list(&raw).is_err());
}

#[test]
fn test_local_mac_learning_is_bounded() {
    let mut peer = victim();
    let router = peer.lab.router_mut("victim").unwrap();
    let vtep = router.vtep_mut().unwrap();
    for i in 0..(MAX_LOCAL_MACS_PER_INSTANCE + 100) {
        vtep.learn_local(
            "eth1",
            MacAddress([2, 0, (i >> 16) as u8, (i >> 8) as u8, i as u8, 9]),
            None,
        );
    }
    assert_eq!(
        peer.lab
            .router("victim")
            .unwrap()
            .vtep()
            .unwrap()
            .local_mac_count(),
        MAX_LOCAL_MACS_PER_INSTANCE
    );
}

// ============================================================================
// Duplicate and conflicting attributes
// ============================================================================

#[test]
fn test_a_duplicate_mp_reach_attribute_is_refused() {
    let mut peer = victim();
    let mp = MpReachNlri::with_ipv4_next_hop(
        AfiSafi::L2VPN_EVPN,
        VTEP2,
        encode_evpn_nlri_list(&[EvpnNlri::build_mac_ip(rd(), mac(1), None, VNI)]),
    );
    let value = mp.encode_value();

    let mut attrs = Vec::new();
    attrs.extend_from_slice(&[BGP_ATTR_FLAG_TRANSITIVE, 1, 1, 0]);
    let path = AsPath::sequence(vec![AS2]).encode_width(true);
    attrs.extend_from_slice(&[BGP_ATTR_FLAG_TRANSITIVE, 2, path.len() as u8]);
    attrs.extend_from_slice(&path);
    for _ in 0..2 {
        attrs.push(BGP_ATTR_FLAG_OPTIONAL);
        attrs.push(BGP_ATTR_MP_REACH_NLRI);
        attrs.push(value.len() as u8);
        attrs.extend_from_slice(&value);
    }

    let mut body = Vec::new();
    body.extend_from_slice(&0u16.to_be_bytes());
    body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    body.extend_from_slice(&attrs);
    let mut frame = Vec::new();
    frame.extend_from_slice(&toy_tcpip::bgp::BGP_MARKER);
    frame.extend_from_slice(&((19 + body.len()) as u16).to_be_bytes());
    frame.push(toy_tcpip::bgp::BGP_MSG_UPDATE);
    frame.extend_from_slice(&body);

    peer.write(&frame);
    assert_ne!(
        peer.state(),
        BgpState::Established,
        "an UPDATE with two MP_REACH attributes was accepted"
    );
    assert_nothing_leaked(&mut peer);
}

#[test]
fn test_an_mp_reach_and_mp_unreach_for_the_same_route_leave_no_stale_entry() {
    // Announcing and withdrawing the same route in one UPDATE is contradictory
    // but not malformed. Whichever order the implementation applies them in, the
    // outcome must be a table that agrees with itself rather than a half-entry.
    let mut peer = victim();
    let route = EvpnNlri::build_mac_ip(rd(), mac(1), None, VNI);
    let nlri = encode_evpn_nlri_list(std::slice::from_ref(&route));

    let mut attrs =
        BgpPathAttributes::new(BgpOrigin::Igp, AsPath::sequence(vec![AS2]), ip(0, 0, 0, 0));
    attrs.ext_communities = vec![RouteTarget::as2(65001, VNI).to_bytes()];
    attrs.mp_reach = Some(MpReachNlri::with_ipv4_next_hop(
        AfiSafi::L2VPN_EVPN,
        VTEP2,
        nlri.clone(),
    ));
    attrs.mp_unreach = Some(MpUnreachNlri::new(AfiSafi::L2VPN_EVPN, nlri));
    peer.write_pdu(BgpPdu::Update(BgpUpdateMessage::mp_announce(attrs)));

    let bgp = peer.victim_bgp();
    let in_rib = bgp.evpn_adj_rib_in.total_routes();
    let programmed = peer
        .lab
        .router("victim")
        .unwrap()
        .vtep()
        .unwrap()
        .remote_mac_count();
    assert_eq!(
        in_rib, programmed,
        "the RIB and the data plane disagree after a contradictory UPDATE"
    );
}

// ============================================================================
// AS_PATH policing on the EVPN family
// ============================================================================

/// Builds an EVPN announcement with an arbitrary AS_PATH.
fn evpn_announce_with_path(path: AsPath) -> BgpPdu {
    let mut attrs = BgpPathAttributes::new(BgpOrigin::Igp, path, ip(0, 0, 0, 0));
    attrs.ext_communities = vec![RouteTarget::as2(65001, VNI).to_bytes()];
    attrs.mp_reach = Some(MpReachNlri::with_ipv4_next_hop(
        AfiSafi::L2VPN_EVPN,
        VTEP2,
        encode_evpn_nlri_list(&[EvpnNlri::build_mac_ip(rd(), mac(1), None, VNI)]),
    ));
    BgpPdu::Update(BgpUpdateMessage::mp_announce(attrs))
}

#[test]
fn test_an_evpn_update_with_an_empty_as_path_is_refused() {
    // AS_PATH length is a tie-break in the EVPN decision process as well, so a
    // zero-length path from an external peer would beat every legitimate
    // advertisement of the same MAC and silently take the host over.
    let mut peer = victim();
    peer.write_pdu(evpn_announce_with_path(AsPath::empty()));

    let note = peer
        .notification()
        .expect("an EVPN UPDATE with an empty AS_PATH was accepted");
    assert_eq!(note.error_code, toy_tcpip::bgp::BGP_ERR_UPDATE_MESSAGE);
    assert_ne!(peer.state(), BgpState::Established);
    assert_nothing_leaked(&mut peer);
}

#[test]
fn test_an_evpn_update_that_disowns_its_own_as_is_refused() {
    // The eBGP leading-AS rule. An EVPN UPDATE never passes through
    // `import_update`, so this check has to exist on the multiprotocol path too
    // or the family would be exempt from it.
    let mut peer = victim();
    peer.write_pdu(evpn_announce_with_path(AsPath::sequence(vec![64_999, AS2])));

    let note = peer
        .notification()
        .expect("an EVPN UPDATE not leading with the neighbour's AS was accepted");
    assert_eq!(note.error_code, toy_tcpip::bgp::BGP_ERR_UPDATE_MESSAGE);
    assert_nothing_leaked(&mut peer);
}

#[test]
fn test_an_evpn_update_that_has_already_crossed_this_as_is_discarded() {
    // A loop is not a protocol violation, so the session survives and the route
    // is simply not taken.
    let mut peer = victim();
    peer.write_pdu(evpn_announce_with_path(AsPath::sequence(vec![AS2, AS1])));

    assert_eq!(peer.state(), BgpState::Established);
    assert_nothing_leaked(&mut peer);
    assert!(peer.victim_bgp().peers()[0].counters.as_loops_rejected > 0);
}

// ============================================================================
// MAC mobility cannot run away
// ============================================================================

#[test]
fn test_a_mac_that_keeps_moving_is_eventually_left_alone() {
    use toy_tcpip::evpn_vtep::MAX_MAC_MOVES;

    // Two VTEPs both genuinely holding the same MAC would otherwise bid the
    // sequence number up forever, one UPDATE per move, for the rest of the
    // session. Simulate the far side always claiming a higher number.
    let mut peer = victim();
    let flapper = mac(0x77);

    for round in 0..(MAX_MAC_MOVES + 3) {
        // The far leaf claims it with an ever-higher sequence.
        let mut attrs =
            BgpPathAttributes::new(BgpOrigin::Igp, AsPath::sequence(vec![AS2]), ip(0, 0, 0, 0));
        attrs.ext_communities = vec![
            RouteTarget::as2(65001, VNI).to_bytes(),
            toy_tcpip::bgp_ext_comm::BgpExtendedCommunity::MacMobility {
                sticky: false,
                sequence: round,
            }
            .serialize(),
        ];
        attrs.mp_reach = Some(MpReachNlri::with_ipv4_next_hop(
            AfiSafi::L2VPN_EVPN,
            VTEP2,
            encode_evpn_nlri_list(&[EvpnNlri::build_mac_ip(rd(), flapper, None, VNI)]),
        ));
        peer.write_pdu(BgpPdu::Update(BgpUpdateMessage::mp_announce(attrs)));

        // ...and the host keeps appearing on the local access port.
        peer.lab
            .router_mut("victim")
            .unwrap()
            .vtep_mut()
            .unwrap()
            .learn_local("eth1", flapper, None);
        peer.run_until(2_000, |_| false);
    }

    let vtep = peer.lab.router("victim").unwrap().vtep().unwrap();
    let inst = vtep.instance(VNI).unwrap();
    assert!(
        inst.duplicate_macs.contains(&flapper),
        "a MAC that moved {} times was still being chased",
        MAX_MAC_MOVES + 3
    );
    assert!(
        !inst.local_macs.contains_key(&flapper),
        "the duplicate MAC is still advertised locally"
    );
    // The sequence number stopped climbing rather than running away.
    assert!(
        inst.remote_macs
            .get(&flapper)
            .is_none_or(|r| r.sequence <= MAX_MAC_MOVES + 3)
    );

    // A different MAC is unaffected: damping is per-MAC, not a whole-instance
    // freeze.
    peer.lab
        .router_mut("victim")
        .unwrap()
        .vtep_mut()
        .unwrap()
        .learn_local("eth1", mac(0x78), None);
    assert!(
        peer.lab
            .router("victim")
            .unwrap()
            .vtep()
            .unwrap()
            .instance(VNI)
            .unwrap()
            .local_macs
            .contains_key(&mac(0x78))
    );
}

// ============================================================================
// Nothing above disturbed a working session
// ============================================================================

#[test]
fn test_a_well_formed_evpn_update_still_works() {
    // The control for every rejection above: the same harness, the same shape of
    // message, correct this time, must be accepted and must program the tunnel.
    let mut peer = victim();
    let mut attrs =
        BgpPathAttributes::new(BgpOrigin::Igp, AsPath::sequence(vec![AS2]), ip(0, 0, 0, 0));
    attrs.ext_communities = vec![RouteTarget::as2(65001, VNI).to_bytes()];
    attrs.mp_reach = Some(MpReachNlri::with_ipv4_next_hop(
        AfiSafi::L2VPN_EVPN,
        VTEP2,
        encode_evpn_nlri_list(&[EvpnNlri::build_mac_ip(
            rd(),
            mac(0xBB),
            Some(ip(192, 168, 10, 22)),
            VNI,
        )]),
    ));
    peer.write_pdu(BgpPdu::Update(BgpUpdateMessage::mp_announce(attrs)));

    assert_eq!(peer.state(), BgpState::Established);
    assert_eq!(peer.victim_bgp().evpn_adj_rib_in.total_routes(), 1);
    assert_eq!(
        peer.lab
            .router("victim")
            .unwrap()
            .vtep()
            .unwrap()
            .lookup_remote(VNI, &mac(0xBB)),
        Some(VTEP2)
    );
}
