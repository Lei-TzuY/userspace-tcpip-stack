//! Adversarial BGP-4 input.
//!
//! Everything here is what a hostile or broken peer can put on the wire. The bar is:
//! the process never panics, no length field is trusted before it is checked, buffers
//! stay bounded, and the session either survives or is torn down with the NOTIFICATION
//! the RFC prescribes - but nothing enters the RIB or the FIB that should not.

mod common;

use common::bgp_lab::{AS1, AS2, AS3, RawBgpPeer, ip, prefix};
use toy_tcpip::bgp::{
    AsPath, AsPathSegment, AsPathSegmentKind, BGP_ATTR_AS_PATH, BGP_ATTR_FLAG_EXT_LEN,
    BGP_ATTR_FLAG_OPTIONAL, BGP_ATTR_FLAG_TRANSITIVE, BGP_ATTR_NEXT_HOP, BGP_ATTR_ORIGIN,
    BGP_ERR_MESSAGE_HEADER, BGP_ERR_UPDATE_MESSAGE, BGP_HEADER_LEN, BGP_MARKER,
    BGP_MAX_MESSAGE_LEN, BGP_MSG_KEEPALIVE, BGP_MSG_OPEN, BGP_MSG_UPDATE,
    BGP_SUB_ATTRIBUTE_LENGTH_ERROR, BGP_SUB_CONNECTION_NOT_SYNCHRONIZED, BGP_SUB_INVALID_NEXT_HOP,
    BGP_SUB_MALFORMED_AS_PATH, BGP_SUB_MALFORMED_ATTRIBUTE_LIST, BGP_SUB_MISSING_WELL_KNOWN_ATTR,
    BGP_SUB_UNRECOGNIZED_WELL_KNOWN_ATTR, BgpFramer, BgpOrigin, BgpPathAttributes, BgpPdu,
    BgpUpdateMessage, Ipv4Prefix,
};
use toy_tcpip::bgp_router::BgpState;
use toy_tcpip::ipv4::Ipv4Address;

/// Wraps a hand-built UPDATE body in a correct 19-byte header, so the test exercises
/// the body parser rather than the header check.
fn frame_update(body: &[u8]) -> Vec<u8> {
    let total = BGP_HEADER_LEN + body.len();
    let mut out = BGP_MARKER.to_vec();
    out.extend_from_slice(&(total as u16).to_be_bytes());
    out.push(BGP_MSG_UPDATE);
    out.extend_from_slice(body);
    out
}

/// Assembles an UPDATE body from raw parts, without any of the validation the normal
/// encoder applies.
fn raw_update_body(withdrawn: &[u8], attrs: &[u8], nlri: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(withdrawn.len() as u16).to_be_bytes());
    body.extend_from_slice(withdrawn);
    body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    body.extend_from_slice(attrs);
    body.extend_from_slice(nlri);
    body
}

fn origin_attr(value: u8) -> Vec<u8> {
    vec![BGP_ATTR_FLAG_TRANSITIVE, BGP_ATTR_ORIGIN, 1, value]
}

fn next_hop_attr(a: u8, b: u8, c: u8, d: u8) -> Vec<u8> {
    vec![BGP_ATTR_FLAG_TRANSITIVE, BGP_ATTR_NEXT_HOP, 4, a, b, c, d]
}

/// A well-formed AS_PATH with one AS_SEQUENCE.
fn as_path_attr(asns: &[u16]) -> Vec<u8> {
    let mut seg = vec![2u8, asns.len() as u8];
    for a in asns {
        seg.extend_from_slice(&a.to_be_bytes());
    }
    let mut out = vec![BGP_ATTR_FLAG_TRANSITIVE, BGP_ATTR_AS_PATH, seg.len() as u8];
    out.extend_from_slice(&seg);
    out
}

// ============================================================================
// Header and framing
// ============================================================================

#[test]
fn test_every_byte_prefix_of_a_valid_message_is_handled_without_panicking() {
    // Truncation at every possible point, for every message type.
    let messages = [
        BgpPdu::Open(toy_tcpip::bgp::BgpOpenMessage::new(AS1, 90, ip(1, 1, 1, 1))).serialize(),
        BgpPdu::Keepalive.serialize(),
        BgpPdu::Notification(toy_tcpip::bgp::BgpNotificationMessage::new(6, 0)).serialize(),
        BgpPdu::Update(BgpUpdateMessage::announce(
            BgpPathAttributes::new(BgpOrigin::Igp, AsPath::sequence(vec![AS2]), ip(10, 0, 0, 1)),
            vec![prefix(192, 0, 2, 0, 24)],
        ))
        .serialize(),
    ];

    for msg in &messages {
        for cut in 0..msg.len() {
            // Direct decode of a truncated frame must error, never panic.
            let _ = BgpPdu::parse(&msg[..cut]);
            // And the framer must simply wait for more, or reject the header.
            let mut framer = BgpFramer::new();
            framer.push(&msg[..cut]).unwrap();
            let _ = framer.next_frame();
        }
    }
}

#[test]
fn test_arbitrary_byte_soup_never_panics_and_never_decodes() {
    // A deterministic pseudo-random sweep: no dependency, same bytes every run.
    let mut state: u32 = 0x1234_5678;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        state
    };

    let mut decoded = 0usize;
    for _ in 0..4_000 {
        let len = (next() % 200) as usize;
        let mut buf: Vec<u8> = (0..len).map(|_| (next() & 0xFF) as u8).collect();
        // Half the cases get a real marker, so the length and type checks are reached.
        if next() % 2 == 0 && buf.len() >= 19 {
            buf[..16].copy_from_slice(&BGP_MARKER);
        }
        if BgpPdu::parse(&buf).is_ok() {
            decoded += 1;
        }
        let mut framer = BgpFramer::new();
        if framer.push(&buf).is_ok() {
            // Draining must terminate: either it errors or it runs out of input.
            let mut guard = 0;
            while guard < 1_000 {
                match framer.next_frame() {
                    Ok(Some(f)) => {
                        let _ = BgpPdu::parse(&f);
                    }
                    _ => break,
                }
                guard += 1;
            }
            assert!(guard < 1_000, "the framer did not terminate");
        }
    }
    // A handful of random KEEPALIVE-shaped frames decoding is fine and expected; the
    // point is that nothing panicked and nothing ran off the end of a buffer.
    assert!(decoded < 4_000);
}

#[test]
fn test_a_bad_marker_tears_the_session_down_with_a_notification() {
    let mut peer = RawBgpPeer::connect(AS1, AS2, ip(9, 9, 9, 9));
    peer.establish_legacy();

    // 19 bytes that look like a header but carry the wrong marker.
    let mut junk = vec![0xAAu8; 16];
    junk.extend_from_slice(&19u16.to_be_bytes());
    junk.push(BGP_MSG_KEEPALIVE);
    peer.write(&junk);

    let note = peer
        .notification()
        .expect("a desynchronised stream should produce a NOTIFICATION");
    assert_eq!(note.error_code, BGP_ERR_MESSAGE_HEADER);
    assert_eq!(note.error_subcode, BGP_SUB_CONNECTION_NOT_SYNCHRONIZED);
    assert_ne!(peer.state(), BgpState::Established);
}

#[test]
fn test_an_impossible_length_field_tears_the_session_down() {
    let mut peer = RawBgpPeer::connect(AS1, AS2, ip(9, 9, 9, 9));
    peer.establish_legacy();

    let mut frame = BGP_MARKER.to_vec();
    frame.extend_from_slice(&65_535u16.to_be_bytes());
    frame.push(BGP_MSG_UPDATE);
    peer.write(&frame);

    let note = peer
        .notification()
        .expect("no NOTIFICATION for a 65535-byte length");
    assert_eq!(note.error_code, BGP_ERR_MESSAGE_HEADER);
    assert_ne!(peer.state(), BgpState::Established);
}

#[test]
fn test_a_peer_that_vanishes_mid_message_leaves_nothing_behind() {
    let mut peer = RawBgpPeer::connect(AS1, AS2, ip(9, 9, 9, 9));
    peer.establish_legacy();

    // Half an UPDATE, then the connection goes away.
    let update = BgpPdu::Update(BgpUpdateMessage::announce(
        BgpPathAttributes::new(
            BgpOrigin::Igp,
            AsPath::sequence(vec![AS2]),
            ip(10, 50, 0, 2),
        ),
        vec![prefix(198, 51, 100, 0, 24)],
    ))
    .serialize();
    peer.write(&update[..update.len() / 2]);

    // The partial message must not have been acted on.
    assert!(peer.victim_bgp().loc_rib.is_empty());

    peer.disconnect();
    let victim = peer.peer;
    assert!(
        peer.run_until(60_000, |l| {
            l.router("victim")
                .unwrap()
                .bgp()
                .unwrap()
                .peer_state(victim)
                != Some(BgpState::Established)
        }),
        "the router did not notice the peer disappearing"
    );

    let bgp = peer.victim_bgp();
    assert_eq!(bgp.adj_rib_in.path_count(), 0);
    assert!(bgp.loc_rib.is_empty());
    assert!(bgp.installed_prefixes().is_empty());
    // The half-message was dropped with the session rather than kept for a future one.
    assert_eq!(bgp.peer(victim).unwrap().buffered_bytes(), 0);
}

#[test]
fn test_a_flood_of_junk_cannot_grow_the_receive_buffer_without_bound() {
    let mut peer = RawBgpPeer::connect(AS1, AS2, ip(9, 9, 9, 9));
    peer.establish_legacy();

    // Far more bytes than any legal message, all header-shaped so the framer keeps
    // looking at them.
    let mut header = BGP_MARKER.to_vec();
    header.extend_from_slice(&4_096u16.to_be_bytes());
    header.push(BGP_MSG_UPDATE);
    let mut flood = header;
    flood.resize(4_000, 0x41);
    for _ in 0..8 {
        // A closed session refuses further writes; stop as soon as that happens.
        if peer
            .lab
            .host_mut("peer")
            .unwrap()
            .stack
            .tcp_write(peer.stream, &flood)
            .is_err()
        {
            break;
        }
        peer.pump();
    }

    // Whatever happened, the buffered byte count stayed inside the documented cap.
    let victim = peer.peer;
    let buffered = peer.victim_bgp().peer(victim).unwrap().buffered_bytes();
    assert!(
        buffered <= 2 * BGP_MAX_MESSAGE_LEN,
        "reassembly buffer grew to {} bytes",
        buffered
    );
    // And nothing bogus reached the RIB.
    assert!(peer.victim_bgp().loc_rib.is_empty());
}

// ============================================================================
// Malformed UPDATE bodies
// ============================================================================

#[test]
fn test_update_without_the_mandatory_attributes_is_rejected() {
    // ORIGIN and AS_PATH present, NEXT_HOP missing.
    let mut attrs = origin_attr(0);
    attrs.extend(as_path_attr(&[AS2 as u16]));
    let body = raw_update_body(&[], &attrs, &[24, 198, 51, 100]);
    let err = BgpUpdateMessage::parse_body(&body[..]).unwrap_err();
    assert_eq!(err.code, BGP_ERR_UPDATE_MESSAGE);
    assert_eq!(err.subcode, BGP_SUB_MISSING_WELL_KNOWN_ATTR);

    let mut peer = RawBgpPeer::connect(AS1, AS2, ip(9, 9, 9, 9));
    peer.establish_legacy();
    peer.write(&frame_update(&body));
    let note = peer
        .notification()
        .expect("no NOTIFICATION for a missing NEXT_HOP");
    assert_eq!(note.error_code, BGP_ERR_UPDATE_MESSAGE);
    assert_eq!(note.error_subcode, BGP_SUB_MISSING_WELL_KNOWN_ATTR);
    assert_ne!(peer.state(), BgpState::Established);
    assert!(peer.victim_bgp().loc_rib.is_empty());
}

#[test]
fn test_a_truncated_as_path_segment_is_rejected() {
    // The segment header claims three ASNs but only two follow.
    let seg = vec![2u8, 3, 0xFD, 0xE9, 0xFD, 0xEA];
    let mut attrs = origin_attr(0);
    attrs.push(BGP_ATTR_FLAG_TRANSITIVE);
    attrs.push(BGP_ATTR_AS_PATH);
    attrs.push(seg.len() as u8);
    attrs.extend_from_slice(&seg);
    attrs.extend(next_hop_attr(10, 50, 0, 2));
    let body = raw_update_body(&[], &attrs, &[24, 198, 51, 100]);

    let err = BgpUpdateMessage::parse_body(&body).unwrap_err();
    assert_eq!(err.code, BGP_ERR_UPDATE_MESSAGE);
    assert_eq!(err.subcode, BGP_SUB_MALFORMED_AS_PATH);

    let mut peer = RawBgpPeer::connect(AS1, AS2, ip(9, 9, 9, 9));
    peer.establish_legacy();
    peer.write(&frame_update(&body));
    let note = peer
        .notification()
        .expect("no NOTIFICATION for a truncated AS_PATH");
    assert_eq!(note.error_subcode, BGP_SUB_MALFORMED_AS_PATH);
    assert!(peer.victim_bgp().adj_rib_in.path_count() == 0);
}

#[test]
fn test_an_as_path_with_an_unknown_segment_type_or_empty_segment_is_rejected() {
    for seg in [vec![7u8, 1, 0xFD, 0xE9], vec![2u8, 0]] {
        let mut attrs = origin_attr(0);
        attrs.push(BGP_ATTR_FLAG_TRANSITIVE);
        attrs.push(BGP_ATTR_AS_PATH);
        attrs.push(seg.len() as u8);
        attrs.extend_from_slice(&seg);
        attrs.extend(next_hop_attr(10, 50, 0, 2));
        let body = raw_update_body(&[], &attrs, &[24, 198, 51, 100]);
        let err = BgpUpdateMessage::parse_body(&body).unwrap_err();
        assert_eq!(err.subcode, BGP_SUB_MALFORMED_AS_PATH, "segment {:?}", seg);
    }
}

#[test]
fn test_an_invalid_next_hop_is_rejected_by_the_live_speaker() {
    for bad in [
        Ipv4Address::new(0, 0, 0, 0),
        Ipv4Address::new(127, 0, 0, 1),
        Ipv4Address::new(224, 0, 0, 5),
        Ipv4Address::new(255, 255, 255, 255),
    ] {
        let mut peer = RawBgpPeer::connect(AS1, AS2, ip(9, 9, 9, 9));
        peer.establish_legacy();
        peer.write(
            &BgpPdu::Update(BgpUpdateMessage::announce(
                BgpPathAttributes::new(BgpOrigin::Igp, AsPath::sequence(vec![AS2]), bad),
                vec![prefix(198, 51, 100, 0, 24)],
            ))
            .serialize(),
        );
        let note = peer
            .notification()
            .unwrap_or_else(|| panic!("NEXT_HOP {} was accepted", bad));
        assert_eq!(note.error_code, BGP_ERR_UPDATE_MESSAGE);
        assert_eq!(note.error_subcode, BGP_SUB_INVALID_NEXT_HOP);
        assert!(peer.victim_bgp().loc_rib.is_empty());
        assert!(peer.victim_bgp().installed_prefixes().is_empty());
    }
}

#[test]
fn test_attribute_lengths_that_run_past_the_end_are_rejected() {
    // NEXT_HOP claiming 200 bytes inside a 7-byte attribute block.
    let mut attrs = origin_attr(0);
    attrs.extend(as_path_attr(&[AS2 as u16]));
    attrs.extend_from_slice(&[
        BGP_ATTR_FLAG_TRANSITIVE,
        BGP_ATTR_NEXT_HOP,
        200,
        10,
        0,
        0,
        1,
    ]);
    let body = raw_update_body(&[], &attrs, &[24, 198, 51, 100]);
    let err = BgpUpdateMessage::parse_body(&body).unwrap_err();
    assert_eq!(err.subcode, BGP_SUB_ATTRIBUTE_LENGTH_ERROR);

    // Extended-length flag with a two-byte length that also overruns.
    let mut attrs = origin_attr(0);
    attrs.extend(as_path_attr(&[AS2 as u16]));
    attrs.extend_from_slice(&[
        BGP_ATTR_FLAG_TRANSITIVE | BGP_ATTR_FLAG_EXT_LEN,
        BGP_ATTR_NEXT_HOP,
        0xFF,
        0xFF,
        10,
        0,
        0,
        1,
    ]);
    let body = raw_update_body(&[], &attrs, &[24, 198, 51, 100]);
    assert_eq!(
        BgpUpdateMessage::parse_body(&body).unwrap_err().subcode,
        BGP_SUB_ATTRIBUTE_LENGTH_ERROR
    );

    // A wrong-but-in-range fixed length is also caught.
    let mut attrs = origin_attr(0);
    attrs.extend(as_path_attr(&[AS2 as u16]));
    attrs.extend_from_slice(&[BGP_ATTR_FLAG_TRANSITIVE, BGP_ATTR_NEXT_HOP, 2, 10, 0]);
    let body = raw_update_body(&[], &attrs, &[24, 198, 51, 100]);
    assert_eq!(
        BgpUpdateMessage::parse_body(&body).unwrap_err().subcode,
        BGP_SUB_ATTRIBUTE_LENGTH_ERROR
    );
}

#[test]
fn test_length_fields_inside_the_update_body_are_bounds_checked() {
    // Withdrawn-routes length longer than the whole body.
    let mut body = Vec::new();
    body.extend_from_slice(&500u16.to_be_bytes());
    body.extend_from_slice(&[24, 10, 0, 0]);
    let err = BgpUpdateMessage::parse_body(&body).unwrap_err();
    assert_eq!(err.subcode, BGP_SUB_MALFORMED_ATTRIBUTE_LIST);

    // Path-attribute length longer than what remains.
    let mut body = Vec::new();
    body.extend_from_slice(&0u16.to_be_bytes());
    body.extend_from_slice(&9_000u16.to_be_bytes());
    body.extend_from_slice(&[0x40, 1, 1, 0]);
    assert_eq!(
        BgpUpdateMessage::parse_body(&body).unwrap_err().subcode,
        BGP_SUB_MALFORMED_ATTRIBUTE_LIST
    );

    // A body too short to even hold its two length fields.
    assert!(BgpUpdateMessage::parse_body(&[0, 0, 0]).is_err());
    assert!(BgpUpdateMessage::parse_body(&[]).is_err());
}

#[test]
fn test_an_nlri_prefix_longer_than_32_bits_is_rejected() {
    let mut attrs = origin_attr(0);
    attrs.extend(as_path_attr(&[AS2 as u16]));
    attrs.extend(next_hop_attr(10, 50, 0, 2));
    let body = raw_update_body(&[], &attrs, &[33, 10, 0, 0, 0, 1]);
    assert!(BgpUpdateMessage::parse_body(&body).is_err());

    // And a prefix whose length octet promises more address bytes than are present.
    let body = raw_update_body(&[], &attrs, &[24, 10, 0]);
    assert!(BgpUpdateMessage::parse_body(&body).is_err());
}

#[test]
fn test_an_undefined_origin_value_is_rejected() {
    let mut attrs = origin_attr(9);
    attrs.extend(as_path_attr(&[AS2 as u16]));
    attrs.extend(next_hop_attr(10, 50, 0, 2));
    let body = raw_update_body(&[], &attrs, &[24, 198, 51, 100]);
    let err = BgpUpdateMessage::parse_body(&body).unwrap_err();
    assert_eq!(err.code, BGP_ERR_UPDATE_MESSAGE);
    assert_eq!(err.subcode, 6); // Invalid ORIGIN Attribute
}

#[test]
fn test_a_duplicated_attribute_is_rejected() {
    let mut attrs = origin_attr(0);
    attrs.extend(origin_attr(1));
    attrs.extend(as_path_attr(&[AS2 as u16]));
    attrs.extend(next_hop_attr(10, 50, 0, 2));
    let body = raw_update_body(&[], &attrs, &[24, 198, 51, 100]);
    assert_eq!(
        BgpUpdateMessage::parse_body(&body).unwrap_err().subcode,
        BGP_SUB_MALFORMED_ATTRIBUTE_LIST
    );
}

#[test]
fn test_an_unknown_well_known_attribute_is_an_error_but_an_unknown_optional_is_ignored() {
    let mut attrs = origin_attr(0);
    attrs.extend(as_path_attr(&[AS2 as u16]));
    attrs.extend(next_hop_attr(10, 50, 0, 2));

    // Type 240 with the optional bit clear: a well-known attribute we do not know.
    let mut well_known = attrs.clone();
    well_known.extend_from_slice(&[BGP_ATTR_FLAG_TRANSITIVE, 240, 1, 0]);
    let body = raw_update_body(&[], &well_known, &[24, 198, 51, 100]);
    assert_eq!(
        BgpUpdateMessage::parse_body(&body).unwrap_err().subcode,
        BGP_SUB_UNRECOGNIZED_WELL_KNOWN_ATTR
    );

    // The same type with the optional bit set must be skipped silently.
    let mut optional = attrs;
    optional.extend_from_slice(&[
        BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANSITIVE,
        240,
        3,
        1,
        2,
        3,
    ]);
    let body = raw_update_body(&[], &optional, &[24, 198, 51, 100]);
    let parsed = BgpUpdateMessage::parse_body(&body).expect("unknown optional must be ignored");
    assert_eq!(parsed.nlri, vec![prefix(198, 51, 100, 0, 24)]);
    assert_eq!(parsed.attributes.unwrap().next_hop, ip(10, 50, 0, 2));
}

// ============================================================================
// Round trip and normalisation
// ============================================================================

#[test]
fn test_update_round_trips_through_the_wire_format() {
    let mut attrs = BgpPathAttributes::new(
        BgpOrigin::Incomplete,
        AsPath::sequence(vec![AS1, AS2, AS3]),
        ip(192, 0, 2, 1),
    );
    attrs.med = Some(42);
    attrs.local_pref = Some(250);
    attrs.atomic_aggregate = true;

    let original = BgpUpdateMessage {
        withdrawn: vec![prefix(203, 0, 113, 0, 24), prefix(10, 0, 0, 0, 8)],
        attributes: Some(attrs),
        nlri: vec![
            prefix(198, 51, 100, 0, 24),
            prefix(192, 0, 2, 0, 25),
            prefix(172, 16, 0, 0, 12),
        ],
    };

    let wire = BgpPdu::Update(original.clone()).serialize();
    assert!(wire.len() <= BGP_MAX_MESSAGE_LEN);
    let BgpPdu::Update(decoded) = BgpPdu::parse(&wire).unwrap() else {
        panic!("expected an UPDATE");
    };
    assert_eq!(decoded, original);
}

#[test]
fn test_prefix_host_bits_are_normalised_so_equal_destinations_compare_equal() {
    // 10.1.2.3/24 and 10.1.2.0/24 describe the same destination.
    let a = Ipv4Prefix::new(Ipv4Address::new(10, 1, 2, 3), 24);
    let b = Ipv4Prefix::new(Ipv4Address::new(10, 1, 2, 0), 24);
    assert_eq!(a, b);
    assert_eq!(a.address, Ipv4Address::new(10, 1, 2, 0));

    // And that survives the wire.
    let update = BgpUpdateMessage::announce(
        BgpPathAttributes::new(BgpOrigin::Igp, AsPath::sequence(vec![AS2]), ip(10, 0, 0, 1)),
        vec![a],
    );
    let wire = BgpPdu::Update(update).serialize();
    let BgpPdu::Update(decoded) = BgpPdu::parse(&wire).unwrap() else {
        panic!()
    };
    assert_eq!(decoded.nlri, vec![b]);

    // A /0 default route encodes as a single length octet.
    let default = Ipv4Prefix::new(Ipv4Address::UNSPECIFIED, 0);
    assert_eq!(default.encoded_len(), 1);
    let update = BgpUpdateMessage::withdraw(vec![default]);
    let wire = BgpPdu::Update(update).serialize();
    let BgpPdu::Update(decoded) = BgpPdu::parse(&wire).unwrap() else {
        panic!()
    };
    assert_eq!(decoded.withdrawn, vec![default]);
}

#[test]
fn test_a_keepalive_with_a_body_is_rejected() {
    let mut frame = BGP_MARKER.to_vec();
    frame.extend_from_slice(&24u16.to_be_bytes());
    frame.push(BGP_MSG_KEEPALIVE);
    frame.extend_from_slice(&[0; 5]);
    let err = BgpPdu::parse(&frame).unwrap_err();
    assert_eq!(err.code, BGP_ERR_MESSAGE_HEADER);
}

#[test]
fn test_unsupported_message_types_are_rejected_by_type_not_by_accident() {
    // Type 5 is ROUTE-REFRESH (RFC 2918), so only genuinely undefined types
    // belong in this negative-control sweep.
    for bad_type in [0u8, 6, 200, 255] {
        let mut frame = BGP_MARKER.to_vec();
        frame.extend_from_slice(&19u16.to_be_bytes());
        frame.push(bad_type);
        let err = BgpPdu::parse(&frame).unwrap_err();
        assert_eq!(err.code, BGP_ERR_MESSAGE_HEADER, "type {}", bad_type);
        assert_eq!(err.subcode, 3, "type {}", bad_type); // Bad Message Type
    }

    // Type 5 is recognised, but its body has exactly the RFC 2918 four-byte
    // AFI/reserved/SAFI shape. A header-only message is therefore a length error,
    // not a Bad Message Type error.
    let mut refresh = BGP_MARKER.to_vec();
    refresh.extend_from_slice(&19u16.to_be_bytes());
    refresh.push(toy_tcpip::bgp::BGP_MSG_ROUTE_REFRESH);
    let err = BgpPdu::parse(&refresh).unwrap_err();
    assert_eq!(err.code, BGP_ERR_MESSAGE_HEADER);
    assert_eq!(err.subcode, 2); // Bad Message Length

    // An OPEN whose declared length cannot hold the fixed part is caught too.
    let mut frame = BGP_MARKER.to_vec();
    frame.extend_from_slice(&20u16.to_be_bytes());
    frame.push(BGP_MSG_OPEN);
    frame.push(4);
    assert!(BgpPdu::parse(&frame).is_err());
}

// ============================================================================
// AS_PATH provenance on an external session
// ============================================================================

/// Sends one announcement with a chosen AS_PATH and reports what the speaker did with
/// it: the NOTIFICATION subcode if the session was reset, and how many prefixes ended
/// up in the Adj-RIB-In.
fn announce_with_as_path(peer: &mut RawBgpPeer, as_path: AsPath) -> (Option<u8>, usize) {
    let attrs = BgpPathAttributes::new(BgpOrigin::Igp, as_path, ip(10, 50, 0, 2));
    let p = Ipv4Prefix::new(ip(10, 99, 0, 0), 24);
    peer.write(&BgpPdu::Update(BgpUpdateMessage::announce(attrs, vec![p])).serialize());
    let held = peer.victim_bgp().adj_rib_in.prefix_count(peer.peer);
    (peer.notification().map(|n| n.error_subcode), held)
}

#[test]
fn test_an_ebgp_peer_cannot_advertise_an_empty_as_path() {
    let mut peer = RawBgpPeer::connect(AS1, AS2, ip(9, 9, 9, 9));
    peer.establish_legacy();

    // A zero-length AS_PATH is the strongest possible route: it wins the shortest
    // AS_PATH step against every legitimate path, for every prefix at once. Accepting
    // one would hand a single neighbour the whole table.
    let (subcode, held) = announce_with_as_path(&mut peer, AsPath::empty());

    assert_eq!(held, 0, "an empty AS_PATH reached the Adj-RIB-In");
    assert_eq!(subcode, Some(BGP_SUB_MALFORMED_AS_PATH));
    assert_eq!(peer.state(), BgpState::Idle);
    assert!(peer.victim_bgp().loc_rib.is_empty());
}

#[test]
fn test_an_ebgp_peer_cannot_disown_the_leading_as() {
    let mut peer = RawBgpPeer::connect(AS1, AS2, ip(9, 9, 9, 9));
    peer.establish_legacy();

    // The harness speaks for AS65002, so a path claiming to arrive straight from
    // AS65099 is a peer misrepresenting the route it is carrying.
    let (subcode, held) = announce_with_as_path(&mut peer, AsPath::sequence(vec![65099, AS3]));

    assert_eq!(
        held, 0,
        "a path that disowns its first AS reached the Adj-RIB-In"
    );
    assert_eq!(subcode, Some(BGP_SUB_MALFORMED_AS_PATH));
    assert_eq!(peer.state(), BgpState::Idle);
    assert_eq!(
        peer.victim_bgp()
            .peer(peer.peer)
            .unwrap()
            .counters
            .as_path_rejected,
        1
    );
}

#[test]
fn test_a_path_leading_with_an_as_set_is_refused_on_an_external_session() {
    let mut peer = RawBgpPeer::connect(AS1, AS2, ip(9, 9, 9, 9));
    peer.establish_legacy();

    // An AS_SET in front hides which AS actually handed the route over, so there is
    // nothing to check the neighbour against.
    let path = AsPath {
        segments: vec![
            AsPathSegment {
                kind: AsPathSegmentKind::Set,
                asns: vec![AS2, AS3],
            },
            AsPathSegment {
                kind: AsPathSegmentKind::Sequence,
                asns: vec![AS2],
            },
        ],
    };
    let (subcode, held) = announce_with_as_path(&mut peer, path);

    assert_eq!(held, 0);
    assert_eq!(subcode, Some(BGP_SUB_MALFORMED_AS_PATH));
}

#[test]
fn test_turning_off_enforce_first_as_relaxes_the_check_but_not_the_empty_path_rule() {
    // With the check disabled a third-party leading AS is tolerated, the way an
    // operator peering through a route server needs it to be.
    let mut peer = RawBgpPeer::connect(AS1, AS2, ip(9, 9, 9, 9));
    peer.establish_legacy();
    let addr = peer.peer;
    peer.lab
        .router_mut("victim")
        .unwrap()
        .bgp_mut()
        .unwrap()
        .set_enforce_first_as(addr, false);

    let (subcode, held) = announce_with_as_path(&mut peer, AsPath::sequence(vec![65099, AS3]));
    assert_eq!(subcode, None, "the session should have survived");
    assert_eq!(held, 1);
    assert_eq!(peer.state(), BgpState::Established);

    // The empty path is a different matter: it is refused whatever the knob says,
    // because no configuration makes a zero-length AS_PATH meaningful.
    let mut peer = RawBgpPeer::connect(AS1, AS2, ip(9, 9, 9, 9));
    peer.establish_legacy();
    let addr = peer.peer;
    peer.lab
        .router_mut("victim")
        .unwrap()
        .bgp_mut()
        .unwrap()
        .set_enforce_first_as(addr, false);

    let (subcode, held) = announce_with_as_path(&mut peer, AsPath::empty());
    assert_eq!(subcode, Some(BGP_SUB_MALFORMED_AS_PATH));
    assert_eq!(held, 0);
}

#[test]
fn test_an_internal_peer_is_not_subject_to_the_leading_as_rule() {
    // Same ASN on both ends, so this is an iBGP session. An internal neighbour passes
    // on paths it did not originate, and a route originated inside the AS has no
    // AS_PATH at all until it leaves - applying the external rule here would break
    // ordinary iBGP.
    let mut peer = RawBgpPeer::connect(AS1, AS1, ip(9, 9, 9, 9));
    peer.establish_legacy();

    let (subcode, held) = announce_with_as_path(&mut peer, AsPath::sequence(vec![65099, AS3]));
    assert_eq!(subcode, None);
    assert_eq!(held, 1);
    assert_eq!(peer.state(), BgpState::Established);

    let (subcode, held) = announce_with_as_path(&mut peer, AsPath::empty());
    assert_eq!(subcode, None, "an empty AS_PATH is normal inside one AS");
    assert_eq!(held, 1);
    assert_eq!(peer.state(), BgpState::Established);
}
