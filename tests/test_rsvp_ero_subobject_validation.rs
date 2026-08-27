use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::rsvp::{RSVP_CLASS_EXPLICIT_ROUTE, RsvpObject};

fn ero_object(body: &[u8]) -> Vec<u8> {
    let object_len = 4 + body.len();
    assert_eq!(object_len % 4, 0, "test fixture must be RSVP-word aligned");
    let mut object = Vec::with_capacity(object_len);
    object.extend_from_slice(&(object_len as u16).to_be_bytes());
    object.push(RSVP_CLASS_EXPLICIT_ROUTE);
    object.push(1);
    object.extend_from_slice(body);
    object
}

#[test]
fn exact_ipv4_prefix_subobject_still_parses() {
    let raw = ero_object(&[1, 8, 192, 0, 2, 1, 32, 0]);
    let (parsed, consumed) = RsvpObject::parse(&raw).unwrap();
    assert_eq!(consumed, raw.len());
    assert_eq!(
        parsed,
        RsvpObject::ExplicitRoute {
            hops: vec![(false, Ipv4Address::new(192, 0, 2, 1))],
        }
    );
}

#[test]
fn loose_bit_is_not_confused_with_subobject_type() {
    let raw = ero_object(&[0x81, 8, 198, 51, 100, 9, 24, 0]);
    let (parsed, _) = RsvpObject::parse(&raw).unwrap();
    assert_eq!(
        parsed,
        RsvpObject::ExplicitRoute {
            hops: vec![(true, Ipv4Address::new(198, 51, 100, 9))],
        }
    );
}

#[test]
fn ipv4_subobject_length_below_eight_is_rejected() {
    let raw = ero_object(&[1, 7, 192, 0, 2, 1, 32, 0]);
    assert!(RsvpObject::parse(&raw).is_none());
}

#[test]
fn ipv4_subobject_length_above_eight_is_rejected() {
    let raw = ero_object(&[1, 12, 192, 0, 2, 1, 32, 0]);
    assert!(RsvpObject::parse(&raw).is_none());
}

#[test]
fn subobject_length_beyond_remaining_ero_is_rejected() {
    let raw = ero_object(&[2, 12, 0, 0, 0, 0, 0, 0]);
    assert!(RsvpObject::parse(&raw).is_none());
}

#[test]
fn zero_length_subobject_is_rejected() {
    let raw = ero_object(&[2, 0, 0, 0, 0, 0, 0, 0]);
    assert!(RsvpObject::parse(&raw).is_none());
}

#[test]
fn ipv4_prefix_length_above_32_is_rejected() {
    let raw = ero_object(&[1, 8, 203, 0, 113, 7, 33, 0]);
    assert!(RsvpObject::parse(&raw).is_none());
}

#[test]
fn unsupported_well_framed_subobject_preserves_entire_ero_as_raw() {
    let body = [2, 8, 0x20, 1, 0x0d, 0xb8, 0, 0];
    let raw = ero_object(&body);
    let (parsed, consumed) = RsvpObject::parse(&raw).unwrap();
    assert_eq!(consumed, raw.len());
    assert_eq!(
        parsed,
        RsvpObject::Raw {
            class_num: RSVP_CLASS_EXPLICIT_ROUTE,
            c_type: 1,
            body: body.to_vec(),
        }
    );
}

#[test]
fn mixed_supported_and_unsupported_subobjects_preserve_entire_ero_as_raw() {
    let body = [1, 8, 192, 0, 2, 1, 32, 0, 32, 4, 0xfd, 0xe8];
    let raw = ero_object(&body);
    let (parsed, _) = RsvpObject::parse(&raw).unwrap();
    assert_eq!(
        parsed,
        RsvpObject::Raw {
            class_num: RSVP_CLASS_EXPLICIT_ROUTE,
            c_type: 1,
            body: body.to_vec(),
        }
    );
}

#[test]
fn partial_subobject_header_at_ero_tail_is_rejected() {
    let raw = ero_object(&[32, 3, 0xaa, 0xbb, 0xcc, 3, 0xdd, 0xee]);
    assert!(RsvpObject::parse(&raw).is_none());
}
