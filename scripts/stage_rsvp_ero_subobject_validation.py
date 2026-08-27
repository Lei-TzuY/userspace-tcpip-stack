from pathlib import Path

rsvp = Path("src/rsvp.rs")
text = rsvp.read_text()
old = '''            (RSVP_CLASS_EXPLICIT_ROUTE, 1) => {
                let mut hops = Vec::new();
                let mut offset = 0;
                while offset + 8 <= body.len() {
                    let loose = (body[offset] & 0x80) != 0;
                    let hop_ip = Ipv4Address([
                        body[offset + 2],
                        body[offset + 3],
                        body[offset + 4],
                        body[offset + 5],
                    ]);
                    hops.push((loose, hop_ip));
                    let sub_len = body[offset + 1] as usize;
                    offset += if sub_len >= 8 { sub_len } else { 8 };
                }
                RsvpObject::ExplicitRoute { hops }
            }
'''
new = '''            (RSVP_CLASS_EXPLICIT_ROUTE, 1) => {
                let mut hops = Vec::new();
                let mut offset = 0;
                let mut has_unsupported_subobject = false;

                while offset < body.len() {
                    if body.len() - offset < 2 {
                        return None;
                    }

                    let sub_type = body[offset] & 0x7f;
                    let sub_len = body[offset + 1] as usize;
                    if sub_len < 2 || sub_len > body.len() - offset {
                        return None;
                    }

                    if sub_type == 1 {
                        // RFC 3209 section 4.3.3.1: IPv4 prefix subobjects are
                        // exactly eight octets and carry a 0..=32 prefix length.
                        if sub_len != 8 || body[offset + 6] > 32 {
                            return None;
                        }
                        let loose = (body[offset] & 0x80) != 0;
                        let hop_ip = Ipv4Address([
                            body[offset + 2],
                            body[offset + 3],
                            body[offset + 4],
                            body[offset + 5],
                        ]);
                        hops.push((loose, hop_ip));
                    } else {
                        // The current public model only represents IPv4 ERO
                        // hops. Preserve a well-framed unsupported ERO as Raw
                        // instead of silently mis-decoding it as IPv4.
                        has_unsupported_subobject = true;
                    }

                    offset += sub_len;
                }

                if has_unsupported_subobject {
                    RsvpObject::Raw {
                        class_num,
                        c_type,
                        body: body.to_vec(),
                    }
                } else {
                    RsvpObject::ExplicitRoute { hops }
                }
            }
'''
if old not in text:
    raise SystemExit("ERO parser marker not found")
rsvp.write_text(text.replace(old, new, 1))

tests = Path("tests/test_rsvp_ero_subobject_validation.rs")
tests.write_text('''use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::rsvp::{RsvpObject, RSVP_CLASS_EXPLICIT_ROUTE};

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
    let body = [
        1, 8, 192, 0, 2, 1, 32, 0,
        32, 4, 0xfd, 0xe8,
    ];
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
    let raw = ero_object(&[
        32, 3, 0xaa,
        0xbb,
        0xcc, 3, 0xdd, 0xee,
    ]);
    assert!(RsvpObject::parse(&raw).is_none());
}
''')
