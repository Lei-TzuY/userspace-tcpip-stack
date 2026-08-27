use toy_tcpip::rsvp::{RSVP_MSG_PATH, RsvpError, RsvpObject, RsvpPacket};

fn packet(declared_length: u16, trailing: &[u8]) -> Vec<u8> {
    let mut data = vec![0u8; 8];
    data[0] = 1 << 4;
    data[1] = RSVP_MSG_PATH;
    data[4] = 64;
    data[6..8].copy_from_slice(&declared_length.to_be_bytes());
    data.extend_from_slice(trailing);
    data
}

#[test]
fn message_length_below_common_header_is_rejected() {
    assert_eq!(
        RsvpPacket::parse(&packet(7, &[])),
        Err(RsvpError::InvalidLength)
    );
}

#[test]
fn header_only_message_remains_a_valid_framing_boundary() {
    let parsed = RsvpPacket::parse(&packet(8, &[])).unwrap();
    assert!(parsed.objects.is_empty());
}

#[test]
fn trailing_partial_object_header_is_rejected() {
    assert_eq!(
        RsvpPacket::parse(&packet(10, &[0, 0])),
        Err(RsvpError::InvalidLength)
    );
}

#[test]
fn object_length_below_header_is_rejected() {
    assert_eq!(
        RsvpPacket::parse(&packet(12, &[0, 3, 99, 1])),
        Err(RsvpError::InvalidLength)
    );
}

#[test]
fn non_word_aligned_object_length_is_rejected() {
    assert_eq!(
        RsvpPacket::parse(&packet(16, &[0, 5, 99, 1, 0xaa, 0, 0, 0])),
        Err(RsvpError::InvalidLength)
    );
}

#[test]
fn object_length_beyond_remaining_message_is_rejected() {
    assert_eq!(
        RsvpPacket::parse(&packet(16, &[0, 12, 99, 1, 0, 0, 0, 0])),
        Err(RsvpError::InvalidLength)
    );
}

#[test]
fn aligned_raw_object_still_parses() {
    let parsed = RsvpPacket::parse(&packet(16, &[0, 8, 99, 1, 1, 2, 3, 4])).unwrap();
    assert_eq!(
        parsed.objects,
        vec![RsvpObject::Raw {
            class_num: 99,
            c_type: 1,
            body: vec![1, 2, 3, 4],
        }]
    );
}

#[test]
fn raw_serializer_includes_padding_in_wire_object_length() {
    let raw = RsvpObject::Raw {
        class_num: 99,
        c_type: 1,
        body: vec![0xaa],
    }
    .serialize();

    assert_eq!(raw.len(), 8);
    assert_eq!(u16::from_be_bytes([raw[0], raw[1]]), 8);
    let (parsed, consumed) = RsvpObject::parse(&raw).unwrap();
    assert_eq!(consumed, 8);
    assert_eq!(
        parsed,
        RsvpObject::Raw {
            class_num: 99,
            c_type: 1,
            body: vec![0xaa, 0, 0, 0],
        }
    );
}
