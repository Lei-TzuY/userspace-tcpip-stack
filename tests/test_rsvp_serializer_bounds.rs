use toy_tcpip::rsvp::{RSVP_MSG_PATH, RsvpHeader, RsvpObject, RsvpPacket, RsvpSerializeError};

fn header() -> RsvpHeader {
    RsvpHeader {
        version: 1,
        flags: 0,
        msg_type: RSVP_MSG_PATH,
        checksum: 0,
        send_ttl: 64,
        length: 0,
    }
}

#[test]
fn object_at_largest_word_aligned_u16_length_serializes() {
    let object = RsvpObject::Raw {
        class_num: 200,
        c_type: 1,
        body: vec![0; 65_528],
    };

    let raw = object.try_serialize().unwrap();
    assert_eq!(raw.len(), 65_532);
    assert_eq!(u16::from_be_bytes([raw[0], raw[1]]) as usize, raw.len());
}

#[test]
fn object_rejects_length_that_overflows_u16_after_padding() {
    let object = RsvpObject::Raw {
        class_num: 200,
        c_type: 1,
        body: vec![0; 65_529],
    };

    assert_eq!(
        object.try_serialize(),
        Err(RsvpSerializeError::ObjectTooLong {
            length: 65_536,
            max: u16::MAX as usize,
        })
    );
}

#[test]
fn packet_at_largest_word_aligned_u16_length_roundtrips() {
    let packet = RsvpPacket {
        header: header(),
        objects: vec![RsvpObject::Raw {
            class_num: 200,
            c_type: 1,
            body: vec![0; 65_520],
        }],
    };

    let raw = packet.try_serialize().unwrap();
    assert_eq!(raw.len(), 65_532);
    assert_eq!(u16::from_be_bytes([raw[6], raw[7]]) as usize, raw.len());
    assert!(RsvpPacket::parse(&raw).is_ok());
}

#[test]
fn packet_rejects_combined_objects_that_overflow_message_length() {
    let packet = RsvpPacket {
        header: header(),
        objects: vec![
            RsvpObject::Raw {
                class_num: 200,
                c_type: 1,
                body: vec![0; 32_760],
            },
            RsvpObject::Raw {
                class_num: 201,
                c_type: 1,
                body: vec![0; 32_760],
            },
        ],
    };

    assert_eq!(
        packet.try_serialize(),
        Err(RsvpSerializeError::MessageTooLong {
            length: 65_536,
            max: u16::MAX as usize,
        })
    );
}

#[test]
fn packet_propagates_oversized_object_error() {
    let packet = RsvpPacket {
        header: header(),
        objects: vec![RsvpObject::Raw {
            class_num: 200,
            c_type: 1,
            body: vec![0; 65_529],
        }],
    };

    assert_eq!(
        packet.try_serialize(),
        Err(RsvpSerializeError::ObjectTooLong {
            length: 65_536,
            max: u16::MAX as usize,
        })
    );
}
