use toy_tcpip::rsvp::{
    RSVP_CLASS_LABEL, RSVP_CLASS_LABEL_REQUEST, RSVP_CLASS_SENDER_TEMPLATE,
    RSVP_CLASS_SENDER_TSPEC, RSVP_CLASS_SESSION, RsvpObject,
};

fn object(class_num: u8, c_type: u8, body_len: usize) -> Vec<u8> {
    let mut raw = Vec::with_capacity(body_len + 4);
    raw.extend_from_slice(&((body_len + 4) as u16).to_be_bytes());
    raw.push(class_num);
    raw.push(c_type);
    raw.resize(body_len + 4, 0);
    raw
}

#[test]
fn fixed_size_known_objects_reject_short_and_overlong_bodies() {
    let cases = [
        (RSVP_CLASS_SESSION, 7, 12usize),
        (RSVP_CLASS_LABEL_REQUEST, 1, 4),
        (RSVP_CLASS_LABEL, 1, 4),
        (RSVP_CLASS_SENDER_TEMPLATE, 7, 8),
    ];

    for (class_num, c_type, expected) in cases {
        let short = object(class_num, c_type, expected - 4);
        let overlong = object(class_num, c_type, expected + 4);
        assert!(RsvpObject::parse(&short).is_none());
        assert!(RsvpObject::parse(&overlong).is_none());
    }
}

#[test]
fn sender_tspec_eight_byte_toy_model_remains_typed() {
    let raw = object(RSVP_CLASS_SENDER_TSPEC, 2, 8);
    let (parsed, consumed) = RsvpObject::parse(&raw).unwrap();

    assert_eq!(consumed, raw.len());
    assert_eq!(
        parsed,
        RsvpObject::SenderTspec {
            bandwidth_bps: 0,
            peak_rate_bps: 0,
        }
    );
}

#[test]
fn longer_sender_tspec_body_remains_raw_and_lossless() {
    let raw = object(RSVP_CLASS_SENDER_TSPEC, 2, 32);
    let (parsed, consumed) = RsvpObject::parse(&raw).unwrap();

    assert_eq!(consumed, raw.len());
    assert_eq!(
        parsed,
        RsvpObject::Raw {
            class_num: RSVP_CLASS_SENDER_TSPEC,
            c_type: 2,
            body: vec![0; 32],
        }
    );
    assert_eq!(parsed.serialize(), raw);
}

#[test]
fn sender_tspec_shorter_than_toy_model_is_rejected() {
    let raw = object(RSVP_CLASS_SENDER_TSPEC, 2, 4);
    assert!(RsvpObject::parse(&raw).is_none());
}

#[test]
fn unknown_object_lengths_remain_raw_and_lossless() {
    let raw = object(200, 9, 8);
    let (parsed, consumed) = RsvpObject::parse(&raw).unwrap();

    assert_eq!(consumed, raw.len());
    assert_eq!(
        parsed,
        RsvpObject::Raw {
            class_num: 200,
            c_type: 9,
            body: vec![0; 8],
        }
    );
    assert_eq!(parsed.serialize(), raw);
}
