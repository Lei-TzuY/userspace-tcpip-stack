use toy_tcpip::gtpc_v2::{GTPV2C_CREATE_SESSION_REQ, Gtpv2cHeader, Gtpv2cMessage};

fn request_wire() -> Vec<u8> {
    Gtpv2cMessage::create_session_request(
        0x1020_3040,
        0x00ab_cd01,
        "310260123456789",
        "internet.example",
        0x5566_7788,
        [10, 0, 0, 1],
        5,
    )
    .serialize()
}

fn set_declared_length(raw: &mut [u8], length: u16) {
    raw[2..4].copy_from_slice(&length.to_be_bytes());
}

#[test]
fn serialized_message_declares_its_exact_frame_length() {
    let raw = request_wire();
    let declared = u16::from_be_bytes([raw[2], raw[3]]) as usize;
    assert_eq!(declared + 4, raw.len());
    assert!(Gtpv2cMessage::parse(&raw).is_some());
}

#[test]
fn declared_length_longer_than_datagram_is_rejected() {
    let mut raw = request_wire();
    let declared = u16::from_be_bytes([raw[2], raw[3]]);
    set_declared_length(&mut raw, declared + 1);
    assert!(Gtpv2cMessage::parse(&raw).is_none());
}

#[test]
fn declared_length_shorter_than_datagram_is_rejected() {
    let mut raw = request_wire();
    let declared = u16::from_be_bytes([raw[2], raw[3]]);
    set_declared_length(&mut raw, declared - 1);
    assert!(Gtpv2cMessage::parse(&raw).is_none());
}

#[test]
fn appended_bytes_outside_declared_message_are_rejected() {
    let mut raw = request_wire();
    raw.extend_from_slice(&[0, 0, 0, 0]);
    assert!(Gtpv2cMessage::parse(&raw).is_none());
}

#[test]
fn teid_message_length_cannot_end_inside_its_header() {
    let message = Gtpv2cMessage {
        header: Gtpv2cHeader {
            version: 2,
            piggyback: false,
            teid_flag: true,
            msg_type: GTPV2C_CREATE_SESSION_REQ,
            teid: 0x1234_5678,
            sequence: 7,
        },
        ies: vec![],
    };
    let mut raw = message.serialize();
    assert_eq!(raw.len(), 12);
    assert_eq!(u16::from_be_bytes([raw[2], raw[3]]), 8);
    set_declared_length(&mut raw, 7);
    assert!(Gtpv2cMessage::parse(&raw).is_none());
}

#[test]
fn non_teid_minimal_message_length_remains_valid() {
    let message = Gtpv2cMessage {
        header: Gtpv2cHeader {
            version: 2,
            piggyback: false,
            teid_flag: false,
            msg_type: GTPV2C_CREATE_SESSION_REQ,
            teid: 0,
            sequence: 9,
        },
        ies: vec![],
    };
    let raw = message.serialize();
    assert_eq!(raw.len(), 8);
    assert_eq!(u16::from_be_bytes([raw[2], raw[3]]), 4);
    assert!(Gtpv2cMessage::parse(&raw).is_some());
}
