use toy_tcpip::checksum::verify_checksum;
use toy_tcpip::rsvp::{RSVP_MSG_PATH, RsvpError, RsvpHeader, RsvpObject, RsvpPacket};

fn sample_packet() -> RsvpPacket {
    RsvpPacket {
        header: RsvpHeader {
            version: 1,
            flags: 0,
            msg_type: RSVP_MSG_PATH,
            checksum: 0,
            send_ttl: 64,
            length: 0,
        },
        objects: vec![RsvpObject::SenderTspec {
            bandwidth_bps: 1_000_000,
            peak_rate_bps: 2_000_000,
        }],
    }
}

#[test]
fn valid_nonzero_checksum_is_accepted() {
    let raw = sample_packet().serialize();
    assert_ne!(&raw[2..4], &[0, 0]);
    assert!(verify_checksum(&raw));
    assert!(RsvpPacket::parse(&raw).is_ok());
}

#[test]
fn corrupted_message_with_nonzero_checksum_is_rejected() {
    let mut raw = sample_packet().serialize();
    raw[4] ^= 1;

    assert_eq!(RsvpPacket::parse(&raw), Err(RsvpError::InvalidChecksum));
}

#[test]
fn zero_checksum_disables_checksum_validation() {
    let mut raw = sample_packet().serialize();
    raw[2] = 0;
    raw[3] = 0;
    raw[4] ^= 1;

    let parsed = RsvpPacket::parse(&raw).unwrap();
    assert_eq!(parsed.header.checksum, 0);
}

#[test]
fn checksum_uses_only_declared_rsvp_length() {
    let mut raw = sample_packet().serialize();
    raw.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);

    assert!(RsvpPacket::parse(&raw).is_ok());
}

#[test]
fn serializer_uses_ffff_when_computed_checksum_is_zero() {
    let packet = RsvpPacket {
        header: RsvpHeader {
            version: 1,
            flags: 0,
            msg_type: RSVP_MSG_PATH,
            checksum: 0,
            send_ttl: 64,
            length: 0,
        },
        objects: vec![RsvpObject::Raw {
            class_num: 200,
            c_type: 9,
            body: vec![0xe7, 0xdc, 0, 0],
        }],
    };

    let raw = packet.serialize();
    assert_eq!(&raw[2..4], &[0xff, 0xff]);
    assert!(verify_checksum(&raw));
    assert!(RsvpPacket::parse(&raw).is_ok());
}
