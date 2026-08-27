use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::rsvp::{RSVP_CLASS_SENDER_TEMPLATE, RSVP_CLASS_SESSION, RsvpObject};

#[test]
fn ipv4_session_uses_rfc3209_reserved_then_tunnel_id_layout() {
    let object = RsvpObject::Session {
        dest_ip: Ipv4Address::new(192, 0, 2, 9),
        tunnel_id: 0x1234,
        ext_tunnel_id: Ipv4Address::new(198, 51, 100, 7),
    };

    let raw = object.serialize();
    assert_eq!(
        raw,
        vec![
            0,
            16,
            RSVP_CLASS_SESSION,
            7,
            192,
            0,
            2,
            9,
            0,
            0,
            0x12,
            0x34,
            198,
            51,
            100,
            7,
        ]
    );

    let (parsed, consumed) = RsvpObject::parse(&raw).unwrap();
    assert_eq!(consumed, raw.len());
    assert_eq!(parsed, object);
}

#[test]
fn ipv4_sender_template_uses_rfc3209_reserved_then_lsp_id_layout() {
    let object = RsvpObject::SenderTemplate {
        src_ip: Ipv4Address::new(203, 0, 113, 5),
        lsp_id: 0x4567,
    };

    let raw = object.serialize();
    assert_eq!(
        raw,
        vec![
            0,
            12,
            RSVP_CLASS_SENDER_TEMPLATE,
            7,
            203,
            0,
            113,
            5,
            0,
            0,
            0x45,
            0x67,
        ]
    );

    let (parsed, consumed) = RsvpObject::parse(&raw).unwrap();
    assert_eq!(consumed, raw.len());
    assert_eq!(parsed, object);
}

#[test]
fn parser_reads_identifiers_from_rfc3209_wire_positions() {
    let session = [
        0,
        16,
        RSVP_CLASS_SESSION,
        7,
        10,
        0,
        0,
        2,
        0,
        0,
        0xab,
        0xcd,
        10,
        0,
        0,
        1,
    ];
    let sender = [
        0,
        12,
        RSVP_CLASS_SENDER_TEMPLATE,
        7,
        10,
        0,
        0,
        1,
        0,
        0,
        0x13,
        0x57,
    ];

    let (parsed_session, _) = RsvpObject::parse(&session).unwrap();
    assert_eq!(
        parsed_session,
        RsvpObject::Session {
            dest_ip: Ipv4Address::new(10, 0, 0, 2),
            tunnel_id: 0xabcd,
            ext_tunnel_id: Ipv4Address::new(10, 0, 0, 1),
        }
    );

    let (parsed_sender, _) = RsvpObject::parse(&sender).unwrap();
    assert_eq!(
        parsed_sender,
        RsvpObject::SenderTemplate {
            src_ip: Ipv4Address::new(10, 0, 0, 1),
            lsp_id: 0x1357,
        }
    );
}
