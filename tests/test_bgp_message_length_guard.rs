use toy_tcpip::bgp::{
    BGP_HEADER_LEN, BGP_MARKER, BGP_MAX_MESSAGE_LEN, BGP_MSG_KEEPALIVE, BgpError, BgpMessage,
};

fn framed_header(length: u16, msg_type: u8) -> Vec<u8> {
    let mut raw = Vec::with_capacity(BGP_HEADER_LEN);
    raw.extend_from_slice(&BGP_MARKER);
    raw.extend_from_slice(&length.to_be_bytes());
    raw.push(msg_type);
    raw
}

#[test]
fn rejects_declared_lengths_below_fixed_header_without_panicking() {
    for declared in [0u16, 18u16] {
        let raw = framed_header(declared, BGP_MSG_KEEPALIVE);
        assert_eq!(
            BgpMessage::parse(&raw),
            Err(BgpError::InvalidLength(declared))
        );
    }
}

#[test]
fn rejects_length_above_rfc4271_message_limit() {
    let declared = (BGP_MAX_MESSAGE_LEN + 1) as u16;
    let raw = framed_header(declared, BGP_MSG_KEEPALIVE);
    assert_eq!(
        BgpMessage::parse(&raw),
        Err(BgpError::InvalidLength(declared))
    );
}

#[test]
fn accepts_minimum_length_keepalive() {
    let raw = framed_header(BGP_HEADER_LEN as u16, BGP_MSG_KEEPALIVE);
    assert_eq!(BgpMessage::parse(&raw), Ok(BgpMessage::Keepalive));
}

#[test]
fn still_reports_truncated_legal_length_as_packet_too_short() {
    let raw = framed_header((BGP_HEADER_LEN + 1) as u16, BGP_MSG_KEEPALIVE);
    assert_eq!(
        BgpMessage::parse(&raw),
        Err(BgpError::PacketTooShort(BGP_HEADER_LEN))
    );
}
