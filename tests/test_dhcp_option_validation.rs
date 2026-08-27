use toy_tcpip::dhcp::{
    DHCP_MAGIC_COOKIE, DHCP_OPT_END, DHCP_OPT_MSG_TYPE, DHCP_OPT_PAD, DhcpError, DhcpMessageType,
    DhcpPacket,
};

fn base_packet() -> Vec<u8> {
    let mut packet = vec![0u8; 240];
    packet[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
    packet
}

#[test]
fn dangling_option_code_is_rejected() {
    let mut packet = base_packet();
    packet.push(DHCP_OPT_MSG_TYPE);

    assert_eq!(
        DhcpPacket::parse(&packet),
        Err(DhcpError::InvalidOptionLength)
    );
}

#[test]
fn pad_at_end_is_a_legal_single_byte_option() {
    let mut packet = base_packet();
    packet.push(DHCP_OPT_PAD);

    let parsed = DhcpPacket::parse(&packet).unwrap();
    assert_eq!(parsed.msg_type, DhcpMessageType::Unknown(0));
}

#[test]
fn end_at_end_is_a_legal_single_byte_option() {
    let mut packet = base_packet();
    packet.push(DHCP_OPT_END);

    let parsed = DhcpPacket::parse(&packet).unwrap();
    assert_eq!(parsed.msg_type, DhcpMessageType::Unknown(0));
}

#[test]
fn complete_message_type_option_still_parses() {
    let mut packet = base_packet();
    packet.extend_from_slice(&[DHCP_OPT_MSG_TYPE, 1, 1, DHCP_OPT_END]);

    let parsed = DhcpPacket::parse(&packet).unwrap();
    assert_eq!(parsed.msg_type, DhcpMessageType::Discover);
}
