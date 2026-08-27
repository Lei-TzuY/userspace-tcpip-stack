from pathlib import Path

path = Path('src/bgp.rs')
text = path.read_text()
old = '''        let length = u16::from_be_bytes([data[16], data[17]]);
        let msg_type = data[18];

        if (data.len() as u16) < length {
            return Err(BgpError::PacketTooShort(data.len()));
        }

        let body = &data[BGP_HEADER_LEN..length as usize];
'''
new = '''        let length = u16::from_be_bytes([data[16], data[17]]);
        let msg_type = data[18];

        if usize::from(length) < BGP_HEADER_LEN {
            return Err(BgpError::InvalidLength(length));
        }
        if data.len() < usize::from(length) {
            return Err(BgpError::PacketTooShort(data.len()));
        }

        let body = &data[BGP_HEADER_LEN..usize::from(length)];
'''
if old not in text:
    raise SystemExit('source marker not found')
path.write_text(text.replace(old, new, 1))

test = Path('tests/test_bgp_length_validation.rs')
test.write_text(r'''use toy_tcpip::bgp::{
    BGP_HEADER_LEN, BGP_MARKER, BGP_MSG_KEEPALIVE, BgpError, BgpMessage,
};

fn message_with_length(length: u16) -> Vec<u8> {
    let mut packet = vec![0u8; BGP_HEADER_LEN];
    packet[..16].copy_from_slice(&BGP_MARKER);
    packet[16..18].copy_from_slice(&length.to_be_bytes());
    packet[18] = BGP_MSG_KEEPALIVE;
    packet
}

#[test]
fn zero_length_is_rejected_without_panicking() {
    let packet = message_with_length(0);
    assert_eq!(BgpMessage::parse(&packet), Err(BgpError::InvalidLength(0)));
}

#[test]
fn length_below_fixed_header_is_rejected_without_panicking() {
    let packet = message_with_length((BGP_HEADER_LEN - 1) as u16);
    assert_eq!(
        BgpMessage::parse(&packet),
        Err(BgpError::InvalidLength((BGP_HEADER_LEN - 1) as u16))
    );
}

#[test]
fn exact_header_length_keepalive_remains_valid() {
    let packet = message_with_length(BGP_HEADER_LEN as u16);
    assert_eq!(BgpMessage::parse(&packet), Ok(BgpMessage::Keepalive));
}

#[test]
fn declared_length_larger_than_available_input_is_still_truncated() {
    let packet = message_with_length((BGP_HEADER_LEN + 1) as u16);
    assert_eq!(
        BgpMessage::parse(&packet),
        Err(BgpError::PacketTooShort(BGP_HEADER_LEN))
    );
}
''')
