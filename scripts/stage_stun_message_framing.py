from pathlib import Path

path = Path('src/stun.rs')
text = path.read_text()
old = '''pub enum StunError {
    PacketTooShort(usize),
    InvalidMagicCookie(u32),
    InvalidAttributeLength,
}
'''
new = '''pub enum StunError {
    PacketTooShort(usize),
    InvalidMagicCookie(u32),
    InvalidMessageLength(usize),
    InvalidAttributeLength,
}
'''
if old not in text:
    raise SystemExit('error enum marker not found')
text = text.replace(old, new, 1)

old = '''            StunError::PacketTooShort(l) => write!(f, "STUN packet too short ({} bytes)", l),
            StunError::InvalidMagicCookie(c) => write!(f, "Invalid STUN Magic Cookie: 0x{:08X}", c),
            StunError::InvalidAttributeLength => write!(f, "Invalid STUN attribute TLV length"),
'''
new = '''            StunError::PacketTooShort(l) => write!(f, "STUN packet too short ({} bytes)", l),
            StunError::InvalidMagicCookie(c) => write!(f, "Invalid STUN Magic Cookie: 0x{:08X}", c),
            StunError::InvalidMessageLength(l) => {
                write!(f, "Invalid STUN message length: {} (must be a multiple of 4)", l)
            }
            StunError::InvalidAttributeLength => write!(f, "Invalid STUN attribute TLV length"),
'''
if old not in text:
    raise SystemExit('display marker not found')
text = text.replace(old, new, 1)

old = '''        if magic_cookie != STUN_MAGIC_COOKIE {
            return Err(StunError::InvalidMagicCookie(magic_cookie));
        }

        let mut transaction_id = [0u8; 12];
'''
new = '''        if magic_cookie != STUN_MAGIC_COOKIE {
            return Err(StunError::InvalidMagicCookie(magic_cookie));
        }
        if msg_len % 4 != 0 {
            return Err(StunError::InvalidMessageLength(msg_len));
        }

        let mut transaction_id = [0u8; 12];
'''
if old not in text:
    raise SystemExit('message length marker not found')
text = text.replace(old, new, 1)

old = '''            let padded_len = (attr_len + 3) & !3;
            offset += 4 + padded_len;
        }

        Ok(StunPacket {
'''
new = '''            let padded_len = (attr_len + 3) & !3;
            offset += 4 + padded_len;
        }

        if offset != end {
            return Err(StunError::InvalidAttributeLength);
        }

        Ok(StunPacket {
'''
if old not in text:
    raise SystemExit('attribute boundary marker not found')
text = text.replace(old, new, 1)
path.write_text(text)

Path('tests/test_stun_framing_validation.rs').write_text(r'''use toy_tcpip::stun::{
    STUN_ATTR_SOFTWARE, STUN_BINDING_REQUEST, STUN_HEADER_LEN, STUN_MAGIC_COOKIE, StunError,
    StunPacket,
};

fn packet(message_length: u16, body: &[u8]) -> Vec<u8> {
    let mut raw = vec![0u8; STUN_HEADER_LEN];
    raw[0..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    raw[2..4].copy_from_slice(&message_length.to_be_bytes());
    raw[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    raw.extend_from_slice(body);
    raw
}

#[test]
fn non_aligned_message_lengths_are_rejected() {
    for length in 1u16..=3 {
        let body = vec![0u8; usize::from(length)];
        assert_eq!(
            StunPacket::parse(&packet(length, &body)),
            Err(StunError::InvalidMessageLength(usize::from(length)))
        );
    }
}

#[test]
fn zero_length_message_remains_valid() {
    let parsed = StunPacket::parse(&packet(0, &[])).unwrap();
    assert_eq!(parsed.msg_type, STUN_BINDING_REQUEST);
    assert!(parsed.attributes.is_empty());
}

#[test]
fn padded_attribute_remains_valid() {
    let body = [
        (STUN_ATTR_SOFTWARE >> 8) as u8,
        STUN_ATTR_SOFTWARE as u8,
        0,
        3,
        b'a',
        b'b',
        b'c',
        0,
    ];
    let parsed = StunPacket::parse(&packet(body.len() as u16, &body)).unwrap();
    assert_eq!(parsed.attributes.len(), 1);
    assert_eq!(parsed.attributes[0].attr_type, STUN_ATTR_SOFTWARE);
    assert_eq!(parsed.attributes[0].value, b"abc");
}

#[test]
fn aligned_attribute_value_overrun_is_rejected() {
    let body = [
        (STUN_ATTR_SOFTWARE >> 8) as u8,
        STUN_ATTR_SOFTWARE as u8,
        0,
        1,
    ];
    assert_eq!(
        StunPacket::parse(&packet(body.len() as u16, &body)),
        Err(StunError::InvalidAttributeLength)
    );
}
''')
