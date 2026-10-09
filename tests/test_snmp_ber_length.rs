use toy_tcpip::snmp::{
    BER_TAG_OCTET_STRING, BER_TAG_SEQUENCE, SNMP_VERSION_2C, SnmpError, SnmpMessage,
    decode_ber_tlv, encode_ber_integer, encode_ber_length,
};

fn header(tag: u8, length: usize) -> Vec<u8> {
    let mut bytes = vec![tag];
    bytes.extend(encode_ber_length(length));
    bytes
}

#[test]
fn ber_rejects_lengths_at_the_usize_addition_boundary() {
    let header_len = 2 + std::mem::size_of::<usize>();
    // Include both overflowing ends and the first representable end. Neither
    // case may wrap into the small input or panic while checking its bounds.
    for delta in 0..=header_len {
        for suffix_len in [0, 16] {
            let mut bytes = header(BER_TAG_OCTET_STRING, usize::MAX - delta);
            bytes.extend(vec![0; suffix_len]);
            assert_eq!(decode_ber_tlv(&bytes), Err(SnmpError::PacketTooShort));
        }
    }
}

#[test]
fn ber_rejects_truncated_values_for_every_supported_length_width() {
    for width in 1..=std::mem::size_of::<usize>() {
        let mut bytes = vec![BER_TAG_OCTET_STRING, 0x80 | width as u8];
        bytes.extend(vec![0xff; width]);
        assert_eq!(decode_ber_tlv(&bytes), Err(SnmpError::PacketTooShort));
    }
}

#[test]
fn ber_length_bounds_preserve_exact_values_and_consumed_prefixes() {
    for length in [0, 1, 127, 128, 255, 256] {
        let mut bytes = header(BER_TAG_OCTET_STRING, length);
        let header_len = bytes.len();
        bytes.extend(vec![0x42; length]);
        let consumed = bytes.len();
        bytes.extend([0x05, 0x00]);
        let (tag, value, actual_consumed) = decode_ber_tlv(&bytes).unwrap();
        assert_eq!(tag, BER_TAG_OCTET_STRING);
        assert_eq!(value, &bytes[header_len..consumed]);
        assert_eq!(value.len(), length);
        assert_eq!(actual_consumed, consumed);
        assert_eq!(
            decode_ber_tlv(&bytes[..consumed - 1]),
            Err(SnmpError::PacketTooShort)
        );
    }
}

#[test]
fn snmp_rejects_overflowing_outer_and_nested_ber_lengths() {
    let outer = header(BER_TAG_SEQUENCE, usize::MAX);
    assert_eq!(SnmpMessage::parse(&outer), Err(SnmpError::PacketTooShort));

    let mut body = encode_ber_integer(SNMP_VERSION_2C);
    body.extend(header(BER_TAG_OCTET_STRING, usize::MAX));
    let mut nested = header(BER_TAG_SEQUENCE, body.len());
    nested.extend(body);
    assert_eq!(SnmpMessage::parse(&nested), Err(SnmpError::PacketTooShort));
}
