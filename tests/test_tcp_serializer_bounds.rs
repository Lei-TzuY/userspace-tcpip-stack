use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::tcp::{TCP_MAX_OPTIONS_LEN, TcpFlags, TcpOption, TcpSegment, TcpSerializeError};

fn serialize(options: &[TcpOption]) -> Result<Vec<u8>, TcpSerializeError> {
    TcpSegment::try_serialize_with_options(
        Ipv4Address::new(10, 0, 0, 1),
        Ipv4Address::new(10, 0, 0, 2),
        12345,
        80,
        100,
        0,
        TcpFlags::syn(),
        65535,
        options,
        &[],
    )
}

#[test]
fn rejects_unknown_option_length_field_overflow() {
    let err = serialize(&[TcpOption::Unknown {
        kind: 30,
        data: vec![0; 254],
    }])
    .unwrap_err();

    assert_eq!(
        err,
        TcpSerializeError::OptionLengthTooLarge {
            kind: 30,
            length: 256,
        }
    );
}

#[test]
fn rejects_options_larger_than_tcp_header_allows() {
    let options = vec![TcpOption::Nop; TCP_MAX_OPTIONS_LEN + 1];
    let err = serialize(&options).unwrap_err();

    assert_eq!(
        err,
        TcpSerializeError::OptionsTooLong {
            length: TCP_MAX_OPTIONS_LEN + 1,
            max: TCP_MAX_OPTIONS_LEN,
        }
    );
}

#[test]
fn accepts_exact_maximum_option_area_and_round_trips() {
    let option = TcpOption::Unknown {
        kind: 30,
        data: vec![0xab; TCP_MAX_OPTIONS_LEN - 2],
    };
    let raw = serialize(std::slice::from_ref(&option)).unwrap();

    assert_eq!(raw.len(), 60);
    assert_eq!(raw[12] >> 4, 15);

    let parsed = TcpSegment::parse(
        Ipv4Address::new(10, 0, 0, 1),
        Ipv4Address::new(10, 0, 0, 2),
        &raw,
        true,
    )
    .unwrap();
    assert_eq!(parsed.options, vec![option]);
}
