use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::tcp::{TCP_OPT_MSS, TCP_OPT_WSCALE, TcpError, TcpOption, TcpSegment};

fn segment_with_options(options: [u8; 4]) -> Vec<u8> {
    let mut segment = vec![0u8; 24];
    segment[0..2].copy_from_slice(&12345u16.to_be_bytes());
    segment[2..4].copy_from_slice(&80u16.to_be_bytes());
    segment[12] = 6 << 4; // 24-byte TCP header.
    segment[14..16].copy_from_slice(&4096u16.to_be_bytes());
    segment[20..24].copy_from_slice(&options);
    segment
}

fn parse(segment: &[u8]) -> Result<TcpSegment<'_>, TcpError> {
    TcpSegment::parse(
        Ipv4Address::new(192, 0, 2, 1),
        Ipv4Address::new(198, 51, 100, 1),
        segment,
        false,
    )
}

#[test]
fn option_kind_without_length_is_rejected() {
    // A valid three-byte Window Scale option leaves one final byte in the
    // options area. That byte cannot start MSS because no length byte remains.
    let segment = segment_with_options([TCP_OPT_WSCALE, 3, 7, TCP_OPT_MSS]);
    assert_eq!(
        parse(&segment),
        Err(TcpError::InvalidOptionLength {
            kind: TCP_OPT_MSS,
            length: None,
        })
    );
}

#[test]
fn zero_length_option_is_rejected() {
    let segment = segment_with_options([30, 0, 0, 0]);
    assert_eq!(
        parse(&segment),
        Err(TcpError::InvalidOptionLength {
            kind: 30,
            length: Some(0),
        })
    );
}

#[test]
fn option_extending_past_data_offset_is_rejected() {
    let segment = segment_with_options([30, 5, 1, 2]);
    assert_eq!(
        parse(&segment),
        Err(TcpError::InvalidOptionLength {
            kind: 30,
            length: Some(5),
        })
    );
}

#[test]
fn malformed_mss_length_is_rejected_instead_of_becoming_unknown() {
    let segment = segment_with_options([TCP_OPT_MSS, 3, 1, 0]);
    assert_eq!(
        parse(&segment),
        Err(TcpError::InvalidOptionLength {
            kind: TCP_OPT_MSS,
            length: Some(3),
        })
    );
}

#[test]
fn malformed_window_scale_length_is_rejected() {
    let segment = segment_with_options([TCP_OPT_WSCALE, 4, 7, 0]);
    assert_eq!(
        parse(&segment),
        Err(TcpError::InvalidOptionLength {
            kind: TCP_OPT_WSCALE,
            length: Some(4),
        })
    );
}

#[test]
fn structurally_valid_unknown_option_remains_accepted() {
    let segment = segment_with_options([30, 2, 1, 1]);
    let parsed = parse(&segment).unwrap();
    assert_eq!(
        parsed.options,
        vec![
            TcpOption::Unknown {
                kind: 30,
                data: vec![]
            },
            TcpOption::Nop,
            TcpOption::Nop
        ]
    );
}
