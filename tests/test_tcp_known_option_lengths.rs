use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::tcp::{TCP_OPT_MSS, TCP_OPT_WSCALE, TcpError, TcpOption, TcpSegment};

fn segment_with_options(options: [u8; 4]) -> Vec<u8> {
    let mut segment = vec![0u8; 24];
    segment[0..2].copy_from_slice(&12345u16.to_be_bytes());
    segment[2..4].copy_from_slice(&80u16.to_be_bytes());
    segment[12] = 6 << 4;
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
fn mss_with_wrong_but_structurally_valid_length_is_rejected() {
    let segment = segment_with_options([TCP_OPT_MSS, 3, 0x05, 0]);
    assert_eq!(
        parse(&segment),
        Err(TcpError::InvalidOptionLength {
            offset: 20,
            kind: TCP_OPT_MSS,
            length: 3,
        })
    );
}

#[test]
fn window_scale_with_wrong_but_structurally_valid_length_is_rejected() {
    let segment = segment_with_options([TCP_OPT_WSCALE, 4, 7, 0]);
    assert_eq!(
        parse(&segment),
        Err(TcpError::InvalidOptionLength {
            offset: 20,
            kind: TCP_OPT_WSCALE,
            length: 4,
        })
    );
}

#[test]
fn valid_mss_length_still_parses() {
    let segment = segment_with_options([TCP_OPT_MSS, 4, 0x05, 0xb4]);
    let parsed = parse(&segment).unwrap();
    assert_eq!(parsed.options, vec![TcpOption::Mss(1460)]);
}

#[test]
fn valid_window_scale_length_still_parses_with_padding() {
    let segment = segment_with_options([TCP_OPT_WSCALE, 3, 7, 1]);
    let parsed = parse(&segment).unwrap();
    assert_eq!(
        parsed.options,
        vec![TcpOption::WindowScale(7), TcpOption::Nop]
    );
}

#[test]
fn unknown_structurally_valid_option_is_still_accepted() {
    let segment = segment_with_options([30, 4, 0xaa, 0xbb]);
    let parsed = parse(&segment).unwrap();
    assert_eq!(
        parsed.options,
        vec![TcpOption::Unknown {
            kind: 30,
            data: vec![0xaa, 0xbb],
        }]
    );
}
