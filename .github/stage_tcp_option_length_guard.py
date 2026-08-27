from pathlib import Path

path = Path('src/tcp.rs')
text = path.read_text()

old_enum = '''    DataOffsetExceedsLength {
        offset_bytes: usize,
        available: usize,
    },
    InvalidChecksum {
'''
new_enum = '''    DataOffsetExceedsLength {
        offset_bytes: usize,
        available: usize,
    },
    InvalidOptionLength {
        kind: u8,
        length: Option<u8>,
    },
    InvalidChecksum {
'''
if text.count(old_enum) != 1:
    raise SystemExit(f'expected one TcpError insertion point, found {text.count(old_enum)}')
text = text.replace(old_enum, new_enum, 1)

old_display = '''            TcpError::DataOffsetExceedsLength {
                offset_bytes,
                available,
            } => {
                write!(
                    f,
                    "TCP header offset {} exceeds segment length {}",
                    offset_bytes, available
                )
            }
            TcpError::InvalidChecksum { found } => {
'''
new_display = '''            TcpError::DataOffsetExceedsLength {
                offset_bytes,
                available,
            } => {
                write!(
                    f,
                    "TCP header offset {} exceeds segment length {}",
                    offset_bytes, available
                )
            }
            TcpError::InvalidOptionLength { kind, length } => match length {
                Some(length) => write!(
                    f,
                    "Invalid TCP option length {} for option kind {}",
                    length, kind
                ),
                None => write!(f, "TCP option kind {} is missing its length field", kind),
            },
            TcpError::InvalidChecksum { found } => {
'''
if text.count(old_display) != 1:
    raise SystemExit(f'expected one TcpError display insertion point, found {text.count(old_display)}')
text = text.replace(old_display, new_display, 1)

old_parse = '''            if opt_offset + 1 >= offset_bytes {
                break;
            }
            let len = data[opt_offset + 1] as usize;
            if len < 2 || opt_offset + len > offset_bytes {
                break;
            }

            match kind {
                TCP_OPT_MSS if len == 4 => {
                    let mss = u16::from_be_bytes([data[opt_offset + 2], data[opt_offset + 3]]);
                    options.push(TcpOption::Mss(mss));
                }
                TCP_OPT_WSCALE if len == 3 => {
                    options.push(TcpOption::WindowScale(data[opt_offset + 2]));
                }
                other => {
                    let opt_data = data[opt_offset + 2..opt_offset + len].to_vec();
                    options.push(TcpOption::Unknown {
                        kind: other,
                        data: opt_data,
                    });
                }
            }
'''
new_parse = '''            if opt_offset + 1 >= offset_bytes {
                return Err(TcpError::InvalidOptionLength { kind, length: None });
            }
            let length = data[opt_offset + 1];
            let len = length as usize;
            if len < 2 || opt_offset + len > offset_bytes {
                return Err(TcpError::InvalidOptionLength {
                    kind,
                    length: Some(length),
                });
            }

            match kind {
                TCP_OPT_MSS => {
                    if len != 4 {
                        return Err(TcpError::InvalidOptionLength {
                            kind,
                            length: Some(length),
                        });
                    }
                    let mss = u16::from_be_bytes([data[opt_offset + 2], data[opt_offset + 3]]);
                    options.push(TcpOption::Mss(mss));
                }
                TCP_OPT_WSCALE => {
                    if len != 3 {
                        return Err(TcpError::InvalidOptionLength {
                            kind,
                            length: Some(length),
                        });
                    }
                    options.push(TcpOption::WindowScale(data[opt_offset + 2]));
                }
                other => {
                    let opt_data = data[opt_offset + 2..opt_offset + len].to_vec();
                    options.push(TcpOption::Unknown {
                        kind: other,
                        data: opt_data,
                    });
                }
            }
'''
if text.count(old_parse) != 1:
    raise SystemExit(f'expected one TCP option parser block, found {text.count(old_parse)}')
text = text.replace(old_parse, new_parse, 1)
path.write_text(text)

Path('tests/test_tcp_option_validation.rs').write_text(r'''use toy_tcpip::ipv4::Ipv4Address;
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
        vec![TcpOption::Unknown { kind: 30, data: vec![] }, TcpOption::Nop, TcpOption::Nop]
    );
}
''')
