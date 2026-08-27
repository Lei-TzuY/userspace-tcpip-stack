#!/usr/bin/env bash
set -euo pipefail

python3 - <<'PY'
from pathlib import Path

p = Path('src/tcp.rs')
s = p.read_text()

def replace_once(old: str, new: str) -> None:
    global s
    count = s.count(old)
    if count != 1:
        raise SystemExit(f'expected exactly one anchor, found {count}: {old[:120]!r}')
    s = s.replace(old, new, 1)

replace_once(
'''    InvalidChecksum {
        found: u16,
    },
''',
'''    TruncatedOption {
        offset: usize,
        kind: u8,
    },
    InvalidOptionLength {
        offset: usize,
        kind: u8,
        length: u8,
    },
    OptionLengthExceedsHeader {
        offset: usize,
        kind: u8,
        length: u8,
        remaining: usize,
    },
    InvalidChecksum {
        found: u16,
    },
''')

replace_once(
'''            TcpError::InvalidChecksum { found } => {
                write!(
                    f,
                    "TCP checksum mismatch with checksum field 0x{:04x}",
                    found
                )
            }
''',
'''            TcpError::TruncatedOption { offset, kind } => write!(
                f,
                "TCP option kind {} at byte {} is missing its length byte",
                kind, offset
            ),
            TcpError::InvalidOptionLength {
                offset,
                kind,
                length,
            } => write!(
                f,
                "TCP option kind {} at byte {} has invalid length {}",
                kind, offset, length
            ),
            TcpError::OptionLengthExceedsHeader {
                offset,
                kind,
                length,
                remaining,
            } => write!(
                f,
                "TCP option kind {} at byte {} declares length {} with only {} header bytes remaining",
                kind, offset, length, remaining
            ),
            TcpError::InvalidChecksum { found } => {
                write!(
                    f,
                    "TCP checksum mismatch with checksum field 0x{:04x}",
                    found
                )
            }
''')

replace_once(
'''            if opt_offset + 1 >= offset_bytes {
                break;
            }
            let len = data[opt_offset + 1] as usize;
            if len < 2 || opt_offset + len > offset_bytes {
                break;
            }
''',
'''            if opt_offset + 1 >= offset_bytes {
                return Err(TcpError::TruncatedOption {
                    offset: opt_offset,
                    kind,
                });
            }
            let length = data[opt_offset + 1];
            let len = usize::from(length);
            if len < 2 {
                return Err(TcpError::InvalidOptionLength {
                    offset: opt_offset,
                    kind,
                    length,
                });
            }
            let remaining = offset_bytes - opt_offset;
            if len > remaining {
                return Err(TcpError::OptionLengthExceedsHeader {
                    offset: opt_offset,
                    kind,
                    length,
                    remaining,
                });
            }
''')

anchor = '''    #[test]
    fn test_tcp_out_of_order_reassembly() {
'''
insert = r'''    #[test]
    fn test_tcp_rejects_malformed_option_tails() {
        let src_ip = Ipv4Address::new(10, 0, 0, 1);
        let dst_ip = Ipv4Address::new(10, 0, 0, 2);
        let base = TcpSegment::serialize_with_options(
            src_ip,
            dst_ip,
            12345,
            80,
            100,
            0,
            TcpFlags::syn(),
            65535,
            &[
                TcpOption::Nop,
                TcpOption::Nop,
                TcpOption::Nop,
                TcpOption::Nop,
            ],
            &[],
        );
        assert_eq!(base.len(), 24);

        let mut missing_length = base.clone();
        missing_length[20..24].copy_from_slice(&[TCP_OPT_NOP, TCP_OPT_NOP, TCP_OPT_NOP, TCP_OPT_MSS]);
        assert_eq!(
            TcpSegment::parse(src_ip, dst_ip, &missing_length, false).unwrap_err(),
            TcpError::TruncatedOption {
                offset: 23,
                kind: TCP_OPT_MSS,
            }
        );

        let mut too_short = base.clone();
        too_short[20..24].copy_from_slice(&[TCP_OPT_MSS, 1, 0, 0]);
        assert_eq!(
            TcpSegment::parse(src_ip, dst_ip, &too_short, false).unwrap_err(),
            TcpError::InvalidOptionLength {
                offset: 20,
                kind: TCP_OPT_MSS,
                length: 1,
            }
        );

        let mut overruns_header = base;
        overruns_header[20..24].copy_from_slice(&[TCP_OPT_MSS, 5, 0, 0]);
        assert_eq!(
            TcpSegment::parse(src_ip, dst_ip, &overruns_header, false).unwrap_err(),
            TcpError::OptionLengthExceedsHeader {
                offset: 20,
                kind: TCP_OPT_MSS,
                length: 5,
                remaining: 4,
            }
        );
    }

    #[test]
    fn test_tcp_terminal_single_byte_options_remain_valid() {
        let src_ip = Ipv4Address::new(10, 0, 0, 1);
        let dst_ip = Ipv4Address::new(10, 0, 0, 2);
        let base = TcpSegment::serialize_with_options(
            src_ip,
            dst_ip,
            12345,
            80,
            100,
            0,
            TcpFlags::syn(),
            65535,
            &[
                TcpOption::Nop,
                TcpOption::Nop,
                TcpOption::Nop,
                TcpOption::Nop,
            ],
            &[],
        );

        let parsed_nop = TcpSegment::parse(src_ip, dst_ip, &base, false).unwrap();
        assert_eq!(parsed_nop.options, vec![TcpOption::Nop; 4]);

        let mut terminal_eol = base;
        terminal_eol[23] = TCP_OPT_EOL;
        let parsed_eol = TcpSegment::parse(src_ip, dst_ip, &terminal_eol, false).unwrap();
        assert_eq!(
            parsed_eol.options,
            vec![
                TcpOption::Nop,
                TcpOption::Nop,
                TcpOption::Nop,
                TcpOption::EndOfOptions,
            ]
        );
    }

'''
count = s.count(anchor)
if count != 1:
    raise SystemExit(f'expected exactly one test anchor, found {count}')
s = s.replace(anchor, insert + anchor, 1)
p.write_text(s)
PY

cargo fmt --all
cargo fmt --all -- --check
git diff --check
cargo test tcp::tests::test_tcp_rejects_malformed_option_tails --verbose
cargo test tcp::tests::test_tcp_terminal_single_byte_options_remain_valid --verbose
cargo test --all-targets --verbose
cargo build --release --verbose

rm .github/workflows/one-shot-tcp-option-validation.yml scripts/one-shot-tcp-option-validation.sh
git add -A
git config user.name 'LeiZ'
git config user.email '52287354+Lei-TzuY@users.noreply.github.com'
git commit -m 'fix(tcp): reject malformed option tails'
git push origin HEAD:stage/tcp-option-tail-validation
