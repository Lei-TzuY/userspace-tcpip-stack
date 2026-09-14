use std::env;
use std::str::FromStr;

use toy_tcpip::ipv6::{Ipv6Address, NEXT_HEADER_ICMPV6, compute_ipv6_transport_checksum};

const ICMPV6_TYPE_PARAMETER_PROBLEM: u8 = 4;
const MAX_INVOKING_BYTES: usize = 1232; // 1280 - IPv6(40) - ICMPv6 error header(8)

fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    if !input.len().is_multiple_of(2) {
        return Err("hex input must contain an even number of digits".into());
    }

    input
        .as_bytes()
        .chunks_exact(2)
        .enumerate()
        .map(|(index, pair)| {
            let pair = std::str::from_utf8(pair).expect("hex chunks are ASCII-sized");
            u8::from_str_radix(pair, 16)
                .map_err(|_| format!("invalid hex byte at offset {}", index * 2))
        })
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut out, "{byte:02x}").expect("writing to String cannot fail");
    }
    out
}

fn build_parameter_problem(
    src_ip: Ipv6Address,
    dst_ip: Ipv6Address,
    code: u8,
    pointer: u32,
    invoking_packet: &[u8],
) -> Result<Vec<u8>, String> {
    if code > 2 {
        return Err("RFC 4443 Parameter Problem code must be 0, 1, or 2".into());
    }
    if invoking_packet.is_empty() {
        return Err("invoking IPv6 packet must not be empty".into());
    }
    let pointer_offset = pointer as usize;
    if pointer_offset >= invoking_packet.len() {
        return Err("pointer must identify an octet inside the invoking packet".into());
    }

    let quoted = invoking_packet.len().min(MAX_INVOKING_BYTES);
    let mut packet = Vec::with_capacity(8 + quoted);
    packet.push(ICMPV6_TYPE_PARAMETER_PROBLEM);
    packet.push(code);
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(&pointer.to_be_bytes());
    packet.extend_from_slice(&invoking_packet[..quoted]);

    let checksum = compute_ipv6_transport_checksum(src_ip, dst_ip, NEXT_HEADER_ICMPV6, &packet);
    packet[2..4].copy_from_slice(&checksum.to_be_bytes());
    Ok(packet)
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 6 {
        return Err(format!(
            "usage: {} <src-ipv6> <dst-ipv6> <code:0|1|2> <pointer> <invoking-packet-hex>",
            args.first()
                .map(String::as_str)
                .unwrap_or("icmpv6_parameter_problem")
        ));
    }

    let src_ip = Ipv6Address::from_str(&args[1])
        .map_err(|_| "invalid source IPv6 address".to_string())?;
    let dst_ip = Ipv6Address::from_str(&args[2])
        .map_err(|_| "invalid destination IPv6 address".to_string())?;
    let code = args[3]
        .parse::<u8>()
        .map_err(|_| "code must be an integer in 0..=2".to_string())?;
    let pointer = args[4]
        .parse::<u32>()
        .map_err(|_| "pointer must be a non-negative 32-bit integer".to_string())?;
    let invoking_packet = decode_hex(&args[5])?;
    let reply = build_parameter_problem(src_ip, dst_ip, code, pointer, &invoking_packet)?;
    println!("{}", encode_hex(&reply));
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addresses() -> (Ipv6Address, Ipv6Address) {
        (
            Ipv6Address::from_str("2001:db8::1").unwrap(),
            Ipv6Address::from_str("2001:db8::2").unwrap(),
        )
    }

    #[test]
    fn builds_checksum_valid_parameter_problem_with_pointer() {
        let (src, dst) = addresses();
        let invoking = vec![0x60; 80];
        let packet = build_parameter_problem(src, dst, 0, 6, &invoking).unwrap();

        assert_eq!(packet[0], ICMPV6_TYPE_PARAMETER_PROBLEM);
        assert_eq!(packet[1], 0);
        assert_eq!(u32::from_be_bytes(packet[4..8].try_into().unwrap()), 6);
        assert_eq!(&packet[8..], invoking.as_slice());
        assert_eq!(
            compute_ipv6_transport_checksum(src, dst, NEXT_HEADER_ICMPV6, &packet),
            0
        );
    }

    #[test]
    fn accepts_all_rfc4443_parameter_problem_codes() {
        let (src, dst) = addresses();
        let invoking = vec![0x60; 64];
        for code in 0..=2 {
            let packet = build_parameter_problem(src, dst, code, 1, &invoking).unwrap();
            assert_eq!(packet[1], code);
        }
        assert!(build_parameter_problem(src, dst, 3, 1, &invoking).is_err());
    }

    #[test]
    fn caps_quote_at_ipv6_minimum_mtu() {
        let (src, dst) = addresses();
        let invoking = vec![0x5a; 1600];
        let packet = build_parameter_problem(src, dst, 1, 39, &invoking).unwrap();

        assert_eq!(packet.len(), 1240);
        assert_eq!(&packet[8..], &invoking[..MAX_INVOKING_BYTES]);
    }

    #[test]
    fn rejects_pointer_outside_invoking_packet() {
        let (src, dst) = addresses();
        let invoking = vec![0x60; 40];
        assert!(build_parameter_problem(src, dst, 2, 40, &invoking).is_err());
    }

    #[test]
    fn hex_round_trip_is_exact() {
        let raw = b"\x60\x00\xab\xff";
        assert_eq!(decode_hex(&encode_hex(raw)).unwrap(), raw);
    }
}
