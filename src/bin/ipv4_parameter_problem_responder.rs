use std::env;
use std::process::ExitCode;
use std::str::FromStr;

use toy_tcpip::checksum::{compute_checksum, verify_checksum};
use toy_tcpip::ethernet::{ETHERTYPE_IPV4, EtherType, EthernetFrame, MacAddress};
use toy_tcpip::icmp::{IcmpPacket, IcmpType};
use toy_tcpip::ipv4::{IP_PROTO_ICMP, Ipv4Address, Ipv4Error, Ipv4Packet};

fn parameter_problem_pointer(error: &Ipv4Error) -> Option<u8> {
    match error {
        Ipv4Error::TotalLengthSmallerThanHeader { .. } => Some(2),
        Ipv4Error::ReservedFragmentFlagSet => Some(6),
        _ => None,
    }
}

fn safe_ipv4_error_source(address: Ipv4Address) -> bool {
    !address.is_unspecified()
        && !address.is_broadcast()
        && !address.is_multicast()
        && !address.is_loopback()
}

fn build_parameter_problem_reply(
    local_mac: MacAddress,
    local_ip: Ipv4Address,
    raw_frame: &[u8],
) -> Option<Vec<u8>> {
    let ethernet = EthernetFrame::parse(raw_frame).ok()?;
    if ethernet.ethertype != EtherType::IPv4 || ethernet.dst_mac != local_mac {
        return None;
    }

    let datagram = ethernet.payload;
    let error = Ipv4Packet::parse(datagram, true).err()?;
    let pointer = parameter_problem_pointer(&error)?;

    // Parameter Problem is emitted only when enough of the invoking header is
    // trustworthy to identify a unicast peer and validate its header checksum.
    if datagram.len() < 20 || datagram[0] >> 4 != 4 {
        return None;
    }
    let ihl = (datagram[0] & 0x0f) as usize;
    if ihl < 5 {
        return None;
    }
    let header_len = ihl.checked_mul(4)?;
    if header_len > datagram.len() || !verify_checksum(&datagram[..header_len]) {
        return None;
    }

    let source = Ipv4Address::from_bytes(datagram[12..16].try_into().ok()?);
    let destination = Ipv4Address::from_bytes(datagram[16..20].try_into().ok()?);
    if destination != local_ip || !safe_ipv4_error_source(source) {
        return None;
    }

    // RFC 1122/1812 error-suppression rules: do not answer an ICMP packet with
    // another ICMP error, and do not answer non-initial fragments.
    if datagram[9] == IP_PROTO_ICMP {
        return None;
    }
    let flags_fragment = u16::from_be_bytes([datagram[6], datagram[7]]);
    if flags_fragment & 0x1fff != 0 {
        return None;
    }

    let icmp = IcmpPacket::build_parameter_problem(pointer, datagram);
    let ip = Ipv4Packet::serialize(local_ip, source, IP_PROTO_ICMP, 0, 64, &icmp);
    Some(EthernetFrame::serialize(
        ethernet.src_mac,
        local_mac,
        ETHERTYPE_IPV4,
        &ip,
    ))
}

fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    let compact: String = input
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect();
    if !compact.len().is_multiple_of(2) {
        return Err("hex input must contain an even number of digits".to_string());
    }
    (0..compact.len())
        .step_by(2)
        .map(|offset| {
            u8::from_str_radix(&compact[offset..offset + 2], 16)
                .map_err(|error| format!("invalid hex at offset {offset}: {error}"))
        })
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let local_mac = args
        .next()
        .ok_or_else(|| {
            "usage: ipv4_parameter_problem_responder <local-mac> <local-ip> <ethernet-frame-hex>"
                .to_string()
        })?
        .parse::<MacAddress>()?;
    let local_ip = args
        .next()
        .ok_or_else(|| "missing local IPv4 address".to_string())?
        .parse::<Ipv4Address>()?;
    let raw_frame = decode_hex(
        &args
            .next()
            .ok_or_else(|| "missing Ethernet frame hex".to_string())?,
    )?;
    if args.next().is_some() {
        return Err("unexpected extra arguments".to_string());
    }

    match build_parameter_problem_reply(local_mac, local_ip, &raw_frame) {
        Some(reply) => println!("{}", encode_hex(&reply)),
        None => println!("drop"),
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 1]);
    const REMOTE_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 2]);
    const LOCAL_IP: Ipv4Address = Ipv4Address([192, 0, 2, 1]);
    const REMOTE_IP: Ipv4Address = Ipv4Address([192, 0, 2, 2]);

    fn malformed_reserved_flag(protocol: u8) -> Vec<u8> {
        let mut datagram =
            Ipv4Packet::serialize(REMOTE_IP, LOCAL_IP, protocol, 0x1234, 64, &[0; 8]);
        datagram[6] |= 0x80;
        datagram[10..12].fill(0);
        let checksum = compute_checksum(&datagram[..20]);
        datagram[10..12].copy_from_slice(&checksum.to_be_bytes());
        EthernetFrame::serialize(LOCAL_MAC, REMOTE_MAC, ETHERTYPE_IPV4, &datagram)
    }

    #[test]
    fn reserved_fragment_flag_emits_parameter_problem_at_byte_six() {
        let frame = malformed_reserved_flag(17);
        let reply = build_parameter_problem_reply(LOCAL_MAC, LOCAL_IP, &frame).unwrap();
        let ethernet = EthernetFrame::parse(&reply).unwrap();
        assert_eq!(ethernet.dst_mac, REMOTE_MAC);
        assert_eq!(ethernet.src_mac, LOCAL_MAC);

        let ipv4 = Ipv4Packet::parse(ethernet.payload, true).unwrap();
        assert_eq!(ipv4.header.src_ip, LOCAL_IP);
        assert_eq!(ipv4.header.dst_ip, REMOTE_IP);
        let icmp = IcmpPacket::parse(ipv4.payload, true).unwrap();
        assert_eq!(icmp.icmp_type, IcmpType::ParameterProblem);
        assert_eq!(icmp.code, 0);
        assert_eq!(ipv4.payload[4], 6);
        assert_eq!(&ipv4.payload[5..8], &[0, 0, 0]);
        assert_eq!(
            &ipv4.payload[8..],
            &EthernetFrame::parse(&frame).unwrap().payload[..28],
        );
    }

    #[test]
    fn malformed_icmp_never_triggers_an_icmp_error() {
        let frame = malformed_reserved_flag(IP_PROTO_ICMP);
        assert!(build_parameter_problem_reply(LOCAL_MAC, LOCAL_IP, &frame).is_none());
    }

    #[test]
    fn invalid_header_checksum_is_silently_dropped() {
        let mut frame = malformed_reserved_flag(17);
        frame[14 + 10] ^= 0xff;
        assert!(build_parameter_problem_reply(LOCAL_MAC, LOCAL_IP, &frame).is_none());
    }

    #[test]
    fn non_initial_fragment_is_silently_dropped() {
        let mut frame = malformed_reserved_flag(17);
        let datagram = &mut frame[14..];
        let flags_fragment = u16::from_be_bytes([datagram[6], datagram[7]]) | 1;
        datagram[6..8].copy_from_slice(&flags_fragment.to_be_bytes());
        datagram[10..12].fill(0);
        let checksum = compute_checksum(&datagram[..20]);
        datagram[10..12].copy_from_slice(&checksum.to_be_bytes());
        assert!(build_parameter_problem_reply(LOCAL_MAC, LOCAL_IP, &frame).is_none());
    }
}
