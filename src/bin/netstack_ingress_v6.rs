use std::env;
use std::process::ExitCode;
use std::str::FromStr;

use toy_tcpip::ethernet::{ETHERTYPE_IPV6, EtherType, EthernetFrame, MacAddress};
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::{
    Ipv6Address, Ipv6Error, Ipv6Packet, NEXT_HEADER_ICMPV6, compute_ipv6_transport_checksum,
};
use toy_tcpip::stack::{NetStack, NetStackConfig};

const ICMPV6_TYPE_PARAMETER_PROBLEM: u8 = 4;
const ICMPV6_ERROR_HEADER_LEN: usize = 8;
const MAX_INVOKING_BYTES: usize = 1232; // 1280 - IPv6(40) - ICMPv6 error header(8)
const PAYLOAD_LENGTH_POINTER: u32 = 4;

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

fn malformed_ipv6_parameter_problem(
    local_mac: MacAddress,
    local_ip: Ipv6Address,
    raw_frame: &[u8],
) -> Option<Vec<u8>> {
    let ethernet = EthernetFrame::parse(raw_frame).ok()?;
    if ethernet.ethertype != EtherType::IPv6 || ethernet.dst_mac != local_mac {
        return None;
    }
    let packet = ethernet.payload;
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return None;
    }
    if !matches!(
        Ipv6Packet::parse(packet),
        Err(Ipv6Error::PayloadLengthMismatch { .. })
    ) {
        return None;
    }

    let mut source = [0u8; 16];
    source.copy_from_slice(&packet[8..24]);
    let source = Ipv6Address(source);
    let mut destination = [0u8; 16];
    destination.copy_from_slice(&packet[24..40]);
    let destination = Ipv6Address(destination);
    if destination != local_ip || source.is_unspecified() || source.is_multicast() {
        return None;
    }

    // RFC 4443 section 2.4(e): never send an ICMPv6 error in response to another
    // ICMPv6 error. For a truncated packet the fixed header still exposes enough
    // bytes to classify a directly encapsulated ICMPv6 message when present.
    if packet[6] == NEXT_HEADER_ICMPV6
        && packet
            .get(40)
            .is_some_and(|message_type| *message_type < 128)
    {
        return None;
    }

    let quoted_len = packet.len().min(MAX_INVOKING_BYTES);
    let mut icmp = Vec::with_capacity(ICMPV6_ERROR_HEADER_LEN + quoted_len);
    icmp.push(ICMPV6_TYPE_PARAMETER_PROBLEM);
    icmp.push(0); // Code 0: erroneous header field.
    icmp.extend_from_slice(&[0, 0]);
    icmp.extend_from_slice(&PAYLOAD_LENGTH_POINTER.to_be_bytes());
    icmp.extend_from_slice(&packet[..quoted_len]);
    let checksum = compute_ipv6_transport_checksum(local_ip, source, NEXT_HEADER_ICMPV6, &icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());

    let reply = Ipv6Packet::serialize(local_ip, source, NEXT_HEADER_ICMPV6, 64, &icmp);
    Some(EthernetFrame::serialize(
        ethernet.src_mac,
        local_mac,
        ETHERTYPE_IPV6,
        &reply,
    ))
}

fn process_frame(local_mac: MacAddress, local_ip: Ipv6Address, raw_frame: &[u8]) -> Vec<Vec<u8>> {
    if let Some(reply) = malformed_ipv6_parameter_problem(local_mac, local_ip, raw_frame) {
        return vec![reply];
    }
    let mut stack = NetStack::new(NetStackConfig {
        mac: local_mac,
        ip: Ipv4Address::UNSPECIFIED,
        ipv6: Some(local_ip),
        subnet_mask: 0,
        gateway: None,
    });
    stack.process_frame(raw_frame)
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let local_mac = args
        .next()
        .ok_or_else(|| {
            "usage: netstack_ingress_v6 <local-mac> <local-ipv6> <ethernet-frame-hex>".to_string()
        })?
        .parse::<MacAddress>()?;
    let local_ip = Ipv6Address::from_str(
        &args
            .next()
            .ok_or_else(|| "missing local IPv6 address".to_string())?,
    )
    .map_err(|_| "invalid local IPv6 address".to_string())?;
    let raw_frame = decode_hex(
        &args
            .next()
            .ok_or_else(|| "missing Ethernet frame hex".to_string())?,
    )?;
    if args.next().is_some() {
        return Err("unexpected extra arguments".to_string());
    }

    let replies = process_frame(local_mac, local_ip, &raw_frame);
    if replies.is_empty() {
        println!("drop");
    } else {
        for reply in replies {
            println!("{}", encode_hex(&reply));
        }
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
    use toy_tcpip::icmpv6::Icmpv6Packet;

    const LOCAL_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 1]);
    const REMOTE_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 2]);
    const LOCAL_IP: Ipv6Address = Ipv6Address([
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ]);
    const REMOTE_IP: Ipv6Address = Ipv6Address([
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
    ]);

    fn ethernet_ipv6(packet: &[u8]) -> Vec<u8> {
        EthernetFrame::serialize(LOCAL_MAC, REMOTE_MAC, ETHERTYPE_IPV6, packet)
    }

    #[test]
    fn truncated_payload_generates_parameter_problem() {
        let mut invoking = Ipv6Packet::serialize(REMOTE_IP, LOCAL_IP, 17, 64, &[0; 8]);
        invoking[4..6].copy_from_slice(&16u16.to_be_bytes());
        let replies = process_frame(LOCAL_MAC, LOCAL_IP, &ethernet_ipv6(&invoking));
        assert_eq!(replies.len(), 1);

        let ethernet = EthernetFrame::parse(&replies[0]).unwrap();
        assert_eq!(ethernet.dst_mac, REMOTE_MAC);
        let ipv6 = Ipv6Packet::parse(ethernet.payload).unwrap();
        assert_eq!(ipv6.header.src_ip, LOCAL_IP);
        assert_eq!(ipv6.header.dst_ip, REMOTE_IP);
        assert_eq!(ipv6.payload[0], ICMPV6_TYPE_PARAMETER_PROBLEM);
        assert_eq!(ipv6.payload[1], 0);
        assert_eq!(u32::from_be_bytes(ipv6.payload[4..8].try_into().unwrap()), 4);
        assert_eq!(
            compute_ipv6_transport_checksum(LOCAL_IP, REMOTE_IP, NEXT_HEADER_ICMPV6, ipv6.payload),
            0
        );
    }

    #[test]
    fn icmpv6_error_does_not_trigger_another_error() {
        let mut invoking =
            Ipv6Packet::serialize(REMOTE_IP, LOCAL_IP, NEXT_HEADER_ICMPV6, 64, &[1; 8]);
        invoking[4..6].copy_from_slice(&16u16.to_be_bytes());
        assert!(process_frame(LOCAL_MAC, LOCAL_IP, &ethernet_ipv6(&invoking)).is_empty());
    }

    #[test]
    fn normal_echo_request_falls_back_to_regular_netstack_ingress() {
        let echo = Icmpv6Packet::build_echo_request(REMOTE_IP, LOCAL_IP, 0x1234, 7, b"ping");
        let invoking = Ipv6Packet::serialize(REMOTE_IP, LOCAL_IP, NEXT_HEADER_ICMPV6, 64, &echo);
        let replies = process_frame(LOCAL_MAC, LOCAL_IP, &ethernet_ipv6(&invoking));
        assert_eq!(replies.len(), 1);
        let ethernet = EthernetFrame::parse(&replies[0]).unwrap();
        let ipv6 = Ipv6Packet::parse(ethernet.payload).unwrap();
        assert_eq!(ipv6.payload[0], 129);
    }

    #[test]
    fn invalid_hex_fails_closed() {
        assert!(decode_hex("0").is_err());
        assert!(decode_hex("zz").is_err());
    }
}
