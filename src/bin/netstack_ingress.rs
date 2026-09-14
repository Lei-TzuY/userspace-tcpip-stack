use std::env;
use std::process::ExitCode;

use toy_tcpip::ethernet::MacAddress;
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::stack::{NetStack, NetStackConfig};

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

fn process_frame(local_mac: MacAddress, local_ip: Ipv4Address, raw_frame: &[u8]) -> Vec<Vec<u8>> {
    let mut stack = NetStack::new(NetStackConfig {
        mac: local_mac,
        ip: local_ip,
        ipv6: None,
        subnet_mask: 24,
        gateway: None,
    });
    stack.process_frame_with_ipv4_errors(raw_frame)
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let local_mac = args
        .next()
        .ok_or_else(|| {
            "usage: netstack_ingress <local-mac> <local-ip> <ethernet-frame-hex>".to_string()
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
    use toy_tcpip::checksum::compute_checksum;
    use toy_tcpip::ethernet::{ETHERTYPE_IPV4, EthernetFrame};
    use toy_tcpip::icmp::{IcmpPacket, IcmpType};
    use toy_tcpip::ipv4::{IP_PROTO_ICMP, IP_PROTO_UDP, Ipv4Packet};

    const LOCAL_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 1]);
    const REMOTE_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 2]);
    const LOCAL_IP: Ipv4Address = Ipv4Address([192, 0, 2, 1]);
    const REMOTE_IP: Ipv4Address = Ipv4Address([192, 0, 2, 2]);

    fn ethernet_ipv4(datagram: &[u8]) -> Vec<u8> {
        EthernetFrame::serialize(LOCAL_MAC, REMOTE_MAC, ETHERTYPE_IPV4, datagram)
    }

    #[test]
    fn normal_echo_request_uses_regular_netstack_ingress() {
        let echo = IcmpPacket::build_echo_request(0x1234, 7, b"ping");
        let datagram = Ipv4Packet::serialize(REMOTE_IP, LOCAL_IP, IP_PROTO_ICMP, 0x1000, 64, &echo);
        let replies = process_frame(LOCAL_MAC, LOCAL_IP, &ethernet_ipv4(&datagram));
        assert_eq!(replies.len(), 1);

        let ethernet = EthernetFrame::parse(&replies[0]).unwrap();
        assert_eq!(ethernet.dst_mac, REMOTE_MAC);
        assert_eq!(ethernet.src_mac, LOCAL_MAC);
        let ipv4 = Ipv4Packet::parse(ethernet.payload, true).unwrap();
        let icmp = IcmpPacket::parse(ipv4.payload, true).unwrap();
        assert_eq!(icmp.icmp_type, IcmpType::EchoReply);
        assert_eq!(icmp.identifier, 0x1234);
        assert_eq!(icmp.sequence_number, 7);
    }

    #[test]
    fn malformed_ipv4_uses_parameter_problem_ingress() {
        let mut datagram =
            Ipv4Packet::serialize(REMOTE_IP, LOCAL_IP, IP_PROTO_UDP, 0x2000, 64, &[0; 8]);
        datagram[6] |= 0x80;
        datagram[10..12].fill(0);
        let checksum = compute_checksum(&datagram[..20]);
        datagram[10..12].copy_from_slice(&checksum.to_be_bytes());

        let frame = ethernet_ipv4(&datagram);
        let replies = process_frame(LOCAL_MAC, LOCAL_IP, &frame);
        assert_eq!(replies.len(), 1);

        let ethernet = EthernetFrame::parse(&replies[0]).unwrap();
        let ipv4 = Ipv4Packet::parse(ethernet.payload, true).unwrap();
        let icmp = IcmpPacket::parse(ipv4.payload, true).unwrap();
        assert_eq!(icmp.icmp_type, IcmpType::ParameterProblem);
        assert_eq!(icmp.code, 0);
        assert_eq!(&ipv4.payload[4..8], &[6, 0, 0, 0]);
    }

    #[test]
    fn invalid_hex_fails_closed() {
        assert!(decode_hex("0").is_err());
        assert!(decode_hex("zz").is_err());
    }
}
