use std::env;
use std::process::ExitCode;
use std::str::FromStr;

use toy_tcpip::ethernet::{ETHERTYPE_IPV6, EtherType, EthernetFrame, MacAddress};
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::{
    Ipv6Address, Ipv6Error, Ipv6Packet, NEXT_HEADER_DEST_OPTS, NEXT_HEADER_FRAGMENT,
    NEXT_HEADER_GRE, NEXT_HEADER_HOP_BY_HOP, NEXT_HEADER_ICMPV6, NEXT_HEADER_NO_NEXT,
    NEXT_HEADER_ROUTING, NEXT_HEADER_TCP, NEXT_HEADER_UDP, compute_ipv6_transport_checksum,
};
use toy_tcpip::ipv6_ext::{
    IPV6_OPT_JUMBO_PAYLOAD, IPV6_OPT_PAD1, IPV6_OPT_PADN, IPV6_OPT_ROUTER_ALERT,
};
use toy_tcpip::stack::{NetStack, NetStackConfig};

const ICMPV6_TYPE_PARAMETER_PROBLEM: u8 = 4;
const ICMPV6_ERROR_HEADER_LEN: usize = 8;
const MAX_INVOKING_BYTES: usize = 1232; // 1280 - IPv6(40) - ICMPv6 error header(8)
const PAYLOAD_LENGTH_POINTER: u32 = 4;
const NEXT_HEADER_POINTER: u32 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OptionPolicy {
    Pass,
    Drop,
    ParameterProblem(u32),
}

#[derive(Debug, PartialEq, Eq)]
enum ParameterProblemOutcome {
    Pass,
    Drop,
    Reply(Vec<u8>),
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

fn is_recognized_next_header(next_header: u8) -> bool {
    matches!(
        next_header,
        NEXT_HEADER_HOP_BY_HOP
            | NEXT_HEADER_TCP
            | NEXT_HEADER_UDP
            | NEXT_HEADER_ROUTING
            | NEXT_HEADER_FRAGMENT
            | NEXT_HEADER_GRE
            | NEXT_HEADER_ICMPV6
            | NEXT_HEADER_NO_NEXT
            | NEXT_HEADER_DEST_OPTS
    )
}

fn is_recognized_option(option_type: u8) -> bool {
    matches!(
        option_type,
        IPV6_OPT_PAD1 | IPV6_OPT_PADN | IPV6_OPT_ROUTER_ALERT | IPV6_OPT_JUMBO_PAYLOAD
    )
}

/// Applies the RFC 8200 section 4.2 action bits for options that this stack does
/// not recognize. The pointer is relative to the start of the invoking IPv6
/// packet, as required by RFC 4443 Parameter Problem Code 2.
fn unrecognized_option_policy(packet: &[u8]) -> OptionPolicy {
    if packet.len() < 40 {
        return OptionPolicy::Drop;
    }

    let mut next_header = packet[6];
    let mut payload = &packet[40..];
    let mut payload_offset = 40usize;

    loop {
        match next_header {
            NEXT_HEADER_HOP_BY_HOP | NEXT_HEADER_DEST_OPTS => {
                if payload.len() < 2 {
                    return OptionPolicy::Drop;
                }
                let header_len = (usize::from(payload[1]) + 1) * 8;
                if payload.len() < header_len {
                    return OptionPolicy::Drop;
                }

                let options = &payload[2..header_len];
                let mut cursor = 0usize;
                while cursor < options.len() {
                    let option_type = options[cursor];
                    if option_type == IPV6_OPT_PAD1 {
                        cursor += 1;
                        continue;
                    }
                    if cursor + 1 >= options.len() {
                        return OptionPolicy::Drop;
                    }
                    let option_len = usize::from(options[cursor + 1]);
                    let option_end = cursor + 2 + option_len;
                    if option_end > options.len() {
                        return OptionPolicy::Drop;
                    }

                    if !is_recognized_option(option_type) {
                        match option_type >> 6 {
                            0 => {}
                            1 => return OptionPolicy::Drop,
                            2 | 3 => {
                                let pointer = payload_offset + 2 + cursor;
                                return OptionPolicy::ParameterProblem(pointer as u32);
                            }
                            _ => unreachable!(),
                        }
                    }
                    cursor = option_end;
                }

                next_header = payload[0];
                payload = &payload[header_len..];
                payload_offset += header_len;
            }
            NEXT_HEADER_ROUTING => {
                if payload.len() < 2 {
                    return OptionPolicy::Drop;
                }
                let header_len = (usize::from(payload[1]) + 1) * 8;
                if payload.len() < header_len {
                    return OptionPolicy::Drop;
                }
                next_header = payload[0];
                payload = &payload[header_len..];
                payload_offset += header_len;
            }
            NEXT_HEADER_FRAGMENT => {
                if payload.len() < 8 {
                    return OptionPolicy::Drop;
                }
                let fragment_field = u16::from_be_bytes([payload[2], payload[3]]);
                if fragment_field & 0xfff8 != 0 {
                    return OptionPolicy::Pass;
                }
                next_header = payload[0];
                payload = &payload[8..];
                payload_offset += 8;
            }
            _ => return OptionPolicy::Pass,
        }
    }
}

/// Classifies whether the invoking IPv6 packet carries an ICMPv6 error after
/// extension headers. `None` means the chain cannot be inspected safely, so
/// callers must conservatively suppress any generated ICMPv6 error.
fn invoking_contains_icmpv6_error(packet: &[u8]) -> Option<bool> {
    if packet.len() < 40 {
        return None;
    }

    let mut next_header = packet[6];
    let mut payload = &packet[40..];
    loop {
        match next_header {
            NEXT_HEADER_ICMPV6 => return payload.first().map(|message_type| *message_type < 128),
            NEXT_HEADER_HOP_BY_HOP | NEXT_HEADER_ROUTING | NEXT_HEADER_DEST_OPTS => {
                if payload.len() < 2 {
                    return None;
                }
                let header_len = (usize::from(payload[1]) + 1) * 8;
                if payload.len() < header_len {
                    return None;
                }
                next_header = payload[0];
                payload = &payload[header_len..];
            }
            NEXT_HEADER_FRAGMENT => {
                if payload.len() < 8 {
                    return None;
                }
                let fragment_field = u16::from_be_bytes([payload[2], payload[3]]);
                if fragment_field & 0xfff8 != 0 {
                    return None;
                }
                next_header = payload[0];
                payload = &payload[8..];
            }
            NEXT_HEADER_NO_NEXT => return Some(false),
            _ => return Some(false),
        }
    }
}

fn build_parameter_problem_reply(
    ethernet: &EthernetFrame<'_>,
    local_ip: Ipv6Address,
    source: Ipv6Address,
    packet: &[u8],
    code: u8,
    pointer: u32,
) -> Vec<u8> {
    let quoted_len = packet.len().min(MAX_INVOKING_BYTES);
    let mut icmp = Vec::with_capacity(ICMPV6_ERROR_HEADER_LEN + quoted_len);
    icmp.push(ICMPV6_TYPE_PARAMETER_PROBLEM);
    icmp.push(code);
    icmp.extend_from_slice(&[0, 0]);
    icmp.extend_from_slice(&pointer.to_be_bytes());
    icmp.extend_from_slice(&packet[..quoted_len]);
    let checksum = compute_ipv6_transport_checksum(local_ip, source, NEXT_HEADER_ICMPV6, &icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());

    let reply = Ipv6Packet::serialize(local_ip, source, NEXT_HEADER_ICMPV6, 64, &icmp);
    EthernetFrame::serialize(ethernet.src_mac, ethernet.dst_mac, ETHERTYPE_IPV6, &reply)
}

fn ipv6_parameter_problem(
    local_mac: MacAddress,
    local_ip: Ipv6Address,
    raw_frame: &[u8],
) -> ParameterProblemOutcome {
    let Ok(ethernet) = EthernetFrame::parse(raw_frame) else {
        return ParameterProblemOutcome::Pass;
    };
    if ethernet.ethertype != EtherType::IPv6 || ethernet.dst_mac != local_mac {
        return ParameterProblemOutcome::Pass;
    }
    let packet = ethernet.payload;
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return ParameterProblemOutcome::Pass;
    }

    let mut source = [0u8; 16];
    source.copy_from_slice(&packet[8..24]);
    let source = Ipv6Address(source);
    let mut destination = [0u8; 16];
    destination.copy_from_slice(&packet[24..40]);
    let destination = Ipv6Address(destination);
    if destination != local_ip || source.is_unspecified() || source.is_multicast() {
        return ParameterProblemOutcome::Pass;
    }

    match Ipv6Packet::parse(packet) {
        Err(Ipv6Error::PayloadLengthMismatch { .. }) => {
            // RFC 4443 section 2.4(e): never send an ICMPv6 error in response to another
            // ICMPv6 error, including one reached through an extension-header chain.
            // If truncation or a non-initial fragment makes the upper-layer type unknowable,
            // fail closed and suppress the generated error.
            if invoking_contains_icmpv6_error(packet) != Some(false) {
                return ParameterProblemOutcome::Drop;
            }
            ParameterProblemOutcome::Reply(build_parameter_problem_reply(
                &ethernet,
                local_ip,
                source,
                packet,
                0,
                PAYLOAD_LENGTH_POINTER,
            ))
        }
        Ok(ipv6) if !is_recognized_next_header(ipv6.header.next_header) => {
            ParameterProblemOutcome::Reply(build_parameter_problem_reply(
                &ethernet,
                local_ip,
                source,
                packet,
                1,
                NEXT_HEADER_POINTER,
            ))
        }
        Ok(_) => match unrecognized_option_policy(packet) {
            OptionPolicy::ParameterProblem(pointer) => {
                if invoking_contains_icmpv6_error(packet) != Some(false) {
                    ParameterProblemOutcome::Drop
                } else {
                    ParameterProblemOutcome::Reply(build_parameter_problem_reply(
                        &ethernet, local_ip, source, packet, 2, pointer,
                    ))
                }
            }
            OptionPolicy::Drop => ParameterProblemOutcome::Drop,
            OptionPolicy::Pass => ParameterProblemOutcome::Pass,
        },
        Err(_) => ParameterProblemOutcome::Pass,
    }
}

fn process_frame(local_mac: MacAddress, local_ip: Ipv6Address, raw_frame: &[u8]) -> Vec<Vec<u8>> {
    match ipv6_parameter_problem(local_mac, local_ip, raw_frame) {
        ParameterProblemOutcome::Reply(reply) => return vec![reply],
        ParameterProblemOutcome::Drop => return Vec::new(),
        ParameterProblemOutcome::Pass => {}
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
    const LOCAL_IP: Ipv6Address =
        Ipv6Address([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    const REMOTE_IP: Ipv6Address =
        Ipv6Address([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

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
        assert_eq!(
            u32::from_be_bytes(ipv6.payload[4..8].try_into().unwrap()),
            4
        );
        assert_eq!(
            compute_ipv6_transport_checksum(LOCAL_IP, REMOTE_IP, NEXT_HEADER_ICMPV6, ipv6.payload),
            0
        );
    }

    #[test]
    fn unrecognized_next_header_generates_code_1() {
        let invoking = Ipv6Packet::serialize(REMOTE_IP, LOCAL_IP, 253, 64, &[0; 8]);
        let replies = process_frame(LOCAL_MAC, LOCAL_IP, &ethernet_ipv6(&invoking));
        assert_eq!(replies.len(), 1);

        let ethernet = EthernetFrame::parse(&replies[0]).unwrap();
        assert_eq!(ethernet.dst_mac, REMOTE_MAC);
        let ipv6 = Ipv6Packet::parse(ethernet.payload).unwrap();
        assert_eq!(ipv6.header.src_ip, LOCAL_IP);
        assert_eq!(ipv6.header.dst_ip, REMOTE_IP);
        assert_eq!(ipv6.payload[0], ICMPV6_TYPE_PARAMETER_PROBLEM);
        assert_eq!(ipv6.payload[1], 1);
        assert_eq!(
            u32::from_be_bytes(ipv6.payload[4..8].try_into().unwrap()),
            NEXT_HEADER_POINTER
        );
        assert_eq!(
            compute_ipv6_transport_checksum(LOCAL_IP, REMOTE_IP, NEXT_HEADER_ICMPV6, ipv6.payload),
            0
        );
    }

    #[test]
    fn unrecognized_option_with_action_10_generates_code_2() {
        let options = [
            NEXT_HEADER_NO_NEXT,
            0,
            0x80,
            0,
            IPV6_OPT_PAD1,
            IPV6_OPT_PAD1,
            0,
            0,
        ];
        let invoking =
            Ipv6Packet::serialize(REMOTE_IP, LOCAL_IP, NEXT_HEADER_HOP_BY_HOP, 64, &options);
        let replies = process_frame(LOCAL_MAC, LOCAL_IP, &ethernet_ipv6(&invoking));
        assert_eq!(replies.len(), 1);

        let ethernet = EthernetFrame::parse(&replies[0]).unwrap();
        let ipv6 = Ipv6Packet::parse(ethernet.payload).unwrap();
        assert_eq!(ipv6.payload[0], ICMPV6_TYPE_PARAMETER_PROBLEM);
        assert_eq!(ipv6.payload[1], 2);
        assert_eq!(
            u32::from_be_bytes(ipv6.payload[4..8].try_into().unwrap()),
            42
        );
        assert_eq!(
            compute_ipv6_transport_checksum(LOCAL_IP, REMOTE_IP, NEXT_HEADER_ICMPV6, ipv6.payload),
            0
        );
    }

    #[test]
    fn unrecognized_option_with_action_01_drops_silently() {
        let options = [
            NEXT_HEADER_NO_NEXT,
            0,
            0x40,
            0,
            IPV6_OPT_PAD1,
            IPV6_OPT_PAD1,
            0,
            0,
        ];
        let invoking =
            Ipv6Packet::serialize(REMOTE_IP, LOCAL_IP, NEXT_HEADER_HOP_BY_HOP, 64, &options);
        assert_eq!(unrecognized_option_policy(&invoking), OptionPolicy::Drop);
        assert!(process_frame(LOCAL_MAC, LOCAL_IP, &ethernet_ipv6(&invoking)).is_empty());
    }

    #[test]
    fn unrecognized_option_with_action_00_is_skipped() {
        let options = [
            NEXT_HEADER_NO_NEXT,
            0,
            0x1e,
            0,
            IPV6_OPT_PAD1,
            IPV6_OPT_PAD1,
            0,
            0,
        ];
        let invoking =
            Ipv6Packet::serialize(REMOTE_IP, LOCAL_IP, NEXT_HEADER_HOP_BY_HOP, 64, &options);
        assert_eq!(unrecognized_option_policy(&invoking), OptionPolicy::Pass);
    }

    #[test]
    fn recognized_no_next_header_does_not_generate_parameter_problem() {
        let invoking = Ipv6Packet::serialize(REMOTE_IP, LOCAL_IP, NEXT_HEADER_NO_NEXT, 64, &[]);
        assert!(process_frame(LOCAL_MAC, LOCAL_IP, &ethernet_ipv6(&invoking)).is_empty());
    }

    #[test]
    fn icmpv6_error_does_not_trigger_another_error() {
        let mut invoking =
            Ipv6Packet::serialize(REMOTE_IP, LOCAL_IP, NEXT_HEADER_ICMPV6, 64, &[1; 8]);
        invoking[4..6].copy_from_slice(&16u16.to_be_bytes());
        assert!(process_frame(LOCAL_MAC, LOCAL_IP, &ethernet_ipv6(&invoking)).is_empty());
    }

    #[test]
    fn extension_header_icmpv6_error_does_not_trigger_another_error() {
        let mut payload = vec![0u8; 16];
        payload[0] = NEXT_HEADER_ICMPV6;
        payload[1] = 0;
        payload[8] = 1;
        let mut invoking =
            Ipv6Packet::serialize(REMOTE_IP, LOCAL_IP, NEXT_HEADER_HOP_BY_HOP, 64, &payload);
        invoking[4..6].copy_from_slice(&24u16.to_be_bytes());
        assert!(process_frame(LOCAL_MAC, LOCAL_IP, &ethernet_ipv6(&invoking)).is_empty());
    }

    #[test]
    fn truncated_extension_chain_suppresses_error() {
        let mut invoking =
            Ipv6Packet::serialize(REMOTE_IP, LOCAL_IP, NEXT_HEADER_HOP_BY_HOP, 64, &[58]);
        invoking[4..6].copy_from_slice(&8u16.to_be_bytes());
        assert!(process_frame(LOCAL_MAC, LOCAL_IP, &ethernet_ipv6(&invoking)).is_empty());
    }

    #[test]
    fn informational_icmpv6_after_extension_header_can_trigger_error() {
        let mut payload = vec![0u8; 16];
        payload[0] = NEXT_HEADER_ICMPV6;
        payload[1] = 0;
        payload[8] = 128;
        let mut invoking =
            Ipv6Packet::serialize(REMOTE_IP, LOCAL_IP, NEXT_HEADER_HOP_BY_HOP, 64, &payload);
        invoking[4..6].copy_from_slice(&24u16.to_be_bytes());
        let replies = process_frame(LOCAL_MAC, LOCAL_IP, &ethernet_ipv6(&invoking));
        assert_eq!(replies.len(), 1);
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
