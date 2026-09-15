use std::env;
use std::process::ExitCode;

use toy_tcpip::fragment::{fragment_payload, IpReassemblyBuffer};
use toy_tcpip::ipv4::{Ipv4Address, Ipv4Packet, IP_PROTO_UDP, IPV4_MIN_HEADER_LEN};
use toy_tcpip::udp::{UdpDatagram, UDP_HEADER_LEN};

fn parse_usize_arg(name: &str, default: usize) -> Result<usize, String> {
    let prefix = format!("--{name}=");
    match env::args()
        .skip(1)
        .find_map(|arg| arg.strip_prefix(&prefix).map(str::to_owned))
    {
        Some(value) => value
            .parse::<usize>()
            .map_err(|_| format!("invalid value for --{name}: {value}")),
        None => Ok(default),
    }
}

fn roundtrip(mtu: usize, payload_len: usize) -> Result<usize, String> {
    let src = Ipv4Address::new(192, 0, 2, 1);
    let dst = Ipv4Address::new(198, 51, 100, 2);
    let identification = 0x4242;
    let payload = (0..payload_len)
        .map(|i| (i % 251) as u8)
        .collect::<Vec<_>>();

    let max_udp_payload = u16::MAX as usize - IPV4_MIN_HEADER_LEN - UDP_HEADER_LEN;
    if payload_len > max_udp_payload {
        return Err(format!(
            "UDP payload {payload_len} exceeds IPv4 datagram capacity {max_udp_payload}"
        ));
    }

    let udp = UdpDatagram::try_serialize(src, dst, 49152, 9000, &payload)
        .map_err(|err| format!("UDP serialization failed: {err}"))?;
    let fragments = fragment_payload(src, dst, IP_PROTO_UDP, identification, 64, mtu, &udp);
    if fragments.is_empty() {
        return Err(format!("fragmentation produced no packets for MTU {mtu}"));
    }

    let mut reassembly = IpReassemblyBuffer::new();
    let mut assembled = None;

    // Reverse delivery exercises parser -> out-of-order reassembly -> UDP checksum
    // validation rather than only round-tripping an opaque IP payload.
    for wire in fragments.iter().rev() {
        if wire.len() > mtu {
            return Err(format!("fragment length {} exceeds MTU {mtu}", wire.len()));
        }
        let packet =
            Ipv4Packet::parse(wire, true).map_err(|err| format!("fragment parse failed: {err}"))?;
        assembled = reassembly.add_fragment(
            packet.header.src_ip,
            packet.header.dst_ip,
            packet.header.protocol.to_u8(),
            packet.header.identification,
            packet.header.fragment_offset,
            packet.header.more_fragments,
            packet.payload,
        );
    }

    let assembled = assembled.ok_or_else(|| "fragment set did not complete".to_string())?;
    let datagram = UdpDatagram::parse(src, dst, &assembled, true)
        .map_err(|err| format!("reassembled UDP parse failed: {err}"))?;
    if datagram.src_port != 49152 || datagram.dst_port != 9000 || datagram.payload != payload {
        return Err("reassembled UDP datagram differs from original input".to_string());
    }

    Ok(fragments.len())
}

fn run() -> Result<(), String> {
    let mtu = parse_usize_arg("mtu", 1280)?;
    let payload_len = parse_usize_arg("payload-len", 4096)?;
    let fragments = roundtrip(mtu, payload_len)?;
    println!(
        "ipv4-fragment-roundtrip ok: udp_payload={} mtu={} fragments={} order=reverse checksum=verified",
        payload_len, mtu, fragments
    );
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("ipv4-fragment-roundtrip failed: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_fragment_roundtrip_crosses_transport_and_ip_boundaries() {
        assert!(roundtrip(1280, 4096).expect("roundtrip") > 1);
    }

    #[test]
    fn rejects_udp_payload_that_cannot_fit_an_ipv4_datagram() {
        let max_udp_payload = u16::MAX as usize - IPV4_MIN_HEADER_LEN - UDP_HEADER_LEN;
        let err =
            roundtrip(1500, max_udp_payload + 1).expect_err("oversized payload must fail");
        assert!(err.contains("exceeds IPv4 datagram capacity"));
    }
}
