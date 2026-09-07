use std::env;
use std::process::ExitCode;

use toy_tcpip::fragment::{IpReassemblyBuffer, fragment_payload};
use toy_tcpip::ipv4::{IP_PROTO_UDP, Ipv4Address, Ipv4Packet};

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

fn run() -> Result<(), String> {
    let mtu = parse_usize_arg("mtu", 1280)?;
    let payload_len = parse_usize_arg("payload-len", 4096)?;
    let src = Ipv4Address::new(192, 0, 2, 1);
    let dst = Ipv4Address::new(198, 51, 100, 2);
    let identification = 0x4242;
    let payload = (0..payload_len)
        .map(|i| (i % 251) as u8)
        .collect::<Vec<_>>();

    let fragments = fragment_payload(src, dst, IP_PROTO_UDP, identification, 64, mtu, &payload);
    if payload_len != 0 && fragments.is_empty() {
        return Err(format!("fragmentation produced no packets for MTU {mtu}"));
    }

    let mut reassembly = IpReassemblyBuffer::new();
    let mut assembled = None;

    // Reverse delivery makes the probe exercise out-of-order reassembly rather
    // than merely round-tripping fragments in the order they were generated.
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

    if payload_len == 0 {
        if !fragments.is_empty() {
            return Err("empty payload unexpectedly produced fragments".to_string());
        }
    } else if assembled.as_deref() != Some(payload.as_slice()) {
        return Err("reassembled payload differs from original input".to_string());
    }

    println!(
        "ipv4-fragment-roundtrip ok: payload={} mtu={} fragments={} order=reverse",
        payload_len,
        mtu,
        fragments.len()
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
