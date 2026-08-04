#!/usr/bin/env python3
"""
gen_encap_pcap.py — captures for link types other than Ethernet, and for tunnels

    python tests/gen_encap_pcap.py

A pcap file names its link layer once, in the global header, so covering four
link types takes four files rather than four packets:

    sample-sll.pcap     LINKTYPE_LINUX_SLL   (tcpdump -i any)
    sample-sll2.pcap    LINKTYPE_LINUX_SLL2  (the newer cooked header)
    sample-raw.pcap     LINKTYPE_RAW         (tunnel and VPN interfaces)
    sample-null.pcap    LINKTYPE_NULL        (BSD loopback)
    sample-encap.pcap   LINKTYPE_ETHERNET, carrying the tunnels

The tunnel capture ends with a packet nested twelve layers deep. The dispatcher
follows eight, so that packet exists to prove it stops rather than following
the chain down: before the depth cap, a packet of this shape built deep enough
to fill the read buffer exhausted the C stack and killed the process.

The BSD loopback capture writes one address family little-endian and one
big-endian, because that header is written in the capturing host's byte order
with nothing recording which that was.
"""

import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TESTS = ROOT / "tests"

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276

MAC_A = bytes.fromhex("aabbcc112233")
MAC_B = bytes.fromhex("ddeeff445566")
IP_A = bytes([192, 168, 1, 10])
IP_B = bytes([192, 168, 1, 20])
IP6_A = bytes.fromhex("20010db8000000000000000000000010")
IP6_B = bytes.fromhex("20010db8000000000000000000000020")


# ── checksums ────────────────────────────────────────────────────────────────

def inet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def icmpv6_checksum(src, dst, body: bytes) -> int:
    pseudo = src + dst + struct.pack(">I", len(body)) + b"\x00\x00\x00" + bytes([58])
    return inet_checksum(pseudo + body)


# ── builders ─────────────────────────────────────────────────────────────────

def ipv4(proto, payload, src=IP_A, dst=IP_B, ip_id=0x1234):
    header = bytearray(struct.pack(">BBHHHBBH4s4s",
                                   0x45, 0, 20 + len(payload), ip_id, 0x4000,
                                   64, proto, 0, src, dst))
    header[10:12] = struct.pack(">H", inet_checksum(bytes(header)))
    return bytes(header) + payload


def ipv6(next_header, payload, src=IP6_A, dst=IP6_B):
    return (struct.pack(">IHBB", 0x60000000, len(payload), next_header, 64)
            + src + dst + payload)


def icmp_echo(seq=1, data=b"encapsulated"):
    body = bytearray(struct.pack(">BBHHH", 8, 0, 0, 0x0042, seq) + data)
    body[2:4] = struct.pack(">H", inet_checksum(bytes(body)))
    return bytes(body)


def icmpv6_echo(src, dst, seq=1, data=b"encapsulated"):
    body = bytearray(struct.pack(">BBHHH", 128, 0, 0, 0x0042, seq) + data)
    body[2:4] = struct.pack(">H", icmpv6_checksum(src, dst, bytes(body)))
    return bytes(body)


def udp(src_port, dst_port, payload):
    # Checksum 0 means the sender disabled it, which is legal over IPv4 and
    # keeps this generator from having to recompute it through every tunnel.
    return struct.pack(">HHHH", src_port, dst_port, 8 + len(payload), 0) + payload


def eth(payload, ethertype, src=MAC_A, dst=MAC_B):
    return dst + src + struct.pack(">H", ethertype) + payload


def sll(ethertype, payload, packet_type=0, addr=MAC_A):
    """Linux cooked v1: 16-byte header, protocol last."""
    return (struct.pack(">HHH", packet_type, 1, len(addr))
            + addr + b"\x00" * (8 - len(addr))
            + struct.pack(">H", ethertype)
            + payload)


def sll2(ethertype, payload, packet_type=0, if_index=2, addr=MAC_A):
    """Linux cooked v2: 20-byte header, protocol first."""
    return (struct.pack(">HHIHBB", ethertype, 0, if_index, 1,
                        packet_type, len(addr))
            + addr + b"\x00" * (8 - len(addr))
            + payload)


def pppoe_session(ppp_protocol, payload, session_id=0x0001):
    body = struct.pack(">H", ppp_protocol) + payload
    return struct.pack(">BBHH", 0x11, 0x00, session_id, len(body)) + body


def vxlan(vni, inner_frame):
    return (bytes([0x08, 0, 0, 0])
            + struct.pack(">I", vni)[1:]      # 24-bit VNI
            + bytes([0])
            + inner_frame)


# ── capture writing ──────────────────────────────────────────────────────────

def write_pcap(path, link_type, packets):
    blob = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0,
                                 65535, link_type))
    for index, frame in enumerate(packets):
        ts = 1 + index
        blob += struct.pack("<IIII", ts, 0, len(frame), len(frame))
        blob += frame
    path.write_bytes(bytes(blob))
    print(f"  {path.name:22s} link-type={link_type:<4d} "
          f"{len(packets)} packet(s), {path.stat().st_size} bytes")


# ── captures ─────────────────────────────────────────────────────────────────

def build_sll():
    v4 = ipv4(1, icmp_echo(seq=1))
    v6 = ipv6(58, icmpv6_echo(IP6_A, IP6_B, seq=2))
    arp = (struct.pack(">HHBBH", 1, 0x0800, 6, 4, 1)
           + MAC_A + IP_A + b"\x00" * 6 + IP_B)
    return [
        sll(0x0800, v4, packet_type=0),           # to us
        sll(0x86DD, v6, packet_type=1),           # broadcast
        sll(0x0806, arp, packet_type=4),          # outgoing
    ]


def build_sll2():
    v4 = ipv4(1, icmp_echo(seq=3))
    v6 = ipv6(58, icmpv6_echo(IP6_A, IP6_B, seq=4))
    return [
        sll2(0x0800, v4, packet_type=0, if_index=2),
        sll2(0x86DD, v6, packet_type=4, if_index=3),
    ]


def build_raw():
    # No link header at all: the version nibble is the only thing identifying
    # what follows.
    return [
        ipv4(1, icmp_echo(seq=5)),
        ipv6(58, icmpv6_echo(IP6_A, IP6_B, seq=6)),
    ]


def build_null():
    v4 = ipv4(1, icmp_echo(seq=7))
    v6 = ipv6(58, icmpv6_echo(IP6_A, IP6_B, seq=8))
    return [
        struct.pack("<I", 2) + v4,      # AF_INET, host byte order (LE)
        struct.pack(">I", 30) + v6,     # AF_INET6 as macOS writes it, BE
        struct.pack("<I", 0xDEAD) + v4, # a family we cannot make sense of
    ]


def build_encap():
    packets = []

    # IPv4 in IPv4 (protocol 4).
    inner = ipv4(1, icmp_echo(seq=10), src=bytes([10, 0, 0, 1]),
                 dst=bytes([10, 0, 0, 2]), ip_id=0x2001)
    packets.append(eth(ipv4(4, inner, ip_id=0x2000), 0x0800))

    # IPv6 in IPv4 (protocol 41), the classic 6in4 tunnel.
    inner6 = ipv6(58, icmpv6_echo(IP6_A, IP6_B, seq=11))
    packets.append(eth(ipv4(41, inner6, ip_id=0x2002), 0x0800))

    # PPPoE session carrying IPv4.
    ppp = pppoe_session(0x0021, ipv4(1, icmp_echo(seq=12), ip_id=0x2003))
    packets.append(eth(ppp, 0x8864))

    # PPPoE discovery, which carries tags rather than a PPP frame.
    padi = struct.pack(">BBHH", 0x11, 0x09, 0x0000, 4) + b"\x01\x01\x00\x00"
    packets.append(eth(padi, 0x8863))

    # VXLAN: UDP carrying a complete inner Ethernet frame. This is the one
    # encapsulation that returns the walk to the link layer.
    inner_frame = eth(ipv4(1, icmp_echo(seq=13), src=bytes([10, 1, 0, 1]),
                           dst=bytes([10, 1, 0, 2]), ip_id=0x2004),
                      0x0800, src=MAC_B, dst=MAC_A)
    packets.append(eth(ipv4(17, udp(45678, 4789, vxlan(0x123456, inner_frame)),
                            ip_id=0x2005), 0x0800))

    # Twelve layers of GRE. The dispatcher follows eight and stops; this is
    # here to prove it stops. Every layer needs a valid header checksum, which
    # is why a fuzzer never produced this shape on its own.
    deep = ipv4(1, icmp_echo(seq=14), ip_id=0x2006)
    for _ in range(12):
        deep = ipv4(47, struct.pack(">HH", 0, 0x0800) + deep, ip_id=0x2007)
    packets.append(eth(deep, 0x0800))

    return packets


def main():
    print("Writing encapsulation and link-type captures:")
    write_pcap(TESTS / "sample-sll.pcap", LINKTYPE_LINUX_SLL, build_sll())
    write_pcap(TESTS / "sample-sll2.pcap", LINKTYPE_LINUX_SLL2, build_sll2())
    write_pcap(TESTS / "sample-raw.pcap", LINKTYPE_RAW, build_raw())
    write_pcap(TESTS / "sample-null.pcap", LINKTYPE_NULL, build_null())
    write_pcap(TESTS / "sample-encap.pcap", LINKTYPE_ETHERNET, build_encap())
    return 0


if __name__ == "__main__":
    sys.exit(main())
