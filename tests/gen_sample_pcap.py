"""
gen_sample_pcap.py — Generate sample capture files for the full TCP/IP stack.

Produces 52 Ethernet II frames covering every implemented parser:
  1. ARP request     — EtherType 0x0806
  2. ARP reply       — EtherType 0x0806
  3. ICMP echo req.  — IPv4 / ICMP type 8  (ping)
  4. ICMP echo reply — IPv4 / ICMP type 0  (pong)
  5. UDP datagram    — IPv4 / UDP  (src→53 DNS response)
  6. TCP SYN         — IPv4 / TCP  (with MSS + WScale options)
  7. TCP SYN-ACK     — IPv4 / TCP  (with MSS + WScale + Timestamps options)
  8-15. TCP handshake, out-of-order stream data, and orderly close
 16-17. UDP fragments — IPv4 / UDP  (reassembled before transport decode)
 18. VLAN UDP datagram — 802.1Q VLAN / IPv4 / UDP
 19. Mid-stream TCP    — inferred connection without captured handshake
 20. IPv6 packet       — fixed header with no next header
 21. ICMPv6 echo req.  — IPv6 / Hop-by-Hop / ICMPv6
 22. IPv6 UDP datagram — IPv6 / UDP  (DNS response, IPv6 checksum)
 23-28. IPv6 TCP session — SYN / SYN-ACK / ACK / PSH-ACK / FIN-ACK / ACK
 29. ICMPv6 Neighbor Solicitation — NDP NS with Source Link-Layer opt
 30. ICMPv6 Neighbor Advertisement — NDP NA with Target Link-Layer opt
 31-32. IPv6 fragments — Fragment ext header; reassembled to ICMPv6 echo

All checksums are computed correctly so the parser reports "OK".

Run with:  python gen_sample_pcap.py
Output:    sample.pcap, sample.pcapng, sample-be.pcapng, sample-spb.pcapng
"""

import struct
import os

# ── pcap helpers ──────────────────────────────────────────────────────────────

PCAP_MAGIC   = 0xa1b2c3d4
LINKTYPE_ETH = 1

def pcap_global_header():
    return struct.pack("<IHHiIII",
        PCAP_MAGIC, 2, 4, 0, 0, 65535, LINKTYPE_ETH)

def pcap_record(ts_sec, ts_usec, raw_bytes):
    ts_sec += ts_usec // 1_000_000
    ts_usec %= 1_000_000
    n = len(raw_bytes)
    return struct.pack("<IIII", ts_sec, ts_usec, n, n) + raw_bytes

def pad4(data):
    return data + b"\x00" * ((-len(data)) % 4)

def pcapng_block(block_type, body, endian="<"):
    assert len(body) % 4 == 0
    total_len = 12 + len(body)
    return (
        struct.pack(f"{endian}II", block_type, total_len)
        + body
        + struct.pack(f"{endian}I", total_len)
    )

def pcapng_section_header(endian="<"):
    body = struct.pack(f"{endian}IHHq", 0x1A2B3C4D, 1, 0, -1)
    return pcapng_block(0x0A0D0D0A, body, endian)

def pcapng_interface_description(endian="<"):
    # if_tsresol=6 means decimal microsecond timestamps.
    options = (
        struct.pack(f"{endian}HHB", 9, 1, 6)
        + b"\x00" * 3
        + struct.pack(f"{endian}HH", 0, 0)
    )
    body = struct.pack(f"{endian}HHI", LINKTYPE_ETH, 0, 65535) + options
    return pcapng_block(1, body, endian)

def pcapng_enhanced_packet(ts_sec, ts_usec, raw_bytes, endian="<"):
    timestamp = (ts_sec * 1_000_000) + ts_usec
    n = len(raw_bytes)
    body = (
        struct.pack(
            f"{endian}IIIII",
            0,
            timestamp >> 32,
            timestamp & 0xFFFFFFFF,
            n,
            n,
        )
        + pad4(raw_bytes)
    )
    return pcapng_block(6, body, endian)

def pcapng_simple_packet(raw_bytes, endian="<"):
    body = struct.pack(f"{endian}I", len(raw_bytes)) + pad4(raw_bytes)
    return pcapng_block(3, body, endian)

def eth_frame(src_mac, dst_mac, ethertype, payload):
    return dst_mac + src_mac + struct.pack("!H", ethertype) + payload

def vlan_eth_frame(src_mac, dst_mac, vid, ethertype, payload, pcp=0, dei=0):
    tci = (pcp << 13) | (dei << 12) | vid
    return (
        dst_mac + src_mac
        + struct.pack("!HHH", 0x8100, tci, ethertype)
        + payload
    )

# ── checksum ──────────────────────────────────────────────────────────────────

def inet_checksum(data: bytes) -> int:
    """One's complement checksum (RFC 1071).  Returns the 16-bit result."""
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def transport_checksum(src_ip: bytes, dst_ip: bytes,
                        proto: int, segment: bytes) -> int:
    """Checksum for TCP/UDP including the IPv4 pseudo-header."""
    pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, proto, len(segment))
    return inet_checksum(pseudo + segment)

def transport_checksum_ipv6(src_ip: bytes, dst_ip: bytes,
                            next_header: int, segment: bytes) -> int:
    pseudo = src_ip + dst_ip + struct.pack("!I3xB", len(segment), next_header)
    return inet_checksum(pseudo + segment)

# ── packet builders ───────────────────────────────────────────────────────────

def build_ipv4_header(src_ip, dst_ip, proto, payload_len,
                      ip_id=0x1234, ttl=64, flags_frag=0):
    total = 20 + payload_len
    hdr = struct.pack("!BBHHHBBH4s4s",
        0x45,          # version=4, IHL=5
        0,             # DSCP/ECN
        total,         # total length
        ip_id,         # identification
        flags_frag,    # flags + fragment offset  (0x4000 = DF)
        ttl,           # TTL
        proto,         # protocol
        0,             # checksum placeholder
        src_ip,
        dst_ip,
    )
    ck = inet_checksum(hdr)
    return hdr[:10] + struct.pack("!H", ck) + hdr[12:]

def build_ipv6_header(src_ip, dst_ip, next_header, payload_len,
                      hop_limit=64, traffic_class=0, flow_label=0):
    first_word = (6 << 28) | (traffic_class << 20) | flow_label
    return struct.pack(
        "!IHBB16s16s",
        first_word,
        payload_len,
        next_header,
        hop_limit,
        src_ip,
        dst_ip,
    )

def build_ipv6_hop_by_hop(next_header):
    # Next Header, Hdr Ext Len=0, then a PadN option filling the 8-byte header.
    return struct.pack("!BB", next_header, 0) + b"\x01\x04\x00\x00\x00\x00"

def build_arp(operation, sender_mac, sender_ip, target_mac, target_ip):
    return struct.pack("!HHBBH",
        0x0001,    # HTYPE: Ethernet
        0x0800,    # PTYPE: IPv4
        6,         # HLEN
        4,         # PLEN
        operation, # 1=request, 2=reply
    ) + sender_mac + sender_ip + target_mac + target_ip

def build_icmp_echo(type_, id_, seq, data):
    hdr = struct.pack("!BBHHh", type_, 0, 0, id_, seq)
    ck  = inet_checksum(hdr + data)
    return struct.pack("!BBHHh", type_, 0, ck, id_, seq) + data

def build_ipv6_fragment_header(next_header, frag_offset_8, more_frags, identification):
    """Build an 8-byte IPv6 Fragment Extension Header (RFC 8200 §4.5).
    frag_offset_8 is in 8-byte units (same as fragment_offset field in Ipv6Payload).
    """
    offset_and_m = (frag_offset_8 << 3) | (1 if more_frags else 0)
    return struct.pack("!BBHI", next_header, 0, offset_and_m, identification)

def build_icmpv6_ns(src_ip6, dst_ip6, target_ip6, src_mac):
    """Neighbor Solicitation with Source Link-Layer Address option."""
    body  = bytes(4) + target_ip6                    # reserved + target
    body += struct.pack("!BB", 1, 1) + src_mac       # opt type=1 len=1 mac
    msg   = struct.pack("!BBH", 135, 0, 0) + body
    ck    = transport_checksum_ipv6(src_ip6, dst_ip6, 58, msg)
    return struct.pack("!BBH", 135, 0, ck) + body

def build_icmpv6_na(src_ip6, dst_ip6, target_ip6, tgt_mac):
    """Neighbor Advertisement (S=1 O=1) with Target Link-Layer Address option."""
    flags = struct.pack("!I", 0x60000000)            # S=1, O=1
    body  = flags + target_ip6                       # flags + target
    body += struct.pack("!BB", 2, 1) + tgt_mac       # opt type=2 len=1 mac
    msg   = struct.pack("!BBH", 136, 0, 0) + body
    ck    = transport_checksum_ipv6(src_ip6, dst_ip6, 58, msg)
    return struct.pack("!BBH", 136, 0, ck) + body

def build_icmpv6_echo(type_, id_, seq, data, src_ip, dst_ip):
    msg = struct.pack("!BBHHH", type_, 0, 0, id_, seq) + data
    ck = transport_checksum_ipv6(src_ip, dst_ip, 58, msg)
    return struct.pack("!BBHHH", type_, 0, ck, id_, seq) + data

def build_udp(src_port, dst_port, src_ip, dst_ip, data):
    length = 8 + len(data)
    seg    = struct.pack("!HHHH", src_port, dst_port, length, 0) + data
    ck     = transport_checksum(src_ip, dst_ip, 17, seg)
    return struct.pack("!HHHH", src_port, dst_port, length, ck) + data

def build_udp_v6(src_port, dst_port, src_ip6, dst_ip6, data):
    """Build a UDP datagram with an IPv6 pseudo-header checksum."""
    length = 8 + len(data)
    seg    = struct.pack("!HHHH", src_port, dst_port, length, 0) + data
    ck     = transport_checksum_ipv6(src_ip6, dst_ip6, 17, seg)
    return struct.pack("!HHHH", src_port, dst_port, length, ck) + data

def build_tcp(src_port, dst_port, seq, ack, flags,
              src_ip, dst_ip, window=65535, options=b'', data=b''):
    # Data offset = (20 + len(options)) / 4  (options must be 4-byte aligned)
    assert len(options) % 4 == 0, "TCP options must be padded to 4-byte boundary"
    data_offset = (20 + len(options)) // 4
    seg = struct.pack("!HHIIBBHHH",
        src_port, dst_port,
        seq, ack,
        (data_offset << 4),  # data offset (high nibble) + reserved
        flags,
        window,
        0,          # checksum placeholder
        0,          # urgent pointer
    ) + options + data
    ck  = transport_checksum(src_ip, dst_ip, 6, seg)
    # Insert checksum at offset 16
    return seg[:16] + struct.pack("!H", ck) + seg[18:]

def build_tcp_v6(src_port, dst_port, seq, ack, flags,
                 src_ip6, dst_ip6, window=65535, options=b'', data=b''):
    """Build a TCP segment with an IPv6 pseudo-header checksum."""
    assert len(options) % 4 == 0, "TCP options must be padded to 4-byte boundary"
    data_offset = (20 + len(options)) // 4
    seg = struct.pack("!HHIIBBHHH",
        src_port, dst_port,
        seq, ack,
        (data_offset << 4),
        flags,
        window,
        0,   # checksum placeholder
        0,   # urgent pointer
    ) + options + data
    ck = transport_checksum_ipv6(src_ip6, dst_ip6, 6, seg)
    return seg[:16] + struct.pack("!H", ck) + seg[18:]

# ── TCP option builders ────────────────────────────────────────────────────────

def opt_mss(mss=1460):
    return struct.pack("!BBH", 2, 4, mss)

def opt_wscale(shift=7):
    return struct.pack("!BBB", 3, 3, shift) + b'\x01'  # NOP pad to 4 bytes

def opt_sack_permitted():
    return struct.pack("!BB", 4, 2) + b'\x01\x01'  # NOP×2 pad to 4 bytes

def opt_timestamps(tsval, tsecr):
    return struct.pack("!BBII", 8, 10, tsval, tsecr) + b'\x01\x01'  # NOP×2

# ── Addresses ─────────────────────────────────────────────────────────────────

MAC_A  = bytes.fromhex("aabbcc112233")
MAC_B  = bytes.fromhex("ddeeff445566")
MAC_BC = bytes.fromhex("ffffffffffff")

IP_A = bytes([192, 168, 1, 10])
IP_B = bytes([192, 168, 1, 20])
IP6_A = bytes.fromhex("20010db8000000000000000000000010")
IP6_B = bytes.fromhex("20010db8000000000000000000000020")

# ── Packet 1: ARP request (A → who has 192.168.1.20?) ─────────────────────────

arp_req = build_arp(1, MAC_A, IP_A, MAC_BC, IP_B)
pkt1    = eth_frame(MAC_A, MAC_BC, 0x0806, arp_req)

# ── Packet 2: ARP reply (B → 192.168.1.20 is at de:ef:f4:45:56:6?) ───────────

arp_rep = build_arp(2, MAC_B, IP_B, MAC_A, IP_A)
pkt2    = eth_frame(MAC_B, MAC_A, 0x0806, arp_rep)

# ── Packet 3: ICMP Echo Request (ping A → B) ──────────────────────────────────

icmp_data    = b"Hello, TCP/IP world!"
icmp_req     = build_icmp_echo(8, 0x0042, 1, icmp_data)
ip3          = build_ipv4_header(IP_A, IP_B, 1, len(icmp_req),
                                 ip_id=0x1111, flags_frag=0x4000)  # DF set
pkt3         = eth_frame(MAC_A, MAC_B, 0x0800, ip3 + icmp_req)

# ── Packet 4: ICMP Echo Reply (pong B → A) ────────────────────────────────────

icmp_rep = build_icmp_echo(0, 0x0042, 1, icmp_data)
ip4      = build_ipv4_header(IP_B, IP_A, 1, len(icmp_rep),
                              ip_id=0x2222, flags_frag=0x4000)
pkt4     = eth_frame(MAC_B, MAC_A, 0x0800, ip4 + icmp_rep)

# ── Packet 5: UDP DNS response (B:53 → A:12345) ───────────────────────────────

dns_payload = (
    b'\xab\xcd'          # transaction ID
    b'\x81\x80'          # flags: standard query response, no error
    b'\x00\x01'          # questions: 1
    b'\x00\x01'          # answers: 1
    b'\x00\x00\x00\x00'  # authority RR / additional RR counts
    # question: example.com A
    b'\x07example\x03com\x00'
    b'\x00\x01\x00\x01'
    # answer: example.com → 93.184.216.34, TTL=3600
    b'\xc0\x0c'          # name pointer
    b'\x00\x01\x00\x01'  # type A, class IN
    b'\x00\x00\x0e\x10'  # TTL 3600
    b'\x00\x04'          # rdlength 4
    b'\x5d\xb8\xd8\x22'  # 93.184.216.34
)
udp5 = build_udp(53, 12345, IP_B, IP_A, dns_payload)
ip5  = build_ipv4_header(IP_B, IP_A, 17, len(udp5), ip_id=0x3333)
pkt5 = eth_frame(MAC_B, MAC_A, 0x0800, ip5 + udp5)

# ── Packet 6: TCP SYN (A:54321 → B:80, with MSS + WScale) ────────────────────

tcp_opts6 = opt_mss(1460) + opt_wscale(7)   # 4 + 4 = 8 bytes (aligned)
tcp6 = build_tcp(
    src_port=54321, dst_port=80,
    seq=0xdeadbeef, ack=0,
    flags=0x02,                              # SYN
    src_ip=IP_A, dst_ip=IP_B,
    window=65535,
    options=tcp_opts6,
)
ip6  = build_ipv4_header(IP_A, IP_B, 6, len(tcp6), ip_id=0x4444, flags_frag=0x4000)
pkt6 = eth_frame(MAC_A, MAC_B, 0x0800, ip6 + tcp6)

# ── Packet 7: TCP SYN-ACK (B:80 → A:54321, with MSS + WScale + Timestamps) ───

ts_opts7 = opt_mss(1460) + opt_wscale(6) + opt_timestamps(0x11223344, 0xdeadbeef)
# opt_mss=4, opt_wscale=4, opt_timestamps=12 → total 20 bytes (aligned)
tcp7 = build_tcp(
    src_port=80, dst_port=54321,
    seq=0xcafebabe, ack=0xdeadbef0,         # ack = syn_seq + 1
    flags=0x12,                             # SYN + ACK
    src_ip=IP_B, dst_ip=IP_A,
    window=65535,
    options=ts_opts7,
)
ip7  = build_ipv4_header(IP_B, IP_A, 6, len(tcp7), ip_id=0x5555, flags_frag=0x4000)
pkt7 = eth_frame(MAC_B, MAC_A, 0x0800, ip7 + tcp7)

# Packet 8: final ACK completes the three-way handshake.
tcp8 = build_tcp(
    src_port=54321, dst_port=80,
    seq=0xdeadbef0, ack=0xcafebabf,
    flags=0x10,                             # ACK
    src_ip=IP_A, dst_ip=IP_B,
)
ip8  = build_ipv4_header(IP_A, IP_B, 6, len(tcp8), ip_id=0x6666, flags_frag=0x4000)
pkt8 = eth_frame(MAC_A, MAC_B, 0x0800, ip8 + tcp8)

# Packet 9: client sends the tail first, leaving a three-byte stream gap.
tcp_data_tail = b"lo"
tcp9 = build_tcp(
    src_port=54321, dst_port=80,
    seq=0xdeadbef3, ack=0xcafebabf,
    flags=0x18,                             # PSH + ACK
    src_ip=IP_A, dst_ip=IP_B,
    data=tcp_data_tail,
)
ip9  = build_ipv4_header(IP_A, IP_B, 6, len(tcp9), ip_id=0x7777, flags_frag=0x4000)
pkt9 = eth_frame(MAC_A, MAC_B, 0x0800, ip9 + tcp9)

# Packet 10: the missing head arrives and releases the contiguous "hello".
tcp_data_head = b"hel"
tcp9b = build_tcp(
    src_port=54321, dst_port=80,
    seq=0xdeadbef0, ack=0xcafebabf,
    flags=0x18,                             # PSH + ACK
    src_ip=IP_A, dst_ip=IP_B,
    data=tcp_data_head,
)
ip9b  = build_ipv4_header(IP_A, IP_B, 6, len(tcp9b), ip_id=0x7778, flags_frag=0x4000)
pkt9b = eth_frame(MAC_A, MAC_B, 0x0800, ip9b + tcp9b)

# Packet 11: server acknowledges the application data.
tcp10 = build_tcp(
    src_port=80, dst_port=54321,
    seq=0xcafebabf, ack=0xdeadbef5,
    flags=0x10,                             # ACK
    src_ip=IP_B, dst_ip=IP_A,
)
ip10  = build_ipv4_header(IP_B, IP_A, 6, len(tcp10), ip_id=0x8888, flags_frag=0x4000)
pkt10 = eth_frame(MAC_B, MAC_A, 0x0800, ip10 + tcp10)

# Packets 12-15: orderly four-way close.
tcp11 = build_tcp(
    src_port=54321, dst_port=80,
    seq=0xdeadbef5, ack=0xcafebabf,
    flags=0x11,                             # FIN + ACK
    src_ip=IP_A, dst_ip=IP_B,
)
ip11  = build_ipv4_header(IP_A, IP_B, 6, len(tcp11), ip_id=0x9999, flags_frag=0x4000)
pkt11 = eth_frame(MAC_A, MAC_B, 0x0800, ip11 + tcp11)

tcp12 = build_tcp(
    src_port=80, dst_port=54321,
    seq=0xcafebabf, ack=0xdeadbef6,
    flags=0x10,                             # ACK
    src_ip=IP_B, dst_ip=IP_A,
)
ip12  = build_ipv4_header(IP_B, IP_A, 6, len(tcp12), ip_id=0xaaaa, flags_frag=0x4000)
pkt12 = eth_frame(MAC_B, MAC_A, 0x0800, ip12 + tcp12)

tcp13 = build_tcp(
    src_port=80, dst_port=54321,
    seq=0xcafebabf, ack=0xdeadbef6,
    flags=0x11,                             # FIN + ACK
    src_ip=IP_B, dst_ip=IP_A,
)
ip13  = build_ipv4_header(IP_B, IP_A, 6, len(tcp13), ip_id=0xbbbb, flags_frag=0x4000)
pkt13 = eth_frame(MAC_B, MAC_A, 0x0800, ip13 + tcp13)

tcp14 = build_tcp(
    src_port=54321, dst_port=80,
    seq=0xdeadbef6, ack=0xcafebac0,
    flags=0x10,                             # ACK
    src_ip=IP_A, dst_ip=IP_B,
)
ip14  = build_ipv4_header(IP_A, IP_B, 6, len(tcp14), ip_id=0xcccc, flags_frag=0x4000)
pkt14 = eth_frame(MAC_A, MAC_B, 0x0800, ip14 + tcp14)

# Packets 16-17: a UDP datagram split into two IPv4 fragments.
udp_fragment1 = udp5[:8]
ip15 = build_ipv4_header(
    IP_B, IP_A, 17, len(udp_fragment1), ip_id=0xdddd, flags_frag=0x2000)
pkt15 = eth_frame(MAC_B, MAC_A, 0x0800, ip15 + udp_fragment1)

udp_fragment2 = udp5[8:]
ip16 = build_ipv4_header(
    IP_B, IP_A, 17, len(udp_fragment2), ip_id=0xdddd, flags_frag=0x0001)
pkt16 = eth_frame(MAC_B, MAC_A, 0x0800, ip16 + udp_fragment2)

# Packet 18: a normal UDP datagram carried inside an 802.1Q VLAN.
ip17 = build_ipv4_header(IP_B, IP_A, 17, len(udp5), ip_id=0xeeee)
pkt17 = vlan_eth_frame(MAC_B, MAC_A, 42, 0x0800, ip17 + udp5, pcp=5)

# Packet 19: payload from a TCP connection whose handshake was not captured.
tcp18 = build_tcp(
    src_port=443, dst_port=60000,
    seq=7000, ack=9000,
    flags=0x18,                             # PSH + ACK
    src_ip=IP_B, dst_ip=IP_A,
    data=b"HTTP",
)
ip18 = build_ipv4_header(IP_B, IP_A, 6, len(tcp18), ip_id=0xefef, flags_frag=0x4000)
pkt18 = eth_frame(MAC_B, MAC_A, 0x0800, ip18 + tcp18)

# Packet 20: IPv6 fixed header with no encapsulated payload.
ip19 = build_ipv6_header(IP6_A, IP6_B, next_header=59, payload_len=0)
pkt19 = eth_frame(MAC_A, MAC_B, 0x86dd, ip19)

# Packet 21: IPv6 Hop-by-Hop Options header followed by ICMPv6 Echo Request.
icmpv6_data = b"hi"
icmpv6_req = build_icmpv6_echo(128, 0x0042, 1, icmpv6_data, IP6_A, IP6_B)
ipv6_hbh = build_ipv6_hop_by_hop(58)
ip20 = build_ipv6_header(
    IP6_A, IP6_B, next_header=0, payload_len=len(ipv6_hbh) + len(icmpv6_req))
pkt20 = eth_frame(MAC_A, MAC_B, 0x86dd, ip20 + ipv6_hbh + icmpv6_req)

# Packet 22: IPv6 UDP DNS response (IP6_B:53 → IP6_A:12345).
udp22 = build_udp_v6(53, 12345, IP6_B, IP6_A, dns_payload)
ip21  = build_ipv6_header(IP6_B, IP6_A, next_header=17, payload_len=len(udp22))
pkt21 = eth_frame(MAC_B, MAC_A, 0x86dd, ip21 + udp22)

# Packets 23-28: complete IPv6 TCP mini-session (IP6_A:60443 → IP6_B:8080).
# SYN
tcp22 = build_tcp_v6(60443, 8080, 0x11111111, 0, 0x02, IP6_A, IP6_B)
ip22  = build_ipv6_header(IP6_A, IP6_B, next_header=6, payload_len=len(tcp22))
pkt22 = eth_frame(MAC_A, MAC_B, 0x86dd, ip22 + tcp22)

# SYN-ACK
tcp23 = build_tcp_v6(8080, 60443, 0x22222222, 0x11111112, 0x12, IP6_B, IP6_A)
ip23  = build_ipv6_header(IP6_B, IP6_A, next_header=6, payload_len=len(tcp23))
pkt23 = eth_frame(MAC_B, MAC_A, 0x86dd, ip23 + tcp23)

# ACK (handshake complete)
tcp24 = build_tcp_v6(60443, 8080, 0x11111112, 0x22222223, 0x10, IP6_A, IP6_B)
ip24  = build_ipv6_header(IP6_A, IP6_B, next_header=6, payload_len=len(tcp24))
pkt24 = eth_frame(MAC_A, MAC_B, 0x86dd, ip24 + tcp24)

# PSH-ACK with 2-byte payload "v6"
tcp25 = build_tcp_v6(60443, 8080, 0x11111112, 0x22222223, 0x18, IP6_A, IP6_B,
                     data=b"v6")
ip25  = build_ipv6_header(IP6_A, IP6_B, next_header=6, payload_len=len(tcp25))
pkt25 = eth_frame(MAC_A, MAC_B, 0x86dd, ip25 + tcp25)

# FIN-ACK from client (client active close; data=2 so next_seq = 0x11111114)
tcp26 = build_tcp_v6(60443, 8080, 0x11111114, 0x22222223, 0x11, IP6_A, IP6_B)
ip26  = build_ipv6_header(IP6_A, IP6_B, next_header=6, payload_len=len(tcp26))
pkt26 = eth_frame(MAC_A, MAC_B, 0x86dd, ip26 + tcp26)

# ACK from server (acks FIN: ack = 0x11111114 + 1)
tcp27 = build_tcp_v6(8080, 60443, 0x22222223, 0x11111115, 0x10, IP6_B, IP6_A)
ip27  = build_ipv6_header(IP6_B, IP6_A, next_header=6, payload_len=len(tcp27))
pkt27 = eth_frame(MAC_B, MAC_A, 0x86dd, ip27 + tcp27)

# Packet 29: ICMPv6 Neighbor Solicitation (A wants MAC for IP6_B).
# Solicited-node multicast dst ff02::1:ff00:20 (last 24 bits of IP6_B = 0x000020)
IPV6_SOL_NODE_B = bytes.fromhex("ff0200000000000000000001ff000020")
ns29  = build_icmpv6_ns(IP6_A, IPV6_SOL_NODE_B, IP6_B, MAC_A)
ip28  = build_ipv6_header(IP6_A, IPV6_SOL_NODE_B, next_header=58,
                          payload_len=len(ns29), hop_limit=255)
pkt28 = eth_frame(MAC_A, MAC_B, 0x86dd, ip28 + ns29)

# Packet 30: ICMPv6 Neighbor Advertisement (B responds to A).
na30  = build_icmpv6_na(IP6_B, IP6_A, IP6_B, MAC_B)
ip29  = build_ipv6_header(IP6_B, IP6_A, next_header=58,
                          payload_len=len(na30), hop_limit=255)
pkt29 = eth_frame(MAC_B, MAC_A, 0x86dd, ip29 + na30)

# Packets 31-32: IPv6 fragmented ICMPv6 echo request (split into two 8-byte fragments).
IPV6_FRAG_ID  = 0xabcd1234
frag_icmpv6   = build_icmpv6_echo(128, 0x0044, 3, b"reassmbl", IP6_A, IP6_B)
# frag_icmpv6 is 8 (ICMPv6 header) + 8 (data) = 16 bytes

# Fragment 1: bytes 0-7, offset=0, MF=1
frag1_ext  = build_ipv6_fragment_header(58, 0, True, IPV6_FRAG_ID)
frag1_data = frag_icmpv6[:8]
ip30  = build_ipv6_header(IP6_A, IP6_B, next_header=44,
                          payload_len=len(frag1_ext) + len(frag1_data))
pkt30 = eth_frame(MAC_A, MAC_B, 0x86dd, ip30 + frag1_ext + frag1_data)

# Fragment 2: bytes 8-15, offset=1 (8 bytes), MF=0 → triggers reassembly
frag2_ext  = build_ipv6_fragment_header(58, 1, False, IPV6_FRAG_ID)
frag2_data = frag_icmpv6[8:]
ip31  = build_ipv6_header(IP6_A, IP6_B, next_header=44,
                          payload_len=len(frag2_ext) + len(frag2_data))
pkt31 = eth_frame(MAC_A, MAC_B, 0x86dd, ip31 + frag2_ext + frag2_data)

# ── Packet 33: IPv6 SRv6 (Type 4 Routing Header) → ICMPv6 echo ────────────────

def build_ipv6_routing_type4(next_header, segs):
    """SRv6 Type-4 Routing Extension Header with a list of 16-byte segments."""
    n = len(segs)
    hdr_ext_len = 2 * n  # (hdr_ext_len+1)*8 = 8 + 16*n bytes total
    hdr = struct.pack("!BBBBBBH",
        next_header, hdr_ext_len, 4, n,  # next_hdr, hdr_ext_len, type=4, segs_left
        n - 1, 0, 0)                      # last_entry, flags, tag
    for seg in segs:
        hdr += seg
    return hdr

IP6_INTERMEDIATE = bytes.fromhex("20010db8000000000000000000000099")
icmpv6_echo33 = build_icmpv6_echo(128, 0x0033, 1, b"SRv6test", IP6_A, IP6_B)
rh33     = build_ipv6_routing_type4(58, [IP6_B])  # next=ICMPv6, 1 segment
ip33     = build_ipv6_header(IP6_A, IP6_B, next_header=43,
                              payload_len=len(rh33) + len(icmpv6_echo33))
pkt32    = eth_frame(MAC_A, MAC_B, 0x86dd, ip33 + rh33 + icmpv6_echo33)

# ── Packets 34-35: DHCP DISCOVER / OFFER ──────────────────────────────────────

DHCP_XID = 0xDEADBEEF
IP_BCAST  = bytes([255, 255, 255, 255])

def build_dhcp_base(op, xid, ciaddr, yiaddr, siaddr, client_mac):
    hdr = struct.pack("!BBBBIHH", op, 1, 6, 0, xid, 0, 0)
    hdr += ciaddr + yiaddr + siaddr + bytes(4)  # giaddr=0
    hdr += client_mac + bytes(10)               # chaddr[16]
    hdr += bytes(64) + bytes(128)               # sname, file
    hdr += struct.pack("!I", 0x63825363)        # magic cookie
    return hdr

def build_dhcp_discover(client_mac, xid):
    msg = build_dhcp_base(1, xid, bytes(4), bytes(4), bytes(4), client_mac)
    msg += bytes([53, 1, 1])           # option 53: DISCOVER
    msg += bytes([55, 4, 1, 3, 6, 15]) # option 55: parameter request list
    msg += bytes([255])                # END
    return msg

def build_dhcp_offer(client_mac, server_ip, your_ip, xid):
    msg = build_dhcp_base(2, xid, bytes(4), your_ip, server_ip, client_mac)
    msg += bytes([53, 1, 2])           # option 53: OFFER
    msg += bytes([1, 4, 255, 255, 255, 0])  # option 1: subnet mask
    msg += bytes([3, 4]) + server_ip   # option 3: router
    msg += bytes([51, 4]) + struct.pack("!I", 86400)  # option 51: lease time
    msg += bytes([54, 4]) + server_ip  # option 54: server ID
    msg += bytes([255])                # END
    return msg

dhcp_disc = build_dhcp_discover(MAC_A, DHCP_XID)
udp34 = build_udp(68, 67, IP_A, IP_BCAST, dhcp_disc)
ip34  = build_ipv4_header(IP_A, IP_BCAST, 17, len(udp34), ip_id=0xd100)
pkt33 = eth_frame(MAC_A, MAC_BC, 0x0800, ip34 + udp34)

dhcp_off = build_dhcp_offer(MAC_A, IP_B, bytes([192, 168, 1, 50]), DHCP_XID)
udp35 = build_udp(67, 68, IP_B, IP_A, dhcp_off)
ip35  = build_ipv4_header(IP_B, IP_A, 17, len(udp35), ip_id=0xd200)
pkt34 = eth_frame(MAC_B, MAC_A, 0x0800, ip35 + udp35)

# ── Packets 36-37: HTTP GET / 200 OK ──────────────────────────────────────────

http_get = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
http_ok  = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello"

tcp36 = build_tcp(4321, 80, 0xA0000001, 0xB0000001, 0x18, IP_A, IP_B, data=http_get)
ip36  = build_ipv4_header(IP_A, IP_B, 6, len(tcp36), ip_id=0xe100)
pkt35 = eth_frame(MAC_A, MAC_B, 0x0800, ip36 + tcp36)

tcp37 = build_tcp(80, 4321, 0xB0000001, 0xA0000001 + len(http_get), 0x18, IP_B, IP_A, data=http_ok)
ip37  = build_ipv4_header(IP_B, IP_A, 6, len(tcp37), ip_id=0xe200)
pkt36 = eth_frame(MAC_B, MAC_A, 0x0800, ip37 + tcp37)

# ── Packet 38: TLS ClientHello (TCP PSH-ACK → port 443) ───────────────────────

sni_name = b"www.example.com"   # 15 bytes
sni_ext  = struct.pack("!HHHBH", 0, 2+1+2+len(sni_name),
                        1+2+len(sni_name), 0, len(sni_name)) + sni_name
# SNI extension: type(2)=0 + len(2) + list_len(2) + name_type(1) + name_len(2) + name = 4+5+15=24 bytes
extensions = struct.pack("!H", len(sni_ext)) + sni_ext

hello_body = (
    struct.pack("!H", 0x0303)  # client version TLS 1.2
    + bytes(32)                # random (32 zero bytes)
    + struct.pack("!B", 0)     # session_id_len = 0
    + struct.pack("!HH", 2, 0x002F)  # cipher_suites_len=2, TLS_RSA_WITH_AES_128_CBC_SHA
    + struct.pack("!BB", 1, 0)       # compression_methods: len=1, no compression
    + extensions
)
hs_msg = struct.pack("!B", 1) + struct.pack("!I", len(hello_body))[1:] + hello_body
tls_rec = struct.pack("!BHH", 22, 0x0301, len(hs_msg)) + hs_msg

tcp38 = build_tcp(4322, 443, 0xC0000001, 0xD0000001, 0x18, IP_A, IP_B, data=tls_rec)
ip38  = build_ipv4_header(IP_A, IP_B, 6, len(tcp38), ip_id=0xf100)
pkt37 = eth_frame(MAC_A, MAC_B, 0x0800, ip38 + tcp38)

# ── Packets 39-40: DNS query then response (for RTT measurement) ───────────────

DNS_XID2 = 0x5678
# Query: test.local A? (QR=0, RD=1)
qname = b"\x04test\x05local\x00"
dns_query2 = (struct.pack("!HHHHHH", DNS_XID2, 0x0100, 1, 0, 0, 0)
              + qname + struct.pack("!HH", 1, 1))  # type A, class IN
udp39 = build_udp(12346, 53, IP_A, IP_B, dns_query2)
ip39  = build_ipv4_header(IP_A, IP_B, 17, len(udp39), ip_id=0x5600)
pkt38 = eth_frame(MAC_A, MAC_B, 0x0800, ip39 + udp39)

# Response: test.local → 10.0.0.1 (QR=1, AA=1, RD=1, RA=1)
dns_resp2 = (struct.pack("!HHHHHH", DNS_XID2, 0x8580, 1, 1, 0, 0)
             + qname + struct.pack("!HH", 1, 1)        # question
             + b"\xc0\x0c"                              # name: ptr to offset 12
             + struct.pack("!HHIH", 1, 1, 300, 4)      # type A, IN, TTL=300, rdlen=4
             + bytes([10, 0, 0, 1]))                    # rdata: 10.0.0.1
udp40 = build_udp(53, 12346, IP_B, IP_A, dns_resp2)
ip40  = build_ipv4_header(IP_B, IP_A, 17, len(udp40), ip_id=0x5700)
pkt39 = eth_frame(MAC_B, MAC_A, 0x0800, ip40 + udp40)

# ── Packet 41: ICMP Destination Unreachable (port unreachable) ────────────────
# B→A: type=3 code=3; embedded original A→B UDP datagram (port 9999→9999)

orig_udp_inner = struct.pack("!HHHH", 9999, 9999, 8, 0)  # UDP header only
orig_ip_inner  = build_ipv4_header(IP_A, IP_B, 17, len(orig_udp_inner),
                                   ip_id=0xabcd)
# ICMP Destination Unreachable body: 4 unused bytes + embedded IP hdr + 8 UDP bytes
icmp_unreach_body = bytes(4) + orig_ip_inner + orig_udp_inner
icmp_unreach_msg  = struct.pack("!BBH", 3, 3, 0) + icmp_unreach_body  # type=3 code=3 cksum=0
ck_unreach = inet_checksum(icmp_unreach_msg)
icmp_unreach_msg  = struct.pack("!BBH", 3, 3, ck_unreach) + icmp_unreach_body
ip41  = build_ipv4_header(IP_B, IP_A, 1, len(icmp_unreach_msg), ip_id=0xa100)
pkt40 = eth_frame(MAC_B, MAC_A, 0x0800, ip41 + icmp_unreach_msg)

# ── Packet 42: mDNS query (UDP port 5353) ─────────────────────────────────────
# A queries local. PTR via mDNS multicast

MDNS_MC = bytes([224, 0, 0, 251])
mdns_query = (
    struct.pack("!HHHHHH", 0x0000, 0x0000, 1, 0, 0, 0)
    + b"\x05local\x00"
    + struct.pack("!HH", 12, 1)   # type PTR, class IN
)
udp42 = build_udp(5353, 5353, IP_A, MDNS_MC, mdns_query)
ip42  = build_ipv4_header(IP_A, MDNS_MC, 17, len(udp42), ip_id=0xb100, ttl=1)
pkt41 = eth_frame(MAC_A, bytes.fromhex("01005e0000fb"), 0x0800, ip42 + udp42)

# ── Packet 43: NTP client request (UDP port 123) ──────────────────────────────
# Mode=3 (client), VN=4, LI=0, stratum=0, transmit timestamp only

NTP_CLIENT_BYTE = (0 << 6) | (4 << 3) | 3   # LI=0, VN=4, Mode=3
ntp_req = struct.pack("!BBBB", NTP_CLIENT_BYTE, 0, 3, 0xEC)  # LI/VN/mode, stratum, poll, precision
ntp_req += struct.pack("!II", 0, 0)            # root delay, root dispersion
ntp_req += b"\x00" * 4                         # reference ID (unknown)
ntp_req += struct.pack("!QQQ", 0, 0, 0)        # ref, originate, receive timestamps
ntp_req += struct.pack("!Q", 0xE3_D3_E3_70 << 32)  # transmit timestamp (approx 2024 era)
udp43 = build_udp(12347, 123, IP_A, IP_B, ntp_req)
ip43  = build_ipv4_header(IP_A, IP_B, 17, len(udp43), ip_id=0xc100)
pkt42 = eth_frame(MAC_A, MAC_B, 0x0800, ip43 + udp43)

# ── Packet 44: DHCPv6 SOLICIT (IPv6 UDP 546→547) ─────────────────────────────
# IP6_A:546 → multicast ff02::1:2:547

IP6_DHCPV6_MC = bytes.fromhex("ff020000000000000000000000010002")
# Client DUID (DUID-LL, type=3, hw=1, mac=MAC_A)
client_duid = struct.pack("!HH", 3, 1) + MAC_A   # type=DUID-LL, hw-type=1, link-addr
dhcpv6_sol  = struct.pack("!B", 1) + struct.pack("!I", 0x00ABCDEF)[1:]  # msg-type=SOLICIT + xid
# Option 1 (CLIENTID)
dhcpv6_sol += struct.pack("!HH", 1, len(client_duid)) + client_duid
# Option 6 (ORO: request DNS servers)
dhcpv6_sol += struct.pack("!HHH", 6, 2, 23)
# Option 8 (ELAPSED-TIME = 0)
dhcpv6_sol += struct.pack("!HHH", 8, 2, 0)

udp44 = build_udp_v6(546, 547, IP6_A, IP6_DHCPV6_MC, dhcpv6_sol)
ip44  = build_ipv6_header(IP6_A, IP6_DHCPV6_MC, next_header=17, payload_len=len(udp44))
pkt43 = eth_frame(MAC_A, bytes.fromhex("333300010002"), 0x86dd, ip44 + udp44)

# ── Packet 45: GRE tunnel (IPv4 proto 47) encapsulating ICMP echo ─────────────
# A→B outer IP; GRE proto=0x0800; inner: A→10.0.0.1 ICMP echo

IP_INNER_DST = bytes([10, 0, 0, 1])
icmp_inner = build_icmp_echo(8, 0x0099, 1, b"gre-test")
inner_ip45 = build_ipv4_header(IP_A, IP_INNER_DST, 1, len(icmp_inner), ip_id=0xd300, ttl=64)
# GRE header: flags=0x0000, proto=0x0800
gre_hdr = struct.pack("!HH", 0x0000, 0x0800)
gre_payload = gre_hdr + inner_ip45 + icmp_inner
ip45  = build_ipv4_header(IP_A, IP_B, 47, len(gre_payload), ip_id=0xd400)
pkt44 = eth_frame(MAC_A, MAC_B, 0x0800, ip45 + gre_payload)

# ── Packets 46-47: TCP RTT via Timestamp option ───────────────────────────────
# New short-lived connection A:9999 → B:8888
# Pkt 46 (A→B SYN): TSval=1000, TSecr=0  → stored in tracker
# Pkt 47 (B→A SYN-ACK): TSval=2000, TSecr=1000 → RTT = T47 - T46 = 100 ms

ts_opt46 = opt_timestamps(1000, 0)       # TSval=1000, TSecr=0
tcp46 = build_tcp(
    src_port=9999, dst_port=8888,
    seq=0xF0000001, ack=0,
    flags=0x02,                           # SYN
    src_ip=IP_A, dst_ip=IP_B,
    options=opt_mss(1460) + ts_opt46,
)
ip46  = build_ipv4_header(IP_A, IP_B, 6, len(tcp46), ip_id=0xe400)
pkt45 = eth_frame(MAC_A, MAC_B, 0x0800, ip46 + tcp46)

ts_opt47 = opt_timestamps(2000, 1000)    # TSval=2000, TSecr=1000 (echoes A's TSval)
tcp47 = build_tcp(
    src_port=8888, dst_port=9999,
    seq=0xF1000001, ack=0xF0000002,
    flags=0x12,                           # SYN + ACK
    src_ip=IP_B, dst_ip=IP_A,
    options=opt_mss(1460) + ts_opt47,
)
ip47  = build_ipv4_header(IP_B, IP_A, 6, len(tcp47), ip_id=0xe500)
pkt46 = eth_frame(MAC_B, MAC_A, 0x0800, ip47 + tcp47)

# ── Packet 48: ICMPv6 Destination Unreachable with embedded IPv6 + UDP ────────
# B→A: type=1 code=4 (port unreachable), inner IPv6 = A→B UDP src=5555 dst=4444

inner_v6_hdr = build_ipv6_header(IP6_A, IP6_B, next_header=17, payload_len=8)
inner_udp_hdr = struct.pack("!HHHH", 5555, 4444, 8, 0)   # checksum=0 in embedded
icmpv6_du_body = bytes(4) + inner_v6_hdr + inner_udp_hdr  # 4+40+8 = 52 bytes
icmpv6_du_msg  = struct.pack("!BBH", 1, 4, 0) + icmpv6_du_body
ck_du = transport_checksum_ipv6(IP6_B, IP6_A, 58, icmpv6_du_msg)
icmpv6_du_msg  = struct.pack("!BBH", 1, 4, ck_du) + icmpv6_du_body
ipv6_du = build_ipv6_header(IP6_B, IP6_A, next_header=58, payload_len=len(icmpv6_du_msg))
pkt47   = eth_frame(MAC_B, MAC_A, 0x86dd, ipv6_du + icmpv6_du_msg)

# ── Packet 49: IPv4 with Router Alert option (IHL=6) ─────────────────────────
# Simple ICMP echo with a 4-byte Router Alert IP option in the header

def build_ipv4_with_opts(src_ip, dst_ip, proto, options, payload_len,
                          ip_id=0x1234, ttl=64):
    """Build IPv4 header with options field (IHL = 5 + len(options)//4)."""
    ihl   = 5 + len(options) // 4
    total = 20 + len(options) + payload_len
    hdr   = struct.pack("!BBHHHBBH",
                (4 << 4) | ihl, 0, total, ip_id, 0, ttl, proto, 0
            ) + src_ip + dst_ip + options
    ck = inet_checksum(hdr)
    return hdr[:10] + struct.pack("!H", ck) + hdr[12:]

router_alert_opt = struct.pack("!BBH", 148, 4, 0)   # type=148, len=4, value=0
icmp_opts  = build_icmp_echo(8, 0x0049, 1, b"opts")
ipv4_opts  = build_ipv4_with_opts(IP_A, IP_B, 1, router_alert_opt,
                                   len(icmp_opts), ip_id=0xa300)
pkt48 = eth_frame(MAC_A, MAC_B, 0x0800, ipv4_opts + icmp_opts)

# ── Packet 50: TLS ServerHello (TCP 443→4322, cipher_suite=0x002F) ────────────

srv_hello_body = (
    struct.pack("!H", 0x0303)    # server version TLS 1.2
    + bytes(32)                  # random
    + struct.pack("!B", 0)       # session_id_len = 0
    + struct.pack("!H", 0x002F)  # selected cipher: TLS_RSA_WITH_AES_128_CBC_SHA
    + struct.pack("!B", 0)       # compression method = null
)
hs50  = struct.pack("!B", 2) + struct.pack("!I", len(srv_hello_body))[1:] + srv_hello_body
tls50 = struct.pack("!BHH", 22, 0x0303, len(hs50)) + hs50
tcp50 = build_tcp(443, 4322, 0xD0000001, 0xC0000001 + len(tls_rec), 0x18,
                  IP_B, IP_A, data=tls50)
ip50  = build_ipv4_header(IP_B, IP_A, 6, len(tcp50), ip_id=0xf200)
pkt49 = eth_frame(MAC_B, MAC_A, 0x0800, ip50 + tcp50)

# ── Packet 51: DNS response — SRV answer + SOA authority ──────────────────────
# Query: _http._tcp.example.com IN SRV?
# Answer: SRV 10 5 80 example.com   Authority: example.com SOA ns1. admin. serial=2024010101

DNS_XID3 = 0x9999
# qname: _http._tcp.example.com  (24 bytes, offsets 12-35 in DNS payload)
#   "example.com" starts at offset 23 → pointer \xc0\x17
qname51 = b"\x05_http\x04_tcp\x07example\x03com\x00"

# SRV RDATA: prio(2)+weight(2)+port(2)+target(name)
srv_rdata51 = struct.pack("!HHH", 10, 5, 80) + b"\xc0\x17"   # target=example.com
srv_rr51    = (b"\xc0\x0c"
               + struct.pack("!HHIH", 33, 1, 300, len(srv_rdata51))
               + srv_rdata51)

# SOA RDATA: mname + rname + 5×uint32
soa_rdata51 = (b"\x03ns1\xc0\x17"                              # ns1.example.com
               + b"\x05admin\xc0\x17"                          # admin.example.com
               + struct.pack("!IIIII", 2024010101, 3600, 900, 86400, 300))
soa_rr51    = (b"\xc0\x17"                                     # name=example.com
               + struct.pack("!HHIH", 6, 1, 86400, len(soa_rdata51))
               + soa_rdata51)

dns51 = (struct.pack("!HHHHHH", DNS_XID3, 0x8580, 1, 1, 1, 0)  # 1 Q, 1 AN, 1 NS
         + qname51 + struct.pack("!HH", 33, 1)                  # question: SRV IN
         + srv_rr51 + soa_rr51)
udp51 = build_udp(53, 12349, IP_B, IP_A, dns51)
ip51  = build_ipv4_header(IP_B, IP_A, 17, len(udp51), ip_id=0xa400)
pkt50 = eth_frame(MAC_B, MAC_A, 0x0800, ip51 + udp51)

# ── Packet 52: IGMPv2 Membership Report (group 224.0.0.1) ────────────────────

IGMP_GROUP = bytes([224, 0, 0, 1])
igmp_msg   = struct.pack("!BBH", 0x16, 10, 0) + IGMP_GROUP  # type=v2 report, mrt=10, cksum=0
ck_igmp    = inet_checksum(igmp_msg)
igmp_msg   = struct.pack("!BBH", 0x16, 10, ck_igmp) + IGMP_GROUP
ip52  = build_ipv4_header(IP_A, IGMP_GROUP, 2, len(igmp_msg), ip_id=0xb200, ttl=1)
pkt51 = eth_frame(MAC_A, bytes.fromhex("01005e000001"), 0x0800, ip52 + igmp_msg)

# ── Write file ─────────────────────────────────────────────────────────────────

out_dir = os.path.dirname(os.path.abspath(__file__))
out_path = os.path.join(out_dir, "sample.pcap")
packets  = [
    pkt1, pkt2, pkt3, pkt4, pkt5, pkt6, pkt7,
    pkt8, pkt9, pkt9b, pkt10, pkt11, pkt12, pkt13, pkt14, pkt15, pkt16, pkt17,
    pkt18, pkt19, pkt20,
    pkt21, pkt22, pkt23, pkt24, pkt25, pkt26, pkt27,
    pkt28, pkt29, pkt30, pkt31,
    pkt32, pkt33, pkt34, pkt35, pkt36, pkt37, pkt38, pkt39,
    pkt40, pkt41, pkt42, pkt43, pkt44, pkt45, pkt46,
    pkt47, pkt48, pkt49, pkt50, pkt51,
]

with open(out_path, "wb") as f:
    f.write(pcap_global_header())
    for i, pkt in enumerate(packets):
        f.write(pcap_record(1_000_000, i * 100_000, pkt))

def write_pcapng(path, endian="<"):
    with open(path, "wb") as f:
        f.write(pcapng_section_header(endian))
        f.write(pcapng_interface_description(endian))
        # Exercise skipping an unknown but structurally valid block.
        f.write(pcapng_block(0x00000BAD, b"\x00" * 4, endian))
        for i, pkt in enumerate(packets):
            f.write(pcapng_enhanced_packet(1_000_000, i * 100_000, pkt, endian))

pcapng_path = os.path.join(out_dir, "sample.pcapng")
pcapng_be_path = os.path.join(out_dir, "sample-be.pcapng")
pcapng_spb_path = os.path.join(out_dir, "sample-spb.pcapng")
write_pcapng(pcapng_path)
write_pcapng(pcapng_be_path, ">")
with open(pcapng_spb_path, "wb") as f:
    f.write(pcapng_section_header())
    f.write(pcapng_interface_description())
    f.write(pcapng_simple_packet(pkt1))

for path in (out_path, pcapng_path, pcapng_be_path, pcapng_spb_path):
    print(f"Written {path}")
    print(f"  {os.path.getsize(path)} bytes total")
print(f"  full captures: {len(packets)} packets")
print()
print("  #1  ARP request          (EtherType 0x0806)")
print("  #2  ARP reply            (EtherType 0x0806)")
print("  #3  ICMP Echo Request    (IPv4 / protocol 1, DF)")
print("  #4  ICMP Echo Reply      (IPv4 / protocol 1, DF)")
print("  #5  UDP DNS response     (IPv4 / protocol 17, port 53→12345)")
print("  #6  TCP SYN              (IPv4 / protocol 6, MSS+WScale opts)")
print("  #7  TCP SYN-ACK          (IPv4 / protocol 6, MSS+WScale+TS opts)")
print("  #8  TCP ACK              (handshake complete)")
print("  #9  TCP PSH-ACK          (tail 'lo'; buffered behind a gap)")
print("  #10 TCP PSH-ACK          (head 'hel'; releases stream 'hello')")
print("  #11 TCP ACK              (data acknowledged)")
print("  #12 TCP FIN-ACK          (client active close)")
print("  #13 TCP ACK              (server acknowledges close)")
print("  #14 TCP FIN-ACK          (server close)")
print("  #15 TCP ACK              (close complete)")
print("  #16 UDP first fragment   (MF set; stored for reassembly)")
print("  #17 UDP final fragment   (reassembly completes; UDP decoded)")
print("  #18 VLAN UDP datagram    (VID 42; IPv4 / UDP decoded)")
print("  #19 TCP mid-stream data  (inferred connection; payload 'HTTP')")
print("  #20 IPv6 fixed header    (No Next Header)")
print("  #21 ICMPv6 Echo Request  (Hop-by-Hop extension header)")
print("  #22 IPv6 UDP DNS response (IPv6 / protocol 17, port 53→12345)")
print("  #23 IPv6 TCP SYN          (IPv6 / protocol 6, 60443→8080)")
print("  #24 IPv6 TCP SYN-ACK      (IPv6 / protocol 6, 8080→60443)")
print("  #25 IPv6 TCP ACK          (handshake complete)")
print("  #26 IPv6 TCP PSH-ACK      (data 'v6')")
print("  #27 IPv6 TCP FIN-ACK      (client active close)")
print("  #28 IPv6 TCP ACK          (server acknowledges FIN)")
print("  #29 ICMPv6 NS             (Neighbor Solicitation + src lladdr opt)")
print("  #30 ICMPv6 NA             (Neighbor Advertisement + tgt lladdr opt)")
print("  #31 IPv6 fragment 1       (offset=0 MF=1; stored for reassembly)")
print("  #32 IPv6 fragment 2       (offset=8 MF=0; reassembly completes ICMPv6)")
print("  #33 IPv6 SRv6             (Type 4 Routing Header + ICMPv6 echo)")
print("  #34 DHCP DISCOVER         (IPv4/UDP 68→67 broadcast)")
print("  #35 DHCP OFFER            (IPv4/UDP 67→68 unicast)")
print("  #36 HTTP GET              (IPv4/TCP PSH-ACK port 4321→80)")
print("  #37 HTTP 200 OK           (IPv4/TCP PSH-ACK port 80→4321)")
print("  #38 TLS ClientHello       (IPv4/TCP PSH-ACK port 4322→443 with SNI)"  )
print("  #39 DNS query             (IPv4/UDP 12346→53  test.local A?)")
print("  #40 DNS response + RTT    (IPv4/UDP 53→12346  test.local=10.0.0.1  rtt=100ms)")
print("  #41 ICMP Unreachable      (IPv4/ICMP type=3 code=3 with embedded UDP header)")
print("  #42 mDNS query            (IPv4/UDP 5353 local. PTR?)")
print("  #43 NTP client request    (IPv4/UDP 12347→123 mode=client)")
print("  #44 DHCPv6 SOLICIT        (IPv6/UDP 546→547 multicast)")
print("  #45 GRE tunnel            (IPv4/proto=47 GRE over A→10.0.0.1 ICMP)")
print("  #46 TCP SYN with TSval    (IPv4/TCP A:9999→B:8888 TSval=1000)")
print("  #47 TCP SYN-ACK TSecr     (IPv4/TCP B:8888→A:9999 TSval=2000 TSecr=1000 RTT=100ms)")
print("  #48 ICMPv6 Dest Unreach   (IPv6/ICMPv6 type=1 embedded IPv6+UDP src=5555 dst=4444)")
print("  #49 IPv4 Router Alert     (IPv4 IHL=6 option type=148 + ICMP ping)")
print("  #50 TLS ServerHello       (IPv4/TCP 443→4322 cipher=0x002F)")
print("  #51 DNS SRV + SOA         (IPv4/UDP 53→12349 SRV prio=10 + SOA serial=2024010101)")
print("  #52 IGMPv2 Report         (IPv4/IGMP type=0x16 group=224.0.0.1)")
