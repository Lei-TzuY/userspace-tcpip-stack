#!/usr/bin/env python3
"""
gen_fuzz_corpus.py — build the fuzz seed corpus under fuzz/corpus/

Run from anywhere:

    python tests/gen_fuzz_corpus.py

Three corpora are produced, one per fuzz target:

    fuzz/corpus/pcap/     whole capture files
    fuzz/corpus/frame/    length-prefixed sequences of Ethernet frames
    fuzz/corpus/parsers/  a selector byte followed by one parser's input

Two kinds of input go in. Valid seeds are lifted straight out of the existing
tests/sample.pcap fixture, which already reaches deep into every parser — a
coverage-guided fuzzer mutates outward from those far faster than it can
rediscover a well-formed frame from scratch. The rest are hand-built malformed
inputs aimed at the places where the stack walks an attacker-controlled length:
TLV option chains, DNS name compression, IPv6 extension headers, and pcapng
block totals. A zero-length TLV entry is the specific shape that turns a
forward-progress bug into an infinite loop, so it appears for every walker.

Regenerating is idempotent. Files are named by case, not by hash, so a diff
shows which case changed. Crash reproducers found by a campaign should be
copied into these directories by hand and left alone; this script only
overwrites the names it generates.
"""

import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "fuzz" / "corpus"
FIXTURES = ROOT / "tests"

# Parser selector values. These MUST match the switch in fuzz/fuzz_parsers.c.
SEL = {
    "eth": 0, "arp": 1, "ipv4": 2, "ipv6": 3, "icmp": 4, "icmpv6": 5,
    "tcp": 6, "udp": 7, "dns": 8, "dhcp": 9, "dhcpv6": 10, "ntp": 11,
    "http": 12, "tls": 13, "gre": 14, "igmp": 15,
    "pppoe": 16, "vxlan": 17,
    "link_null": 18, "link_raw": 19, "link_sll": 20, "link_sll2": 21,
    "sctp": 22, "quic": 23,
}

written = 0


def write(target, name, data):
    """Write one corpus input, creating the target directory as needed."""
    global written
    directory = CORPUS / target
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_bytes(bytes(data))
    written += 1


def write_parser(kind, name, payload):
    """Write a fuzz_parsers input: selector byte, then the parser's buffer."""
    write("parsers", f"{kind}_{name}", bytes([SEL[kind]]) + bytes(payload))


def frame_input(frames, time_step=1):
    """
    Encode frames for fuzz_frame: one time-step byte, then u16 big-endian
    length + frame bytes, repeated.
    """
    out = bytearray([time_step & 0xFF])
    for frame in frames:
        out += struct.pack(">H", len(frame) & 0xFFFF)
        out += bytes(frame)
    return bytes(out)


_CRC32C_NIBBLE = []
for _i in range(16):
    _c = _i
    for _ in range(4):
        _c = (_c >> 1) ^ (0x82F63B78 if (_c & 1) else 0)
    _CRC32C_NIBBLE.append(_c)


def crc32c(data):
    """Reflected CRC-32C, which is what SCTP's checksum field carries."""
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        crc = (crc >> 4) ^ _CRC32C_NIBBLE[crc & 0xF]
        crc = (crc >> 4) ^ _CRC32C_NIBBLE[crc & 0xF]
    return crc ^ 0xFFFFFFFF


def inet_checksum(data):
    """Standard one's-complement Internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


# ── Valid seeds lifted from the existing fixtures ────────────────────────────

def read_classic_pcap_frames(path):
    """Return the raw frames of a classic little-endian pcap file."""
    blob = path.read_bytes()
    if len(blob) < 24:
        return []
    magic = struct.unpack("<I", blob[:4])[0]
    endian = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
    frames = []
    offset = 24
    while offset + 16 <= len(blob):
        _, _, incl, _ = struct.unpack(endian + "IIII", blob[offset:offset + 16])
        offset += 16
        if incl > len(blob) - offset:
            break
        frames.append(blob[offset:offset + incl])
        offset += incl
    return frames


def seed_from_fixtures():
    """Copy the capture fixtures in whole, and reuse their frames."""
    for fixture in ("sample.pcap", "sample.pcapng",
                    "sample-be.pcapng", "sample-spb.pcapng",
                    "sample-analysis.pcap",
                    # Link types other than Ethernet, and the tunnel capture.
                    # These are the only seeds that reach the cooked, raw-IP
                    # and loopback headers, since a capture's link type is
                    # fixed by its global header.
                    "sample-sll.pcap", "sample-sll2.pcap",
                    "sample-raw.pcap", "sample-null.pcap",
                    "sample-encap.pcap",
                    "sample-dns.pcap",
                    "sample-transport.pcap"):
        path = FIXTURES / fixture
        if path.is_file():
            write("pcap", f"valid_{fixture.replace('.', '_')}",
                  path.read_bytes())
        else:
            print(f"  note: fixture {fixture} not found, skipping", file=sys.stderr)

    # The analysis capture is the only fixture carrying SACK options, duplicate
    # ACK runs, and zero-window advertisements, so its frames are what reach the
    # expert-analysis code at all.
    analysis_frames = read_classic_pcap_frames(FIXTURES / "sample-analysis.pcap")
    if analysis_frames:
        write("frame", "valid_analysis_all", frame_input(analysis_frames))
        for index in range(0, len(analysis_frames) - 1, 4):
            write("frame", f"valid_analysis_{index:02d}",
                  frame_input(analysis_frames[index:index + 4]))
        for index, frame in enumerate(analysis_frames):
            if len(frame) >= 14 and struct.unpack(">H", frame[12:14])[0] == 0x0800:
                seed_ipv4_transport(1000 + index, frame[14:])

    # The EDNS0/DNSSEC capture is the only fixture whose DNS messages carry an
    # OPT record or signed records, so its payloads are the only valid seeds
    # that reach that code. Its frames are Ethernet + a 20-byte IPv4 header +
    # UDP, so the DNS message starts at a fixed offset.
    dns_frames = read_classic_pcap_frames(FIXTURES / "sample-dns.pcap")
    if dns_frames:
        write("frame", "valid_dns_all", frame_input(dns_frames))
        for index, frame in enumerate(dns_frames):
            if len(frame) > 14 + 20 + 8:
                write_parser("dns", f"valid_edns_{index:02d}",
                             frame[14 + 20 + 8:])

    # The transport capture is the only fixture carrying SCTP or QUIC, so its
    # payloads are the only valid seeds that reach either parser at all.
    transport_frames = read_classic_pcap_frames(FIXTURES / "sample-transport.pcap")
    if transport_frames:
        write("frame", "valid_transport_all", frame_input(transport_frames))
        for index, frame in enumerate(transport_frames):
            if len(frame) < 14:
                continue
            ethertype = struct.unpack(">H", frame[12:14])[0]
            if ethertype == 0x0800:
                write_parser("ipv4", f"valid_transport_{index:02d}", frame[14:])
                seed_ipv4_transport(2000 + index, frame[14:])
            elif ethertype == 0x86DD:
                # A fixed 40-byte IPv6 header with no extension headers, so
                # the transport payload starts at a known offset.
                write_parser("ipv6", f"valid_transport_{index:02d}", frame[14:])
                if len(frame) > 14 + 40:
                    write_parser("sctp", f"valid_v6_{index:02d}", frame[14 + 40:])

    frames = read_classic_pcap_frames(FIXTURES / "sample.pcap")
    if not frames:
        print("  note: no frames recovered from sample.pcap", file=sys.stderr)
        return

    # The whole capture as one input: this is what reaches reassembly
    # completion, the TCP state machine, and the ARP cache's second sighting.
    write("frame", "valid_all_frames", frame_input(frames))

    # Adjacent pairs keep individual inputs small, which makes libFuzzer's
    # mutations far more targeted than editing one huge blob.
    for index in range(0, len(frames) - 1, 2):
        write("frame", f"valid_pair_{index:02d}",
              frame_input(frames[index:index + 2]))

    # A large time step per frame reaches the idle-expiry paths.
    write("frame", "valid_all_frames_slow", frame_input(frames, time_step=255))

    # Feed each frame to the Ethernet parser directly, and its L3 payload to
    # the matching L3 parser, so every parser gets at least one valid seed.
    for index, frame in enumerate(frames):
        if index < 8:
            write_parser("eth", f"valid_{index:02d}", frame)
        if len(frame) < 14:
            continue
        ethertype = struct.unpack(">H", frame[12:14])[0]
        payload = frame[14:]
        if ethertype == 0x0806:
            write_parser("arp", f"valid_{index:02d}", payload)
        elif ethertype == 0x0800:
            write_parser("ipv4", f"valid_{index:02d}", payload)
            seed_ipv4_transport(index, payload)
        elif ethertype == 0x86DD:
            write_parser("ipv6", f"valid_{index:02d}", payload)


def seed_ipv4_transport(index, packet):
    """Hand an IPv4 packet's transport payload to the right parser."""
    if len(packet) < 20:
        return
    ihl = (packet[0] & 0x0F) * 4
    if ihl < 20 or ihl > len(packet):
        return
    proto = packet[9]
    payload = packet[ihl:]
    if not payload:
        return
    if proto == 1:
        write_parser("icmp", f"valid_{index:02d}", payload)
    elif proto == 2:
        write_parser("igmp", f"valid_{index:02d}", payload)
    elif proto == 47:
        write_parser("gre", f"valid_{index:02d}", payload)
    elif proto == 6:
        write_parser("tcp", f"valid_{index:02d}", payload)
        seed_tcp_payload(index, payload)
    elif proto == 17:
        write_parser("udp", f"valid_{index:02d}", payload)
        seed_udp_payload(index, payload)
    elif proto == 132:
        write_parser("sctp", f"valid_{index:02d}", payload)


def seed_tcp_payload(index, segment):
    if len(segment) < 20:
        return
    data_offset = ((segment[12] >> 4) & 0x0F) * 4
    if data_offset < 20 or data_offset > len(segment):
        return
    body = segment[data_offset:]
    if not body:
        return
    if body[:1] in (b"\x14", b"\x15", b"\x16", b"\x17", b"\x18"):
        write_parser("tls", f"valid_{index:02d}", body)
    else:
        write_parser("http", f"valid_{index:02d}", body)


def seed_udp_payload(index, datagram):
    if len(datagram) < 8:
        return
    src, dst = struct.unpack(">HH", datagram[:4])
    body = datagram[8:]
    if not body:
        return
    ports = {src, dst}
    if ports & {53, 5353}:
        write_parser("dns", f"valid_{index:02d}", body)
    elif ports & {67, 68}:
        write_parser("dhcp", f"valid_{index:02d}", body)
    elif ports & {546, 547}:
        write_parser("dhcpv6", f"valid_{index:02d}", body)
    elif 123 in ports:
        write_parser("ntp", f"valid_{index:02d}", body)
    elif ports & {443, 4433, 8443, 853}:
        write_parser("quic", f"valid_{index:02d}", body)


# ── DNS: name compression is the classic non-termination trap ────────────────

def dns_message(payload, qdcount=1, ancount=0, nscount=0, arcount=0):
    header = struct.pack(">HHHHHH", 0x1234, 0x8180,
                         qdcount, ancount, nscount, arcount)
    return header + bytes(payload)


def dns_rr(name=b"\x00", rtype=1, rclass=1, ttl=60, rdata=b"", rdlength=None):
    """One resource record. rdlength defaults to the truth; pass it explicitly
    to build a record that lies about its own size."""
    if rdlength is None:
        rdlength = len(rdata)
    return name + struct.pack(">HHIH", rtype, rclass, ttl, rdlength) + rdata


def dns_opt(udp_size=1232, rcode_high=0, version=0, flags=0,
            options=b"", rdlength=None):
    """An OPT pseudo-record: root owner, class reused as the UDP payload size,
    TTL reused as (extended RCODE, version, flags)."""
    ttl = (rcode_high << 24) | (version << 16) | flags
    return dns_rr(b"\x00", 41, udp_size, ttl, options, rdlength)


def edns_option(code, payload, length=None):
    if length is None:
        length = len(payload)
    return struct.pack(">HH", code, length) + payload


def seed_dns():
    # A pointer to its own offset. A resolver that follows pointers without
    # bounding the hops never returns.
    write_parser("dns", "ptr_self_loop", dns_message(b"\xc0\x0c\x00\x01\x00\x01"))

    # Two pointers pointing at each other.
    write_parser("dns", "ptr_two_cycle",
                 dns_message(b"\xc0\x10\x00\x01\x00\x01\xc0\x0c"))

    # A pointer past the end of the message.
    write_parser("dns", "ptr_out_of_range",
                 dns_message(b"\xc0\xff\x00\x01\x00\x01"))

    # A chain of pointers, each one hop forward: bounded, but only if the hop
    # count is capped rather than the offsets merely being validated.
    body = bytearray()
    for step in range(64):
        body += struct.pack(">H", 0xC000 | (12 + 2 * (step + 1)))
    body += b"\x00\x00\x01\x00\x01"
    write_parser("dns", "ptr_long_chain", dns_message(body))

    # Label length 63 with nothing behind it.
    write_parser("dns", "label_truncated", dns_message(b"\x3f" + b"a" * 4))

    # Label length bits 0b10 and 0b01 are reserved, not pointers.
    write_parser("dns", "label_reserved_bits", dns_message(b"\x80\x00\x01\x00\x01"))

    # Counts that promise far more records than the message holds.
    write_parser("dns", "counts_overpromise",
                 struct.pack(">HHHHHH", 1, 0x8180, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF))

    # An answer whose rdlength runs past the end.
    answer = (b"\x00" + struct.pack(">HHIH", 1, 1, 60, 0xFFFF) + b"\x01\x02")
    write_parser("dns", "rdlength_overrun", dns_message(answer, qdcount=0, ancount=1))

    # A name built entirely of maximum-length labels, to see how much a single
    # small message can be made to expand.
    bomb = bytearray()
    for _ in range(4):
        bomb += bytes([63]) + b"x" * 63
    bomb += b"\x00\x00\x01\x00\x01"
    write_parser("dns", "long_name", dns_message(bomb))


# ── EDNS0: the OPT record's options are another self-describing TLV walk ─────

def seed_dns_edns():
    # An option that claims far more bytes than the RDATA holds.
    write_parser("dns", "opt_option_overrun",
                 dns_message(dns_opt(options=edns_option(10, b"\xaa", 0xFFFF)),
                             qdcount=0, arcount=1))

    # RDLENGTH stops mid-option-header: four bytes are needed to start one.
    write_parser("dns", "opt_trailing_bytes",
                 dns_message(dns_opt(options=b"\x00\x0a\x00"),
                             qdcount=0, arcount=1))

    # Client Subnet with a source prefix of 255 bits — 32 octets of address,
    # inside an option carrying one. Both numbers are the sender's.
    write_parser("dns", "opt_ecs_prefix_overrun",
                 dns_message(dns_opt(options=edns_option(
                     8, struct.pack(">HBB", 1, 255, 0) + b"\xc0")),
                     qdcount=0, arcount=1))

    # The same, for a family nothing knows, so the width check has nothing to
    # compare against.
    write_parser("dns", "opt_ecs_family_unknown",
                 dns_message(dns_opt(options=edns_option(
                     8, struct.pack(">HBB", 0xFFFF, 200, 200) + b"\x01\x02")),
                     qdcount=0, arcount=1))

    # Scope prefix longer than the source prefix, which RFC 7871 forbids in a
    # query but nothing stops a sender writing.
    write_parser("dns", "opt_ecs_scope_over_source",
                 dns_message(dns_opt(options=edns_option(
                     8, struct.pack(">HBB", 1, 8, 128) + b"\xc0")),
                     qdcount=0, arcount=1))

    # Sixty-four zero-length options: the walk must make progress on each one
    # from the header alone.
    write_parser("dns", "opt_many_empty_options",
                 dns_message(dns_opt(options=edns_option(0, b"") * 64),
                             qdcount=0, arcount=1))

    # Two OPT records, which RFC 6891 §6.1.1 forbids.
    write_parser("dns", "opt_duplicate",
                 dns_message(dns_opt() + dns_opt(udp_size=512),
                             qdcount=0, arcount=2))

    # An OPT in the answer section, where it does not belong.
    write_parser("dns", "opt_misplaced",
                 dns_message(dns_opt(), qdcount=0, ancount=1))

    # An owner name that is not the root, and a version nothing defines.
    write_parser("dns", "opt_bad_owner_and_version",
                 dns_message(dns_rr(b"\x03abc\x00", 41, 1232,
                                    (1 << 16), b""),
                             qdcount=0, arcount=1))

    # A cookie of a length RFC 7873 does not allow, and an extended error whose
    # text runs to the end of the record.
    write_parser("dns", "opt_cookie_and_error",
                 dns_message(dns_opt(options=(
                     edns_option(10, b"\xaa" * 3)
                     + edns_option(15, struct.pack(">H", 6) + b"\xff" * 40))),
                     qdcount=0, arcount=1))

    # RDLENGTH lies upward: the options walk must stay inside the message even
    # when the record claims more than arrived.
    write_parser("dns", "opt_rdlength_overrun",
                 dns_message(dns_opt(options=edns_option(3, b"\xaa"),
                                     rdlength=0xFFFF),
                             qdcount=0, arcount=1))


# ── DNSSEC: every record here walks a length the sender chose ────────────────

def seed_dns_dnssec():
    # NSEC type bit map: a window claiming 33 octets, over the 32 RFC 4034
    # §4.1.2 allows, and one claiming zero, which would never advance.
    write_parser("dns", "nsec_bitmap_len_over_32",
                 dns_message(dns_rr(rtype=47,
                                    rdata=b"\x00" + b"\x00\x21" + b"\x40"),
                             qdcount=0, ancount=1))
    write_parser("dns", "nsec_bitmap_len_zero",
                 dns_message(dns_rr(rtype=47,
                                    rdata=b"\x00" + b"\x00\x00" + b"\x40"),
                             qdcount=0, ancount=1))

    # A bitmap block whose length runs past the RDATA.
    write_parser("dns", "nsec_bitmap_past_rdata",
                 dns_message(dns_rr(rtype=47, rdata=b"\x00\x00\x20\x40"),
                             qdcount=0, ancount=1))

    # The next-domain name is not allowed to be compressed, so a pointer here
    # escapes the record's own RDATA.
    write_parser("dns", "nsec_next_name_compressed",
                 dns_message(dns_rr(rtype=47, rdata=b"\xc0\x0c\x00\x01\x40"),
                             qdcount=0, ancount=1))

    # NSEC3 salt and hash lengths, each declared far beyond what arrived.
    write_parser("dns", "nsec3_salt_overrun",
                 dns_message(dns_rr(rtype=50,
                                    rdata=b"\x01\x00\x00\x0a\xff\xaa"),
                             qdcount=0, ancount=1))
    write_parser("dns", "nsec3_hash_overrun",
                 dns_message(dns_rr(rtype=50,
                                    rdata=b"\x01\x00\x00\x0a\x00\xff\xaa"),
                             qdcount=0, ancount=1))
    write_parser("dns", "nsec3param_salt_overrun",
                 dns_message(dns_rr(rtype=51, rdata=b"\x01\x00\x00\x0a\xff"),
                             qdcount=0, ancount=1))

    # RRSIG: one byte short of the fixed fields, and a signer's name that runs
    # past RDLENGTH.
    write_parser("dns", "rrsig_short_fixed_part",
                 dns_message(dns_rr(rtype=46, rdata=b"\x00" * 17),
                             qdcount=0, ancount=1))
    write_parser("dns", "rrsig_signer_past_rdlength",
                 dns_message(dns_rr(rtype=46,
                                    rdata=b"\x00" * 18 + b"\x03com\x00",
                                    rdlength=18),
                             qdcount=0, ancount=1))
    # A signer's name given as a compression pointer, which RFC 4034 §3.1.7
    # forbids and which would otherwise be counted against the wrong length.
    write_parser("dns", "rrsig_signer_compressed",
                 dns_message(dns_rr(rtype=46, rdata=b"\x00" * 18 + b"\xc0\x0c"),
                             qdcount=0, ancount=1))

    # DNSKEY and DS truncated to less than their fixed fields.
    write_parser("dns", "dnskey_short",
                 dns_message(dns_rr(rtype=48, rdata=b"\x01\x00\x03"),
                             qdcount=0, ancount=1))
    write_parser("dns", "dnskey_no_key_material",
                 dns_message(dns_rr(rtype=48, rdata=b"\x01\x00\x03\x08"),
                             qdcount=0, ancount=1))
    write_parser("dns", "ds_short",
                 dns_message(dns_rr(rtype=43, rdata=b"\x00\x01\x08"),
                             qdcount=0, ancount=1))

    # A DNSKEY whose RDLENGTH claims 65535 bytes: the key tag is summed over
    # RDATA, so the length that drives that loop must be the checked one.
    write_parser("dns", "dnskey_rdlength_overrun",
                 dns_message(dns_rr(rtype=48, rdata=b"\x01\x00\x03\x08\xab",
                                    rdlength=0xFFFF),
                             qdcount=0, ancount=1))

    # A well-formed DNSSEC response, as a seed a mutator can work from: NSEC
    # with a full bitmap, an RRSIG, and a DNSKEY.
    nsec = dns_rr(b"\x03www\x00", 47, 1, 3600,
                  b"\x04next\x00" + b"\x00\x06\x60\x00\x00\x00\x00\x03")
    rrsig = dns_rr(b"\x03www\x00", 46, 1, 3600,
                   struct.pack(">HBBIIIH", 1, 8, 2, 3600,
                               0xF4865700, 0x00000000, 40663)
                   + b"\x00" + b"\xde\xad\xbe\xef")
    dnskey = dns_rr(b"\x00", 48, 1, 3600,
                    struct.pack(">HBB", 0x0101, 3, 8) + b"\xab\xcd\xef\x01")
    write_parser("dns", "dnssec_response",
                 dns_message(nsec + rrsig + dnskey
                             + dns_opt(flags=0x8000,
                                       options=edns_option(
                                           8, struct.pack(">HBB", 1, 24, 0)
                                           + b"\xc0\x00\x02")),
                             qdcount=0, ancount=3, arcount=1))


# ── TCP and IPv4 options: zero-length entries must still make progress ───────

def tcp_segment(options=b"", payload=b"", flags=0x18):
    data_offset_words = 5 + (len(options) + 3) // 4
    padded = options + b"\x00" * (data_offset_words * 4 - 20 - len(options))
    header = struct.pack(">HHIIBBHHH",
                         12345, 80, 0x1000, 0x2000,
                         (data_offset_words << 4), flags, 8192, 0, 0)
    return header + padded + payload


def seed_tcp_options():
    # Kind 2 (MSS) with length 0: advancing by the stated length never moves.
    write_parser("tcp", "opt_len_zero", tcp_segment(b"\x02\x00\x05\xb4"))

    # Length 1 on a multi-byte option: shorter than the kind+len pair itself.
    write_parser("tcp", "opt_len_one", tcp_segment(b"\x02\x01\x05\xb4"))

    # An option whose length reaches past the end of the header.
    write_parser("tcp", "opt_len_overrun", tcp_segment(b"\x02\xff\x05\xb4"))

    # Data offset claims 60 bytes of header but the segment is 20 bytes long.
    header = bytearray(tcp_segment())
    header[12] = 0x0F << 4
    write_parser("tcp", "data_offset_overrun", bytes(header[:20]))

    # Data offset below the 20-byte minimum.
    header = bytearray(tcp_segment())
    header[12] = 0x02 << 4
    write_parser("tcp", "data_offset_too_small", bytes(header[:20]))

    # 40 bytes of options: the maximum, all SACK blocks.
    sack = b"\x05\x22" + bytes(range(32)) + b"\x01" * 6
    write_parser("tcp", "opt_sack_full", tcp_segment(sack))

    # A single option spending the whole 40-byte option space, so its data
    # section is the largest that can occur: 38 bytes. Anything that stores
    # option data has to hold this without truncating, and anything that loops
    # to the stored length has to stay inside that storage.
    write_parser("tcp", "opt_max_data",
                 tcp_segment(b"\x05\x28" + bytes(range(1, 39))))

    # The same option declaring more data than the header can hold.
    write_parser("tcp", "opt_len_beyond_header",
                 tcp_segment(b"\x05\xff" + bytes(range(1, 39))))

    # A wall of NOPs, then an option that starts in the last byte.
    write_parser("tcp", "opt_trailing_kind", tcp_segment(b"\x01" * 39 + b"\x02"))

    # Every flag bit set at once, including the reserved ones.
    write_parser("tcp", "flags_all_set", tcp_segment(flags=0xFF))


def ipv4_packet(options=b"", proto=6, payload=b"", total_len=None,
                flags_frag=0, fix_checksum=True):
    ihl_words = 5 + (len(options) + 3) // 4
    padded = options + b"\x00" * (ihl_words * 4 - 20 - len(options))
    length = total_len if total_len is not None else ihl_words * 4 + len(payload)
    header = bytearray(struct.pack(">BBHHHBBH4s4s",
                                   0x40 | ihl_words, 0, length,
                                   0x1234, flags_frag, 64, proto, 0,
                                   bytes([192, 168, 1, 10]),
                                   bytes([192, 168, 1, 20])))
    header += padded
    if fix_checksum:
        checksum = inet_checksum(bytes(header))
        header[10:12] = struct.pack(">H", checksum)
    return bytes(header) + payload


def seed_ipv4_options():
    # Option 130 with length 0.
    write_parser("ipv4", "opt_len_zero", ipv4_packet(b"\x82\x00\x00\x00"))

    # Option length 1, shorter than the type+length pair.
    write_parser("ipv4", "opt_len_one", ipv4_packet(b"\x82\x01\x00\x00"))

    # Option length running past the end of the header.
    write_parser("ipv4", "opt_len_overrun", ipv4_packet(b"\x82\xff\x00\x00"))

    # IHL below the 20-byte minimum.
    packet = bytearray(ipv4_packet())
    packet[0] = 0x40 | 3
    write_parser("ipv4", "ihl_too_small", bytes(packet))

    # IHL claiming 60 bytes with only 20 present.
    packet = bytearray(ipv4_packet())
    packet[0] = 0x40 | 15
    write_parser("ipv4", "ihl_overrun", bytes(packet[:20]))

    # total_len shorter than the header, and longer than the buffer.
    write_parser("ipv4", "total_len_below_header",
                 ipv4_packet(total_len=8))
    write_parser("ipv4", "total_len_above_buffer",
                 ipv4_packet(total_len=0xFFFF))

    # Version 6 in an IPv4 parse, and version 0.
    packet = bytearray(ipv4_packet())
    packet[0] = 0x60 | 5
    write_parser("ipv4", "wrong_version", bytes(packet))

    # Full 40 bytes of Record Route.
    write_parser("ipv4", "opt_record_route",
                 ipv4_packet(b"\x07\x27\x04" + b"\x00" * 37))


# ── IPv4 fragmentation: overlap and offset arithmetic ────────────────────────

def seed_ipv4_fragments():
    payload = bytes(range(64))
    mf, df = 0x2000, 0x4000

    # Tiny leading fragment, then one that overlaps it with different bytes.
    # An implementation that lets a later fragment rewrite already-received
    # bytes can be steered into reassembling something neither sender wrote.
    first = ipv4_packet(proto=17, payload=payload[:8], flags_frag=mf | 0)
    overlap = ipv4_packet(proto=17, payload=b"\xff" * 16, flags_frag=0 | 1)
    write("frame", "frag_overlap",
          frame_input([eth(first), eth(overlap)]))

    # Offset at the top of the 13-bit field with a full-size payload: the
    # reassembled datagram would exceed 65535 bytes.
    teardrop = ipv4_packet(proto=17, payload=b"A" * 64, flags_frag=0x1FFF)
    write("frame", "frag_offset_max", frame_input([eth(teardrop)]))

    # More-fragments set on a zero-length payload.
    write("frame", "frag_empty_mf",
          frame_input([eth(ipv4_packet(proto=17, flags_frag=mf))]))

    # Same fragment sent twice.
    write("frame", "frag_duplicate", frame_input([eth(first), eth(first)]))

    # A final fragment with no preceding first fragment.
    write("frame", "frag_last_only",
          frame_input([eth(ipv4_packet(proto=17, payload=payload,
                                       flags_frag=0x0010))]))

    # Don't-fragment together with more-fragments.
    write("frame", "frag_df_and_mf",
          frame_input([eth(ipv4_packet(proto=17, payload=payload[:8],
                                       flags_frag=df | mf))]))


# ── IPv6 extension headers: a linked list the sender controls ───────────────

def ipv6_packet(next_header, payload, payload_len=None):
    length = payload_len if payload_len is not None else len(payload)
    header = struct.pack(">IHBB", 0x60000000, length, next_header, 64)
    return (header
            + bytes.fromhex("20010db8000000000000000000000010")
            + bytes.fromhex("20010db8000000000000000000000020")
            + bytes(payload))


def seed_ipv6_extensions():
    # Hop-by-hop whose inner TLV claims length 0 for a non-pad option.
    hbh = bytes([59, 0, 0x05, 0x00, 0, 0, 0, 0])
    write_parser("ipv6", "hbh_tlv_len_zero", ipv6_packet(0, hbh))

    # Hop-by-hop whose inner TLV runs past the extension header.
    hbh = bytes([59, 0, 0x05, 0xFF, 0, 0, 0, 0])
    write_parser("ipv6", "hbh_tlv_overrun", ipv6_packet(0, hbh))

    # A chain of 64 destination-options headers: bounded work only if the
    # walker caps the number of headers it will follow.
    chain = bytearray()
    for _ in range(64):
        chain += bytes([60, 0, 1, 4, 0, 0, 0, 0])
    chain += bytes([59, 0, 1, 4, 0, 0, 0, 0])
    write_parser("ipv6", "ext_chain_long", ipv6_packet(60, chain))

    # An extension header that says it is longer than the packet.
    write_parser("ipv6", "ext_len_overrun",
                 ipv6_packet(60, bytes([59, 0xFF, 0, 0, 0, 0, 0, 0])))

    # Routing header with segments-left far beyond the address list.
    routing = bytes([59, 2, 4, 0xFF, 0, 0, 0, 0]) + b"\x00" * 16
    write_parser("ipv6", "routing_segments_left", ipv6_packet(43, routing))

    # Routing header whose declared length runs far past the packet. This is
    # the case the seeds above miss: they are all internally consistent, so
    # they never make the declared length and the real length disagree. One
    # byte of hdr_ext_len decides how many 16-byte addresses get copied out,
    # so it has to be checked against the packet before any of them is read.
    write_parser("ipv6", "routing_len_overrun",
                 ipv6_packet(43, bytes([59, 0x3A, 4, 1, 0, 0, 0, 0])
                             + b"\x00" * 16))

    # The same disagreement for the other extension-header shapes.
    write_parser("ipv6", "hbh_len_overrun_declared",
                 ipv6_packet(0, bytes([59, 0x3A, 1, 4, 0, 0, 0, 0])
                             + b"\x00" * 16))
    write_parser("ipv6", "ah_len_overrun_declared",
                 ipv6_packet(51, bytes([59, 0xFF, 0, 0, 0, 0, 0, 0])
                             + b"\x00" * 16))

    # Routing header claiming an odd extension length for a Type 4 header.
    write_parser("ipv6", "routing_odd_len",
                 ipv6_packet(43, bytes([59, 1, 4, 1, 0, 0, 0, 0])))

    # payload_length larger than the bytes present, and zero with a payload.
    write_parser("ipv6", "payload_len_overrun",
                 ipv6_packet(58, b"\x80\x00\x00\x00", payload_len=0xFFFF))
    write_parser("ipv6", "payload_len_zero",
                 ipv6_packet(58, b"\x80\x00\x00\x00" * 4, payload_len=0))

    # Two fragment headers in one packet.
    double = (bytes([44, 0, 0, 0x01, 0, 0, 0, 1])
              + bytes([59, 0, 0, 0x01, 0, 0, 0, 1]))
    write_parser("ipv6", "fragment_twice", ipv6_packet(44, double))

    # Fragment header with more-fragments set and no payload behind it.
    write_parser("ipv6", "fragment_empty_mf",
                 ipv6_packet(44, bytes([58, 0, 0, 0x01, 0, 0, 0, 1])))


# ── ICMPv6 NDP options are counted in 8-byte units; zero is fatal ───────────

def seed_icmpv6():
    target = bytes.fromhex("20010db8000000000000000000000030")

    # Neighbour Advertisement with an option length of 0.
    na = bytes([136, 0, 0, 0]) + b"\x60\x00\x00\x00" + target
    write_parser("icmpv6", "ndp_opt_len_zero", na + bytes([1, 0, 0, 0, 0, 0, 0, 0]))

    # Option length that reaches past the packet.
    write_parser("icmpv6", "ndp_opt_overrun",
                 na + bytes([1, 0xFF, 0, 0, 0, 0, 0, 0]))

    # Router Advertisement with a prefix option truncated mid-prefix.
    ra = bytes([134, 0, 0, 0, 64, 0x08, 0x07, 0x08]) + b"\x00" * 8
    write_parser("icmpv6", "ra_prefix_truncated", ra + bytes([3, 4, 64, 0xC0, 0, 0]))

    # A long run of valid minimum-size options.
    write_parser("icmpv6", "ndp_many_options",
                 na + bytes([1, 1, 0, 0, 0, 0, 0, 0]) * 128)

    # Echo request with the code and checksum fields at extremes.
    write_parser("icmpv6", "echo_max_fields",
                 bytes([128, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]))


# ── SCTP: two nested TLV walks, and a checksum over the whole packet ─────────

def sctp_packet(chunks, src=9899, dst=9900, vtag=0x11223344, checksum=0):
    return (struct.pack(">HHII", src, dst, vtag, checksum)
            + b"".join(bytes(c) for c in chunks))


def sctp_chunk(ctype, value=b"", flags=0, length=None):
    """One chunk. Pass `length` explicitly to build one that lies about its
    own size — which is the field the whole walk is steered by."""
    declared = length if length is not None else 4 + len(value)
    body = struct.pack(">BBH", ctype, flags, declared) + bytes(value)
    return body + b"\x00" * (-len(body) % 4)


def sctp_param(ptype, value=b"", length=None):
    declared = length if length is not None else 4 + len(value)
    body = struct.pack(">HH", ptype, declared) + bytes(value)
    return body + b"\x00" * (-len(body) % 4)


def seed_sctp():
    init_fixed = struct.pack(">IIHHI", 0xAABBCCDD, 106496, 10, 5, 10000)

    # A chunk length below the four-byte header: advancing by it never moves.
    for declared in (0, 1, 2, 3):
        write_parser("sctp", f"chunk_len_{declared}",
                     sctp_packet([sctp_chunk(11, length=declared),
                                  sctp_chunk(11)]))

    # A chunk claiming far more than the packet holds.
    write_parser("sctp", "chunk_len_overrun",
                 sctp_packet([sctp_chunk(7, b"\x00\x00\x00\x2a", length=0xFFFF)]))

    # Sixty-four minimum-size chunks: bounded work only if each step advances.
    write_parser("sctp", "many_empty_chunks",
                 sctp_packet([sctp_chunk(11)] * 64))

    # A chunk header in the last bytes of the packet, and one cut in half.
    write_parser("sctp", "chunk_header_only",
                 sctp_packet([]) + b"\x00\x00\x00\x10")
    write_parser("sctp", "trailing_partial_chunk",
                 sctp_packet([sctp_chunk(11)]) + b"\x00\x00")

    # The common header alone, and one byte short of it.
    write_parser("sctp", "common_header_only", sctp_packet([]))
    write_parser("sctp", "truncated_common_header", sctp_packet([])[:11])

    # INIT parameters: the walk inside the walk, with the same hazards.
    write_parser("sctp", "init_param_len_zero",
                 sctp_packet([sctp_chunk(1, init_fixed
                                         + sctp_param(5, length=0))]))
    write_parser("sctp", "init_param_len_overrun",
                 sctp_packet([sctp_chunk(1, init_fixed
                                         + sctp_param(7, b"\x01\x02",
                                                      length=0xFFFF))]))
    write_parser("sctp", "init_many_empty_params",
                 sctp_packet([sctp_chunk(1, init_fixed
                                         + sctp_param(0xC000) * 64)]))
    write_parser("sctp", "init_short_fixed_part",
                 sctp_packet([sctp_chunk(1, init_fixed[:15])]))
    # A parameter whose declared length is inside the chunk but whose padding
    # would take the walk past it.
    write_parser("sctp", "init_param_ends_on_the_boundary",
                 sctp_packet([sctp_chunk(1, init_fixed
                                         + struct.pack(">HH", 5, 5) + b"\x01")]))

    # SACK: two counts, four bytes each, multiplied by the sender.
    write_parser("sctp", "sack_counts_absurd",
                 sctp_packet([sctp_chunk(3, struct.pack(">IIHH", 1000, 65536,
                                                        0xFFFF, 0xFFFF))]))
    write_parser("sctp", "sack_short",
                 sctp_packet([sctp_chunk(3, b"\x00" * 11)]))
    write_parser("sctp", "sack_gaps_past_the_chunk",
                 sctp_packet([sctp_chunk(3, struct.pack(">IIHH", 1000, 65536,
                                                        4, 4)
                                         + b"\x00\x01\x00\x02")]))

    # DATA one byte short of its fixed fields, and with none at all.
    write_parser("sctp", "data_short_fixed_part",
                 sctp_packet([sctp_chunk(0, b"\x00" * 11, flags=0x03)]))
    write_parser("sctp", "data_empty", sctp_packet([sctp_chunk(0, flags=0x03)]))

    # ABORT and ERROR causes.
    write_parser("sctp", "abort_cause_len_zero",
                 sctp_packet([sctp_chunk(6, sctp_param(12, length=0))]))
    write_parser("sctp", "error_cause_overrun",
                 sctp_packet([sctp_chunk(9, sctp_param(1, b"\xaa",
                                                       length=0xFFFF))]))

    # One chunk type from each of the four unknown-type quadrants, since the
    # top two bits are what tells a receiver whether to stop or skip.
    for ctype in (0x3F, 0x7F, 0xBF, 0xFF):
        write_parser("sctp", f"unknown_type_{ctype:02x}",
                     sctp_packet([sctp_chunk(ctype, b"\x01\x02\x03\x04"),
                                  sctp_chunk(11)]))

    # A packet with a correct CRC-32C, as a seed a mutator can work outward
    # from: the checksum path is otherwise only ever reached in the failing
    # direction, since random bytes never sum correctly.
    body = sctp_packet([sctp_chunk(0, struct.pack(">IHHI", 1000, 1, 0, 51)
                                   + b"hello", flags=0x03)])
    write_parser("sctp", "valid_checksum",
                 body[:8] + struct.pack("<I", crc32c(body)) + body[12:])


# ── QUIC: a self-describing integer width, and a sender-chosen packet length ─

def quic_varint(value):
    if value < (1 << 6):
        return bytes([value])
    if value < (1 << 14):
        return struct.pack(">H", 0x4000 | value)
    if value < (1 << 30):
        return struct.pack(">I", 0x80000000 | value)
    return struct.pack(">Q", 0xC000000000000000 | value)


def quic_long(first, version, dcid=b"", scid=b"", rest=b"",
              dcid_len=None, scid_len=None):
    return (bytes([first]) + struct.pack(">I", version)
            + bytes([dcid_len if dcid_len is not None else len(dcid)]) + dcid
            + bytes([scid_len if scid_len is not None else len(scid)]) + scid
            + bytes(rest))


def seed_quic():
    dcid = bytes.fromhex("0102030405060708")
    scid = bytes.fromhex("aabbccdd")

    # A well-formed Initial, and one with a token, as mutation seeds.
    write_parser("quic", "initial_v1",
                 quic_long(0xC0, 1, dcid, scid,
                           quic_varint(0) + quic_varint(32) + bytes(32)))
    write_parser("quic", "initial_with_token",
                 quic_long(0xC0, 1, dcid, scid,
                           quic_varint(16) + bytes(16)
                           + quic_varint(32) + bytes(32)))

    # Connection ID lengths: past the version 1 limit, and past the datagram.
    write_parser("quic", "dcid_len_255",
                 quic_long(0xC0, 1, b"\x01\x02\x03", scid, dcid_len=255))
    write_parser("quic", "scid_len_255",
                 quic_long(0xC0, 1, dcid, b"\x01", scid_len=255))
    write_parser("quic", "cid_len_over_20",
                 quic_long(0xC0, 1, bytes(25), bytes(25),
                           quic_varint(0) + quic_varint(0)))

    # Variable-length integers announcing more bytes than arrived.
    write_parser("quic", "token_varint_truncated",
                 quic_long(0xC0, 1, b"", b"", b"\xc0\x00"))
    write_parser("quic", "token_len_huge",
                 quic_long(0xC0, 1, b"", b"",
                           quic_varint(1 << 40) + b"\x01\x02"))
    write_parser("quic", "length_huge",
                 quic_long(0xC0, 1, b"", b"",
                           quic_varint(0) + quic_varint(1 << 40) + b"\x01"))
    write_parser("quic", "length_varint_truncated",
                 quic_long(0xC0, 1, b"", b"", quic_varint(0) + b"\x80\x00"))

    # A Length of zero, repeated: legal on the wire, and a step of zero for
    # anything that walks payloads rather than whole packets.
    empty = quic_long(0xE0, 1, b"", b"", quic_varint(0))
    write_parser("quic", "coalesced_empty_many", empty * 64)
    write_parser("quic", "coalesced_initial_handshake",
                 quic_long(0xC0, 1, dcid, scid,
                           quic_varint(0) + quic_varint(4) + bytes(4))
                 + quic_long(0xE0, 1, dcid, scid,
                             quic_varint(4) + bytes(4)))

    # Version Negotiation: a list of 32-bit versions that need not be whole.
    write_parser("quic", "version_negotiation",
                 quic_long(0xC0, 0, dcid, scid,
                           struct.pack(">III", 1, 0x6B3343CF, 0x1A2A3A4A)))
    write_parser("quic", "version_negotiation_ragged",
                 quic_long(0xC0, 0, dcid, scid, b"\x00\x00\x00\x01\xff"))
    write_parser("quic", "version_negotiation_long",
                 quic_long(0xC0, 0, b"", b"", struct.pack(">I", 1) * 64))

    # Retry, whose trailing 16 bytes are an integrity tag.
    write_parser("quic", "retry",
                 quic_long(0xF0, 1, dcid, scid, bytes(8) + bytes(16)))
    write_parser("quic", "retry_shorter_than_its_tag",
                 quic_long(0xF0, 1, dcid, scid, b"\x01\x02"))

    # Version 2, whose type numbering differs, and a reserved version, where
    # RFC 8999 says nothing past the connection IDs may be read at all.
    write_parser("quic", "initial_v2",
                 quic_long(0xD0, 0x6B3343CF, dcid, b"",
                           quic_varint(0) + quic_varint(8) + bytes(8)))
    write_parser("quic", "reserved_version",
                 quic_long(0xC0, 0x1A2A3A4A, dcid, scid,
                           quic_varint(0) + quic_varint(8) + bytes(8)))

    # Short header, and headers cut off at each field boundary.
    write_parser("quic", "short_header", bytes([0x41]) + dcid + bytes(16))
    for cut in (1, 2, 5, 6, 7, 14, 15):
        write_parser("quic", f"truncated_at_{cut:02d}",
                     quic_long(0xC0, 1, dcid, scid,
                               quic_varint(0) + quic_varint(4))[:cut])


# ── Application-layer parsers ───────────────────────────────────────────────

def seed_http():
    write_parser("http", "no_crlf", b"GET /index.html HTTP/1.1")
    write_parser("http", "method_only", b"GET ")
    write_parser("http", "header_no_colon",
                 b"GET / HTTP/1.1\r\nBrokenHeaderLine\r\n\r\n")
    write_parser("http", "header_empty_name",
                 b"GET / HTTP/1.1\r\n: value\r\n\r\n")

    # More headers than the parser stores, and a value longer than its field.
    many = b"".join(b"X-Pad-%d: v\r\n" % i for i in range(200))
    write_parser("http", "too_many_headers", b"GET / HTTP/1.1\r\n" + many + b"\r\n")
    write_parser("http", "value_too_long",
                 b"GET / HTTP/1.1\r\nX-Long: " + b"v" * 4096 + b"\r\n\r\n")
    write_parser("http", "uri_too_long",
                 b"GET /" + b"a" * 4096 + b" HTTP/1.1\r\n\r\n")

    # Bare LF line endings, and a header split across a continuation line.
    write_parser("http", "bare_lf", b"GET / HTTP/1.1\nHost: x\n\n")
    write_parser("http", "obs_fold",
                 b"GET / HTTP/1.1\r\nHost: x\r\n \tcontinued\r\n\r\n")

    # Status line variants.
    write_parser("http", "status_not_numeric", b"HTTP/1.1 abc Bad\r\n\r\n")
    write_parser("http", "status_truncated", b"HTTP/1.1 2")
    write_parser("http", "version_junk", b"HTTP/9.9 999 Weird\r\n\r\n")

    # Content-Length that disagrees with the body actually present.
    write_parser("http", "content_length_lies",
                 b"POST / HTTP/1.1\r\nContent-Length: 99999\r\n\r\nshort")

    # NUL bytes inside the header block.
    write_parser("http", "embedded_nul",
                 b"GET / HTTP/1.1\r\nHost: a\x00b\r\n\r\n")


def tls_record(content_type, body, version=0x0303, length=None):
    declared = length if length is not None else len(body)
    return struct.pack(">BHH", content_type, version, declared) + bytes(body)


def seed_tls():
    # A record header claiming a body that is not there.
    write_parser("tls", "record_len_overrun", tls_record(22, b"\x01", length=0xFFFF))

    # Zero-length record: a reader that trusts the length to advance stalls.
    write_parser("tls", "record_len_zero", tls_record(23, b"", length=0))

    # A run of zero-length records.
    write_parser("tls", "record_len_zero_many", tls_record(23, b"", length=0) * 64)

    # Handshake sub-header claiming more than the record holds.
    handshake = bytes([1]) + b"\xff\xff\xff"
    write_parser("tls", "handshake_len_overrun", tls_record(22, handshake))

    # ClientHello with an extensions block that overruns, and an SNI length
    # that overruns inside an otherwise valid extensions block.
    hello = bytearray()
    hello += bytes([1])                      # ClientHello
    hello += b"\x00\x00\x2c"                 # handshake length
    hello += b"\x03\x03"                     # client version
    hello += b"\x00" * 32                    # random
    hello += b"\x00"                         # session id length
    hello += b"\x00\x02\x00\x2f"             # cipher suites
    hello += b"\x01\x00"                     # compression
    hello += b"\xff\xff"                     # extensions length: overruns
    write_parser("tls", "hello_ext_len_overrun", tls_record(22, hello))

    sni_body = b"\x00\x00" + b"\xff\xff" + b"\x00\x00" + b"\x00" + b"\xff\xff"
    hello2 = bytearray(hello)
    hello2[-2:] = struct.pack(">H", len(sni_body))
    hello2 += sni_body
    write_parser("tls", "hello_sni_len_overrun", tls_record(22, bytes(hello2)))

    # Certificate message with an absurd chain length.
    cert = bytes([11]) + b"\x00\x00\x06" + b"\xff\xff\xff" + b"\xff\xff\xff"
    write_parser("tls", "cert_chain_len_overrun", tls_record(22, cert))

    # Alert with a truncated body, and an unknown content type.
    write_parser("tls", "alert_truncated", tls_record(21, b"\x02"))
    write_parser("tls", "unknown_content_type", tls_record(99, b"\x00\x01\x02"))

    # A header cut off mid-field.
    write_parser("tls", "header_truncated", b"\x16\x03")


def seed_dhcp():
    base = bytearray(240)
    base[0] = 2                                   # BOOTREPLY
    base[1] = 1                                   # Ethernet
    base[2] = 6                                   # hardware address length
    base[236:240] = b"\x63\x82\x53\x63"           # magic cookie

    # Option length 0 for a type that needs data.
    write_parser("dhcp", "opt_len_zero", bytes(base) + bytes([53, 0]))

    # Option length past the end of the buffer.
    write_parser("dhcp", "opt_len_overrun", bytes(base) + bytes([53, 0xFF, 1]))

    # No END option at all.
    write_parser("dhcp", "no_end_option", bytes(base) + bytes([53, 1, 5]) * 32)

    # Wrong magic cookie.
    bad = bytearray(base)
    bad[236:240] = b"\x00\x00\x00\x00"
    write_parser("dhcp", "bad_magic_cookie", bytes(bad))

    # Truncated right after the cookie, and truncated mid-header.
    write_parser("dhcp", "truncated_at_cookie", bytes(base[:240]))
    write_parser("dhcp", "truncated_header", bytes(base[:20]))

    # hardware address length larger than the field that holds it.
    huge = bytearray(base)
    huge[2] = 0xFF
    write_parser("dhcp", "hlen_too_large", bytes(huge))


def seed_dhcpv6():
    # SOLICIT with an option whose length overruns.
    write_parser("dhcpv6", "opt_len_overrun",
                 bytes([1, 0x11, 0x22, 0x33]) + struct.pack(">HH", 1, 0xFFFF))

    # An option of length 0, repeated.
    write_parser("dhcpv6", "opt_len_zero_many",
                 bytes([1, 0, 0, 1]) + struct.pack(">HH", 1, 0) * 64)

    # Nested IA_NA containing an option that overruns the enclosing one.
    inner = struct.pack(">HH", 5, 0xFFFF)
    write_parser("dhcpv6", "nested_opt_overrun",
                 bytes([1, 0, 0, 1]) + struct.pack(">HH", 3, len(inner)) + inner)

    # Message type only.
    write_parser("dhcpv6", "truncated", bytes([1]))


def seed_misc_parsers():
    # ARP with hardware and protocol lengths that do not match Ethernet/IPv4.
    write_parser("arp", "lengths_absurd",
                 struct.pack(">HHBBH", 1, 0x0800, 0xFF, 0xFF, 1) + b"\x00" * 8)
    write_parser("arp", "truncated", struct.pack(">HHBBH", 1, 0x0800, 6, 4, 1))
    write_parser("arp", "opcode_unknown",
                 struct.pack(">HHBBH", 1, 0x0800, 6, 4, 0xFFFF) + b"\x11" * 20)

    # Ethernet with stacked VLAN tags, and a tag with nothing behind it.
    mac = b"\xaa\xbb\xcc\x11\x22\x33" + b"\xdd\xee\xff\x44\x55\x66"
    write_parser("eth", "vlan_stack_deep",
                 mac[6:] + mac[:6] + b"\x81\x00\x00\x2a" * 8 + b"\x08\x00")
    write_parser("eth", "vlan_truncated", mac[6:] + mac[:6] + b"\x81\x00")
    write_parser("eth", "header_truncated", mac[6:] + b"\xaa")

    # GRE with every flag bit set but no room for the fields they announce.
    write_parser("gre", "flags_all_no_fields", struct.pack(">HH", 0xF000, 0x0800))
    write_parser("gre", "version_unknown", struct.pack(">HH", 0x0007, 0x0800))
    write_parser("gre", "truncated", b"\x00")

    # GRE nesting: an IPv4 packet carrying GRE carrying IPv4 carrying GRE.
    innermost = ipv4_packet(proto=1, payload=bytes([8, 0, 0, 0, 0, 0, 0, 0]))
    level2 = ipv4_packet(proto=47, payload=struct.pack(">HH", 0, 0x0800) + innermost)
    level1 = ipv4_packet(proto=47, payload=struct.pack(">HH", 0, 0x0800) + level2)
    write("frame", "gre_nested_deep", frame_input([eth(level1)]))

    # ICMP error carrying an embedded packet that is itself truncated.
    write_parser("icmp", "embedded_truncated",
                 bytes([3, 3, 0, 0, 0, 0, 0, 0]) + ipv4_packet(proto=17)[:12])
    write_parser("icmp", "type_unknown", bytes([0xFF, 0xFF, 0, 0, 0, 0, 0, 0]))
    write_parser("icmp", "truncated", bytes([8, 0]))

    # IGMPv3 report promising more group records than it carries.
    write_parser("igmp", "v3_group_count_lies",
                 bytes([0x22, 0, 0, 0]) + struct.pack(">HH", 0, 0xFFFF))
    write_parser("igmp", "truncated", bytes([0x16, 0]))

    # NTP with the shortest possible body and with a huge extension field.
    write_parser("ntp", "truncated", bytes([0x1B, 0, 0, 0]))
    write_parser("ntp", "extension_overrun",
                 bytes([0x1B]) + b"\x00" * 47 + struct.pack(">HH", 2, 0xFFFF))

    # UDP length field disagreeing with the buffer, in both directions.
    write_parser("udp", "length_above_buffer",
                 struct.pack(">HHHH", 53, 12345, 0xFFFF, 0))
    write_parser("udp", "length_below_header",
                 struct.pack(">HHHH", 53, 12345, 4, 0))
    write_parser("udp", "length_zero", struct.pack(">HHHH", 53, 12345, 0, 0))


# ── pcap and pcapng readers ─────────────────────────────────────────────────

def pcapng_block(block_type, body):
    total = 12 + len(body) + (-len(body) % 4)
    padded = bytes(body) + b"\x00" * (-len(body) % 4)
    return (struct.pack("<II", block_type, total) + padded
            + struct.pack("<I", total))


# ── encapsulation: link headers and tunnels ─────────────────────────────────

def seed_encapsulation():
    # PPPoE. The declared length is the sender's claim about how much follows,
    # so the cases that matter are the ones where it disagrees with reality.
    write_parser("pppoe", "session_ipv4",
                 bytes([0x11, 0x00, 0x00, 0x01, 0x00, 0x06])
                 + b"\x00\x21" + b"\x45\x00\x00\x14")
    write_parser("pppoe", "length_overrun",
                 bytes([0x11, 0x00, 0x00, 0x01, 0xFF, 0xFF]) + b"\x00\x21\x45")
    write_parser("pppoe", "length_zero",
                 bytes([0x11, 0x00, 0x00, 0x01, 0x00, 0x00]) + b"\x00\x21\x45")
    write_parser("pppoe", "no_room_for_protocol",
                 bytes([0x11, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00]))
    write_parser("pppoe", "discovery_padi",
                 bytes([0x11, 0x09, 0x00, 0x00, 0x00, 0x04])
                 + b"\x01\x01\x00\x00")
    write_parser("pppoe", "unknown_ppp_protocol",
                 bytes([0x11, 0x00, 0x00, 0x01, 0x00, 0x04])
                 + b"\xff\xff" + b"\x00\x00")
    write_parser("pppoe", "truncated", bytes([0x11, 0x00, 0x00]))

    # VXLAN.
    inner = eth(ipv4_packet(proto=1, payload=bytes([8, 0, 0, 0, 0, 0, 0, 0])))
    write_parser("vxlan", "valid",
                 bytes([0x08, 0, 0, 0, 0x12, 0x34, 0x56, 0]) + inner)
    write_parser("vxlan", "no_i_bit",
                 bytes([0x00, 0, 0, 0, 0x12, 0x34, 0x56, 0]) + inner)
    write_parser("vxlan", "reserved_set",
                 bytes([0x08, 0xFF, 0xFF, 0xFF, 0x12, 0x34, 0x56, 0xFF]) + inner)
    write_parser("vxlan", "header_only", bytes([0x08, 0, 0, 0, 0, 0, 0, 0]))
    write_parser("vxlan", "truncated", bytes([0x08, 0, 0, 0, 0, 0, 0]))

    # BSD loopback: the address family is written in the capturing host's byte
    # order with nothing saying which, so both orientations are worth feeding.
    write_parser("link_null", "af_inet_le",
                 struct.pack("<I", 2) + b"\x45\x00\x00\x14")
    write_parser("link_null", "af_inet6_be",
                 struct.pack(">I", 30) + b"\x60\x00\x00\x00")
    write_parser("link_null", "af_inet6_le",
                 struct.pack("<I", 10) + b"\x60\x00\x00\x00")
    write_parser("link_null", "unknown_family",
                 struct.pack("<I", 0xDEADBEEF) + b"\x45\x00")
    write_parser("link_null", "truncated", b"\x02\x00\x00")

    # Raw IP: the version nibble is the only thing identifying the payload.
    write_parser("link_raw", "ipv4", b"\x45\x00\x00\x14" + b"\x00" * 16)
    write_parser("link_raw", "ipv6", b"\x60\x00\x00\x00" + b"\x00" * 36)
    write_parser("link_raw", "bad_version", b"\x35\x00\x00\x00")
    write_parser("link_raw", "single_byte", b"\x45")

    # Linux cooked v1 and v2. The address length is the interesting field: it
    # describes a fixed eight-byte area, so a larger value must not widen it.
    sll = bytearray(16)
    sll[4:6] = struct.pack(">H", 6)
    sll[6:12] = b"\xaa\xbb\xcc\x11\x22\x33"
    sll[14:16] = struct.pack(">H", 0x0800)
    write_parser("link_sll", "valid", bytes(sll) + b"\x45\x00\x00\x14")
    bad = bytearray(sll)
    bad[4:6] = struct.pack(">H", 0xFFFF)
    write_parser("link_sll", "addr_len_overrun", bytes(bad) + b"\x45\x00")
    write_parser("link_sll", "truncated", bytes(sll[:15]))
    write_parser("link_sll", "header_only", bytes(sll))

    sll2 = bytearray(20)
    sll2[0:2] = struct.pack(">H", 0x86DD)
    sll2[4:8] = struct.pack(">I", 3)
    sll2[11] = 6
    sll2[12:18] = b"\xaa\xbb\xcc\x11\x22\x33"
    write_parser("link_sll2", "valid", bytes(sll2) + b"\x60\x00\x00\x00")
    bad2 = bytearray(sll2)
    bad2[11] = 0xFF
    write_parser("link_sll2", "addr_len_overrun", bytes(bad2) + b"\x60\x00")
    write_parser("link_sll2", "truncated", bytes(sll2[:19]))

    # ── tunnels reached through an Ethernet frame ────────────────────────────
    icmp = bytes([8, 0, 0, 0, 0, 0, 0, 0])

    # IPv4 in IPv4, and IPv6 in IPv4.
    write("frame", "tunnel_ipip",
          frame_input([eth(ipv4_packet(proto=4,
                                       payload=ipv4_packet(proto=1,
                                                           payload=icmp)))]))
    write("frame", "tunnel_6in4",
          frame_input([eth(ipv4_packet(proto=41, payload=ipv6_packet(58, icmp)))]))

    # PPPoE session carrying IPv4.
    ppp_payload = ipv4_packet(proto=1, payload=icmp)
    ppp = (struct.pack(">BBHH", 0x11, 0x00, 1, 2 + len(ppp_payload))
           + b"\x00\x21" + ppp_payload)
    write("frame", "tunnel_pppoe", frame_input([eth(ppp, 0x8864)]))

    # VXLAN, which returns the walk to a fresh Ethernet frame.
    def vxlan_frame(inner_frame, vni=0x123456):
        body = (bytes([0x08, 0, 0, 0])
                + struct.pack(">I", vni)[1:] + bytes([0]) + inner_frame)
        udp = struct.pack(">HHHH", 45678, 4789, 8 + len(body), 0) + body
        return eth(ipv4_packet(proto=17, payload=udp))

    plain = eth(ipv4_packet(proto=1, payload=icmp))
    write("frame", "tunnel_vxlan", frame_input([vxlan_frame(plain)]))

    # VXLAN inside VXLAN: each layer returns to the link layer, which is the
    # shape that makes an unbounded walk unbounded.
    write("frame", "tunnel_vxlan_nested",
          frame_input([vxlan_frame(vxlan_frame(plain))]))

    # Nested GRE at the cap and past it. Every layer needs a valid header
    # checksum, so a mutation will not produce this on its own -- which is
    # exactly why it belongs in the corpus rather than being left to chance.
    for depth in (7, 8, 9, 16):
        packet = ipv4_packet(proto=1, payload=icmp)
        for _ in range(depth):
            packet = ipv4_packet(proto=47,
                                 payload=struct.pack(">HH", 0, 0x0800) + packet)
        write("frame", f"tunnel_gre_depth_{depth:02d}",
              frame_input([eth(packet)]))


def seed_pcap_files():
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    shb = pcapng_block(0x0A0D0D0A, shb_body)
    idb = pcapng_block(0x00000001, struct.pack("<HHI", 1, 0, 0xFFFF))

    # A block whose declared total length is 0. A reader that seeks forward by
    # the declared length never reaches the end of the file.
    write("pcap", "ng_block_len_zero",
          shb + struct.pack("<III", 0x00000006, 0, 0))

    # A total length below the 12-byte block overhead.
    write("pcap", "ng_block_len_too_small",
          shb + struct.pack("<III", 0x00000006, 4, 4))

    # A total length past the end of the file.
    write("pcap", "ng_block_len_overrun",
          shb + struct.pack("<III", 0x00000006, 0xFFFFFFF0, 0))

    # Trailing length that disagrees with the leading one.
    write("pcap", "ng_trailer_mismatch",
          shb + struct.pack("<II", 0x00000006, 32) + b"\x00" * 20
          + struct.pack("<I", 999))

    # Enhanced packet block whose captured length exceeds its own block.
    epb_body = struct.pack("<IIIII", 0, 0, 0, 0xFFFFFF00, 0xFFFFFF00)
    write("pcap", "ng_epb_caplen_overrun", shb + idb + pcapng_block(6, epb_body))

    # Enhanced packet block naming an interface that was never described.
    epb_body = struct.pack("<IIIII", 99, 0, 0, 4, 4) + b"\x01\x02\x03\x04"
    write("pcap", "ng_epb_bad_interface", shb + idb + pcapng_block(6, epb_body))

    # Simple packet block whose original length exceeds the block.
    write("pcap", "ng_spb_len_overrun",
          shb + idb + pcapng_block(3, struct.pack("<I", 0xFFFFFF00)))

    # Section header with a byte-order magic that is neither endianness.
    write("pcap", "ng_bad_byte_order",
          pcapng_block(0x0A0D0D0A, struct.pack("<IHHq", 0xDEADBEEF, 1, 0, -1)))

    # Interface description with a link type the stack does not handle.
    write("pcap", "ng_unknown_linktype",
          shb + pcapng_block(1, struct.pack("<HHI", 0xFFFF, 0, 0xFFFF)))

    # Many interface descriptions, to overflow the reader's fixed table.
    write("pcap", "ng_many_interfaces", shb + idb * 64)

    # An unknown block type, which the reader is meant to skip safely.
    write("pcap", "ng_unknown_block",
          shb + pcapng_block(0x0BADF00D, b"\x00" * 16) + idb)

    # Section header only, and a section header cut off mid-body.
    write("pcap", "ng_shb_only", shb)
    write("pcap", "ng_shb_truncated", shb[:16])

    # Classic pcap: a record claiming more bytes than the file holds.
    classic = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 0xFFFF, 1)
    write("pcap", "classic_reclen_overrun",
          classic + struct.pack("<IIII", 0, 0, 0xFFFFFF00, 0xFFFFFF00))

    # Classic pcap with incl_len larger than orig_len.
    write("pcap", "classic_incl_gt_orig",
          classic + struct.pack("<IIII", 0, 0, 100, 4) + b"\x00" * 100)

    # Classic pcap with a zero-length record, repeated.
    write("pcap", "classic_reclen_zero",
          classic + struct.pack("<IIII", 0, 0, 0, 0) * 64)

    # A snaplen far larger than any buffer the reader allocates.
    write("pcap", "classic_huge_snaplen",
          struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 0xFFFFFFFF, 1))

    # Nanosecond-resolution magic, and the byte-swapped magic.
    write("pcap", "classic_nsec_magic",
          struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 0xFFFF, 1)
          + struct.pack("<IIII", 0, 999999999, 4, 4) + b"\x01\x02\x03\x04")
    write("pcap", "classic_swapped_magic",
          struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 0xFFFF, 1)
          + struct.pack(">IIII", 0, 0, 4, 4) + b"\x01\x02\x03\x04")

    # Global header only, an empty file, and four bytes of nothing.
    write("pcap", "classic_header_only", classic[:24])
    write("pcap", "empty", b"")
    write("pcap", "four_bytes", b"\x00\x00\x00\x00")


# ── Ethernet framing helper and frame-level cases ───────────────────────────

def eth(payload, ethertype=0x0800,
        src=b"\xaa\xbb\xcc\x11\x22\x33", dst=b"\xdd\xee\xff\x44\x55\x66"):
    return dst + src + struct.pack(">H", ethertype) + bytes(payload)


def seed_frame_cases():
    # An empty input, a lone time-step byte, and a length with no frame.
    write("frame", "empty", b"")
    write("frame", "step_only", b"\x01")
    write("frame", "length_no_frame", b"\x01\xff\xff")

    # A declared length far beyond the bytes present; the driver clamps, so
    # this exercises the parsers at a short length rather than being rejected.
    write("frame", "length_overrun", b"\x01\xff\xff\x00\x01\x02")

    # Many zero-length frames.
    write("frame", "many_empty_frames", b"\x01" + b"\x00\x00" * 64)

    # 802.3 length field rather than an EtherType.
    write("frame", "ethertype_is_length", frame_input([eth(b"\x00" * 8, 0x0100)]))

    # An unknown EtherType, and one the stack knows but with no payload.
    write("frame", "ethertype_unknown", frame_input([eth(b"\x00" * 8, 0x1234)]))
    write("frame", "ipv4_no_payload", frame_input([eth(b"", 0x0800)]))

    # The same ARP reply twice, which is what makes the cache report a change.
    arp = struct.pack(">HHBBH", 1, 0x0800, 6, 4, 2) \
        + b"\xaa\xbb\xcc\x11\x22\x33" + bytes([192, 168, 1, 10]) \
        + b"\xdd\xee\xff\x44\x55\x66" + bytes([192, 168, 1, 20])
    write("frame", "arp_reply_twice",
          frame_input([eth(arp, 0x0806), eth(arp, 0x0806)]))

    # An ARP reply that rebinds an address already in the cache to a new MAC:
    # the shape of ARP spoofing, and the case the cache is meant to report.
    spoof = bytearray(arp)
    spoof[8:14] = b"\x99\x99\x99\x99\x99\x99"
    write("frame", "arp_rebind",
          frame_input([eth(arp, 0x0806), eth(bytes(spoof), 0x0806)]))

    # More TCP connections than the tracker has slots, to force eviction.
    frames = []
    for port in range(80):
        segment = struct.pack(">HHIIBBHHH",
                              1024 + port, 80, 0, 0, 5 << 4, 0x02, 8192, 0, 0)
        frames.append(eth(ipv4_packet(proto=6, payload=segment)))
    write("frame", "tcp_many_connections", frame_input(frames[:64]))
    write("frame", "tcp_evict_connections", frame_input(frames))

    # A minimal handshake, so the state machine advances rather than inferring.
    syn = struct.pack(">HHIIBBHHH", 1234, 80, 1000, 0, 5 << 4, 0x02, 8192, 0, 0)
    synack = struct.pack(">HHIIBBHHH", 80, 1234, 5000, 1001, 5 << 4, 0x12,
                         8192, 0, 0)
    ack = struct.pack(">HHIIBBHHH", 1234, 80, 1001, 5001, 5 << 4, 0x10,
                      8192, 0, 0)
    write("frame", "tcp_handshake",
          frame_input([eth(ipv4_packet(proto=6, payload=syn)),
                       eth(ipv4_packet(proto=6, payload=synack)),
                       eth(ipv4_packet(proto=6, payload=ack))]))

    # A segment sequence with a permanent gap, so the stream buffer fills and
    # never drains.
    frames = []
    for index in range(32):
        seq = 2000 + index * 100          # gaps between every segment
        segment = struct.pack(">HHIIBBHHH",
                              1234, 80, seq, 0, 5 << 4, 0x18, 8192, 0, 0) \
            + bytes([index]) * 40
        frames.append(eth(ipv4_packet(proto=6, payload=segment)))
    write("frame", "tcp_stream_all_gaps", frame_input(frames))


def main():
    print(f"Writing fuzz corpus under {CORPUS}")
    seed_from_fixtures()
    seed_dns()
    seed_dns_edns()
    seed_dns_dnssec()
    seed_tcp_options()
    seed_ipv4_options()
    seed_ipv4_fragments()
    seed_ipv6_extensions()
    seed_icmpv6()
    seed_sctp()
    seed_quic()
    seed_http()
    seed_tls()
    seed_dhcp()
    seed_dhcpv6()
    seed_misc_parsers()
    seed_encapsulation()
    seed_pcap_files()
    seed_frame_cases()

    for target in ("frame", "parsers", "pcap"):
        directory = CORPUS / target
        count = len(list(directory.iterdir())) if directory.is_dir() else 0
        print(f"  {target:8s} {count:4d} input(s)")
    print(f"Done. {written} file(s) written.")


if __name__ == "__main__":
    main()
