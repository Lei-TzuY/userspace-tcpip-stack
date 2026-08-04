#!/usr/bin/env python3
"""
gen_transport_pcap.py — a capture covering SCTP and QUIC

    python tests/gen_transport_pcap.py     # writes tests/sample-transport.pcap

These do not belong in tests/sample.pcap: adding packets there would shift
every packet index the existing assertions depend on, and both protocols need
shapes that fixture has no room for — an SCTP chunk walk with real CRC-32C
checksums, and QUIC datagrams large enough to carry a plausible Initial.

Each packet isolates one thing worth asserting, so a regression names what
broke rather than failing somewhere in a long capture:

     1  SCTP INIT, with the variable parameters an association offers
     2  SCTP INIT ACK, carrying the state cookie
     3  SCTP DATA followed by SACK in one packet — the chunk padding walk
     4  SCTP SACK with gap blocks and a duplicate TSN
     5  SCTP ABORT with an error cause
     6  SCTP over IPv6: SHUTDOWN, so the other dispatch path is covered
     7  SCTP whose checksum is wrong, so the CRC-32C verdict is tested both ways
     8  QUIC v1 Initial with a token, and a Handshake packet coalesced behind it
     9  QUIC Version Negotiation
    10  QUIC Retry
    11  QUIC v2 Initial, whose packet type number means something else in v1
    12  QUIC 1-RTT, the short header nothing but the port identifies

The SCTP checksums are computed here rather than copied, so packet 7's is
wrong by construction rather than by accident. UDP checksums are written as
zero, which over IPv4 means the sender declined to compute one; that is what
the other capture generators here do.
"""

import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TESTS = ROOT / "tests"

LINKTYPE_ETHERNET = 1

MAC_CLIENT = bytes.fromhex("aabbcc112233")
MAC_SERVER = bytes.fromhex("ddeeff445566")
IP_CLIENT = bytes([192, 168, 1, 10])
IP_SERVER = bytes([192, 168, 1, 20])
IP6_CLIENT = bytes.fromhex("20010db8000000000000000000000010")
IP6_SERVER = bytes.fromhex("20010db8000000000000000000000020")

IPPROTO_UDP = 17
IPPROTO_SCTP = 132

# SCTP chunk types
DATA, INIT, INIT_ACK, SACK, HEARTBEAT = 0, 1, 2, 3, 4
ABORT, SHUTDOWN, ERROR, COOKIE_ECHO, COOKIE_ACK = 6, 7, 9, 10, 11

# QUIC versions
QUIC_V1 = 0x00000001
QUIC_V2 = 0x6B3343CF


# ── checksums and framing ────────────────────────────────────────────────────

def inet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


# Reflected CRC-32C, four bits at a time; the same table src/sctp.c carries.
_CRC32C_POLY = 0x82F63B78
_CRC32C_NIBBLE = []
for _i in range(16):
    _c = _i
    for _ in range(4):
        _c = (_c >> 1) ^ (_CRC32C_POLY if (_c & 1) else 0)
    _CRC32C_NIBBLE.append(_c)


def crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        crc = (crc >> 4) ^ _CRC32C_NIBBLE[crc & 0xF]
        crc = (crc >> 4) ^ _CRC32C_NIBBLE[crc & 0xF]
    return crc ^ 0xFFFFFFFF


def ipv4(payload, src, dst, ip_id, proto=IPPROTO_UDP):
    header = bytearray(struct.pack(">BBHHHBBH4s4s",
                                   0x45, 0, 20 + len(payload), ip_id, 0x4000,
                                   64, proto, 0, src, dst))
    header[10:12] = struct.pack(">H", inet_checksum(bytes(header)))
    return bytes(header) + payload


def ipv6(payload, src, dst, next_header):
    return (struct.pack(">IHBB", 0x60000000, len(payload), next_header, 64)
            + src + dst + payload)


def udp(src_port, dst_port, payload):
    return struct.pack(">HHHH", src_port, dst_port, 8 + len(payload), 0) + payload


def eth(payload, src, dst, ethertype=0x0800):
    return dst + src + struct.pack(">H", ethertype) + payload


# ── SCTP wire format ─────────────────────────────────────────────────────────

def chunk(ctype, value=b"", flags=0):
    """One chunk. The declared length excludes the padding that follows it,
    which is exactly the thing a walker has to round up past."""
    length = 4 + len(value)
    body = struct.pack(">BBH", ctype, flags, length) + value
    return body + b"\x00" * (-len(body) % 4)


def param(ptype, value=b""):
    """A parameter of an INIT, or an error cause of an ABORT. Same shape."""
    body = struct.pack(">HH", ptype, 4 + len(value)) + value
    return body + b"\x00" * (-len(body) % 4)


def sctp(src_port, dst_port, vtag, chunks, break_checksum=False):
    body = struct.pack(">HHII", src_port, dst_port, vtag, 0) + b"".join(chunks)
    crc = crc32c(body)
    if break_checksum:
        crc ^= 0xFFFFFFFF          # any other value; this one is not close
    # RFC 9260 Appendix A stores the result byte-swapped, so the field reads
    # little-endian while every other field in the packet is big endian.
    return body[:8] + struct.pack("<I", crc) + body[12:]


def init_chunk(ctype, tag, a_rwnd, out_streams, in_streams, tsn, params=b""):
    return chunk(ctype,
                 struct.pack(">IIHHI", tag, a_rwnd, out_streams,
                             in_streams, tsn) + params)


# ── QUIC wire format ─────────────────────────────────────────────────────────

def varint(value):
    """RFC 9000 §16: the top two bits of the first byte give the width."""
    if value < (1 << 6):
        return bytes([value])
    if value < (1 << 14):
        return struct.pack(">H", 0x4000 | value)
    if value < (1 << 30):
        return struct.pack(">I", 0x80000000 | value)
    return struct.pack(">Q", 0xC000000000000000 | value)


def long_header(first_byte, version, dcid, scid, rest=b""):
    return (bytes([first_byte]) + struct.pack(">I", version)
            + bytes([len(dcid)]) + dcid
            + bytes([len(scid)]) + scid + rest)


def quic_initial(version, dcid, scid, token, payload, type_bits=None):
    """Type 0 in version 1; RFC 9369 renumbers it to 1 in version 2."""
    if type_bits is None:
        type_bits = 1 if version == QUIC_V2 else 0
    first = 0xC0 | (type_bits << 4)
    return long_header(first, version, dcid, scid,
                       varint(len(token)) + token
                       + varint(len(payload)) + payload)


def quic_handshake(version, dcid, scid, payload):
    type_bits = 3 if version == QUIC_V2 else 2
    return long_header(0xC0 | (type_bits << 4), version, dcid, scid,
                       varint(len(payload)) + payload)


def quic_retry(version, dcid, scid, token):
    type_bits = 0 if version == QUIC_V2 else 3
    # The last 16 bytes are the Retry Integrity Tag, not part of the token.
    return long_header(0xC0 | (type_bits << 4), version, dcid, scid,
                       token + bytes.fromhex("f0f1f2f3f4f5f6f7"
                                             "f8f9fafbfcfdfeff"))


def quic_version_negotiation(dcid, scid, versions):
    return long_header(0xC0, 0, dcid, scid,
                       b"".join(struct.pack(">I", v) for v in versions))


def quic_short_header(dcid, payload):
    # Header form clear, fixed bit set; everything else is protected.
    return bytes([0x41]) + dcid + payload


# ── the packets this capture carries ─────────────────────────────────────────

DCID = bytes.fromhex("0102030405060708")
SCID = bytes.fromhex("aabbccdd")
TOKEN = bytes.fromhex("00112233445566778899aabbccddeeff")


def build_packets():
    packets = []

    def to_server(payload, ip_id, proto=IPPROTO_UDP):
        return eth(ipv4(payload, IP_CLIENT, IP_SERVER, ip_id, proto),
                   MAC_CLIENT, MAC_SERVER)

    def to_client(payload, ip_id, proto=IPPROTO_UDP):
        return eth(ipv4(payload, IP_SERVER, IP_CLIENT, ip_id, proto),
                   MAC_SERVER, MAC_CLIENT)

    # 1 ── INIT. The parameters are the association's offer: an address it can
    #      also be reached on, the address families it understands, and the
    #      extensions it supports.
    packets.append(to_server(sctp(9899, 9900, 0, [
        init_chunk(INIT, 0xAABBCCDD, 106496, 10, 5, 10000,
                   param(5, IP_CLIENT)                      # IPv4 Address
                   + param(12, struct.pack(">H", 5))        # Supported Address
                   + param(0x8008, bytes([192, 130]))       # Supported Ext
                   + param(0xC000))                         # Forward-TSN
    ]), 1, IPPROTO_SCTP))

    # 2 ── INIT ACK, whose state cookie is the server's whole idea of the
    #      association until the client echoes it back.
    packets.append(to_client(sctp(9900, 9899, 0xAABBCCDD, [
        init_chunk(INIT_ACK, 0x11223344, 106496, 5, 10, 20000,
                   param(7, bytes.fromhex("cafebabe") * 4)  # State Cookie
                   + param(0xC000))
    ]), 2, IPPROTO_SCTP))

    # 3 ── DATA and SACK bundled in one packet. The DATA chunk's length is 26,
    #      so two pad bytes sit between it and the SACK — a walk that does not
    #      round up to the next four-byte boundary never finds the second one.
    packets.append(to_server(sctp(9899, 9900, 0x11223344, [
        chunk(DATA,
              struct.pack(">IHHI", 1000, 1, 0, 51) + b"hello sctp",
              flags=0x03),                                  # B and E
        chunk(SACK, struct.pack(">IIHH", 19999, 106496, 0, 0))
    ]), 3, IPPROTO_SCTP))

    # 4 ── SACK reporting two blocks above the cumulative point and one TSN
    #      that arrived twice. The counts are the sender's, and they are what
    #      would drive a reader off the end of the chunk.
    packets.append(to_client(sctp(9900, 9899, 0xAABBCCDD, [
        chunk(SACK, struct.pack(">IIHH", 1000, 65536, 2, 1)
              + struct.pack(">HH", 2, 3)
              + struct.pack(">HH", 5, 7)
              + struct.pack(">I", 999))
    ]), 4, IPPROTO_SCTP))

    # 5 ── ABORT with a cause, which is how an association ends badly.
    packets.append(to_client(sctp(9900, 9899, 0xAABBCCDD, [
        # Twenty bytes of text, so neither the cause nor the chunk needs
        # padding — RFC 9260 §3.2 excludes a chunk's own trailing padding from
        # its declared length, and a fixture should not depend on that corner.
        chunk(ABORT, param(12, b"closed by the client"))     # User Initiated
    ]), 5, IPPROTO_SCTP))

    # 6 ── The same protocol over IPv6, which is a separate dispatch path.
    packets.append(eth(ipv6(sctp(9899, 9900, 0x11223344, [
        chunk(SHUTDOWN, struct.pack(">I", 2000))
    ]), IP6_CLIENT, IP6_SERVER, IPPROTO_SCTP),
        MAC_CLIENT, MAC_SERVER, ethertype=0x86DD))

    # 7 ── A packet whose CRC-32C is wrong. Without one of these the checksum
    #      code is only ever tested in the direction that agrees.
    packets.append(to_server(sctp(9899, 9900, 0x11223344, [
        chunk(COOKIE_ACK)
    ], break_checksum=True), 7, IPPROTO_SCTP))

    # 8 ── A QUIC Initial with a token — what a client sends after a Retry —
    #      and a Handshake packet coalesced into the same datagram. The
    #      Initial's Length field is the only thing saying where the second
    #      packet begins.
    packets.append(to_server(udp(50001, 443,
                                 quic_initial(QUIC_V1, DCID, SCID, TOKEN,
                                              bytes(200))
                                 + quic_handshake(QUIC_V1, DCID, SCID,
                                                  bytes(40))), 8))

    # 9 ── Version Negotiation: not really a packet of any version, just a
    #      list of what the server does speak.
    packets.append(to_client(udp(443, 50001,
                                 quic_version_negotiation(
                                     SCID, DCID,
                                     [QUIC_V1, QUIC_V2, 0x1A2A3A4A])), 9))

    # 10 ── Retry, whose last sixteen bytes are an integrity tag rather than
    #       part of the token.
    packets.append(to_client(udp(443, 50001,
                                 quic_retry(QUIC_V1, SCID, DCID, TOKEN)), 10))

    # 11 ── A version 2 Initial. Its packet type number is 1, which in version
    #       1 means 0-RTT — reading the type without the version gets this
    #       wrong rather than merely incomplete.
    packets.append(to_server(udp(50002, 443,
                                 quic_initial(QUIC_V2, DCID, b"", b"",
                                              bytes(100))), 11))

    # 12 ── A 1-RTT packet. Nothing in it identifies QUIC: the connection ID
    #       has no length prefix, so only the port says what this is.
    packets.append(to_server(udp(50001, 443,
                                 quic_short_header(DCID, bytes(50))), 12))

    return packets


def write_pcap(path, packets):
    blob = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0,
                                 65535, LINKTYPE_ETHERNET))
    for index, frame in enumerate(packets):
        blob += struct.pack("<IIII", 1 + index, 0, len(frame), len(frame))
        blob += frame
    path.write_bytes(bytes(blob))
    print(f"  {path.name:24s} {len(packets)} packet(s), "
          f"{path.stat().st_size} bytes")


def main():
    print("Writing the SCTP and QUIC capture:")
    write_pcap(TESTS / "sample-transport.pcap", build_packets())


if __name__ == "__main__":
    main()
