#!/usr/bin/env python3
"""
gen_dns_pcap.py — a capture covering EDNS0 and DNSSEC

    python tests/gen_dns_pcap.py     # writes tests/sample-dns.pcap

The DNS records in tests/sample.pcap predate EDNS0 in this parser, and adding
these to that file would have shifted every packet index the existing
assertions depend on. They also need a message shape the older fixture has no
room for: an OPT pseudo-record whose class and TTL fields mean something other
than a class and a TTL.

Each packet isolates one thing worth asserting, so a regression names what
broke rather than failing somewhere in a long capture:

    1  query with OPT: DO bit, Client Subnet, and a client cookie
    2  answer with OPT: NSID, and a server cookie
    3  DNSSEC-signed answer: A + RRSIG, NSEC in authority, DNSKEY
    4  BADVERS, which only exists once the OPT extends the RCODE to 12 bits
    5  SERVFAIL carrying an Extended DNS Error explaining why
    6  delegation: DS and NSEC3 with opt-out, in the authority section

UDP checksums are written as zero, which over IPv4 means the sender declined to
compute one. That keeps this generator from re-deriving a checksum for every
edit and is what the other capture generators here do.
"""

import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TESTS = ROOT / "tests"

LINKTYPE_ETHERNET = 1

MAC_CLIENT = bytes.fromhex("aabbcc112233")
MAC_SERVER = bytes.fromhex("ddeeff445566")
IP_CLIENT = bytes([192, 168, 1, 10])
IP_SERVER = bytes([192, 168, 1, 53])

# RR types
A, NS, SOA, MX, TXT, AAAA = 1, 2, 6, 15, 16, 28
OPT, DS, RRSIG, NSEC, DNSKEY, NSEC3, NSEC3PARAM = 41, 43, 46, 47, 48, 50, 51

# EDNS option codes
O_NSID, O_ECS, O_COOKIE, O_KEEPALIVE, O_PADDING, O_ERROR = 3, 8, 10, 11, 12, 15


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


def ipv4(payload, src, dst, ip_id):
    header = bytearray(struct.pack(">BBHHHBBH4s4s",
                                   0x45, 0, 20 + len(payload), ip_id, 0x4000,
                                   64, 17, 0, src, dst))
    header[10:12] = struct.pack(">H", inet_checksum(bytes(header)))
    return bytes(header) + payload


def udp(src_port, dst_port, payload):
    return struct.pack(">HHHH", src_port, dst_port, 8 + len(payload), 0) + payload


def eth(payload, src, dst):
    return dst + src + struct.pack(">H", 0x0800) + payload


def query_frame(payload, ip_id):
    return eth(ipv4(udp(40000 + ip_id, 53, payload), IP_CLIENT, IP_SERVER, ip_id),
               MAC_CLIENT, MAC_SERVER)


def response_frame(payload, ip_id):
    return eth(ipv4(udp(53, 40000 + ip_id, payload), IP_SERVER, IP_CLIENT, ip_id),
               MAC_SERVER, MAC_CLIENT)


# ── DNS wire format ──────────────────────────────────────────────────────────

def name(text):
    if text in (".", ""):
        return b"\x00"
    out = b""
    for label in text.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def question(qname, qtype=A, qclass=1):
    return name(qname) + struct.pack(">HH", qtype, qclass)


def rr(owner, rtype, rdata, ttl=3600, rclass=1):
    return (name(owner) + struct.pack(">HHIH", rtype, rclass, ttl, len(rdata))
            + rdata)


def opt_record(udp_size=1232, rcode_high=0, version=0, dnssec_ok=False,
               options=b""):
    """The OPT pseudo-record: owner is the root, class carries the requestor's
    UDP payload size, and TTL carries (extended RCODE, version, flags)."""
    ttl = (rcode_high << 24) | (version << 16) | (0x8000 if dnssec_ok else 0)
    return (b"\x00" + struct.pack(">HHIH", OPT, udp_size, ttl, len(options))
            + options)


def edns_option(code, payload):
    return struct.pack(">HH", code, len(payload)) + payload


def client_subnet(prefix, source, scope=0, family=1):
    return edns_option(O_ECS,
                       struct.pack(">HBB", family, source, scope) + prefix)


def message(qid, flags, questions=b"", answers=b"", authority=b"",
            additional=b"", counts=None):
    """counts overrides the section counts, which is needed because the OPT
    record is counted in ARCOUNT like any other additional record."""
    qd, an, ns, ar = counts
    return (struct.pack(">HHHHHH", qid, flags, qd, an, ns, ar)
            + questions + answers + authority + additional)


def type_bitmap(types):
    """RFC 4034 §4.1.2: {window, length, bitmap} blocks, one per high byte."""
    windows = {}
    for t in types:
        window, low = t >> 8, t & 0xFF
        bitmap = windows.setdefault(window, bytearray(32))
        bitmap[low // 8] |= 0x80 >> (low % 8)
    out = b""
    for window in sorted(windows):
        bitmap = windows[window]
        length = max(i for i in range(32) if bitmap[i]) + 1
        out += bytes([window, length]) + bytes(bitmap[:length])
    return out


def key_tag(rdata: bytes) -> int:
    """RFC 4034 Appendix B, so the fixture's expected tag is derived rather
    than copied from whatever the parser happened to print."""
    total = 0
    for i, byte in enumerate(rdata):
        total += byte if i & 1 else byte << 8
    total += (total >> 16) & 0xFFFF
    return total & 0xFFFF


# ── the records this capture carries ─────────────────────────────────────────

DNSKEY_RDATA = struct.pack(">HBB", 0x0101, 3, 8) + bytes.fromhex("abcdef01")
KEY_TAG = key_tag(DNSKEY_RDATA)

# 2024-01-01 and 2024-02-01, 00:00:00 UTC. Written as constants so the printed
# presentation form can be asserted exactly.
INCEPTION = 1704067200
EXPIRATION = 1706745600


def rrsig_rdata(covered, signer):
    return (struct.pack(">HBBIIIH", covered, 8, 3, 3600,
                        EXPIRATION, INCEPTION, KEY_TAG)
            + name(signer)
            + bytes.fromhex("deadbeefcafe1234"))


def build_packets():
    packets = []

    # 1 ── A query that asks for DNSSEC records, tells the server which client
    #      subnet it is for, and offers a cookie.
    packets.append(query_frame(message(
        0xa001, 0x0120,                      # RD, AD
        questions=question("www.example.com"),
        additional=opt_record(
            udp_size=1232, dnssec_ok=True,
            options=(client_subnet(bytes([192, 0, 2]), 24)
                     + edns_option(O_COOKIE, bytes.fromhex("0102030405060708"))
                     + edns_option(O_KEEPALIVE, b""))),
        counts=(1, 0, 0, 1)), 1))

    # 2 ── The answer, naming the server that produced it and echoing a cookie
    #      with the server half appended.
    packets.append(response_frame(message(
        0xa001, 0x8180,
        questions=question("www.example.com"),
        answers=rr("www.example.com", A, bytes([192, 0, 2, 1])),
        additional=opt_record(
            udp_size=1232, dnssec_ok=True,
            options=(edns_option(O_NSID, b"ns1.example")
                     + edns_option(O_COOKIE, bytes.fromhex(
                         "0102030405060708") + bytes.fromhex("1122334455667788"))
                     + client_subnet(bytes([192, 0, 2]), 24, scope=24)
                     + edns_option(O_PADDING, b"\x00" * 16))),
        counts=(1, 1, 0, 1)), 2))

    # 3 ── A signed answer: the A record, its RRSIG, an NSEC proving what else
    #      the name has, and the zone's DNSKEY.
    packets.append(response_frame(message(
        0xa002, 0x85a0,                      # AA, RD, RA, AD
        questions=question("www.example.com"),
        answers=(rr("www.example.com", A, bytes([192, 0, 2, 1]))
                 + rr("www.example.com", RRSIG, rrsig_rdata(A, "example.com"))),
        authority=rr("www.example.com", NSEC,
                     name("mail.example.com")
                     + type_bitmap([A, NS, SOA, RRSIG, NSEC, DNSKEY])),
        additional=(rr("example.com", DNSKEY, DNSKEY_RDATA)
                    + opt_record(udp_size=4096, dnssec_ok=True)),
        counts=(1, 2, 1, 2)), 3))

    # 4 ── BADVERS. The header's four RCODE bits are zero; the OPT supplies the
    #      1 that makes this 16. Reading only the header reports NOERROR.
    packets.append(response_frame(message(
        0xa003, 0x8180,
        questions=question("www.example.com"),
        additional=opt_record(udp_size=512, rcode_high=1, version=0),
        counts=(1, 0, 0, 1)), 4))

    # 5 ── SERVFAIL with an Extended DNS Error saying which validation failed.
    packets.append(response_frame(message(
        0xa004, 0x8182,
        questions=question("bogus.example.com"),
        additional=opt_record(
            udp_size=1232, dnssec_ok=True,
            options=edns_option(O_ERROR, struct.pack(">H", 6)
                                + b"no RRSIG covering the A record")),
        counts=(1, 0, 0, 1)), 5))

    # 6 ── A delegation: the DS that links the child zone to this one, and an
    #      NSEC3 with opt-out covering the names in between.
    ds_rdata = struct.pack(">HBB", KEY_TAG, 8, 2) + bytes.fromhex(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    nsec3_rdata = (struct.pack(">BBH", 1, 1, 10)
                   + bytes([4]) + bytes.fromhex("aabbccdd")
                   + bytes([20]) + bytes.fromhex(
                       "0123456789abcdef0123456789abcdef01234567")
                   + type_bitmap([NS, DS, RRSIG]))
    packets.append(response_frame(message(
        0xa005, 0x8180,
        questions=question("sub.example.com", qtype=DS),
        authority=(rr("sub.example.com", DS, ds_rdata)
                   + rr("h9p7u7tr2u91d0v0ljs9l1gidnp90u3h.example.com",
                        NSEC3, nsec3_rdata)
                   + rr("example.com", NSEC3PARAM,
                        struct.pack(">BBH", 1, 0, 10)
                        + bytes([4]) + bytes.fromhex("aabbccdd"))),
        additional=opt_record(udp_size=4096, dnssec_ok=True),
        counts=(1, 0, 3, 1)), 6))

    return packets


def write_pcap(path, packets):
    blob = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0,
                                 65535, LINKTYPE_ETHERNET))
    for index, frame in enumerate(packets):
        blob += struct.pack("<IIII", 1 + index, 0, len(frame), len(frame))
        blob += frame
    path.write_bytes(bytes(blob))
    print(f"  {path.name:22s} {len(packets)} packet(s), "
          f"{path.stat().st_size} bytes")


def main():
    print("Writing the EDNS0 and DNSSEC capture:")
    write_pcap(TESTS / "sample-dns.pcap", build_packets())
    print(f"  DNSKEY key tag = {KEY_TAG}  (RFC 4034 Appendix B)")


if __name__ == "__main__":
    main()
