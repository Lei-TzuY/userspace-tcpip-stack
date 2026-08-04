#!/usr/bin/env python3
"""
gen_analysis_pcap.py — build tests/sample-analysis.pcap

    python tests/gen_analysis_pcap.py

A capture built to exercise src/tcp_analysis.c. The existing sample.pcap has no
loss, no window pressure, and no SACK, so none of the expert analysis has
anything to report on it. Rather than extend that fixture and risk disturbing
the forty-odd assertions pinned to its packet numbering, this is a separate
capture with one connection per scenario.

Separate connections matter for more than tidiness: several of the verdicts
depend on per-endpoint history (duplicate-ACK runs, the last time data was
sent), so mixing scenarios into one connection would let them interfere.

    port 40001  duplicate ACKs, then a fast retransmission
    port 40002  a SACK block revealing which bytes went missing
    port 40003  zero window, a one-byte probe, then a window update
    port 40004  a retransmission of data already acknowledged
    port 40005  a retransmission after a silence long enough to be an RTO
    port 40006  a gap filled immediately: reordering, not loss
    port 40007  a keep-alive and its response

Timing is deliberate throughout. The analysis separates reordering from
retransmission on a three-millisecond threshold and calls a resend an RTO only
after 200 ms of silence, so every timestamp here is chosen to land on a
specific side of one of those lines. Connections that must not acquire an RTT
estimate omit the timestamp option, since a measured RTT would move the RTO
threshold off the floor the fixture relies on.
"""

import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT_PATH = ROOT / "tests" / "sample-analysis.pcap"

PCAP_MAGIC = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1

MAC_CLIENT = bytes.fromhex("aabbcc112233")
MAC_SERVER = bytes.fromhex("ddeeff445566")
IP_CLIENT = bytes([192, 168, 1, 10])
IP_SERVER = bytes([192, 168, 1, 20])

# TCP flag bits
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


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


def transport_checksum(src_ip, dst_ip, proto, segment: bytes) -> int:
    pseudo = src_ip + dst_ip + bytes([0, proto]) + struct.pack(">H", len(segment))
    return inet_checksum(pseudo + segment)


# ── framing ──────────────────────────────────────────────────────────────────

def eth_frame(src_mac, dst_mac, ethertype, payload) -> bytes:
    return dst_mac + src_mac + struct.pack(">H", ethertype) + payload


def ipv4_header(src_ip, dst_ip, proto, payload_len, ip_id) -> bytes:
    header = bytearray(struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0, 20 + payload_len, ip_id,
        0x4000,          # Don't Fragment
        64, proto, 0, src_ip, dst_ip))
    header[10:12] = struct.pack(">H", inet_checksum(bytes(header)))
    return bytes(header)


# ── TCP options ──────────────────────────────────────────────────────────────

def opt_mss(mss=1460):
    return struct.pack(">BBH", 2, 4, mss)


def opt_wscale(shift):
    return struct.pack(">BBB", 3, 3, shift) + b"\x01"   # padded with a NOP


def opt_sack_permitted():
    return struct.pack(">BB", 4, 2) + b"\x01\x01"       # padded to 4 bytes


def opt_sack(blocks):
    """blocks is a list of (left, right) sequence-number pairs."""
    body = b"".join(struct.pack(">II", left, right) for left, right in blocks)
    option = struct.pack(">BB", 5, 2 + len(body)) + body
    # Options must end on a 4-byte boundary; NOPs are the conventional filler.
    return option + b"\x01" * (-len(option) % 4)


def opt_timestamps(tsval, tsecr):
    return b"\x01\x01" + struct.pack(">BBII", 8, 10, tsval, tsecr)


# ── segment construction ─────────────────────────────────────────────────────

def tcp_segment(src_ip, dst_ip, src_port, dst_port, seq, ack, flags,
                window, payload=b"", options=b""):
    if len(options) % 4:
        raise ValueError("TCP options must be a multiple of 4 bytes")
    data_offset = 5 + len(options) // 4

    header = struct.pack(">HHIIBBHHH",
                         src_port, dst_port, seq, ack,
                         data_offset << 4, flags, window, 0, 0)
    segment = bytearray(header + options + payload)
    checksum = transport_checksum(src_ip, dst_ip, 6, bytes(segment))
    segment[16:18] = struct.pack(">H", checksum)
    return bytes(segment)


class Capture:
    """Collects packets with explicit timestamps."""

    def __init__(self):
        self.packets = []   # (ts_usec, raw_frame)
        self.ip_id = 0x1000
        self.notes = []

    def next_ip_id(self):
        self.ip_id = (self.ip_id + 1) & 0xFFFF
        return self.ip_id

    def add(self, ts_usec, frame):
        self.packets.append((ts_usec, frame))

    def note(self, text):
        self.notes.append(text)

    def tcp(self, ts_usec, from_client, src_port, dst_port, seq, ack, flags,
            window, payload=b"", options=b""):
        if from_client:
            src_ip, dst_ip = IP_CLIENT, IP_SERVER
            src_mac, dst_mac = MAC_CLIENT, MAC_SERVER
        else:
            src_ip, dst_ip = IP_SERVER, IP_CLIENT
            src_mac, dst_mac = MAC_SERVER, MAC_CLIENT

        segment = tcp_segment(src_ip, dst_ip, src_port, dst_port,
                              seq, ack, flags, window, payload, options)
        ip = ipv4_header(src_ip, dst_ip, 6, len(segment), self.next_ip_id())
        self.add(ts_usec, eth_frame(src_mac, dst_mac, 0x0800, ip + segment))

    def write(self, path):
        blob = bytearray(struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0,
                                     65535, LINKTYPE_ETHERNET))
        for ts_usec, frame in self.packets:
            blob += struct.pack("<IIII",
                                ts_usec // 1000000, ts_usec % 1000000,
                                len(frame), len(frame))
            blob += frame
        path.write_bytes(bytes(blob))


# ── scenarios ────────────────────────────────────────────────────────────────

def handshake(cap, base_us, port, client_isn, server_isn,
              client_options=b"", server_options=b"", window=8192):
    """
    Three-way handshake. Returns the timestamp just after it completes.

    The SYN options decide how every later window in the connection is read, so
    each scenario chooses them to suit what it needs to demonstrate.
    """
    cap.tcp(base_us, True, port, 80, client_isn, 0, SYN, window,
            options=opt_mss() + client_options)
    cap.tcp(base_us + 10000, False, 80, port, server_isn, client_isn + 1,
            SYN | ACK, window, options=opt_mss() + server_options)
    cap.tcp(base_us + 20000, True, port, 80, client_isn + 1, server_isn + 1,
            ACK, window)
    return base_us + 20000


def scenario_fast_retransmit(cap, base_us):
    """
    Three duplicate ACKs, then the resend they triggered.

    Three is the protocol-defined threshold (RFC 5681 §3.2), so this is the one
    retransmission cause that rests on a signal rather than on a timer.
    """
    port = 40001
    client, server = 1000, 5000
    # Window scaling on both sides, so the analysis has a shift to apply.
    now = handshake(cap, base_us, port, client, server,
                    client_options=opt_wscale(7) + opt_sack_permitted(),
                    server_options=opt_wscale(6) + opt_sack_permitted())
    seq = client + 1
    ack = server + 1
    data = b"A" * 100

    for i in range(3):
        cap.tcp(now + 1000 + i * 1000, True, port, 80,
                seq + i * 100, ack, PSH | ACK, 64, payload=data)
    now += 5000

    # The receiver acknowledges the first segment, then repeats that same ACK
    # three times: it is receiving data but cannot advance past the hole.
    cap.tcp(now, False, 80, port, ack, seq + 100, ACK, 128)
    for i in range(1, 4):
        cap.tcp(now + i * 1000, False, 80, port, ack, seq + 100, ACK, 128)
    now += 5000

    # The resend. Its timing is irrelevant: three duplicate ACKs already
    # explain it, and that outranks any timing guess.
    cap.tcp(now, True, port, 80, seq + 100, ack, PSH | ACK, 64, payload=data)
    cap.note(f"port {port}  duplicate ACKs then a fast retransmission")
    return now + 10000


def scenario_sack_hole(cap, base_us):
    """
    A SACK block naming data the receiver holds, above the cumulative ACK.

    The range between the two is the closest TCP ever comes to stating outright
    which bytes went missing.
    """
    port = 40002
    client, server = 2000, 6000
    now = handshake(cap, base_us, port, client, server,
                    client_options=opt_sack_permitted(),
                    server_options=opt_sack_permitted())
    seq = client + 1
    ack = server + 1
    data = b"B" * 100

    # Three segments go out; the middle one never reaches the receiver.
    cap.tcp(now + 1000, True, port, 80, seq, ack, PSH | ACK, 8192, payload=data)
    cap.tcp(now + 2000, True, port, 80, seq + 200, ack, PSH | ACK, 8192,
            payload=data)
    now += 5000

    # Acknowledges through seq+100, but holds seq+200..seq+300. The 100 bytes
    # between are the hole.
    cap.tcp(now, False, 80, port, ack, seq + 100, ACK, 8192,
            options=opt_sack([(seq + 200, seq + 300)]))
    cap.note(f"port {port}  SACK block revealing a 100-byte hole")
    return now + 10000


def scenario_zero_window(cap, base_us):
    """Zero window, a one-byte probe, then the update that reopens it."""
    port = 40003
    client, server = 3000, 7000
    # No window scaling here: a zero window is zero at any shift, and leaving
    # scaling out keeps the advertised numbers readable in the output.
    now = handshake(cap, base_us, port, client, server)
    seq = client + 1
    ack = server + 1

    # The server's receive buffer fills.
    cap.tcp(now + 1000, False, 80, port, ack, seq, ACK, 0)
    # A second advertisement of the same condition, which must not be counted
    # as a new event.
    cap.tcp(now + 2000, False, 80, port, ack, seq, ACK, 0)
    # One byte, sent only to prompt an update.
    cap.tcp(now + 3000, True, port, 80, seq, ack, PSH | ACK, 8192, payload=b"P")
    # The buffer drains and the window reopens.
    cap.tcp(now + 4000, False, 80, port, ack, seq + 1, ACK, 4096)
    cap.note(f"port {port}  zero window, probe, then window update")
    return now + 14000


def scenario_spurious_retransmission(cap, base_us):
    """
    Data resent after the receiver had already acknowledged it.

    The receiver said it had these bytes, so this verdict does not depend on a
    timer — which is why the analysis checks it before anything else.
    """
    port = 40004
    client, server = 4000, 8000
    now = handshake(cap, base_us, port, client, server)
    seq = client + 1
    ack = server + 1
    data = b"D" * 100

    cap.tcp(now + 1000, True, port, 80, seq, ack, PSH | ACK, 8192, payload=data)
    cap.tcp(now + 2000, False, 80, port, ack, seq + 100, ACK, 8192)
    # Resent 50 ms later: far enough out to rule out reordering, and already
    # acknowledged, so it is spurious rather than an RTO.
    cap.tcp(now + 52000, True, port, 80, seq, ack, PSH | ACK, 8192, payload=data)
    cap.note(f"port {port}  retransmission of already-acknowledged data")
    return now + 62000


def scenario_rto_retransmission(cap, base_us):
    """
    A resend after a silence longer than any plausible retransmission timer.

    No timestamp option anywhere in this connection: an RTT estimate would
    raise the RTO threshold above the 200 ms floor this scenario relies on.
    """
    port = 40005
    client, server = 5000, 9000
    now = handshake(cap, base_us, port, client, server)
    seq = client + 1
    ack = server + 1
    data = b"E" * 100

    cap.tcp(now + 1000, True, port, 80, seq, ack, PSH | ACK, 8192, payload=data)
    # Nothing from the receiver at all — no ACK, no duplicate ACKs. After half
    # a second the sender's timer is the only remaining explanation.
    cap.tcp(now + 501000, True, port, 80, seq, ack, PSH | ACK, 8192,
            payload=data)
    cap.note(f"port {port}  retransmission after a 500 ms silence (RTO)")
    return now + 511000


def scenario_reordering(cap, base_us):
    """
    Two segments swapped in flight.

    The later one arrives first, leaving a gap; its predecessor follows half a
    millisecond behind. Nothing was lost, so the gap is withdrawn rather than
    counted against the connection.
    """
    port = 40006
    client, server = 6000, 10000
    now = handshake(cap, base_us, port, client, server)
    seq = client + 1
    ack = server + 1
    data = b"F" * 100

    cap.tcp(now + 1000, True, port, 80, seq + 100, ack, PSH | ACK, 8192,
            payload=data)
    cap.tcp(now + 1500, True, port, 80, seq, ack, PSH | ACK, 8192, payload=data)
    cap.note(f"port {port}  reordered pair, gap filled 500 us later")
    return now + 11000


def scenario_keep_alive(cap, base_us):
    """
    A keep-alive and the ACK that answers it.

    A keep-alive sits one byte below what the sender owes next (RFC 1122
    §4.2.3.6), which is what distinguishes it from a retransmission of the same
    shape.
    """
    port = 40007
    client, server = 7000, 11000
    now = handshake(cap, base_us, port, client, server)
    seq = client + 1
    ack = server + 1
    data = b"G" * 100

    cap.tcp(now + 1000, True, port, 80, seq, ack, PSH | ACK, 8192, payload=data)
    cap.tcp(now + 2000, False, 80, port, ack, seq + 100, ACK, 8192)

    # Idle, then a probe one below the next byte owed.
    idle = now + 45000000
    cap.tcp(idle, True, port, 80, seq + 99, ack, ACK, 8192)
    cap.tcp(idle + 1000, False, 80, port, ack, seq + 100, ACK, 8192)
    cap.note(f"port {port}  keep-alive and keep-alive ACK")
    return idle + 11000


def main():
    cap = Capture()

    # Scenarios are spaced two seconds apart, comfortably inside the tracker's
    # five-minute idle timeout so every connection is still in the table at the
    # end of the capture. The keep-alive scenario deliberately idles for 45
    # seconds, which is still well short of that timeout.
    now = 1_000_000
    for scenario in (scenario_fast_retransmit,
                     scenario_sack_hole,
                     scenario_zero_window,
                     scenario_spurious_retransmission,
                     scenario_rto_retransmission,
                     scenario_reordering,
                     scenario_keep_alive):
        now = scenario(cap, now) + 2_000_000

    cap.packets.sort(key=lambda entry: entry[0])
    cap.write(OUT_PATH)

    print(f"Wrote {OUT_PATH.relative_to(ROOT)}  "
          f"({len(cap.packets)} packets, {OUT_PATH.stat().st_size} bytes)")
    for note in cap.notes:
        print(f"  {note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
