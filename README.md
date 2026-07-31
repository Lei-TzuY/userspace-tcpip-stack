# TCP/IP Stack

A C99 educational network-stack and packet-analysis project. It parses Ethernet, ARP, IPv4/IPv6, ICMP, TCP, UDP, and higher-level protocol data, and includes stream/state tracking, IPv4 reassembly, ARP cache behavior, and classic pcap/pcapng readers.

## Highlights

- Protocol parsers for Ethernet, ARP, IPv4, IPv6, ICMP/ICMPv6, TCP, UDP, DNS, DHCP/DHCPv6, HTTP, TLS, NTP, GRE, IGMP, and mDNS.
- DNS covering what today's traffic actually carries: EDNS0 with its options decoded, the 12-bit extended RCODE, and DNSSEC records reported structurally.
- Link layers beyond Ethernet: Linux cooked v1/v2, raw IP, and BSD loopback, so captures from `tcpdump -i any`, a VPN interface, or loopback parse rather than being skipped.
- Tunnels decapsulated recursively: GRE, IPv4-in-IPv4, 6in4, PPPoE, and VXLAN, with a depth cap.
- Stateful behaviors including TCP stream tracking, UDP tracking, ARP caching, IPv4 reassembly, and IPv6 reassembly.
- TCP expert analysis: retransmissions attributed to a cause, reordering told apart from loss, window scaling applied, SACK-inferred loss, and per-direction throughput.
- A conversation table, exportable as JSON or CSV.
- Fixture-backed coverage for classic pcap plus little-endian, big-endian, and simple-packet-block pcapng captures.
- A fuzz harness over the same dispatch path the CLI uses, with a checked-in corpus of malformed inputs replayed on every build.
- Portable C99 build configuration with Windows Winsock support and GitHub Actions CMake/CTest validation.

## Repository layout

```text
src/               Protocol parsers, state machines, analysis, dispatch, and CLI
tests/             Unit tests, packet-capture fixtures, and fixture generators
fuzz/              Fuzz targets, drivers, and the checked-in seed corpus
CMakeLists.txt     CMake build and CTest definitions
CLAUDE.md          How to build, test, and extend this without breaking it
PROJECT_STATE.md   What exists, why it is shaped this way, and what is unverified
task_plan.md       Candidate next rounds and their trade-offs
```

`src/main.c` owns only the command line and the capture-reading loop. The
per-frame protocol walk lives in `src/dispatch.c`, so the CLI, the tests, and
the fuzz targets all exercise one implementation rather than three.

## Build and test

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

The integration fixtures under `tests/` cover little- and big-endian pcapng files, simple packet blocks, and a classic pcap capture. Build directories and compiled objects are intentionally excluded from version control.

The unit tests check things with `assert()`, and CMake puts `-DNDEBUG` in every
Release configuration, which compiles `assert()` out. The test targets are
therefore built with `-UNDEBUG` so a Release run still checks what it claims to
— see the `TEST_TARGETS` loop in CMakeLists.txt. **A new test target has to be
added to that list**, or its assertions will silently do nothing in the four CI
jobs that build Release.

### Build options

| Option | Default | Effect |
| --- | --- | --- |
| `TCPIP_SANITIZE` | `OFF` | AddressSanitizer, plus UndefinedBehaviorSanitizer on GCC/Clang. On MSVC, AddressSanitizer only. |
| `TCPIP_FUZZ` | `OFF` | Additionally build libFuzzer-instrumented targets. Requires Clang. |

## Run

After building, pass a capture to the generated `tcpip` executable:

```sh
./build/tcpip tests/sample.pcap
```

```text
Usage: tcpip [options] <file.pcap|file.pcapng>

  -q, --quiet         suppress the per-packet output; print only the
                      end-of-capture summaries
      --no-summary    suppress the human-readable summaries
      --json[=PATH]   write the analysis as JSON (default stdout)
      --csv[=PATH]    write the conversation table as CSV (default stdout)
  -h, --help          show this help and exit
```

Asking for JSON or CSV on stdout implies `--quiet --no-summary`, since a
structured document has to be the only thing on the stream. Diagnostics always
go to stderr, so a malformed packet is still reported in quiet mode.

## Link layers and tunnels

A capture names its link layer once, in its global header. Ethernet is the most
common but far from the only one, and a capture in another shape used to parse
to nothing.

| Link type | Where it comes from |
| --- | --- |
| `LINKTYPE_ETHERNET` (1) | ordinary interface captures |
| `LINKTYPE_LINUX_SLL` (113) | `tcpdump -i any` on Linux |
| `LINKTYPE_LINUX_SLL2` (276) | the same, with newer libpcap |
| `LINKTYPE_RAW` (101) | tunnel and VPN interfaces, which have no link header |
| `LINKTYPE_NULL` (0) | BSD and macOS loopback |

The loopback header is a four-byte address family written in the *capturing
host's* byte order with nothing recording which that was, so both orientations
are tried and the one yielding a known family wins. The IPv6 constant differs
per system — 10, 24, 28, or 30 — and all are accepted, which is what libpcap's
own readers do.

Tunnels are followed into their payload: GRE, IPv4-in-IPv4 (protocol 4), 6in4
(protocol 41), the IPv6 equivalents, PPPoE sessions, and VXLAN. VXLAN is the
one that returns the walk to the link layer, since it carries a complete inner
Ethernet frame.

That recursion is capped at `STACK_MAX_ENCAP_DEPTH` (8). The cap is not
cosmetic: the packet alone decides how many layers there are, each one costs a
stack frame, and a single packet small enough to fit the read buffer can name
thousands. `tests/gen_encap_pcap.py` includes a twelve-deep packet so the suite
checks that the walk stops.

## DNS: EDNS0 and DNSSEC

Almost every query on the wire today carries an OPT record, and the parser used
to show it as an ordinary additional-section entry — owner `.`, class 1232,
TTL 32768. All three of those readings are wrong. OPT is a pseudo-record: it
describes this one message rather than a name, its class field is the
requestor's UDP payload size, and its TTL field is a flags word. It is lifted
into its own block instead.

```text
|  -- EDNS0 (RFC 6891) --
|    UDP size : 1232  version=0  flags=0x8000  [DO]
|    option 8     Client Subnet   192.0.2.0/24 scope /0
|    option 10    Cookie          client 0102030405060708
|    option 15    Extended Error  6 (DNSSEC Bogus) "no RRSIG covering the A record"
```

The consequence worth knowing is the response code. Without EDNS0 the RCODE is
the header's low four bits; an OPT supplies eight more significant bits, and
that is the only way `BADVERS` (16) or `BADCOOKIE` (23) can be expressed at
all. Reading just the header reports those as `NOERROR` and `YXRRSET` — not a
truncated answer but a different one. `dns_full_rcode()` composes both halves,
and every RCODE the tool prints comes from it.

Client Subnet is the option worth watching in a parser: the sender declares a
prefix length, and the address is truncated to that many bits rounded up to an
octet. The declared length is checked against the address family's width and
against how many bytes actually arrived, before either drives a copy.

DNSSEC records are reported, never validated:

| Record | Reported |
| --- | --- |
| DNSKEY | flags (ZONE/SEP/REVOKE), algorithm, and the key tag computed per RFC 4034 Appendix B |
| DS | key tag, algorithm, digest type, digest |
| RRSIG | type covered, algorithm, validity window, key tag, signer |
| NSEC / NSEC3 | next name or hash, and the types in the bit map |
| NSEC3PARAM | hash algorithm, iterations, salt |

The key tag is worth computing even without validation: it is what links a
DNSKEY to the DS above it and the RRSIGs below it, so a capture can be read as
a chain rather than as three unrelated records.

RRSIG validity times are formatted without `gmtime()`. The wire field is 32
bits unsigned, `time_t` is signed and still 32 bits in places, so a signature
expiring after 2038 would come back negative or NULL — the conversion is
written out instead, and `tests/sample-dns.pcap` carries a 2100 timestamp to
keep that honest.

`tests/gen_dns_pcap.py` builds that capture, one scenario per packet.

## TCP analysis

The tracker decides where a segment sits in sequence space; `src/tcp_analysis.c`
decides what that placement means.

| Reported | Basis |
| --- | --- |
| spurious retransmission | the peer had already acknowledged those bytes |
| fast retransmission | the peer had sent three or more duplicate ACKs (RFC 5681 §3.2) |
| RTO retransmission | sent after a silence exceeding SRTT + 4·RTTVAR, floored at 200 ms (RFC 6298) |
| out-of-order | a gap filled within 3 ms, or data below the expected point arriving too fast for a resend to explain |
| duplicate ACK | no data, no new acknowledgement, unchanged window, peer still has data outstanding |
| window full / zero window / zero-window probe | bytes in flight against the peer's advertised window |
| keep-alive | positioned one byte below what the sender owes next (RFC 1122 §4.2.3.6) |
| SACK holes | the ranges between the cumulative ACK and the SACK blocks |
| window scaling | applied only when both directions offered it, and never to a SYN's own window (RFC 7323 §2.2) |

Two things are worth knowing about the verdicts. Where one rests on a timing
threshold rather than on something the protocol states outright, the comment at
the decision in `tcp_analysis.c` says so — those are heuristics, and a capture
taken at the other end of the path can disagree. And an endpoint whose own SYN
was never captured has an unknown window-scale shift; that is reported as
`null` in JSON and left empty in CSV rather than as `0`, which would claim it
asked for no scaling.

Ordering matters in the retransmission verdicts: spurious is tested first
because it is the only one the peer confirms outright, then fast retransmit
because three duplicate ACKs are a protocol-defined trigger, and only then the
timer-based guess.

### Export

`--json` emits the whole structure; `--csv` emits one row per direction of each
connection, which is the unit the analysis measures — a retransmission count
for a "connection" would have to hide which side did the retransmitting.

```sh
./build/tcpip --json=report.json tests/sample-analysis.pcap
./build/tcpip --csv tests/sample-analysis.pcap | column -t -s,
```

`tests/sample-analysis.pcap` is generated by `tests/gen_analysis_pcap.py` and
carries one connection per scenario — duplicate ACKs and fast retransmit, a
SACK hole, zero window and probe, a spurious resend, an RTO resend, a reordered
pair, and a keep-alive. Its timestamps are chosen to land on specific sides of
the analysis thresholds, so regenerate it with that script rather than editing
it by hand:

```sh
python tests/gen_analysis_pcap.py
```

## Fuzzing

Every parser here consumes bytes chosen by whoever sent the packet, so the
bounds checks are the part most worth testing. Three targets sit on the same
`LLVMFuzzerTestOneInput` entry point:

| Target | Input | Reaches |
| --- | --- | --- |
| `frame` | length-prefixed sequence of Ethernet frames | the whole dispatch chain, including reassembly, the TCP state machine, and the ARP cache, which need several frames to enter |
| `parsers` | a selector byte, then one parser's buffer | any single parser directly, without having to keep the outer headers plausible |
| `pcap` | a whole capture file | the pcap/pcapng reader: block totals, option padding, and the byte-swap paths |

Each is built two ways. `fuzz_<name>_replay` uses a standalone driver that
works with any compiler and replays the corpus under CTest. `fuzz_<name>` is
libFuzzer-instrumented and needs Clang.

Replay the corpus under a sanitizer — this is what CTest runs:

```sh
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DTCPIP_SANITIZE=ON
cmake --build build-asan
ctest --test-dir build-asan --output-on-failure
```

Run a coverage-guided campaign (Clang):

```sh
CC=clang cmake -S . -B build-fuzz -DCMAKE_BUILD_TYPE=Debug \
    -DTCPIP_SANITIZE=ON -DTCPIP_FUZZ=ON
cmake --build build-fuzz
./build-fuzz/fuzz_frame -close_fd_mask=3 fuzz/corpus/frame
```

Without Clang, the replay driver also has a dumb mutation mode. It has no
coverage feedback, so it is far weaker than libFuzzer, but paired with a
sanitizer it still finds bounds bugs — and it is the only option on MSVC:

```sh
./build-asan/fuzz_parsers_replay --mutate=100000 --seed=1 \
    --save-current=/tmp/current.bin fuzz/corpus/parsers
```

Mutation is deterministic given `--seed`, so a crash reproduces: re-run with
the same seed and `--save-current`, and that file holds the candidate that was
executing when the process died.

### The corpus

`fuzz/corpus/` is generated by `tests/gen_fuzz_corpus.py` and checked in. Valid
seeds come from `tests/sample.pcap`, which already reaches deep into every
parser; from `tests/sample-analysis.pcap`, which is the only fixture carrying
SACK options, duplicate-ACK runs, and zero-window advertisements — so it is
what reaches the expert analysis at all; and from `tests/sample-dns.pcap`,
which is the only one carrying an OPT record or a signed RRset. The rest are
hand-built malformed inputs aimed at the places where the stack walks an
attacker-controlled length: TLV option chains, DNS name compression, EDNS
option lists, NSEC type bit maps, IPv6 extension headers, and pcapng block
totals.

Four scripts generate checked-in files, and the corpus seeds from the captures
the other three produce, so it goes last:

```sh
python tests/gen_analysis_pcap.py   # tests/sample-analysis.pcap
python tests/gen_encap_pcap.py      # tests/sample-{sll,sll2,raw,null,encap}.pcap
python tests/gen_dns_pcap.py        # tests/sample-dns.pcap
python tests/gen_fuzz_corpus.py     # fuzz/corpus/
```

CI checks that all of them still match their generators.

When a campaign finds a crash, copy the reproducer into the matching corpus
directory and commit it. Nothing else needs editing — CTest picks it up, and
the crash cannot come back unnoticed.

## Continuous integration

Every push and pull request runs:

- Release build and test on Linux, Windows/MSVC, and macOS.
- A big-endian build and test on emulated s390x. Every multi-byte field here is
  assembled by hand or through `ntohs`, and the pcap reader picks a byte-swap
  path from the file's magic number; on a big-endian host those paths trade
  places, so this is the only configuration that covers the other half.
- AddressSanitizer and UndefinedBehaviorSanitizer under both GCC and Clang.
- A short libFuzzer campaign on each target, as a tripwire for a change that
  breaks a bounds check the checked-in corpus does not already cover.
- A check that `fuzz/corpus/` and `tests/sample-analysis.pcap` still match their
  generators.

This is an educational userspace parser/state-machine project, not an operating-system network stack or a hardened packet-processing library.
