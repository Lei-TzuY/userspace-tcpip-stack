# task_plan.md

What is worth doing next, in what order, and how to tell when a round is done.
Current state is in `PROJECT_STATE.md`; working rules are in `CLAUDE.md`.

## Where we are

Five rounds are complete and committed on `tcp-analysis-and-fuzz-harness`:
robustness (fuzzing, sanitizers, CI), TCP expert analysis with JSON/CSV export,
encapsulation breadth, DNS depth, and transport breadth (SCTP and QUIC).
134/134 tests pass in the plain, ASan, and Release builds. Nothing is
half-finished; any of the options below can start from a clean tree.

Round 4 also fixed two defects in the test suite itself: `-DNDEBUG` had been
compiling every assertion out of the four CI jobs that build Release, and a
failing assertion on Windows opened a dialog box instead of failing. Both are
recorded in `PROJECT_STATE.md`, and the rule they imply — new test targets go
in `TEST_TARGETS` — is in `CLAUDE.md`.

Round 5 turned up one thing worth carrying forward: the `IPPROTO_*` defines in
`dispatch.c` had always been macro redefinitions on glibc, which is a
diagnostic on GCC and Clang. Nobody had seen it because the jobs that would
print it have never run. That is the third time a defect has survived because
CI is unexecuted rather than because it was hard to find.

## Definition of done — applies to every round

A round is not finished until all of these hold:

1. `ctest` is green in the plain build **and** the ASan build, with the count
   higher than it started. Run Release too when the change touches tests — it
   is what four CI jobs build, and it is where a broken assertion hides.
2. Every new parser has a unit test, a `fuzz_parsers` selector, and malformed
   seeds in `tests/gen_fuzz_corpus.py`.
3. A mutation campaign over the affected targets runs clean (three targets ×
   two seeds is what the last rounds used).
4. `/W4` and `-Wall -Wextra` stay silent.
5. New behaviour is documented in `README.md`, and any new invariant is added to
   the numbered list in `CLAUDE.md`.
6. The commit message explains *why*, not *what*.

## Option A — push the branch and get CI actually green

**Recommended first.** This is the largest unknown in the project and the
cheapest to resolve.

Seven CI jobs exist and none has ever executed. Three carry real risk:

- **s390x big-endian under QEMU.** The one configuration that exercises the
  other half of every byte-swap path. Genuinely likely to find something.
- **libFuzzer smoke.** Never run at all; the first coverage-guided campaign
  reaches places 210,000 dumb mutations did not.
- **ASan + UBSan on GCC/Clang.** UBSan has never run anywhere, and
  `-fno-sanitize-recover=undefined` makes any finding fatal. Unaligned loads and
  signed overflow in the checksum paths are the plausible candidates.

Everything else in this plan is built on the assumption that the current tree is
correct. This is the cheapest way to test that assumption, and any finding
changes what the next round should be.

**Done when:** all 7 jobs pass on the pushed branch, or the failures are fixed
and pass.

## ~~Option B — transport breadth: SCTP and QUIC~~ — done, round 5

Delivered: the SCTP common header, chunk walk, and the parameter and
error-cause walks nested inside it, with a CRC-32C verified against published
check values; QUIC long headers for v1, v2, the drafts and Version
Negotiation, including coalesced packets and the RFC 9000 §16 variable-length
integer. `tests/sample-transport.pcap` and 84 new corpus inputs came with it.

The estimate was right about where the risk was — the varint and the coalescing
walk are the fiddly parts — but wrong about what would take the time. The
parsers were straightforward; what needed thought was deciding *when* to claim
a datagram is QUIC, since the long header is not distinctive enough to sniff on
its own.

Two things it did not do, both recorded in `PROJECT_STATE.md`: neither protocol
is tracked across packets (no SCTP association state, no QUIC connection table
keyed by connection ID), and QUIC is only looked for on four ports.

## Option C — TLS depth: certificates, ALPN, JA3

**Scope.** Parse the Certificate message's DER far enough to report subject,
issuer, and validity dates; extract ALPN from ClientHello and ServerHello; and
compute the JA3/JA3S fingerprints.

**Why.** The most *useful* addition to an analysis tool — it is what an analyst
actually wants from a capture. It also exercises a genuinely adversarial
format: DER length encoding is nested, self-describing, and attacker-controlled,
which is the same shape as the bugs already found.

**Risk.** Highest of the options here, and that is the point. Also: JA3 is an
MD5 of a formatted string, so it needs an MD5 implementation in-tree (the
no-dependency rule forbids linking one). MD5 is ~150 lines and only ever used
for a fingerprint here, never for security — say so in the comment.

**Size.** Large. DER alone is a round.

## Option D — application breadth: SSH, SMTP, MQTT, SIP, SNMP

**Scope.** Sniffers and light parsers on the existing `handle_tcp_payload` /
`handle_udp_payload` hooks. SSH version exchange and KEXINIT algorithm lists;
SMTP command/response; MQTT CONNECT/PUBLISH; SIP request line and key headers;
SNMP v1/v2c, which needs a small BER decoder.

**Why.** Broad, visible coverage gain for modest effort. Each protocol is
independent, so it parallelises well and a single failure does not block the
rest.

**Risk.** Low, except SNMP's BER — same family of hazard as DER, so if Option C
happens first the decoder can be shared.

**Size.** Medium, and easily split across several commits.

## ~~Option E — DNS depth: EDNS0 and DNSSEC~~ — done, round 4

Delivered: the OPT pseudo-record hoisted out of the additional section, its
options decoded (Client Subnet, Cookie, Extended DNS Error, TCP Keepalive,
NSID, Padding), the 12-bit extended RCODE, and DS / DNSKEY / RRSIG / NSEC /
NSEC3 / NSEC3PARAM reported structurally with the DNSKEY key tag computed.
`tests/sample-dns.pcap` and 32 new corpus inputs came with it.

The estimate held — it was the small round it looked like. What it did not
predict is that verifying one of its own assertions would surface two defects
in how the suite is built. That is worth remembering when sizing the options
below: the parser work is usually the predictable part.

## Option F — layer 2/3 breadth: MPLS, IPsec, 802.1ad

**Scope.** MPLS label stacks (with a stack-depth cap, same reasoning as the
tunnel cap), IPsec ESP and AH headers reported without decryption, and QinQ
double VLAN tagging.

**Why.** Completes the encapsulation work from round 3. MPLS in particular is
another unbounded-nesting shape, and the cap infrastructure already exists.

**Risk.** Low — this is the same pattern round 3 established, applied again.

**Size.** Small to medium.

## Option G — track SCTP associations and QUIC connections

**Scope.** For SCTP: an association table keyed by the verification tag and the
address/port pair, TSN accounting, and retransmission and gap detection of the
kind `tcp_analysis.c` already does for TCP. For QUIC: a connection table keyed
by connection ID, so a datagram can be attributed to a handshake seen earlier
and a connection migration is visible rather than looking like a new flow.

**Why.** Round 5 made both protocols readable per packet, which is where the
existing UDP support already was and well short of what the TCP side does.
The analysis machinery is the project's most distinctive part and neither new
transport reaches it.

**Risk.** Medium. QUIC connection IDs are chosen by the receiver and can be
retired and replaced mid-connection, and the frames that do so are encrypted —
so the table can only ever be keyed on what the handshake exposed in clear.
Say so rather than implying more.

**Size.** Medium for SCTP, larger for QUIC.

## Recommended order

**A → G → D → F → C.** (B and E are done.)

A first, and now with more reason than before. Round 4 established that four of
the seven jobs would have run hollow unit tests; round 5 found a macro
redefinition that GCC and Clang would both have flagged on the first run. That
is twice now that the cost of unexecuted CI has been paid in defects found
later than they should have been. Everything below still assumes the current
tree is correct, and CI remains the only thing that can test that assumption on
three architectures and two sanitizers.

Then G, which is what makes round 5's parsers worth as much as the TCP side.
D and F are interchangeable filler that can absorb a partial session. C last,
because it is the largest and benefits from a shared BER/DER decoder if D
landed SNMP first.

If the goal is *demonstrable* capability rather than correctness, invert this:
C produces the most striking output. But it should not go first while three CI
jobs have never run.

## Explicitly not planned

- **Live capture.** Needs libpcap, which breaks the no-dependency rule. Offline
  analysis is the project's scope.
- **Packet transmission.** This is a parser, not a stack that speaks.
- **TLS decryption.** Out of scope even with keys; a different project.
- **QUIC decryption.** The Initial keys are derivable from the version and the
  client's connection ID, so an Initial packet's CRYPTO frames *could* be read
  without any secret — but it needs HKDF-SHA256 and AES-GCM in-tree, which is
  a cryptography project wearing a parser's clothes. Everything after the
  handshake needs keys the capture does not contain.
- **Performance work.** Nothing here is slow enough to matter, and optimising a
  parser before it is proven correct is the wrong order.
