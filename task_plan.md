# task_plan.md

What is worth doing next, in what order, and how to tell when a round is done.
Current state is in `PROJECT_STATE.md`; working rules are in `CLAUDE.md`.

## Where we are

Four rounds are complete and committed on `tcp-analysis-and-fuzz-harness`:
robustness (fuzzing, sanitizers, CI), TCP expert analysis with JSON/CSV export,
encapsulation breadth, and DNS depth. 115/115 tests pass in the plain, ASan,
and Release builds. Nothing is half-finished; any of the options below can
start from a clean tree.

Round 4 also fixed two defects in the test suite itself: `-DNDEBUG` had been
compiling every assertion out of the four CI jobs that build Release, and a
failing assertion on Windows opened a dialog box instead of failing. Both are
recorded in `PROJECT_STATE.md`, and the rule they imply — new test targets go
in `TEST_TARGETS` — is in `CLAUDE.md`.

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

## Option B — transport breadth: SCTP and QUIC

**Scope.** SCTP common header and chunk walk (DATA, INIT, SACK, HEARTBEAT),
including the CRC32c checksum. QUIC long-header Initial packets: version,
connection IDs, and enough to name the version and the handshake — *not*
decryption, which needs the HKDF key schedule and is a different project.

**Why.** SCTP is the last classic transport the stack does not know, and its
chunk walk is exactly the TLV-length pattern where the other bugs lived. QUIC
carries a growing share of real traffic and currently shows as unremarkable UDP.

**Risk.** Low for SCTP. QUIC has a variable-length integer encoding that is easy
to get subtly wrong on the boundary cases — fuzz it hard.

**Size.** Medium. SCTP alone is small and self-contained.

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

## Recommended order

**A → B → D → F → C.** (E is done.)

A first, and now with more reason than before. Round 4 established that four of
the seven jobs would have run hollow unit tests, which means the value of
actually running CI is higher than the original estimate — it is not only
"does it build on s390x" but "does the suite check anything there". Everything
below still assumes the current tree is correct, and CI remains the only thing
that can test that assumption on three architectures and two sanitizers.

Then B for SCTP (small, self-contained) before QUIC. D and F are interchangeable
filler that can absorb a partial session. C last, because it is the largest and
benefits from a shared BER/DER decoder if D landed SNMP first.

If the goal is *demonstrable* capability rather than correctness, invert this:
C produces the most striking output. But it should not go first while three CI
jobs have never run.

## Explicitly not planned

- **Live capture.** Needs libpcap, which breaks the no-dependency rule. Offline
  analysis is the project's scope.
- **Packet transmission.** This is a parser, not a stack that speaks.
- **TLS decryption.** Out of scope even with keys; a different project.
- **Performance work.** Nothing here is slow enough to matter, and optimising a
  parser before it is proven correct is the wrong order.
