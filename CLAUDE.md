# CLAUDE.md — working notes for an agent session

Operational guidance for anyone (human or agent) picking this repository up
cold. `PROJECT_STATE.md` records *what exists and why*; `task_plan.md` records
*what is worth doing next*. This file records *how to work here without
breaking anything*.

## What this is

A C99 educational TCP/IP stack and offline packet analyser. It reads a pcap or
pcapng capture, walks each packet down through the protocol layers, prints what
it finds, tracks per-connection state across packets, and can export the result
as JSON or CSV.

It is a userspace parser and state machine. It is **not** an operating-system
network stack, it sends nothing, and it opens no sockets — the Winsock link is
for `ntohs`/`ntohl` only.

## Build and test

Portable form, works anywhere with CMake and a C99 compiler:

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

Sanitizer build — this is the one that matters, because it is what turns the
fuzz corpus replay from a crash check into a memory-error check:

```sh
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DTCPIP_SANITIZE=ON
cmake --build build-asan
ctest --test-dir build-asan --output-on-failure
```

Both must be **99/99** before a commit. See `PROJECT_STATE.md` for the baseline
breakdown.

### On this machine (Windows)

There is no compiler on `PATH` by default. Visual Studio 18 Community is
installed and carries everything needed, including CMake and an ASan runtime;
`ninja` comes from a Python 3.10 install. Nothing needs installing. Write this
helper to a scratch directory and run every build command through it:

```bat
@echo off
REM Set up MSVC x64 environment and expose bundled CMake + Python's ninja.
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
set "PATH=C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;C:\Users\User\AppData\Local\Programs\Python\Python310\Scripts;%PATH%"
cd /d "c:\Users\User\Desktop\All project\computer-science-labs\TCP-IP Stack"
%*
```

Then, from PowerShell:

```powershell
& "$scratch\devbuild.bat" cmake -S . -B build-msvc -G Ninja -DCMAKE_BUILD_TYPE=Debug
& "$scratch\devbuild.bat" cmake --build build-msvc
& "$scratch\devbuild.bat" ctest --test-dir build-msvc --output-on-failure
```

`vcvars64.bat` prints a `vswhere.exe is not recognized` line on this
installation. It is noise — the environment is still set correctly and the
build works. Do not go chasing it.

`build-msvc/` (plain) and `build-asan/` (`-DTCPIP_SANITIZE=ON`) already exist
and are gitignored.

## Layout

```text
src/            Parsers, state machines, analysis, dispatch, CLI
  main.c          command line + capture-reading loop, nothing else
  dispatch.c      the per-frame protocol walk — one implementation, shared
  tcp_analysis.c  expert verdicts; depends only on tcp.h
  report.c        JSON/CSV export
  linktype.c      non-Ethernet link layers
  pppoe.c vxlan.c gre.c   tunnels
tests/          Unit tests, capture fixtures, and the generators for both
fuzz/           Three targets, two drivers each, plus the checked-in corpus
.github/        7 CI jobs
```

`src/main.c` deliberately owns *only* argument parsing and the read loop. The
protocol walk lives in `src/dispatch.c` so the CLI, the tests, and the three
fuzz targets exercise one code path rather than three near-copies. **Do not put
protocol logic back into main.c.**

## Conventions

- **C99, no dependencies.** Standard library plus Winsock for byte order. Do
  not add a third-party library, a build-system feature newer than CMake 3.13,
  or a compiler extension.
- **Warnings are errors in practice.** MSVC `/W4` and GCC/Clang
  `-Wall -Wextra` must stay silent. Watch narrowing conversions in particular —
  most fields here are `uint8_t`/`uint16_t` and MSVC is stricter than GCC.
- **Every parser takes `(const uint8_t* data, size_t len, T* out)` and returns
  0 or −1.** It must never read past `len`, whatever the packet's own length
  fields claim. Validate a declared length *before* using it to index.
- **Comments explain why, not what.** The existing comments say what the RFC
  requires, what an attacker controls, or why a threshold was chosen. Match
  that; do not add narration of the next line of code.
- **Cite the RFC when a rule comes from one** (`RFC 5681 §3.2`), and say
  outright when a rule is a heuristic instead.

## Invariants — do not break these

These are load-bearing. Each one exists because something went wrong without
it, and most are pinned by a test that will not obviously name the invariant
when it fails.

1. **`STACK_MAX_ENCAP_DEPTH` is enforced on every function a tunnel can
   re-enter**, and `depth` is passed as an argument, never stored in
   `StackContext`. Storing it would let it leak between packets. Without the
   cap, one packet that fits the 64 KB read buffer exhausts the C stack and
   kills the process.
2. **A structured document on stdout is the only thing on stdout.** `--json` or
   `--csv` without a path implies `--quiet --no-summary`, and the stdout
   silencer is installed *before* `pcap_open`, whose banner would otherwise sit
   in front of the JSON. Refusing `--json --csv` both to stdout is deliberate.
3. **Diagnostics go to stderr and are never silenced.** A malformed packet is
   still reported in quiet mode.
4. **An unknown TCP window scale is `null` in JSON and empty in CSV — never
   `0`.** Zero means "asked for no scaling", which is a different claim from
   "we never saw the SYN".
5. **Retransmission verdicts are tested in order: spurious, then fast, then
   RTO.** Spurious is the only one the peer confirms outright; fast has a
   protocol-defined trigger; the timer-based guess is last because it is a
   guess.
6. **`TcpOption.data_len` is the number of bytes actually stored, not the
   length the sender declared.** They differ for an oversized option, and the
   whole point of the field is that a consumer can walk it safely.
7. **Window scaling applies only when both directions offered it**, and never
   to a SYN's own window (RFC 7323 §2.2).
8. **The fuzz drivers hand the dispatcher an allocation sized exactly to the
   input.** Dispatching out of a large fixed buffer puts every overread inside
   a valid object where ASan cannot see it. This is what made the harness give
   a false green once already — see `PROJECT_STATE.md`.
9. **`.gitattributes` keeps `fuzz/corpus/**` and `*.pcap*` binary.** `core.autocrlf`
   is on for this user; without the marking, the bare-LF HTTP corpus inputs are
   silently rewritten into different test cases on checkout.
10. **Generated files are regenerated in dependency order**, because the corpus
    seeds from the captures:

    ```sh
    python tests/gen_analysis_pcap.py   # tests/sample-analysis.pcap
    python tests/gen_encap_pcap.py      # tests/sample-{sll,sll2,raw,null,encap}.pcap
    python tests/gen_fuzz_corpus.py     # fuzz/corpus/
    ```

    CI fails if the checked-in copies differ. Never hand-edit them —
    `sample-analysis.pcap`'s timestamps are placed on specific sides of the
    analysis thresholds, so an edit silently changes which verdict is tested.

## Adding things

**A new parser.** Add `src/foo.{c,h}`; the `file(GLOB)` in CMakeLists picks it
up. Dispatch from `src/dispatch.c`. Add a `test_foo.c` with an `add_test`, add
a selector case in `fuzz/fuzz_parsers.c`, and add malformed seeds to
`tests/gen_fuzz_corpus.py`. A parser with no fuzz selector is not covered by
anything.

**A new fuzz-corpus entry after a crash.** Drop the reproducer into
`fuzz/corpus/<target>/` and commit. CTest picks it up automatically and the
crash cannot come back unnoticed. Nothing else needs editing.

**A new capture-driven assertion.** Use the `add_capture_test(name, fixture,
regex)` and `add_analysis_test(name, regex)` helpers at the bottom of
CMakeLists.txt. One assertion per behaviour, so a failure names what broke.

## Gotchas on this machine

- **PowerShell `>` writes a UTF-8 BOM.** `json.load` and `csv.DictReader` choke
  on it. Use the tool's own `--json=PATH` / `--csv=PATH` instead of redirecting.
- **`Select-Object -First N` on a native command's output kills the process and
  reports exit 255.** Redirect to a log file first, then filter the file.
- **A `|` inside a quoted `ctest -R "a|b"` gets reinterpreted** when the command
  passes through a batch file's `%*`. Use a regex without an alternation.
- **CMake's object-path limit is 250 characters.** A build directory under the
  scratchpad path is already ~120 characters deep and will hit `RC2136` /
  "object file directory has 235 characters". If you need a throwaway worktree,
  put it somewhere short like `C:/Users/User/AppData/Local/Temp/tv`.
- **A running fuzz campaign holds the binary open**, and the next build fails
  with `LNK1104`. That is not a code error.
- Prefer writing a `.py` helper to the scratchpad over `python -c` with a
  heredoc; the quoting does not survive the shell layers.

## Before you commit

1. Both builds green: `ctest` on plain **and** on the ASan build, 99/99 each.
2. If you touched a parser, run a mutation campaign as well — see
   `PROJECT_STATE.md` for the invocation. libFuzzer is unavailable here (no
   Clang); the replay driver's `--mutate` mode is the substitute.
3. If you touched a generator, re-run all three in order and check the diff is
   what you meant.
4. Commit messages explain *why*, in the style of the existing history — read
   `git log` before writing one.
