# Contributing

Contributions are welcome when they keep the stack portable, inspectable, and safe on malformed input. Small changes with focused tests are easier to review than broad protocol rewrites.

## Development setup

The default build requires a C99 compiler and CMake 3.13 or newer:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Parser changes should also pass the sanitizer configuration:

```sh
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DTCPIP_SANITIZE=ON
cmake --build build-asan --parallel
ctest --test-dir build-asan --output-on-failure
```

Clang contributors can run the same libFuzzer targets used by CI:

```sh
CC=clang cmake -S . -B build-fuzz -DCMAKE_BUILD_TYPE=Debug \
  -DTCPIP_SANITIZE=ON -DTCPIP_FUZZ=ON
cmake --build build-fuzz --parallel
./build-fuzz/fuzz_frame -max_total_time=60 fuzz/corpus/frame
```

## Change requirements

- Treat packet lengths, offsets, counts, and nested encapsulation as untrusted.
- Check a complete field is present before reading or advancing a cursor.
- Preserve the C99 build and avoid compiler-specific behavior unless it is isolated.
- Add a focused unit test for protocol logic and a fixture-backed test when dispatch, link type, or capture parsing is involved.
- Add malformed and truncated examples, not only a valid happy path.
- Keep output stable unless the change deliberately updates the CLI contract.
- Document protocol ambiguity or unsupported encrypted fields instead of guessing.

Tests use `assert()`, so their CMake targets explicitly undefine `NDEBUG`. Add new test executables to the `TEST_TARGETS` handling in `CMakeLists.txt` so Release CI does not silently compile assertions out.

## Generated fixtures and corpus

The checked-in captures and fuzz seeds are reproducible. If a generator changes, regenerate files in this order:

```sh
python tests/gen_analysis_pcap.py
python tests/gen_encap_pcap.py
python tests/gen_dns_pcap.py
python tests/gen_transport_pcap.py
python tests/gen_fuzz_corpus.py
```

Commit the generator and its resulting fixtures together. CI regenerates them and fails on drift.

## Pull requests

Describe:

1. the invariant or protocol behavior being changed;
2. the failure mode the new test demonstrates;
3. the commands used to validate the change;
4. any portability, compatibility, or output-format impact.

Do not include capture files containing private traffic or credentials. Prefer minimal synthetic fixtures produced by the repository generators.
