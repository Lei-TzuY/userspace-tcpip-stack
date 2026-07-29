# TCP/IP Stack

A C99 educational network-stack and packet-analysis project. It parses Ethernet, ARP, IPv4/IPv6, ICMP, TCP, UDP, and higher-level protocol data, and includes stream/state tracking, IPv4 reassembly, ARP cache behavior, and classic pcap/pcapng readers.

## Highlights

- Protocol parsers for Ethernet, ARP, IPv4, IPv6, ICMP/ICMPv6, TCP, UDP, DNS, DHCP/DHCPv6, HTTP, TLS, NTP, GRE, IGMP, and mDNS.
- Stateful behaviors including TCP stream tracking, UDP tracking, ARP caching, IPv4 reassembly, and IPv6 reassembly.
- Fixture-backed coverage for classic pcap plus little-endian, big-endian, and simple-packet-block pcapng captures.
- Portable C99 build configuration with Windows Winsock support and GitHub Actions CMake/CTest validation.

## Repository layout

```text
src/            Protocol parsers, state machines, and CLI entry point
tests/          Unit tests and packet-capture fixtures
CMakeLists.txt  CMake build and CTest definitions
```

## Build and test

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

The integration fixtures under `tests/` cover little- and big-endian pcapng files, simple packet blocks, and a classic pcap capture. Build directories and compiled objects are intentionally excluded from version control.

The CI workflow runs the same CMake configure, build, and CTest sequence on every pull request and push to `main`.

## Run

After building, pass a capture to the generated `tcpip` executable:

```sh
./build/tcpip tests/sample.pcap
```

This is an educational userspace parser/state-machine project, not an operating-system network stack or a hardened packet-processing library.
