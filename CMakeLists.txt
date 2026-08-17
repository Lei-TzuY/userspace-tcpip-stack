# 3.13 for add_link_options / target_link_options, used by the sanitizer and
# fuzzer configurations below.
cmake_minimum_required(VERSION 3.13)
project(ToyTCPIP C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)

# Compiler-specific flags
if(MSVC)
    # /W4           — all warnings
    # /utf-8        — source and execution character set = UTF-8 (box-drawing chars)
    # /wd4996       — suppress CRT "unsafe" deprecation noise (strcat etc.)
    add_compile_options(/W4 /utf-8 /wd4996)
    # Link the Winsock2 library required by common.h on Windows
    link_libraries(ws2_32)
else()
    add_compile_options(-Wall -Wextra)
endif()

option(TCPIP_SANITIZE
       "Build with AddressSanitizer (plus UndefinedBehaviorSanitizer on GCC/Clang)"
       OFF)
option(TCPIP_FUZZ
       "Additionally build libFuzzer-instrumented fuzz targets (Clang only)"
       OFF)

# ── Sanitizers ────────────────────────────────────────────────────────────────
# These parsers consume untrusted bytes, so the sanitizer builds are the real
# test of the bounds checks; the assertions in tests/ only cover what we thought
# to assert.
if(TCPIP_SANITIZE)
    if(MSVC)
        # /RTC1 and the Debug runtime checks are incompatible with /fsanitize,
        # and ASan needs the non-incremental linker.
        string(REGEX REPLACE "/RTC[1csu]+" "" CMAKE_C_FLAGS_DEBUG
               "${CMAKE_C_FLAGS_DEBUG}")
        add_compile_options(/fsanitize=address /Zi)
        add_link_options(/INCREMENTAL:NO /DEBUG)
        message(STATUS "Sanitizers: AddressSanitizer (MSVC; no UBSan available)")
    else()
        # -fno-sanitize-recover makes a UBSan finding abort instead of printing
        # and continuing, so CTest actually fails on it.
        add_compile_options(-fsanitize=address,undefined
                            -fno-sanitize-recover=undefined
                            -fno-omit-frame-pointer -g)
        add_link_options(-fsanitize=address,undefined)
        message(STATUS "Sanitizers: AddressSanitizer + UndefinedBehaviorSanitizer")
    endif()
endif()

file(GLOB SOURCES "src/*.c")

# Everything except the CLI entry point, for drivers that supply their own
# main(): the fuzz targets, and any future test that wants the whole pipeline.
set(STACK_SOURCES ${SOURCES})
list(REMOVE_ITEM STACK_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/main.c")

add_executable(tcpip ${SOURCES})

include(CTest)

if(BUILD_TESTING)
    add_executable(test_tcp_state
        tests/test_tcp_state.c
        src/tcp_state.c
        src/tcp_stream.c
        src/tcp_analysis.c
    )
    target_include_directories(test_tcp_state PRIVATE src)
    add_test(NAME tcp_state COMMAND test_tcp_state)

    add_executable(test_tcp_analysis
        tests/test_tcp_analysis.c
        src/tcp_analysis.c
    )
    target_include_directories(test_tcp_analysis PRIVATE src)
    add_test(NAME tcp_analysis COMMAND test_tcp_analysis)

    add_executable(test_linktype
        tests/test_linktype.c
        src/linktype.c
        src/ethernet.c
    )
    target_include_directories(test_linktype PRIVATE src)
    add_test(NAME linktype COMMAND test_linktype)

    add_executable(test_tunnel
        tests/test_tunnel.c
        src/pppoe.c
        src/vxlan.c
        src/ethernet.c
    )
    target_include_directories(test_tunnel PRIVATE src)
    add_test(NAME tunnel COMMAND test_tunnel)

    add_executable(test_tcp_parse
        tests/test_tcp_parse.c
        src/tcp.c
    )
    target_include_directories(test_tcp_parse PRIVATE src)
    add_test(NAME tcp_parse COMMAND test_tcp_parse)

    add_executable(test_sctp_parse
        tests/test_sctp_parse.c
        src/sctp.c
    )
    target_include_directories(test_sctp_parse PRIVATE src)
    add_test(NAME sctp_parse COMMAND test_sctp_parse)

    add_executable(test_quic_parse
        tests/test_quic_parse.c
        src/quic.c
    )
    target_include_directories(test_quic_parse PRIVATE src)
    add_test(NAME quic_parse COMMAND test_quic_parse)

    add_executable(test_tcp_stream
        tests/test_tcp_stream.c
        src/tcp_stream.c
    )
    target_include_directories(test_tcp_stream PRIVATE src)
    add_test(NAME tcp_stream COMMAND test_tcp_stream)

    add_executable(test_ipv4_parse
        tests/test_ipv4_parse.c
        src/ipv4.c
    )
    target_include_directories(test_ipv4_parse PRIVATE src)
    add_test(NAME ipv4_parse COMMAND test_ipv4_parse)

    add_executable(test_ipv6_parse
        tests/test_ipv6_parse.c
        src/ipv6.c
    )
    target_include_directories(test_ipv6_parse PRIVATE src)
    add_test(NAME ipv6_parse COMMAND test_ipv6_parse)

    add_executable(test_ipv6_fragment_dispatch
        tests/test_ipv6_fragment_dispatch.c
        ${STACK_SOURCES}
    )
    target_include_directories(test_ipv6_fragment_dispatch PRIVATE src)
    add_test(NAME ipv6_fragment_extension_chain
        COMMAND test_ipv6_fragment_dispatch)
    set_tests_properties(ipv6_fragment_extension_chain PROPERTIES
        PASS_REGULAR_EXPRESSION "Src Port  : 1234"
    )

    add_executable(test_icmpv6_parse
        tests/test_icmpv6_parse.c
        src/icmpv6.c
    )
    target_include_directories(test_icmpv6_parse PRIVATE src)
    add_test(NAME icmpv6_parse COMMAND test_icmpv6_parse)

    add_executable(test_dns_parse
        tests/test_dns_parse.c
        src/dns.c
    )
    target_include_directories(test_dns_parse PRIVATE src)
    add_test(NAME dns_parse COMMAND test_dns_parse)

    add_executable(test_udp_parse
        tests/test_udp_parse.c
        src/udp.c
    )
    target_include_directories(test_udp_parse PRIVATE src)
    add_test(NAME udp_parse COMMAND test_udp_parse)

    add_executable(test_ntp_parse
        tests/test_ntp_parse.c
        src/ntp.c
    )
    target_include_directories(test_ntp_parse PRIVATE src)
    add_test(NAME ntp_parse COMMAND test_ntp_parse)

    add_executable(test_http_parse
        tests/test_http_parse.c
        src/http.c
    )
    target_include_directories(test_http_parse PRIVATE src)
    add_test(NAME http_parse COMMAND test_http_parse)

    add_executable(test_ipv4_reassembly
        tests/test_ipv4_reassembly.c
        src/ipv4_reassembly.c
    )
    target_include_directories(test_ipv4_reassembly PRIVATE src)
    add_test(NAME ipv4_reassembly COMMAND test_ipv4_reassembly)

    add_executable(test_ethernet_parse
        tests/test_ethernet_parse.c
        src/ethernet.c
    )
    target_include_directories(test_ethernet_parse PRIVATE src)
    add_test(NAME ethernet_parse COMMAND test_ethernet_parse)

    add_executable(test_arp_parse
        tests/test_arp_parse.c
        src/arp.c
    )
    target_include_directories(test_arp_parse PRIVATE src)
    add_test(NAME arp_parse COMMAND test_arp_parse)

    add_executable(test_arp_cache
        tests/test_arp_cache.c
        src/arp_cache.c
    )
    target_include_directories(test_arp_cache PRIVATE src)
    add_test(NAME arp_cache COMMAND test_arp_cache)

    add_executable(test_pcap_reader
        tests/test_pcap_reader.c
        src/pcap.c
    )
    target_include_directories(test_pcap_reader PRIVATE src)
    add_test(NAME pcap_reader
        COMMAND test_pcap_reader
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcapng
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample-be.pcapng
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample-spb.pcapng
    )

    # ── what every test target needs ──────────────────────────────────────────
    #
    # These tests check things with assert(), and two build settings quietly
    # stop that from meaning anything:
    #
    #   -DNDEBUG, which CMake puts in every Release configuration, compiles
    #   assert() out entirely. Four of the seven CI jobs build Release, so
    #   without -UNDEBUG their unit tests verify only that the process exits 0.
    #   Undefining it here rather than forcing Debug keeps the optimiser on,
    #   which is worth having: -O2 and -O0 do not always agree about
    #   uninitialised reads.
    #
    #   On Windows the debug CRT answers a failed assertion with a dialog box
    #   instead of a message, so a failing test hangs. tests/test_support.c
    #   sends those reports to stderr; see the comment there.
    set(TEST_TARGETS
        test_tcp_state test_tcp_analysis test_linktype test_tunnel
        test_tcp_parse test_tcp_stream test_ipv4_parse test_ipv6_parse
        test_ipv6_fragment_dispatch
        test_icmpv6_parse test_dns_parse test_udp_parse test_ipv4_reassembly
        test_ethernet_parse test_arp_parse test_arp_cache test_pcap_reader
        test_sctp_parse test_quic_parse test_ntp_parse test_http_parse
    )
    foreach(test_target IN LISTS TEST_TARGETS)
        target_sources(${test_target} PRIVATE tests/test_support.c)
        target_compile_options(${test_target} PRIVATE -UNDEBUG)
    endforeach()

    add_test(NAME sample_pcap
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap PROPERTIES
        PASS_REGULAR_EXPRESSION "client=TIME_WAIT server=CLOSED"
    )

    add_test(NAME sample_pcap_reassembly
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_reassembly PROPERTIES
        PASS_REGULAR_EXPRESSION "complete: 53 bytes from 2 fragments"
    )

    add_test(NAME sample_pcap_reassembly_summary
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_reassembly_summary PROPERTIES
        PASS_REGULAR_EXPRESSION "completed datagrams: 1"
    )

    add_test(NAME sample_pcap_vlan
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_vlan PROPERTIES
        PASS_REGULAR_EXPRESSION "TPID=0x8100 PCP=5 DEI=0 VID=42"
    )

    add_test(NAME sample_pcap_tcp_gap
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_tcp_gap PROPERTIES
        PASS_REGULAR_EXPRESSION "buffered  : 2 byte.s. waiting for a gap"
    )

    add_test(NAME sample_pcap_tcp_stream
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_tcp_stream PROPERTIES
        PASS_REGULAR_EXPRESSION "stream    : emitted 5 byte.s.  \"hello\""
    )

    add_test(NAME sample_pcap_tcp_midstream
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_tcp_midstream PROPERTIES
        PASS_REGULAR_EXPRESSION "connection #2 .new, inferred mid-stream."
    )

    add_test(NAME sample_pcap_arp_cache
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_arp_cache PROPERTIES
        PASS_REGULAR_EXPRESSION "tracked neighbors: 2"
    )

    add_test(NAME sample_pcap_ipv6
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_ipv6 PROPERTIES
        PASS_REGULAR_EXPRESSION "Next Hdr  : 59  \\(No Next Header\\)"
    )

    add_test(NAME sample_pcap_icmpv6
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_icmpv6 PROPERTIES
        PASS_REGULAR_EXPRESSION "Type      : 128  \\(Echo Request\\)"
    )

    add_test(NAME sample_pcapng
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcapng
    )
    set_tests_properties(sample_pcapng PROPERTIES
        PASS_REGULAR_EXPRESSION "Done. Parsed 52 packet"
    )

    add_test(NAME sample_pcapng_be
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample-be.pcapng
    )
    set_tests_properties(sample_pcapng_be PROPERTIES
        PASS_REGULAR_EXPRESSION "Done. Parsed 52 packet"
    )

    add_test(NAME sample_pcap_ipv6_udp
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_ipv6_udp PROPERTIES
        PASS_REGULAR_EXPRESSION "Src Port  : 53"
    )

    add_test(NAME sample_pcap_ipv6_tcp_stream
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_ipv6_tcp_stream PROPERTIES
        PASS_REGULAR_EXPRESSION "stream    : emitted 2 byte.s.  \"v6\""
    )

    add_test(NAME sample_pcap_ipv6_tcp_endpoint
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_ipv6_tcp_endpoint PROPERTIES
        PASS_REGULAR_EXPRESSION "\\[2001:db8:0:0:0:0:0:10\\]:60443"
    )

    add_test(NAME sample_pcap_dns
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_dns PROPERTIES
        PASS_REGULAR_EXPRESSION "example.com.*A"
    )

    add_test(NAME sample_pcap_ndp_ns
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_ndp_ns PROPERTIES
        PASS_REGULAR_EXPRESSION "Neighbor Solicitation"
    )

    add_test(NAME sample_pcap_ndp_na
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_ndp_na PROPERTIES
        PASS_REGULAR_EXPRESSION "Neighbor Advertisement"
    )

    add_test(NAME sample_pcap_ndp_lladdr
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_ndp_lladdr PROPERTIES
        PASS_REGULAR_EXPRESSION "Tgt LLAddr.*dd:ee:ff:44:55:66"
    )

    add_test(NAME sample_pcap_ipv6_reassembly
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_ipv6_reassembly PROPERTIES
        PASS_REGULAR_EXPRESSION "ipv6-reassembly.*complete: 16 bytes"
    )

    add_test(NAME sample_pcap_ipv6_routing
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_ipv6_routing PROPERTIES
        PASS_REGULAR_EXPRESSION "IPv6 Routing Header"
    )

    add_test(NAME sample_pcap_dhcp
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_dhcp PROPERTIES
        PASS_REGULAR_EXPRESSION "DHCP.*DISCOVER"
    )

    add_test(NAME sample_pcap_dhcp_offer
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_dhcp_offer PROPERTIES
        PASS_REGULAR_EXPRESSION "DHCP.*OFFER"
    )

    add_test(NAME sample_pcap_http
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_http PROPERTIES
        PASS_REGULAR_EXPRESSION "GET /index.html HTTP"
    )

    add_test(NAME sample_pcap_http_response
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_http_response PROPERTIES
        PASS_REGULAR_EXPRESSION "HTTP/1.1 200 OK"
    )

    add_test(NAME sample_pcap_tls
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_tls PROPERTIES
        PASS_REGULAR_EXPRESSION "ClientHello"
    )

    add_test(NAME sample_pcap_tls_sni
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_tls_sni PROPERTIES
        PASS_REGULAR_EXPRESSION "SNI=www.example.com"
    )

    add_test(NAME sample_pcap_dns_rtt
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_dns_rtt PROPERTIES
        PASS_REGULAR_EXPRESSION "dns-rtt.*100"
    )

    add_test(NAME sample_pcap_udp_tracker
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_udp_tracker PROPERTIES
        PASS_REGULAR_EXPRESSION "UDP tracker"
    )

    add_test(NAME sample_pcap_icmp_embedded
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_icmp_embedded PROPERTIES
        PASS_REGULAR_EXPRESSION "Inner IP"
    )

    add_test(NAME sample_pcap_mdns
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_mdns PROPERTIES
        PASS_REGULAR_EXPRESSION "Src Port  : 5353|Dst Port  : 5353"
    )

    add_test(NAME sample_pcap_ntp
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_ntp PROPERTIES
        PASS_REGULAR_EXPRESSION "NTP"
    )

    add_test(NAME sample_pcap_dhcpv6
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_dhcpv6 PROPERTIES
        PASS_REGULAR_EXPRESSION "DHCPv6.*SOLICIT"
    )

    add_test(NAME sample_pcap_gre
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_gre PROPERTIES
        PASS_REGULAR_EXPRESSION "GRE"
    )

    add_test(NAME sample_pcap_tcp_rtt
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_tcp_rtt PROPERTIES
        PASS_REGULAR_EXPRESSION "rtt.*100"
    )

    add_test(NAME sample_pcap_icmpv6_embedded
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_icmpv6_embedded PROPERTIES
        PASS_REGULAR_EXPRESSION "Inner IPv6 Src"
    )

    add_test(NAME sample_pcap_ipv4_options
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_ipv4_options PROPERTIES
        PASS_REGULAR_EXPRESSION "Router Alert"
    )

    add_test(NAME sample_pcap_tls_server_hello
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_tls_server_hello PROPERTIES
        PASS_REGULAR_EXPRESSION "cipher=0x002f"
    )

    add_test(NAME sample_pcap_dns_soa
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_dns_soa PROPERTIES
        PASS_REGULAR_EXPRESSION "serial=2024010101"
    )

    add_test(NAME sample_pcap_dns_srv
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_dns_srv PROPERTIES
        PASS_REGULAR_EXPRESSION "prio=10"
    )

    add_test(NAME sample_pcap_igmp
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap
    )
    set_tests_properties(sample_pcap_igmp PROPERTIES
        PASS_REGULAR_EXPRESSION "v2 Membership Report"
    )

    # ── TCP expert analysis ───────────────────────────────────────────────────
    #
    # sample-analysis.pcap carries one connection per scenario; see
    # tests/gen_analysis_pcap.py for why they are kept apart. Each assertion
    # below pins one verdict, so a regression names the analysis that broke
    # rather than just failing somewhere in a long output.
    set(ANALYSIS_CAPTURE
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample-analysis.pcap)

    function(add_analysis_test name pattern)
        add_test(NAME ${name} COMMAND tcpip --quiet ${ANALYSIS_CAPTURE})
        set_tests_properties(${name} PROPERTIES
            PASS_REGULAR_EXPRESSION "${pattern}")
    endfunction()

    # Three duplicate ACKs, and the fast retransmission they triggered.
    add_analysis_test(analysis_dup_acks       "dup-ack=3")
    add_analysis_test(analysis_fast_retransmit "retrans: fast=1")
    # A SACK block above the cumulative ACK, naming the bytes that went missing.
    add_analysis_test(analysis_sack_hole      "sack-hole=1")
    # Window pressure.
    add_analysis_test(analysis_zero_window    "zero-window=1")
    # Resending data the peer had already acknowledged.
    add_analysis_test(analysis_spurious       "retrans: spurious=1")
    # A resend after a silence longer than the retransmission timer.
    add_analysis_test(analysis_rto            "retrans: rto=1")
    # A gap filled immediately is reordering, and must not be called a resend.
    add_analysis_test(analysis_out_of_order   "out-of-order=1")
    add_analysis_test(analysis_keep_alive     "keep-alive=1")
    # Window scaling actually applied: 8192 << 7.
    add_analysis_test(analysis_window_scaling "max 1048576 byte.s.  scale 2.7")

    # Per-segment findings, which are only printed in the full packet walk.
    add_test(NAME analysis_segment_findings
        COMMAND tcpip ${ANALYSIS_CAPTURE})
    set_tests_properties(analysis_segment_findings PROPERTIES
        PASS_REGULAR_EXPRESSION "findings  : duplicate ACK \\(#3\\)")

    add_test(NAME analysis_segment_probe
        COMMAND tcpip ${ANALYSIS_CAPTURE})
    set_tests_properties(analysis_segment_probe PROPERTIES
        PASS_REGULAR_EXPRESSION "zero-window probe")

    add_test(NAME analysis_segment_sack_loss
        COMMAND tcpip ${ANALYSIS_CAPTURE})
    set_tests_properties(analysis_segment_sack_loss PROPERTIES
        PASS_REGULAR_EXPRESSION "lost      : 100 byte.s. in 1 hole.s. inferred from SACK")

    add_test(NAME analysis_segment_retrans_label
        COMMAND tcpip ${ANALYSIS_CAPTURE})
    set_tests_properties(analysis_segment_retrans_label PROPERTIES
        PASS_REGULAR_EXPRESSION "analysis  : fast retransmission")

    # ── machine-readable export ───────────────────────────────────────────────
    # Asking for a structured document on stdout must suppress the packet walk,
    # or the result parses as neither JSON nor CSV.
    add_test(NAME report_json_is_first_line
        COMMAND tcpip --json ${ANALYSIS_CAPTURE})
    set_tests_properties(report_json_is_first_line PROPERTIES
        PASS_REGULAR_EXPRESSION "^\\{\n  \"packets\": 47,"
    )

    add_test(NAME report_json_scale_shift
        COMMAND tcpip --json ${ANALYSIS_CAPTURE})
    set_tests_properties(report_json_scale_shift PROPERTIES
        PASS_REGULAR_EXPRESSION "\"scaling_active\": true, \"scale_shift\": 7"
    )

    # An endpoint whose own SYN was never captured has no known shift, and must
    # report null rather than claiming it asked for none.
    add_test(NAME report_json_unknown_shift
        COMMAND tcpip --json ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample.pcap)
    set_tests_properties(report_json_unknown_shift PROPERTIES
        PASS_REGULAR_EXPRESSION "\"scaling_active\": false, \"scale_shift\": null"
    )

    add_test(NAME report_csv_header
        COMMAND tcpip --csv ${ANALYSIS_CAPTURE})
    set_tests_properties(report_csv_header PROPERTIES
        PASS_REGULAR_EXPRESSION "^connection_id,direction,"
    )

    add_test(NAME report_csv_row
        COMMAND tcpip --csv ${ANALYSIS_CAPTURE})
    set_tests_properties(report_csv_row PROPERTIES
        PASS_REGULAR_EXPRESSION "1,c->s,0,1,192.168.1.10,40001,"
    )

    # Two structured formats on one stream would parse as neither.
    add_test(NAME report_rejects_two_stdout_formats
        COMMAND tcpip --json --csv ${ANALYSIS_CAPTURE})
    set_tests_properties(report_rejects_two_stdout_formats PROPERTIES
        WILL_FAIL TRUE
    )

    add_test(NAME cli_rejects_unknown_option
        COMMAND tcpip --nonsense ${ANALYSIS_CAPTURE})
    set_tests_properties(cli_rejects_unknown_option PROPERTIES
        WILL_FAIL TRUE
    )

    add_test(NAME cli_help COMMAND tcpip --help)
    set_tests_properties(cli_help PROPERTIES
        PASS_REGULAR_EXPRESSION "--json\\[=PATH\\]"
    )

    # ── link types other than Ethernet ────────────────────────────────────────
    #
    # A pcap file names its link layer once, in the global header, so each of
    # these is its own capture. See tests/gen_encap_pcap.py.
    function(add_capture_test name capture pattern)
        add_test(NAME ${name}
            COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/${capture})
        set_tests_properties(${name} PROPERTIES
            PASS_REGULAR_EXPRESSION "${pattern}")
    endfunction()

    # Linux cooked captures, what `tcpdump -i any` produces.
    add_capture_test(link_sll_header    sample-sll.pcap  "Linux cooked v1")
    add_capture_test(link_sll_direction sample-sll.pcap  "Direction : 1  .broadcast.")
    add_capture_test(link_sll_dispatch  sample-sll.pcap  "Type      : 8  .Echo Request.")
    add_capture_test(link_sll2_header   sample-sll2.pcap "Linux cooked v2")
    add_capture_test(link_sll2_ifindex  sample-sll2.pcap "Interface : index=3")

    # No link header at all, as on a tunnel or VPN interface.
    add_capture_test(link_raw_ipv4 sample-raw.pcap "Raw IP")
    add_capture_test(link_raw_ipv6 sample-raw.pcap "Version   : 6")

    # BSD loopback. The second packet writes AF_INET6 big-endian, so this also
    # covers the byte-order guess; the third names a family we cannot place.
    add_capture_test(link_null_ipv4        sample-null.pcap "Family    : 2  .AF_INET.")
    add_capture_test(link_null_ipv6_swapped sample-null.pcap "Family    : 30  .AF_INET6.")
    add_capture_test(link_null_unknown     sample-null.pcap "no recognisable payload")

    # ── tunnels ───────────────────────────────────────────────────────────────
    add_capture_test(tunnel_ipip     sample-encap.pcap "ipip. IPv4 in IPv4")
    add_capture_test(tunnel_ipip_inner sample-encap.pcap "Src IP    : 10.0.0.1")
    add_capture_test(tunnel_6in4     sample-encap.pcap "6in4. IPv6 in IPv4")
    add_capture_test(tunnel_pppoe    sample-encap.pcap "PPP proto : 0x0021  .IPv4.")
    add_capture_test(tunnel_pppoe_padi sample-encap.pcap "Code      : 0x09  .PADI.")
    add_capture_test(tunnel_vxlan    sample-encap.pcap "VNI       : 1193046")
    add_capture_test(tunnel_vxlan_inner sample-encap.pcap "Src IP    : 10.1.0.1")

    # A packet nested twelve layers deep. The walk follows eight and stops;
    # before the cap, this shape scaled up to fill the read buffer exhausted
    # the C stack and killed the process.
    add_capture_test(tunnel_depth_capped sample-encap.pcap
        "encap. nested deeper than 8 layers")

    # ── EDNS0 and DNSSEC ──────────────────────────────────────────────────────
    #
    # tests/sample-dns.pcap, one scenario per packet. See gen_dns_pcap.py for
    # why these are not in sample.pcap.
    add_capture_test(dns_edns_udp_size  sample-dns.pcap "UDP size : 1232")
    add_capture_test(dns_edns_do_bit    sample-dns.pcap "flags=0x8000  .DO.")
    add_capture_test(dns_edns_subnet    sample-dns.pcap
        "Client Subnet   192.0.2.0/24 scope /0")
    add_capture_test(dns_edns_cookie    sample-dns.pcap
        "client 0102030405060708 . 8-byte server")
    add_capture_test(dns_edns_nsid      sample-dns.pcap "NSID")
    add_capture_test(dns_edns_padding   sample-dns.pcap "Padding         16 byte")

    # The OPT is counted in ARCOUNT but is not a record about a name, so it
    # must never be printed as one. Its class field is a UDP payload size and
    # its TTL field is a flags word, so a line reading "OPT ... TTL=32768"
    # would be three separate lies. FAIL_REGULAR_EXPRESSION wins over PASS in
    # CTest, so this asserts the absence rather than merely finding the EDNS
    # block somewhere.
    add_test(NAME dns_opt_not_listed_as_a_record
        COMMAND tcpip ${CMAKE_CURRENT_SOURCE_DIR}/tests/sample-dns.pcap)
    set_tests_properties(dns_opt_not_listed_as_a_record PROPERTIES
        PASS_REGULAR_EXPRESSION "-- EDNS0 .RFC 6891. --"
        FAIL_REGULAR_EXPRESSION "OPT     TTL=")

    # BADVERS exists only once the OPT extends the RCODE past four bits.
    # Reading the header alone would print NOERROR here.
    add_capture_test(dns_extended_rcode sample-dns.pcap "RCODE=16 .BADVERS.")
    add_capture_test(dns_extended_error sample-dns.pcap
        "6 .DNSSEC Bogus. .no RRSIG covering")

    # DNSSEC records, reported structurally and never validated.
    add_capture_test(dns_rrsig_times    sample-dns.pcap
        "20240101000000..20240201000000")
    add_capture_test(dns_rrsig_signer   sample-dns.pcap
        "keytag=40664 signer=example.com")
    add_capture_test(dns_dnskey_flags   sample-dns.pcap
        "keytag=40664 flags=0x0101 ZONE SEP")
    add_capture_test(dns_nsec_bitmap    sample-dns.pcap
        "mail.example.com A NS SOA RRSIG NSEC DNSKEY")
    add_capture_test(dns_ds_algorithms  sample-dns.pcap
        "alg=8 .RSASHA256. digest=2 .SHA-256.")
    add_capture_test(dns_nsec3_optout   sample-dns.pcap
        "OPTOUT iter=10 salt=aabbccdd")
    add_capture_test(dns_ad_flag        sample-dns.pcap "AA RD RA AD")

    # ── SCTP and QUIC ─────────────────────────────────────────────────────────
    #
    # tests/sample-transport.pcap, one scenario per packet. See
    # gen_transport_pcap.py for why these are not in sample.pcap.
    add_capture_test(transport_sctp_init sample-transport.pcap
        "tag=0xaabbccdd a_rwnd=106496 out=10 in=5 initial TSN=10000")
    add_capture_test(transport_sctp_init_param sample-transport.pcap
        "param 12    Supported Address Types")

    # The CRC-32C, tested in both directions: packet 7 of the capture carries a
    # deliberately wrong checksum, so "valid" is not merely what this prints
    # for everything.
    add_capture_test(transport_sctp_checksum_valid sample-transport.pcap
        "CRC-32C valid")
    add_capture_test(transport_sctp_checksum_invalid sample-transport.pcap
        "CRC-32C INVALID")

    add_capture_test(transport_sctp_data sample-transport.pcap
        "TSN=1000 stream=1 seq=0 ppid=51")
    # The DATA chunk before it declares 26 bytes, so two pad bytes separate
    # them. A walk that does not round up to the next four-byte boundary never
    # finds this second chunk.
    add_capture_test(transport_sctp_chunk_padding sample-transport.pcap
        "chunk 1   : SACK")
    add_capture_test(transport_sctp_sack_gaps sample-transport.pcap
        "gap 0: TSN 1002..1003")
    add_capture_test(transport_sctp_abort_cause sample-transport.pcap
        "cause 12    User Initiated Abort")
    # The same protocol over IPv6, which reaches it through the other switch.
    add_capture_test(transport_sctp_over_ipv6 sample-transport.pcap
        "cum TSN=2000")

    add_capture_test(transport_quic_initial sample-transport.pcap
        "Initial  version=0x00000001")
    add_capture_test(transport_quic_dcid sample-transport.pcap
        "0102030405060708")
    # Two packets in one datagram, found only by following the first one's
    # Length field.
    add_capture_test(transport_quic_coalesced sample-transport.pcap
        "Packets   : 2 in 298 byte")
    add_capture_test(transport_quic_token sample-transport.pcap
        "Token : 16 byte")
    add_capture_test(transport_quic_version_negotiation sample-transport.pcap
        "Offers: 3 version")
    add_capture_test(transport_quic_retry_tag sample-transport.pcap
        "plus a 16-byte integrity tag")
    # Packet type 1 is Initial in version 2 and 0-RTT in version 1, so reading
    # the type without the version gives a different answer, not a partial one.
    add_capture_test(transport_quic_v2 sample-transport.pcap
        "Initial  version=0x6b3343cf")
    add_capture_test(transport_quic_short_header sample-transport.pcap
        "no length prefix here")
endif()

# ── Fuzz targets ──────────────────────────────────────────────────────────────
#
# Each target is built twice over the same LLVMFuzzerTestOneInput():
#
#   fuzz_<name>_replay  standalone driver, built always. Replays the corpus in
#                       fuzz/corpus/<name>/ under CTest. Combine with
#                       -DTCPIP_SANITIZE=ON to make it catch memory errors
#                       rather than only hard crashes.
#   fuzz_<name>         libFuzzer-instrumented, built when -DTCPIP_FUZZ=ON under
#                       Clang, for coverage-guided campaigns.
#
# Corpus inputs are checked in, so a crash found by a campaign becomes a
# permanent regression test by dropping the reproducer into the corpus
# directory. Nothing else needs editing.

set(FUZZ_TARGET_NAMES frame parsers pcap)

foreach(fuzz_name IN LISTS FUZZ_TARGET_NAMES)
    add_executable(fuzz_${fuzz_name}_replay
        fuzz/fuzz_${fuzz_name}.c
        fuzz/fuzz_util.c
        fuzz/standalone_main.c
        ${STACK_SOURCES}
    )
    target_include_directories(fuzz_${fuzz_name}_replay PRIVATE src fuzz)

    if(BUILD_TESTING)
        add_test(NAME fuzz_corpus_${fuzz_name}
            COMMAND fuzz_${fuzz_name}_replay
                ${CMAKE_CURRENT_SOURCE_DIR}/fuzz/corpus/${fuzz_name}
        )
    endif()
endforeach()

if(TCPIP_FUZZ)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR
            "TCPIP_FUZZ=ON needs Clang for -fsanitize=fuzzer; "
            "found ${CMAKE_C_COMPILER_ID}. The fuzz_*_replay targets are built "
            "with any compiler — use those, ideally with -DTCPIP_SANITIZE=ON.")
    endif()

    foreach(fuzz_name IN LISTS FUZZ_TARGET_NAMES)
        add_executable(fuzz_${fuzz_name}
            fuzz/fuzz_${fuzz_name}.c
            fuzz/fuzz_util.c
            ${STACK_SOURCES}
        )
        target_include_directories(fuzz_${fuzz_name} PRIVATE src fuzz)
        # fuzzer-no-link on the sources, fuzzer on the link line: libFuzzer
        # supplies main(), so standalone_main.c must not be in this target.
        target_compile_options(fuzz_${fuzz_name} PRIVATE
            -fsanitize=fuzzer-no-link)
        target_link_options(fuzz_${fuzz_name} PRIVATE -fsanitize=fuzzer)
    endforeach()

    message(STATUS "Fuzzing: libFuzzer targets enabled (fuzz_frame, fuzz_parsers, fuzz_pcap)")
endif()

# ── a bound on every test ─────────────────────────────────────────────────────
#
# The whole suite finishes in seconds natively, so anything still running after
# five minutes has stopped making progress — a parser looping on a length that
# never advances, or a test waiting on something that will not arrive. CTest's
# own default is 1500 seconds, long enough that a hang reads as a stuck CI job
# rather than as a failure. This is deliberately loose enough for the emulated
# big-endian job, where everything runs an order of magnitude slower.
if(BUILD_TESTING)
    get_property(ALL_TESTS DIRECTORY PROPERTY TESTS)
    if(ALL_TESTS)
        set_tests_properties(${ALL_TESTS} PROPERTIES TIMEOUT 300)
    endif()
endif()
