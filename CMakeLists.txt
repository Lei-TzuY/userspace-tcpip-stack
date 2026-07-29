cmake_minimum_required(VERSION 3.10)
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

file(GLOB SOURCES "src/*.c")

add_executable(tcpip ${SOURCES})

include(CTest)

if(BUILD_TESTING)
    add_executable(test_tcp_state
        tests/test_tcp_state.c
        src/tcp_state.c
        src/tcp_stream.c
    )
    target_include_directories(test_tcp_state PRIVATE src)
    add_test(NAME tcp_state COMMAND test_tcp_state)

    add_executable(test_tcp_parse
        tests/test_tcp_parse.c
        src/tcp.c
    )
    target_include_directories(test_tcp_parse PRIVATE src)
    add_test(NAME tcp_parse COMMAND test_tcp_parse)

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
endif()
