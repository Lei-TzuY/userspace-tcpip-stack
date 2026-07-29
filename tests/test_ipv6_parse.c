#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "ipv6.h"

static void init_packet(uint8_t* packet, size_t len, uint16_t payload_len) {
    memset(packet, 0, len);
    packet[0] = 0x6a; /* IPv6, traffic class 0xab */
    packet[1] = 0xb1;
    packet[2] = 0x23;
    packet[3] = 0x45; /* flow label 0x12345 */
    packet[4] = (uint8_t)(payload_len >> 8);
    packet[5] = (uint8_t)(payload_len & 0xff);
    packet[6] = 59; /* No Next Header */
    packet[7] = 64;
    packet[8] = 0x20;
    packet[9] = 0x01;
    packet[10] = 0x0d;
    packet[11] = 0xb8;
    packet[39] = 1;
}

static void test_valid_header_with_ethernet_padding(void) {
    uint8_t packet[48];
    Ipv6Header header;
    init_packet(packet, sizeof(packet), 0);

    assert(ipv6_parse(packet, sizeof(packet), &header) == 0);
    assert(header.version == 6);
    assert(header.traffic_class == 0xab);
    assert(header.flow_label == 0x12345);
    assert(header.payload_len == 0);
    assert(header.next_header == 59);
    assert(header.hop_limit == 64);
    assert(header.src[0] == 0x20);
    assert(header.dst[15] == 1);
}

static void test_bad_version(void) {
    uint8_t packet[IPV6_HDR_LEN];
    Ipv6Header header;
    init_packet(packet, sizeof(packet), 0);
    packet[0] = 0x4a;

    assert(ipv6_parse(packet, sizeof(packet), &header) == -1);
}

static void test_truncated_header(void) {
    uint8_t packet[IPV6_HDR_LEN];
    Ipv6Header header;
    init_packet(packet, sizeof(packet), 0);

    assert(ipv6_parse(packet, sizeof(packet) - 1, &header) == -1);
}

static void test_truncated_payload(void) {
    uint8_t packet[IPV6_HDR_LEN];
    Ipv6Header header;
    init_packet(packet, sizeof(packet), 1);

    assert(ipv6_parse(packet, sizeof(packet), &header) == -1);
}

static void test_locates_payload_after_hop_by_hop(void) {
    uint8_t packet[IPV6_HDR_LEN + 16];
    Ipv6Header header;
    Ipv6Payload payload;
    init_packet(packet, sizeof(packet), 16);
    packet[6] = 0; /* Hop-by-Hop Options */
    packet[IPV6_HDR_LEN + 0] = IPPROTO_ICMPV6;
    packet[IPV6_HDR_LEN + 1] = 0; /* 8 bytes total */
    packet[IPV6_HDR_LEN + 2] = 1; /* PadN */
    packet[IPV6_HDR_LEN + 3] = 4;
    packet[IPV6_HDR_LEN + 8] = 128; /* ICMPv6 Echo Request */

    assert(ipv6_parse(packet, sizeof(packet), &header) == 0);
    assert(ipv6_locate_payload(&header, packet, sizeof(packet), &payload) == 0);
    assert(payload.final_next_header == IPPROTO_ICMPV6);
    assert(payload.extension_len == 8);
    assert(payload.payload == packet + IPV6_HDR_LEN + 8);
    assert(payload.payload_len == 8);
    assert(!payload.fragment_seen);
}

static void test_reports_fragment_header(void) {
    uint8_t packet[IPV6_HDR_LEN + 16];
    Ipv6Header header;
    Ipv6Payload payload;
    init_packet(packet, sizeof(packet), 16);
    packet[6] = 44; /* Fragment */
    packet[IPV6_HDR_LEN + 0] = IPPROTO_ICMPV6;
    packet[IPV6_HDR_LEN + 2] = 0;
    packet[IPV6_HDR_LEN + 3] = 0x09; /* offset=1, M=1 */
    packet[IPV6_HDR_LEN + 4] = 0x12;
    packet[IPV6_HDR_LEN + 5] = 0x34;
    packet[IPV6_HDR_LEN + 6] = 0x56;
    packet[IPV6_HDR_LEN + 7] = 0x78;

    assert(ipv6_parse(packet, sizeof(packet), &header) == 0);
    assert(ipv6_locate_payload(&header, packet, sizeof(packet), &payload) == 0);
    assert(payload.final_next_header == IPPROTO_ICMPV6);
    assert(payload.extension_len == 8);
    assert(payload.fragment_seen);
    assert(payload.fragment_offset == 1);
    assert(payload.more_fragments);
    assert(payload.fragment_id == 0x12345678u);
}

int main(void) {
    test_valid_header_with_ethernet_padding();
    test_bad_version();
    test_truncated_header();
    test_truncated_payload();
    test_locates_payload_after_hop_by_hop();
    test_reports_fragment_header();
    printf("ipv6_parse tests passed\n");
    return 0;
}
