#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "dispatch.h"
#include "pcap.h"

#define FRAGMENT_PACKET_LEN (IPV6_HDR_LEN + 8u + 8u)

static void put16be(uint8_t* out, uint16_t value) {
    out[0] = (uint8_t)(value >> 8);
    out[1] = (uint8_t)value;
}

static void put32be(uint8_t* out, uint32_t value) {
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static void make_fragment(uint8_t* packet, uint16_t offset,
                          int more_fragments, const uint8_t data[8]) {
    static const uint8_t src[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
    };
    static const uint8_t dst[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2
    };

    memset(packet, 0, FRAGMENT_PACKET_LEN);
    packet[0] = 0x60;
    put16be(packet + 4, 16);       /* Fragment header plus eight data bytes. */
    packet[6] = 44;                /* Fragment */
    packet[7] = 64;
    memcpy(packet + 8, src, sizeof(src));
    memcpy(packet + 24, dst, sizeof(dst));

    packet[40] = 60;               /* Destination Options after reassembly. */
    put16be(packet + 42,
            (uint16_t)((offset << 3) | (more_fragments ? 1u : 0u)));
    put32be(packet + 44, 0x12345678u);
    memcpy(packet + 48, data, 8);
}

static void test_fragmentable_extension_header_is_reassembled(void) {
    static const uint8_t destination_options[8] = {
        IPPROTO_UDP, 0, 0, 0, 0, 0, 0, 0
    };
    static const uint8_t udp_header[8] = {
        0x04, 0xd2, 0x10, 0xe1, 0x00, 0x08, 0x8e, 0xb6
    };
    uint8_t first[FRAGMENT_PACKET_LEN];
    uint8_t second[FRAGMENT_PACKET_LEN];
    Ipv6Header header;
    Ipv6Payload inner;
    StackContext* ctx;

    make_fragment(first, 0, 1, destination_options);
    make_fragment(second, 1, 0, udp_header);

    assert(ipv6_parse(first, sizeof(first), &header) == 0);
    assert(ipv6_locate_payload(
        &header, first, sizeof(first), &inner) == 0);
    assert(inner.fragment_seen == 1);
    assert(inner.final_next_header == 60);
    assert(inner.payload == first + 48);
    assert(inner.payload_len == 8);

    ctx = stack_create();
    assert(ctx != NULL);
    stack_dispatch_link(ctx, LINKTYPE_RAW, first, sizeof(first), 1);
    stack_dispatch_link(ctx, LINKTYPE_RAW, second, sizeof(second), 2);
    stack_destroy(ctx);
}

static void test_atomic_fragment_continues_extension_traversal(void) {
    static const uint8_t destination_options[8] = {
        IPPROTO_UDP, 0, 0, 0, 0, 0, 0, 0
    };
    static const uint8_t udp_header[8] = {
        0x04, 0xd2, 0x10, 0xe1, 0x00, 0x08, 0x8e, 0xb6
    };
    uint8_t packet[IPV6_HDR_LEN + 8u + 8u + 8u];
    Ipv6Header header;
    Ipv6Payload inner;

    make_fragment(packet, 0, 0, destination_options);
    put16be(packet + 4, 24);
    memcpy(packet + 56, udp_header, sizeof(udp_header));

    assert(ipv6_parse(packet, sizeof(packet), &header) == 0);
    assert(ipv6_locate_payload(
        &header, packet, sizeof(packet), &inner) == 0);
    assert(inner.fragment_seen == 1);
    assert(inner.fragment_offset == 0);
    assert(inner.more_fragments == 0);
    assert(inner.final_next_header == IPPROTO_UDP);
    assert(inner.extension_len == 16);
    assert(inner.payload == packet + 56);
    assert(inner.payload_len == sizeof(udp_header));
}

int main(void) {
    test_fragmentable_extension_header_is_reassembled();
    test_atomic_fragment_continues_extension_traversal();
    printf("ipv6_fragment_dispatch tests passed\n");
    return 0;
}
