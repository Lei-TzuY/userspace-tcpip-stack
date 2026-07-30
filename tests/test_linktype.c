#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "linktype.h"
#include "pcap.h"

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

static void put32le(uint8_t* out, uint32_t value) {
    out[0] = (uint8_t)value;
    out[1] = (uint8_t)(value >> 8);
    out[2] = (uint8_t)(value >> 16);
    out[3] = (uint8_t)(value >> 24);
}

/* ── LINKTYPE_NULL ───────────────────────────────────────────────────────── */

static void test_null_little_endian_ipv4(void) {
    uint8_t packet[8] = { 0 };
    LinkFrame frame;

    put32le(packet, 2);            /* AF_INET */
    packet[4] = 0x45;              /* start of an IPv4 header */

    assert(link_decode(LINKTYPE_NULL, packet, sizeof(packet), &frame) == 0);
    assert(frame.kind == LINK_PAYLOAD_IPV4);
    assert(frame.null_family == 2);
    assert(frame.hdr_len == 4);
    assert(frame.payload == packet + 4);
    assert(frame.payload_len == 4);
}

static void test_null_big_endian_ipv6(void) {
    uint8_t packet[8] = { 0 };
    LinkFrame frame;

    /* The loopback header is written in the capturing host's byte order with
       nothing recording which that was, so the orientation that yields a
       recognised family is the one to believe. */
    put32be(packet, 30);           /* AF_INET6 as macOS numbers it */

    assert(link_decode(LINKTYPE_NULL, packet, sizeof(packet), &frame) == 0);
    assert(frame.kind == LINK_PAYLOAD_IPV6);
    assert(frame.null_family == 30);
}

static void test_null_accepts_every_ipv6_family_constant(void) {
    /* The constant differs per system: 10 on Linux, 24 on NetBSD and OpenBSD,
       28 on FreeBSD, 30 on macOS. A capture does not say which wrote it. */
    static const uint32_t families[] = { 10, 24, 28, 30 };
    size_t i;

    for (i = 0; i < sizeof(families) / sizeof(families[0]); i++) {
        uint8_t packet[8] = { 0 };
        LinkFrame frame;
        put32le(packet, families[i]);
        assert(link_decode(LINKTYPE_NULL, packet, sizeof(packet), &frame) == 0);
        assert(frame.kind == LINK_PAYLOAD_IPV6);
    }
}

static void test_null_unrecognised_family(void) {
    uint8_t packet[8] = { 0 };
    LinkFrame frame;

    put32le(packet, 0xDEAD);

    /* Decoding succeeds -- the header is well formed -- but nothing is claimed
       about the payload, which is more useful than guessing. */
    assert(link_decode(LINKTYPE_NULL, packet, sizeof(packet), &frame) == 0);
    assert(frame.kind == LINK_PAYLOAD_NONE);
    assert(frame.null_family == 0xDEAD);
}

static void test_null_truncated(void) {
    uint8_t packet[3] = { 0 };
    LinkFrame frame;

    assert(link_decode(LINKTYPE_NULL, packet, sizeof(packet), &frame) == -1);
}

/* ── LINKTYPE_RAW ────────────────────────────────────────────────────────── */

static void test_raw_uses_the_version_nibble(void) {
    uint8_t packet[4] = { 0x45, 0, 0, 0 };
    LinkFrame frame;

    assert(link_decode(LINKTYPE_RAW, packet, sizeof(packet), &frame) == 0);
    assert(frame.kind == LINK_PAYLOAD_IPV4);
    assert(frame.hdr_len == 0);
    assert(frame.payload == packet);
    assert(frame.payload_len == sizeof(packet));

    packet[0] = 0x60;
    assert(link_decode(LINKTYPE_RAW, packet, sizeof(packet), &frame) == 0);
    assert(frame.kind == LINK_PAYLOAD_IPV6);

    packet[0] = 0x35;   /* neither 4 nor 6 */
    assert(link_decode(LINKTYPE_RAW, packet, sizeof(packet), &frame) == 0);
    assert(frame.kind == LINK_PAYLOAD_NONE);
}

static void test_raw_empty(void) {
    LinkFrame frame;
    uint8_t packet[1] = { 0x45 };

    assert(link_decode(LINKTYPE_RAW, packet, 0, &frame) == -1);
}

/* ── LINKTYPE_LINUX_SLL ──────────────────────────────────────────────────── */

static void test_sll_header(void) {
    uint8_t packet[20] = { 0 };
    LinkFrame frame;

    put16be(packet + 0, 4);        /* packet type: outgoing */
    put16be(packet + 2, 1);        /* ARPHRD_ETHER */
    put16be(packet + 4, 6);        /* address length */
    memcpy(packet + 6, "\xaa\xbb\xcc\x11\x22\x33", 6);
    put16be(packet + 14, 0x0800);  /* protocol */

    assert(link_decode(LINKTYPE_LINUX_SLL, packet, sizeof(packet), &frame) == 0);
    assert(frame.kind == LINK_PAYLOAD_ETHERTYPE);
    assert(frame.ethertype == 0x0800);
    assert(frame.hdr_len == 16);
    assert(frame.payload_len == 4);
    assert(frame.sll_packet_type == 4);
    assert(frame.sll_arphrd_type == 1);
    assert(frame.sll_addr_len == 6);
    assert(memcmp(frame.sll_addr, "\xaa\xbb\xcc\x11\x22\x33", 6) == 0);
}

static void test_sll_address_length_is_clamped(void) {
    uint8_t packet[16] = { 0 };
    LinkFrame frame;

    /* The address field is a fixed eight bytes. A larger declared length
       describes an address that was truncated to fit, and honouring it would
       walk past the field. */
    put16be(packet + 4, 0xFFFF);
    put16be(packet + 14, 0x0800);

    assert(link_decode(LINKTYPE_LINUX_SLL, packet, sizeof(packet), &frame) == 0);
    assert(frame.sll_addr_len == sizeof(frame.sll_addr));
}

static void test_sll_truncated(void) {
    uint8_t packet[15] = { 0 };
    LinkFrame frame;

    assert(link_decode(LINKTYPE_LINUX_SLL, packet, sizeof(packet), &frame) == -1);
}

static void test_sll_exact_header_no_payload(void) {
    uint8_t packet[16] = { 0 };
    LinkFrame frame;

    put16be(packet + 14, 0x0800);
    assert(link_decode(LINKTYPE_LINUX_SLL, packet, sizeof(packet), &frame) == 0);
    assert(frame.payload_len == 0);
}

/* ── LINKTYPE_LINUX_SLL2 ─────────────────────────────────────────────────── */

static void test_sll2_header(void) {
    uint8_t packet[24] = { 0 };
    LinkFrame frame;

    put16be(packet + 0, 0x86DD);   /* protocol comes first in v2 */
    put32be(packet + 4, 7);        /* interface index */
    put16be(packet + 8, 1);        /* ARPHRD_ETHER */
    packet[10] = 1;                /* packet type: broadcast */
    packet[11] = 6;                /* address length */
    memcpy(packet + 12, "\xaa\xbb\xcc\x11\x22\x33", 6);

    assert(link_decode(LINKTYPE_LINUX_SLL2, packet, sizeof(packet), &frame) == 0);
    assert(frame.kind == LINK_PAYLOAD_ETHERTYPE);
    assert(frame.ethertype == 0x86DD);
    assert(frame.hdr_len == 20);
    assert(frame.payload_len == 4);
    assert(frame.sll_interface_index == 7);
    assert(frame.sll_packet_type == 1);
    assert(frame.sll_addr_len == 6);
}

static void test_sll2_address_length_is_clamped(void) {
    uint8_t packet[20] = { 0 };
    LinkFrame frame;

    packet[11] = 0xFF;
    assert(link_decode(LINKTYPE_LINUX_SLL2, packet, sizeof(packet), &frame) == 0);
    assert(frame.sll_addr_len == sizeof(frame.sll_addr));
}

static void test_sll2_truncated(void) {
    uint8_t packet[19] = { 0 };
    LinkFrame frame;

    assert(link_decode(LINKTYPE_LINUX_SLL2, packet, sizeof(packet), &frame) == -1);
}

/* ── dispatch of unsupported types ───────────────────────────────────────── */

static void test_unsupported_link_types(void) {
    uint8_t packet[32] = { 0 };
    LinkFrame frame;

    /* Ethernet is deliberately not handled here: it has VLAN stacking and its
       own header struct. */
    assert(link_decode(LINKTYPE_ETHERNET, packet, sizeof(packet), &frame) == -1);
    assert(link_decode(9999, packet, sizeof(packet), &frame) == -1);

    assert(link_type_supported(LINKTYPE_NULL));
    assert(link_type_supported(LINKTYPE_RAW));
    assert(link_type_supported(LINKTYPE_LINUX_SLL));
    assert(link_type_supported(LINKTYPE_LINUX_SLL2));
    assert(!link_type_supported(LINKTYPE_ETHERNET));
    assert(!link_type_supported(9999));
}

static void test_null_arguments(void) {
    LinkFrame frame;
    uint8_t packet[8] = { 0 };

    assert(link_decode(LINKTYPE_RAW, NULL, sizeof(packet), &frame) == -1);
    assert(link_decode(LINKTYPE_RAW, packet, sizeof(packet), NULL) == -1);
}

static void test_link_type_names(void) {
    assert(strcmp(link_type_name(LINKTYPE_NULL), "BSD loopback") == 0);
    assert(strcmp(link_type_name(LINKTYPE_ETHERNET), "Ethernet") == 0);
    assert(strcmp(link_type_name(LINKTYPE_RAW), "Raw IP") == 0);
    assert(strcmp(link_type_name(9999), "UNKNOWN") == 0);
}

int main(void) {
    test_null_little_endian_ipv4();
    test_null_big_endian_ipv6();
    test_null_accepts_every_ipv6_family_constant();
    test_null_unrecognised_family();
    test_null_truncated();

    test_raw_uses_the_version_nibble();
    test_raw_empty();

    test_sll_header();
    test_sll_address_length_is_clamped();
    test_sll_truncated();
    test_sll_exact_header_no_payload();

    test_sll2_header();
    test_sll2_address_length_is_clamped();
    test_sll2_truncated();

    test_unsupported_link_types();
    test_null_arguments();
    test_link_type_names();

    printf("linktype tests passed\n");
    return 0;
}
