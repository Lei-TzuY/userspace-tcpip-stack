#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "icmpv6.h"

static void init_ipv6(Ipv6Header* ip) {
    memset(ip, 0, sizeof(*ip));
    ip->version = 6;
    ip->payload_len = 10;
    ip->next_header = IPPROTO_ICMPV6;
    ip->hop_limit = 64;
    ip->src[0] = 0x20;
    ip->src[1] = 0x01;
    ip->src[2] = 0x0d;
    ip->src[3] = 0xb8;
    ip->src[15] = 0x10;
    ip->dst[0] = 0x20;
    ip->dst[1] = 0x01;
    ip->dst[2] = 0x0d;
    ip->dst[3] = 0xb8;
    ip->dst[15] = 0x20;
}

static void test_echo_request_and_checksum(void) {
    static const uint8_t message[] = {
        0x80, 0x00, 0xbb, 0x6c, 0x00, 0x42, 0x00, 0x01, 'h', 'i'
    };
    Ipv6Header ip;
    Icmpv6Header icmp;
    init_ipv6(&ip);

    assert(icmpv6_parse(message, sizeof(message), &icmp) == 0);
    assert(icmp.type == ICMPV6_TYPE_ECHO_REQ);
    assert(icmp.code == 0);
    assert(icmp.checksum == 0xbb6c);
    assert(icmp.echo_id == 0x42);
    assert(icmp.echo_seq == 1);
    assert(icmp.payload_len == 2);
    assert(memcmp(icmp.payload, "hi", 2) == 0);
    assert(icmpv6_checksum_ok(&ip, message, sizeof(message)) == 1);
}

static void test_checksum_rejects_modified_message(void) {
    uint8_t message[] = {
        0x80, 0x00, 0xbb, 0x6c, 0x00, 0x42, 0x00, 0x01, 'h', 'i'
    };
    Ipv6Header ip;
    init_ipv6(&ip);
    message[9] = '!';

    assert(icmpv6_checksum_ok(&ip, message, sizeof(message)) == 0);
}

static void test_truncated_message(void) {
    uint8_t message[ICMPV6_MIN_LEN - 1] = {0};
    Icmpv6Header icmp;

    assert(icmpv6_parse(message, sizeof(message), &icmp) == -1);
}

static void test_rejects_malformed_ndp_option_lists(void) {
    uint8_t zero_length[16] = {0};
    uint8_t truncated[16] = {0};
    uint8_t trailing_byte[9] = {0};
    uint8_t after_storage_limit[ICMPV6_MIN_LEN + 9u * 8u] = {0};
    Icmpv6Header icmp;

    zero_length[0] = ICMPV6_TYPE_ROUTER_SOL;
    zero_length[8] = ICMPV6_OPT_SRC_LLADDR;
    assert(icmpv6_parse(zero_length, sizeof(zero_length), &icmp) == -1);

    truncated[0] = ICMPV6_TYPE_ROUTER_SOL;
    truncated[8] = ICMPV6_OPT_PREFIX_INFO;
    truncated[9] = 2; /* Claims 16 option bytes; only eight remain. */
    assert(icmpv6_parse(truncated, sizeof(truncated), &icmp) == -1);

    trailing_byte[0] = ICMPV6_TYPE_ROUTER_SOL;
    trailing_byte[8] = ICMPV6_OPT_SRC_LLADDR;
    assert(icmpv6_parse(trailing_byte, sizeof(trailing_byte), &icmp) == -1);

    after_storage_limit[0] = ICMPV6_TYPE_ROUTER_SOL;
    for (size_t i = 0; i < 8; i++) {
        after_storage_limit[8 + i * 8] = 0xff; /* Unknown but well-formed. */
        after_storage_limit[9 + i * 8] = 1;
    }
    after_storage_limit[8 + 8 * 8] = ICMPV6_OPT_MTU;
    assert(icmpv6_parse(after_storage_limit,
                        sizeof(after_storage_limit), &icmp) == -1);
}

static void test_accepts_bounded_well_formed_ndp_options(void) {
    uint8_t message[ICMPV6_MIN_LEN + 9u * 8u] = {0};
    Icmpv6Header icmp;

    message[0] = ICMPV6_TYPE_ROUTER_SOL;
    for (size_t i = 0; i < 9; i++) {
        message[8 + i * 8] = 0xff; /* Unknown options are permitted. */
        message[9 + i * 8] = 1;
    }

    assert(icmpv6_parse(message, sizeof(message), &icmp) == 0);
    assert(icmp.ndp_opt_count == ICMPV6_NDP_MAX_OPTS);
}

int main(void) {
    test_echo_request_and_checksum();
    test_checksum_rejects_modified_message();
    test_truncated_message();
    test_rejects_malformed_ndp_option_lists();
    test_accepts_bounded_well_formed_ndp_options();
    printf("icmpv6_parse tests passed\n");
    return 0;
}
