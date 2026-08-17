#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "udp.h"

static void init_datagram(uint8_t* datagram, size_t len, uint16_t udp_len) {
    memset(datagram, 0, len);
    datagram[0] = 0x00;
    datagram[1] = 0x35;
    datagram[2] = 0x30;
    datagram[3] = 0x39;
    datagram[4] = (uint8_t)(udp_len >> 8);
    datagram[5] = (uint8_t)(udp_len & 0xff);
}

static void test_declared_length_bounds_payload(void) {
    uint8_t datagram[14];
    UdpHeader header;
    init_datagram(datagram, sizeof(datagram), 10);

    assert(udp_parse(datagram, sizeof(datagram), &header) == 0);
    assert(header.src_port == 53);
    assert(header.dst_port == 12345);
    assert(header.payload_len == 2);
    assert(header.payload == datagram + UDP_HDR_LEN);
}

static void test_length_smaller_than_header(void) {
    uint8_t datagram[8];
    UdpHeader header;
    init_datagram(datagram, sizeof(datagram), 7);

    assert(udp_parse(datagram, sizeof(datagram), &header) == -1);
}

static void test_truncated_datagram(void) {
    uint8_t datagram[8];
    UdpHeader header;
    init_datagram(datagram, sizeof(datagram), 9);

    assert(udp_parse(datagram, sizeof(datagram), &header) == -1);
}

static void test_checksum_rejects_short_segment(void) {
    static const uint8_t ip[4] = { 192, 0, 2, 1 };
    uint8_t datagram[7] = { 0 };

    assert(udp_checksum_ok(ip, ip, datagram, sizeof(datagram)) == 0);
}

static void test_disabled_checksum_is_valid(void) {
    static const uint8_t ip[4] = { 192, 0, 2, 1 };
    uint8_t datagram[8];
    init_datagram(datagram, sizeof(datagram), sizeof(datagram));

    assert(udp_checksum_ok(ip, ip, datagram, sizeof(datagram)) == 1);
}

static void test_zero_checksum_is_invalid_over_ipv6(void) {
    static const uint8_t src_ip[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
    };
    static const uint8_t dst_ip[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2
    };
    /* The non-checksum words deliberately sum to 0xffff. A verifier that
     * checks only the folded sum will therefore accept this forbidden zero. */
    static const uint8_t datagram[8] = {
        0x04, 0xd2, 0x9f, 0x97, 0x00, 0x08, 0x00, 0x00
    };

    assert(udp_checksum_ok_v6(
        src_ip, dst_ip, datagram, sizeof(datagram)) == 0);
}

int main(void) {
    test_declared_length_bounds_payload();
    test_length_smaller_than_header();
    test_truncated_datagram();
    test_checksum_rejects_short_segment();
    test_disabled_checksum_is_valid();
    test_zero_checksum_is_invalid_over_ipv6();
    printf("udp_parse tests passed\n");
    return 0;
}
