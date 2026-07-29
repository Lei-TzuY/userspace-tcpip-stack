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

int main(void) {
    test_declared_length_bounds_payload();
    test_length_smaller_than_header();
    test_truncated_datagram();
    test_checksum_rejects_short_segment();
    test_disabled_checksum_is_valid();
    printf("udp_parse tests passed\n");
    return 0;
}
