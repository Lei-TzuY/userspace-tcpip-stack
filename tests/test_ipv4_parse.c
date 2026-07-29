#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "ipv4.h"

static void init_packet(uint8_t* packet, size_t len, uint16_t total_len) {
    memset(packet, 0, len);
    packet[0] = 0x45; /* IPv4, 20-byte header */
    packet[2] = (uint8_t)(total_len >> 8);
    packet[3] = (uint8_t)(total_len & 0xff);
    packet[8] = 64;
    packet[9] = IPPROTO_UDP;
}

static void test_valid_packet_with_ethernet_padding(void) {
    uint8_t packet[24];
    Ipv4Header header;
    init_packet(packet, sizeof(packet), 20);

    assert(ipv4_parse(packet, sizeof(packet), &header) == 0);
    assert(header.total_len == 20);
    assert(header.hdr_len == 20);
}

static void test_total_length_smaller_than_header(void) {
    uint8_t packet[20];
    Ipv4Header header;
    init_packet(packet, sizeof(packet), 19);

    assert(ipv4_parse(packet, sizeof(packet), &header) == -1);
}

static void test_truncated_packet(void) {
    uint8_t packet[20];
    Ipv4Header header;
    init_packet(packet, sizeof(packet), 21);

    assert(ipv4_parse(packet, sizeof(packet), &header) == -1);
}

int main(void) {
    test_valid_packet_with_ethernet_padding();
    test_total_length_smaller_than_header();
    test_truncated_packet();
    printf("ipv4_parse tests passed\n");
    return 0;
}
