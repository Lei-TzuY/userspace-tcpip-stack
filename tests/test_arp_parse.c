#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "arp.h"

static void init_packet(uint8_t* packet) {
    memset(packet, 0, ARP_HDR_LEN);
    packet[0] = 0x00;
    packet[1] = ARP_HW_ETHERNET;
    packet[2] = 0x08;
    packet[3] = 0x00;
    packet[4] = 6;
    packet[5] = 4;
    packet[6] = 0x00;
    packet[7] = ARP_OP_REQUEST;
}

static void test_valid_ethernet_ipv4_arp(void) {
    uint8_t packet[ARP_HDR_LEN];
    ArpHeader header;
    init_packet(packet);
    packet[8] = 0xaa;
    packet[14] = 192;
    packet[15] = 168;
    packet[16] = 1;
    packet[17] = 10;

    assert(arp_parse(packet, sizeof(packet), &header) == 0);
    assert(header.hw_type == ARP_HW_ETHERNET);
    assert(header.proto_type == ARP_PROTO_IPV4);
    assert(header.operation == ARP_OP_REQUEST);
    assert(header.sender_mac[0] == 0xaa);
    assert(header.sender_ip[3] == 10);
}

static void test_unknown_operation_is_preserved(void) {
    uint8_t packet[ARP_HDR_LEN];
    ArpHeader header;
    init_packet(packet);
    packet[7] = 99;

    assert(arp_parse(packet, sizeof(packet), &header) == 0);
    assert(header.operation == 99);
}

static void test_rejects_truncated_packet(void) {
    uint8_t packet[ARP_HDR_LEN];
    ArpHeader header;
    init_packet(packet);

    assert(arp_parse(packet, sizeof(packet) - 1, &header) == -1);
}

static void test_rejects_non_ethernet_format(void) {
    uint8_t packet[ARP_HDR_LEN];
    ArpHeader header;
    init_packet(packet);
    packet[1] = 2;

    assert(arp_parse(packet, sizeof(packet), &header) == -1);
}

static void test_rejects_non_ipv4_format(void) {
    uint8_t packet[ARP_HDR_LEN];
    ArpHeader header;
    init_packet(packet);
    packet[3] = 0x06;

    assert(arp_parse(packet, sizeof(packet), &header) == -1);
}

static void test_rejects_different_address_lengths(void) {
    uint8_t packet[ARP_HDR_LEN];
    ArpHeader header;
    init_packet(packet);
    packet[4] = 8;

    assert(arp_parse(packet, sizeof(packet), &header) == -1);
}

int main(void) {
    test_valid_ethernet_ipv4_arp();
    test_unknown_operation_is_preserved();
    test_rejects_truncated_packet();
    test_rejects_non_ethernet_format();
    test_rejects_non_ipv4_format();
    test_rejects_different_address_lengths();
    printf("arp_parse tests passed\n");
    return 0;
}
