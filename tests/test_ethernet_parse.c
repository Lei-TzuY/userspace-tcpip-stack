#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "ethernet.h"

static void init_frame(uint8_t* frame, size_t len) {
    memset(frame, 0, len);
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        frame[i] = (uint8_t)i;
        frame[ETHER_ADDR_LEN + i] = (uint8_t)(0x10 + i);
    }
}

static void write16(uint8_t* data, uint16_t value) {
    data[0] = (uint8_t)(value >> 8);
    data[1] = (uint8_t)(value & 0xff);
}

static void test_plain_ipv4_frame(void) {
    uint8_t frame[ETHER_HDR_LEN];
    EtherHeader header;
    init_frame(frame, sizeof(frame));
    write16(frame + 12, ETHERTYPE_IPV4);

    assert(eth_parse(frame, sizeof(frame), &header) == 0);
    assert(header.outer_ethertype == ETHERTYPE_IPV4);
    assert(header.ethertype == ETHERTYPE_IPV4);
    assert(header.hdr_len == ETHER_HDR_LEN);
    assert(header.vlan_count == 0);
}

static void test_single_vlan_tag(void) {
    uint8_t frame[ETHER_HDR_LEN + ETHER_VLAN_TAG_LEN];
    EtherHeader header;
    uint16_t tci = (uint16_t)((5u << 13) | (1u << 12) | 42u);
    init_frame(frame, sizeof(frame));
    write16(frame + 12, ETHERTYPE_VLAN);
    write16(frame + 14, tci);
    write16(frame + 16, ETHERTYPE_IPV4);

    assert(eth_parse(frame, sizeof(frame), &header) == 0);
    assert(header.outer_ethertype == ETHERTYPE_VLAN);
    assert(header.ethertype == ETHERTYPE_IPV4);
    assert(header.hdr_len == ETHER_HDR_LEN + ETHER_VLAN_TAG_LEN);
    assert(header.vlan_count == 1);
    assert(header.vlan_tags[0].tpid == ETHERTYPE_VLAN);
    assert(header.vlan_tags[0].pcp == 5);
    assert(header.vlan_tags[0].dei == 1);
    assert(header.vlan_tags[0].vid == 42);
}

static void test_qinq_tags(void) {
    uint8_t frame[ETHER_HDR_LEN + 2 * ETHER_VLAN_TAG_LEN];
    EtherHeader header;
    init_frame(frame, sizeof(frame));
    write16(frame + 12, ETHERTYPE_QINQ);
    write16(frame + 14, 100);
    write16(frame + 16, ETHERTYPE_VLAN);
    write16(frame + 18, 200);
    write16(frame + 20, ETHERTYPE_ARP);

    assert(eth_parse(frame, sizeof(frame), &header) == 0);
    assert(header.outer_ethertype == ETHERTYPE_QINQ);
    assert(header.ethertype == ETHERTYPE_ARP);
    assert(header.hdr_len == ETHER_HDR_LEN + 2 * ETHER_VLAN_TAG_LEN);
    assert(header.vlan_count == 2);
    assert(header.vlan_tags[0].tpid == ETHERTYPE_QINQ);
    assert(header.vlan_tags[0].vid == 100);
    assert(header.vlan_tags[1].tpid == ETHERTYPE_VLAN);
    assert(header.vlan_tags[1].vid == 200);
}

static void test_truncated_vlan_tag(void) {
    uint8_t frame[ETHER_HDR_LEN + ETHER_VLAN_TAG_LEN - 1];
    EtherHeader header;
    init_frame(frame, sizeof(frame));
    write16(frame + 12, ETHERTYPE_VLAN);

    assert(eth_parse(frame, sizeof(frame), &header) == -1);
}

static void test_rejects_too_many_vlan_tags(void) {
    uint8_t frame[ETHER_HDR_LEN + 3 * ETHER_VLAN_TAG_LEN];
    EtherHeader header;
    init_frame(frame, sizeof(frame));
    write16(frame + 12, ETHERTYPE_QINQ);
    write16(frame + 14, 100);
    write16(frame + 16, ETHERTYPE_VLAN);
    write16(frame + 18, 200);
    write16(frame + 20, ETHERTYPE_VLAN);
    write16(frame + 22, 300);
    write16(frame + 24, ETHERTYPE_IPV4);

    assert(eth_parse(frame, sizeof(frame), &header) == -1);
}

int main(void) {
    test_plain_ipv4_frame();
    test_single_vlan_tag();
    test_qinq_tags();
    test_truncated_vlan_tag();
    test_rejects_too_many_vlan_tags();
    printf("ethernet_parse tests passed\n");
    return 0;
}
