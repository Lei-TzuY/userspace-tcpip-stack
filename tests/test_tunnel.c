#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "pppoe.h"
#include "vxlan.h"
#include "ethernet.h"

/* ── PPPoE ───────────────────────────────────────────────────────────────── */

static void test_pppoe_session_ipv4(void) {
    /* version/type, code, session id, length, then the PPP protocol. */
    uint8_t packet[] = {
        0x11, 0x00, 0x00, 0x01, 0x00, 0x06,
        0x00, 0x21,                      /* PPP: IPv4 */
        0x45, 0x00, 0x00, 0x14           /* start of an IPv4 header */
    };
    PppoeHeader hdr;

    assert(pppoe_parse(ETHERTYPE_PPPOE_SESSION, packet, sizeof(packet), &hdr) == 0);
    assert(hdr.version == 1 && hdr.type == 1);
    assert(hdr.code == 0);
    assert(hdr.session_id == 1);
    assert(hdr.length == 6);
    assert(hdr.is_session == 1);
    assert(hdr.has_ppp_protocol == 1);
    assert(hdr.ppp_protocol == PPP_PROTO_IPV4);
    assert(hdr.payload_len == 4);
    assert(hdr.payload == packet + 8);
}

static void test_pppoe_length_cannot_exceed_the_packet(void) {
    /* The declared length is the sender's claim. Believing one larger than
       what arrived would hand the next parser bytes that are not there. */
    uint8_t packet[] = {
        0x11, 0x00, 0x00, 0x01, 0xFF, 0xFF,
        0x00, 0x21,
        0x45, 0x00
    };
    PppoeHeader hdr;

    assert(pppoe_parse(ETHERTYPE_PPPOE_SESSION, packet, sizeof(packet), &hdr) == 0);
    assert(hdr.length == 0xFFFF);
    /* 10 bytes present, 6 of header, 2 of PPP protocol, so 2 remain. */
    assert(hdr.payload_len == 2);
}

static void test_pppoe_shorter_declared_length_wins(void) {
    uint8_t packet[] = {
        0x11, 0x00, 0x00, 0x01, 0x00, 0x03,
        0x00, 0x21,
        0x45, 0x00, 0x00, 0x14
    };
    PppoeHeader hdr;

    /* Declared 3: two bytes of PPP protocol and one of payload, even though
       four bytes follow. */
    assert(pppoe_parse(ETHERTYPE_PPPOE_SESSION, packet, sizeof(packet), &hdr) == 0);
    assert(hdr.payload_len == 1);
}

static void test_pppoe_session_without_room_for_protocol(void) {
    uint8_t packet[] = { 0x11, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00 };
    PppoeHeader hdr;

    assert(pppoe_parse(ETHERTYPE_PPPOE_SESSION, packet, sizeof(packet), &hdr) == 0);
    assert(hdr.is_session == 1);
    assert(hdr.has_ppp_protocol == 0);
    assert(hdr.payload_len == 0);
}

static void test_pppoe_discovery_is_not_a_session(void) {
    /* PADI carries TLV tags, not a PPP frame, so no protocol is claimed. */
    uint8_t packet[] = {
        0x11, 0x09, 0x00, 0x00, 0x00, 0x04,
        0x01, 0x01, 0x00, 0x00
    };
    PppoeHeader hdr;

    assert(pppoe_parse(ETHERTYPE_PPPOE_DISCOVERY, packet, sizeof(packet), &hdr) == 0);
    assert(hdr.is_session == 0);
    assert(hdr.has_ppp_protocol == 0);
    assert(hdr.code == 0x09);
    assert(hdr.payload_len == 4);
}

static void test_pppoe_session_ethertype_with_nonzero_code(void) {
    /* A session EtherType carrying a discovery code is not session data. */
    uint8_t packet[] = { 0x11, 0xa7, 0x00, 0x01, 0x00, 0x00 };
    PppoeHeader hdr;

    assert(pppoe_parse(ETHERTYPE_PPPOE_SESSION, packet, sizeof(packet), &hdr) == 0);
    assert(hdr.is_session == 0);
}

static void test_pppoe_truncated(void) {
    uint8_t packet[5] = { 0 };
    PppoeHeader hdr;

    assert(pppoe_parse(ETHERTYPE_PPPOE_SESSION, packet, sizeof(packet), &hdr) == -1);
    assert(pppoe_parse(ETHERTYPE_PPPOE_SESSION, NULL, 16, &hdr) == -1);
    assert(pppoe_parse(ETHERTYPE_PPPOE_SESSION, packet, sizeof(packet), NULL) == -1);
}

static void test_ppp_protocol_names(void) {
    assert(strcmp(ppp_protocol_name(PPP_PROTO_IPV4), "IPv4") == 0);
    assert(strcmp(ppp_protocol_name(PPP_PROTO_IPV6), "IPv6") == 0);
    assert(strcmp(ppp_protocol_name(0xFFFF), "UNKNOWN") == 0);
}

/* ── VXLAN ───────────────────────────────────────────────────────────────── */

static void test_vxlan_header(void) {
    uint8_t packet[8 + 14] = { 0 };
    VxlanHeader hdr;

    packet[0] = 0x08;              /* I bit */
    packet[4] = 0x12;              /* VNI */
    packet[5] = 0x34;
    packet[6] = 0x56;

    assert(vxlan_parse(packet, sizeof(packet), &hdr) == 0);
    assert(hdr.vni_valid == 1);
    assert(hdr.vni == 0x123456);
    assert(hdr.payload_len == 14);
    assert(hdr.payload == packet + 8);
}

static void test_vxlan_without_the_i_bit(void) {
    uint8_t packet[16] = { 0 };
    VxlanHeader hdr;

    /* The VNI field is present but means nothing without the I bit. */
    packet[4] = 0x12;
    assert(vxlan_parse(packet, sizeof(packet), &hdr) == 0);
    assert(hdr.vni_valid == 0);
}

static void test_vxlan_truncated(void) {
    uint8_t packet[7] = { 0 };
    VxlanHeader hdr;

    assert(vxlan_parse(packet, sizeof(packet), &hdr) == -1);
    assert(vxlan_parse(NULL, 16, &hdr) == -1);
    assert(vxlan_parse(packet, 16, NULL) == -1);
}

static void test_vxlan_sniff_demands_the_reserved_bits(void) {
    uint8_t packet[8 + 14] = { 0 };

    /* A port number alone is weak evidence, so the flag and reserved fields
       have to look right too. */
    packet[0] = 0x08;
    assert(vxlan_sniff(packet, sizeof(packet)) == 1);

    packet[0] = 0x0C;              /* a second flag bit set */
    assert(vxlan_sniff(packet, sizeof(packet)) == 0);

    packet[0] = 0x08;
    packet[1] = 0x01;              /* reserved byte not zero */
    assert(vxlan_sniff(packet, sizeof(packet)) == 0);

    packet[1] = 0x00;
    packet[7] = 0x01;              /* the other reserved byte */
    assert(vxlan_sniff(packet, sizeof(packet)) == 0);

    packet[7] = 0x00;
    assert(vxlan_sniff(packet, sizeof(packet)) == 1);
}

static void test_vxlan_sniff_needs_room_for_an_inner_frame(void) {
    uint8_t packet[8 + 13] = { 0 };

    /* Nothing shorter than an Ethernet header can be an inner frame. */
    packet[0] = 0x08;
    assert(vxlan_sniff(packet, sizeof(packet)) == 0);
    assert(vxlan_sniff(packet, 8) == 0);
    assert(vxlan_sniff(NULL, 64) == 0);
}

int main(void) {
    test_pppoe_session_ipv4();
    test_pppoe_length_cannot_exceed_the_packet();
    test_pppoe_shorter_declared_length_wins();
    test_pppoe_session_without_room_for_protocol();
    test_pppoe_discovery_is_not_a_session();
    test_pppoe_session_ethertype_with_nonzero_code();
    test_pppoe_truncated();
    test_ppp_protocol_names();

    test_vxlan_header();
    test_vxlan_without_the_i_bit();
    test_vxlan_truncated();
    test_vxlan_sniff_demands_the_reserved_bits();
    test_vxlan_sniff_needs_room_for_an_inner_frame();

    printf("tunnel tests passed\n");
    return 0;
}
