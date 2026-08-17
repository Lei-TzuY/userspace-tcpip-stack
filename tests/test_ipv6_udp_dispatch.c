#include <assert.h>
#include <stdio.h>

#include "dispatch.h"
#include "pcap.h"
#include "udp.h"

static void test_checksum_uses_udp_declared_length(void) {
    /* A valid eight-byte UDP datagram followed by two bytes that belong to the
     * enclosing IPv6 payload, but not to the UDP datagram. */
    static const uint8_t packet[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x11, 0x40,
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x04, 0xd2, 0x10, 0xe1, 0x00, 0x08, 0x8e, 0xb6,
        0xde, 0xad
    };
    const uint8_t* udp = packet + IPV6_HDR_LEN;
    StackContext* ctx = stack_create();

    assert(ctx != NULL);
    assert(udp_checksum_ok_v6(packet + 8, packet + 24,
                              udp, UDP_HDR_LEN) == 1);
    assert(udp_checksum_ok_v6(packet + 8, packet + 24,
                              udp, UDP_HDR_LEN + 2) == 0);

    stack_dispatch_link(ctx, LINKTYPE_RAW, packet, sizeof(packet), 1);
    stack_destroy(ctx);
}

int main(void) {
    test_checksum_uses_udp_declared_length();
    printf("ipv6_udp_dispatch tests passed\n");
    return 0;
}
