#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ipv6_reassembly.h"

static Ipv6Reassembler* new_reassembler(void) {
    Ipv6Reassembler* reassembler =
        (Ipv6Reassembler*)malloc(sizeof(*reassembler));
    assert(reassembler != NULL);
    ipv6_reassembly_init(reassembler);
    return reassembler;
}

static Ipv6Header make_header(void) {
    Ipv6Header header;
    memset(&header, 0, sizeof(header));
    header.src[15] = 1;
    header.dst[15] = 2;
    return header;
}

static Ipv6Payload make_fragment(uint16_t offset, int more_fragments,
                                 const uint8_t* payload, size_t payload_len) {
    Ipv6Payload fragment;
    memset(&fragment, 0, sizeof(fragment));
    fragment.final_next_header = IPPROTO_UDP;
    fragment.payload = payload;
    fragment.payload_len = payload_len;
    fragment.fragment_seen = 1;
    fragment.fragment_offset = offset;
    fragment.more_fragments = more_fragments;
    fragment.fragment_id = 0x12345678u;
    return fragment;
}

static void test_rejects_data_beyond_final_fragment_end(void) {
    static const uint8_t first_data[8] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };
    static const uint8_t far_data[8] = {
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    static const uint8_t final_data[8] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    };
    Ipv6Reassembler* reassembler = new_reassembler();
    Ipv6ReassemblyResult result;
    Ipv6Header header = make_header();
    Ipv6Payload first = make_fragment(0, 1, first_data, sizeof(first_data));
    Ipv6Payload high_fragment =
        make_fragment(3, 1, far_data, sizeof(far_data));
    Ipv6Payload final = make_fragment(2, 0, final_data, sizeof(final_data));

    assert(ipv6_reassembly_add_at(
        reassembler, &header, &first, 1, &result)
        == IPV6_REASSEMBLY_INCOMPLETE);
    assert(ipv6_reassembly_add_at(
        reassembler, &header, &high_fragment, 2, &result)
        == IPV6_REASSEMBLY_INCOMPLETE);

    /* The final fragment declares a 24-byte datagram, but bytes 24..31 were
     * already received while bytes 8..15 are still missing. */
    assert(ipv6_reassembly_add_at(
        reassembler, &header, &final, 3, &result)
        == IPV6_REASSEMBLY_ERROR);
    assert(reassembler->completed_datagrams == 0);
    assert(reassembler->rejected_datagrams == 1);
    free(reassembler);
}

int main(void) {
    test_rejects_data_beyond_final_fragment_end();
    printf("ipv6_reassembly tests passed\n");
    return 0;
}
