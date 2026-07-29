#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ipv4_reassembly.h"

static const uint8_t SRC_IP[4] = { 192, 0, 2, 1 };
static const uint8_t DST_IP[4] = { 198, 51, 100, 2 };

static Ipv4Reassembler* new_reassembler(void) {
    Ipv4Reassembler* reassembler =
        (Ipv4Reassembler*)malloc(sizeof(*reassembler));
    assert(reassembler != NULL);
    ipv4_reassembly_init(reassembler);
    return reassembler;
}

static Ipv4Header make_fragment(uint16_t id, uint16_t offset,
                                int more_fragments, size_t payload_len) {
    Ipv4Header header;
    memset(&header, 0, sizeof(header));
    header.hdr_len = IPV4_MIN_HDR_LEN;
    header.total_len = (uint16_t)(header.hdr_len + payload_len);
    header.id = id;
    header.flags = more_fragments ? IPV4_FLAG_MF : 0;
    header.frag_offset = offset;
    header.protocol = IPPROTO_UDP;
    memcpy(header.src, SRC_IP, sizeof(header.src));
    memcpy(header.dst, DST_IP, sizeof(header.dst));
    return header;
}

static size_t active_entries(const Ipv4Reassembler* reassembler) {
    size_t count = 0;
    for (size_t i = 0; i < IPV4_REASSEMBLY_MAX_ENTRIES; i++) {
        if (reassembler->entries[i].in_use)
            count++;
    }
    return count;
}

static void test_reassembles_in_order(void) {
    static const uint8_t payload[] = "abcdefghijklmnopqrstuvwx";
    Ipv4Reassembler* reassembler = new_reassembler();
    Ipv4ReassemblyResult result;
    Ipv4Header first = make_fragment(1, 0, 1, 16);
    Ipv4Header second = make_fragment(1, 2, 0, 8);

    assert(ipv4_reassembly_add(
        reassembler, &first, payload, 16, &result) == IPV4_REASSEMBLY_INCOMPLETE);
    assert(ipv4_reassembly_add(
        reassembler, &second, payload + 16, 8, &result) == IPV4_REASSEMBLY_COMPLETE);
    assert(result.payload_len == sizeof(payload) - 1);
    assert(result.fragment_count == 2);
    assert(memcmp(result.payload, payload, result.payload_len) == 0);
    assert(reassembler->completed_datagrams == 1);
    free(reassembler);
}

static void test_reassembles_out_of_order(void) {
    static const uint8_t payload[] = "abcdefghijklmnopqrstuvwx";
    Ipv4Reassembler* reassembler = new_reassembler();
    Ipv4ReassemblyResult result;
    Ipv4Header first = make_fragment(2, 0, 1, 16);
    Ipv4Header second = make_fragment(2, 2, 0, 8);

    assert(ipv4_reassembly_add(
        reassembler, &second, payload + 16, 8, &result) == IPV4_REASSEMBLY_INCOMPLETE);
    assert(ipv4_reassembly_add(
        reassembler, &first, payload, 16, &result) == IPV4_REASSEMBLY_COMPLETE);
    assert(memcmp(result.payload, payload, result.payload_len) == 0);
    free(reassembler);
}

static void test_accepts_identical_duplicate_fragment(void) {
    static const uint8_t payload[] = "abcdefghijklmnopqrstuvwx";
    Ipv4Reassembler* reassembler = new_reassembler();
    Ipv4ReassemblyResult result;
    Ipv4Header first = make_fragment(3, 0, 1, 16);
    Ipv4Header second = make_fragment(3, 2, 0, 8);

    assert(ipv4_reassembly_add(
        reassembler, &first, payload, 16, &result) == IPV4_REASSEMBLY_INCOMPLETE);
    assert(ipv4_reassembly_add(
        reassembler, &first, payload, 16, &result) == IPV4_REASSEMBLY_INCOMPLETE);
    assert(ipv4_reassembly_add(
        reassembler, &second, payload + 16, 8, &result) == IPV4_REASSEMBLY_COMPLETE);
    assert(result.fragment_count == 3);
    free(reassembler);
}

static void test_rejects_conflicting_overlap(void) {
    static const uint8_t first_payload[] = "abcdefghijklmnop";
    static const uint8_t conflicting_payload[] = "XXXXXXXX";
    Ipv4Reassembler* reassembler = new_reassembler();
    Ipv4ReassemblyResult result;
    Ipv4Header first = make_fragment(4, 0, 1, 16);
    Ipv4Header overlap = make_fragment(4, 1, 0, 8);

    assert(ipv4_reassembly_add(
        reassembler, &first, first_payload, 16, &result) == IPV4_REASSEMBLY_INCOMPLETE);
    assert(ipv4_reassembly_add(
        reassembler, &overlap, conflicting_payload, 8, &result) == IPV4_REASSEMBLY_ERROR);
    assert(reassembler->rejected_datagrams == 1);
    free(reassembler);
}

static void test_rejects_unaligned_non_final_fragment(void) {
    static const uint8_t payload[] = "1234567";
    Ipv4Reassembler* reassembler = new_reassembler();
    Ipv4ReassemblyResult result;
    Ipv4Header fragment = make_fragment(5, 0, 1, 7);

    assert(ipv4_reassembly_add(
        reassembler, &fragment, payload, 7, &result) == IPV4_REASSEMBLY_ERROR);
    free(reassembler);
}

static void test_evicts_oldest_incomplete_datagram(void) {
    static const uint8_t payload[] = "12345678";
    Ipv4Reassembler* reassembler = new_reassembler();
    Ipv4ReassemblyResult result;

    for (uint16_t id = 10; id < 10 + IPV4_REASSEMBLY_MAX_ENTRIES; id++) {
        Ipv4Header fragment = make_fragment(id, 0, 1, sizeof(payload) - 1);
        assert(ipv4_reassembly_add(
            reassembler, &fragment, payload, sizeof(payload) - 1,
            &result) == IPV4_REASSEMBLY_INCOMPLETE);
    }

    Ipv4Header replacement = make_fragment(99, 0, 1, sizeof(payload) - 1);
    assert(ipv4_reassembly_add(
        reassembler, &replacement, payload, sizeof(payload) - 1,
        &result) == IPV4_REASSEMBLY_INCOMPLETE);
    assert(reassembler->evicted_datagrams == 1);

    Ipv4Header evicted_tail = make_fragment(10, 1, 0, sizeof(payload) - 1);
    assert(ipv4_reassembly_add(
        reassembler, &evicted_tail, payload, sizeof(payload) - 1,
        &result) == IPV4_REASSEMBLY_INCOMPLETE);
    free(reassembler);
}

static void test_expires_idle_datagram(void) {
    static const uint8_t payload[] = "12345678";
    Ipv4Reassembler* reassembler = new_reassembler();
    Ipv4ReassemblyResult result;
    Ipv4Header fragment = make_fragment(100, 0, 1, sizeof(payload) - 1);

    assert(ipv4_reassembly_add_at(
        reassembler, &fragment, payload, sizeof(payload) - 1, 10,
        &result) == IPV4_REASSEMBLY_INCOMPLETE);
    assert(active_entries(reassembler) == 1);

    ipv4_reassembly_expire_idle(
        reassembler, 11 + IPV4_REASSEMBLY_TIMEOUT_USEC);
    assert(active_entries(reassembler) == 0);
    assert(reassembler->expired_datagrams == 1);
    free(reassembler);
}

static void test_activity_refreshes_timeout(void) {
    static const uint8_t payload[] = "12345678";
    Ipv4Reassembler* reassembler = new_reassembler();
    Ipv4ReassemblyResult result;
    Ipv4Header fragment = make_fragment(101, 0, 1, sizeof(payload) - 1);

    assert(ipv4_reassembly_add_at(
        reassembler, &fragment, payload, sizeof(payload) - 1, 10,
        &result) == IPV4_REASSEMBLY_INCOMPLETE);
    assert(ipv4_reassembly_add_at(
        reassembler, &fragment, payload, sizeof(payload) - 1,
        10 + IPV4_REASSEMBLY_TIMEOUT_USEC,
        &result) == IPV4_REASSEMBLY_INCOMPLETE);

    ipv4_reassembly_expire_idle(
        reassembler, 11 + IPV4_REASSEMBLY_TIMEOUT_USEC);
    assert(active_entries(reassembler) == 1);
    assert(reassembler->expired_datagrams == 0);
    free(reassembler);
}

static void test_first_header_options_reduce_payload_limit(void) {
    static const uint8_t payload[] = "12345678";
    Ipv4Reassembler* reassembler = new_reassembler();
    Ipv4ReassemblyResult result;
    Ipv4Header first = make_fragment(6, 0, 1, sizeof(payload) - 1);
    Ipv4Header oversized_tail =
        make_fragment(6, 8185, 0, sizeof(payload) - 1);
    first.hdr_len = IPV4_MAX_HDR_LEN;
    first.total_len = (uint16_t)(first.hdr_len + sizeof(payload) - 1);

    assert(ipv4_reassembly_add(
        reassembler, &first, payload, sizeof(payload) - 1,
        &result) == IPV4_REASSEMBLY_INCOMPLETE);
    assert(ipv4_reassembly_add(
        reassembler, &oversized_tail, payload, sizeof(payload) - 1,
        &result) == IPV4_REASSEMBLY_ERROR);
    free(reassembler);
}

int main(void) {
    test_reassembles_in_order();
    test_reassembles_out_of_order();
    test_accepts_identical_duplicate_fragment();
    test_rejects_conflicting_overlap();
    test_rejects_unaligned_non_final_fragment();
    test_evicts_oldest_incomplete_datagram();
    test_first_header_options_reduce_payload_limit();
    test_expires_idle_datagram();
    test_activity_refreshes_timeout();
    printf("ipv4_reassembly tests passed\n");
    return 0;
}
