#include <assert.h>
#include <stdio.h>

#include "udp_tracker.h"

static const uint8_t client_ip[4] = { 192, 0, 2, 1 };
static const uint8_t server_ip[4] = { 198, 51, 100, 2 };

static void test_earlier_clock_does_not_expire_flow(void) {
    UdpTracker tracker;
    int slot;

    udp_tracker_init(&tracker);
    slot = udp_tracker_observe(&tracker, client_ip, server_ip, 4,
                               12345, 53, 40000000u);
    assert(slot >= 0);

    udp_tracker_expire_idle(&tracker, 20000000u);
    assert(tracker.flows[slot].active);
}

static void test_earlier_packet_does_not_rewind_last_seen(void) {
    UdpTracker tracker;
    int slot;

    udp_tracker_init(&tracker);
    slot = udp_tracker_observe(&tracker, client_ip, server_ip, 4,
                               12345, 53, 40000000u);
    assert(slot >= 0);
    assert(udp_tracker_observe(&tracker, client_ip, server_ip, 4,
                               12345, 53, 10000000u) == slot);
    assert(tracker.flows[slot].last_seen_usec == 40000000u);

    udp_tracker_expire_idle(&tracker, 40000001u);
    assert(tracker.flows[slot].active);
}

static void test_negative_dns_rtt_is_not_recorded(void) {
    UdpTracker tracker;

    udp_tracker_init(&tracker);
    udp_tracker_dns_query(&tracker, 0x1234, client_ip, server_ip, 4,
                          12345, 1000u);

    assert(udp_tracker_dns_response(&tracker, 0x1234, server_ip, client_ip, 4,
                                    12345, 900u) == 0);
    assert(tracker.dns_pending[0].active);
    assert(tracker.dns_rtt_count == 0);

    assert(udp_tracker_dns_response(&tracker, 0x1234, server_ip, client_ip, 4,
                                    12345, 1100u) == 100u);
    assert(!tracker.dns_pending[0].active);
    assert(tracker.dns_rtt_count == 1);
}

static void test_earlier_response_can_match_an_older_duplicate_xid(void) {
    UdpTracker tracker;

    udp_tracker_init(&tracker);
    udp_tracker_dns_query(&tracker, 0x1234, client_ip, server_ip, 4,
                          12345, 1000u);
    udp_tracker_dns_query(&tracker, 0x1234, client_ip, server_ip, 4,
                          12345, 800u);

    assert(udp_tracker_dns_response(&tracker, 0x1234, server_ip, client_ip, 4,
                                    12345, 900u) == 100u);
    assert(tracker.dns_pending[0].active);
    assert(!tracker.dns_pending[1].active);
}

int main(void) {
    test_earlier_clock_does_not_expire_flow();
    test_earlier_packet_does_not_rewind_last_seen();
    test_negative_dns_rtt_is_not_recorded();
    test_earlier_response_can_match_an_older_duplicate_xid();
    printf("udp_tracker tests passed\n");
    return 0;
}
