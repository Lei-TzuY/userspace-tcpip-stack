#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "arp_cache.h"

static void test_learns_updates_and_ignores(void) {
    static const uint8_t ip[4] = { 192, 168, 1, 10 };
    static const uint8_t mac1[6] = { 0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33 };
    static const uint8_t mac2[6] = { 0xaa, 0xbb, 0xcc, 0x44, 0x55, 0x66 };
    static const uint8_t zero_ip[4] = { 0 };
    static const uint8_t broadcast[6] =
        { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    ArpCache cache;
    arp_cache_init(&cache);

    assert(arp_cache_learn(&cache, ip, mac1) == ARP_CACHE_ADDED);
    assert(arp_cache_learn(&cache, ip, mac1) == ARP_CACHE_UNCHANGED);
    assert(arp_cache_learn(&cache, ip, mac2) == ARP_CACHE_UPDATED);
    assert(memcmp(cache.entries[0].mac, mac2, sizeof(mac2)) == 0);
    assert(arp_cache_learn(&cache, zero_ip, mac1) == ARP_CACHE_IGNORED);
    assert(arp_cache_learn(&cache, ip, broadcast) == ARP_CACHE_IGNORED);
}

static void test_reports_full_table(void) {
    static const uint8_t mac[6] = { 0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33 };
    ArpCache cache;
    arp_cache_init(&cache);

    for (size_t i = 0; i < ARP_CACHE_MAX_ENTRIES; i++) {
        uint8_t ip[4] = { 192, 0, 2, (uint8_t)(i + 1) };
        assert(arp_cache_learn(&cache, ip, mac) == ARP_CACHE_ADDED);
    }

    static const uint8_t extra_ip[4] = { 198, 51, 100, 1 };
    assert(arp_cache_learn(&cache, extra_ip, mac) == ARP_CACHE_FULL);
}

int main(void) {
    test_learns_updates_and_ignores();
    test_reports_full_table();
    printf("arp_cache tests passed\n");
    return 0;
}
