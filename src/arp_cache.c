#include "arp_cache.h"

static int bytes_all_equal(const uint8_t* data, size_t len, uint8_t value) {
    for (size_t i = 0; i < len; i++) {
        if (data[i] != value)
            return 0;
    }
    return 1;
}

static int sender_is_cacheable(const uint8_t* ip, const uint8_t* mac) {
    return !bytes_all_equal(ip, 4, 0)
        && !bytes_all_equal(mac, 6, 0)
        && !bytes_all_equal(mac, 6, 0xff);
}

void arp_cache_init(ArpCache* cache) {
    memset(cache, 0, sizeof(*cache));
}

ArpCacheStatus arp_cache_learn(
    ArpCache* cache, const uint8_t* ip, const uint8_t* mac) {
    ArpCacheEntry* free_entry = NULL;

    if (!cache || !ip || !mac || !sender_is_cacheable(ip, mac))
        return ARP_CACHE_IGNORED;

    for (size_t i = 0; i < ARP_CACHE_MAX_ENTRIES; i++) {
        ArpCacheEntry* entry = &cache->entries[i];
        if (!entry->in_use) {
            if (!free_entry)
                free_entry = entry;
            continue;
        }
        if (memcmp(entry->ip, ip, 4) != 0)
            continue;
        if (memcmp(entry->mac, mac, 6) == 0)
            return ARP_CACHE_UNCHANGED;
        memcpy(entry->mac, mac, 6);
        return ARP_CACHE_UPDATED;
    }

    if (!free_entry)
        return ARP_CACHE_FULL;

    free_entry->in_use = 1;
    memcpy(free_entry->ip, ip, 4);
    memcpy(free_entry->mac, mac, 6);
    return ARP_CACHE_ADDED;
}

const char* arp_cache_status_name(ArpCacheStatus status) {
    switch (status) {
        case ARP_CACHE_FULL:      return "table full";
        case ARP_CACHE_UNCHANGED: return "unchanged";
        case ARP_CACHE_ADDED:     return "learned";
        case ARP_CACHE_UPDATED:   return "updated";
        case ARP_CACHE_IGNORED:   return "ignored";
        default:                  return "unknown";
    }
}

void arp_cache_print_summary(const ArpCache* cache) {
    size_t count = 0;

    printf("\n-- ARP cache summary --\n");
    for (size_t i = 0; i < ARP_CACHE_MAX_ENTRIES; i++) {
        const ArpCacheEntry* entry = &cache->entries[i];
        if (!entry->in_use)
            continue;
        count++;
        printf("  %u.%u.%u.%u -> %02x:%02x:%02x:%02x:%02x:%02x\n",
               entry->ip[0], entry->ip[1], entry->ip[2], entry->ip[3],
               entry->mac[0], entry->mac[1], entry->mac[2],
               entry->mac[3], entry->mac[4], entry->mac[5]);
    }
    printf("  tracked neighbors: %zu\n", count);
}
