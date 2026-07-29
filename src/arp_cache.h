#ifndef ARP_CACHE_H
#define ARP_CACHE_H

/*
 * Fixed-size passive ARP cache.
 *
 * Offline inspection cannot actively resolve neighbors, but valid ARP sender
 * fields still provide useful IPv4-to-MAC mappings. Entries are updated in
 * place when a later packet advertises a different MAC for the same IP.
 */

#include "arp.h"

#define ARP_CACHE_MAX_ENTRIES 32

typedef enum {
    ARP_CACHE_FULL = -1,
    ARP_CACHE_UNCHANGED = 0,
    ARP_CACHE_ADDED,
    ARP_CACHE_UPDATED,
    ARP_CACHE_IGNORED
} ArpCacheStatus;

typedef struct {
    int     in_use;
    uint8_t ip[4];
    uint8_t mac[6];
} ArpCacheEntry;

typedef struct {
    ArpCacheEntry entries[ARP_CACHE_MAX_ENTRIES];
} ArpCache;

void arp_cache_init(ArpCache* cache);
ArpCacheStatus arp_cache_learn(
    ArpCache* cache, const uint8_t* ip, const uint8_t* mac);
const char* arp_cache_status_name(ArpCacheStatus status);
void arp_cache_print_summary(const ArpCache* cache);

#endif /* ARP_CACHE_H */
