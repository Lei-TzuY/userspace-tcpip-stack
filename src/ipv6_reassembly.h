#ifndef IPV6_REASSEMBLY_H
#define IPV6_REASSEMBLY_H

/*
 * Bounded IPv6 fragment reassembly for offline packet inspection.
 *
 * Datagrams are keyed by source address, destination address, and the 32-bit
 * Identification field from the Fragment extension header (RFC 8200 §4.5).
 * The final_next_header of the first fragment (offset 0) becomes the next
 * protocol identifier for the reassembled payload.
 *
 * The reassembler mirrors the IPv4 implementation: a fixed-size table of
 * slots, with oldest-slot eviction when full, and a 60-second idle timeout
 * matching the RFC 2460 recommended reassembly timeout.
 */

#include "ipv6.h"

#define IPV6_REASSEMBLY_MAX_ENTRIES   8
#define IPV6_REASSEMBLY_MAX_PAYLOAD   65535u
#define IPV6_REASSEMBLY_BITMAP_SIZE   ((IPV6_REASSEMBLY_MAX_PAYLOAD + 7u) / 8u)
#define IPV6_REASSEMBLY_TIMEOUT_USEC  (60ULL * 1000000ULL)

typedef enum {
    IPV6_REASSEMBLY_ERROR      = -1,
    IPV6_REASSEMBLY_INCOMPLETE =  0,
    IPV6_REASSEMBLY_COMPLETE   =  1
} Ipv6ReassemblyStatus;

typedef struct {
    const uint8_t* payload;
    size_t         payload_len;
    size_t         fragment_count;
    uint8_t        final_next_header;
} Ipv6ReassemblyResult;

typedef struct {
    int      in_use;
    uint8_t  src[16];
    uint8_t  dst[16];
    uint32_t id;
    uint8_t  final_next_header;
    int      first_seen;           /* fragment at offset 0 was received */
    int      final_seen;           /* fragment with M=0 was received */
    size_t   total_len;            /* byte length once final fragment known */
    size_t   received_count;       /* bytes received so far */
    size_t   fragment_count;
    uint64_t last_seen_sequence;
    uint64_t last_seen_usec;
    uint8_t  payload[IPV6_REASSEMBLY_MAX_PAYLOAD];
    uint8_t  received[IPV6_REASSEMBLY_BITMAP_SIZE];
} Ipv6ReassemblyEntry;

typedef struct {
    Ipv6ReassemblyEntry entries[IPV6_REASSEMBLY_MAX_ENTRIES];
    uint64_t            next_sequence;
    uint64_t            logical_now_usec;
    size_t              completed_datagrams;
    size_t              expired_datagrams;
    size_t              rejected_datagrams;
    size_t              evicted_datagrams;
} Ipv6Reassembler;

void ipv6_reassembly_init(Ipv6Reassembler* reassembler);

/*
 * Advance capture time and discard incomplete datagrams older than 60 seconds.
 * Call this for every packet so non-fragment traffic also advances lifecycle.
 */
void ipv6_reassembly_expire_idle(Ipv6Reassembler* reassembler,
                                 uint64_t now_usec);

/*
 * Add one fragmented IPv6 fragment.
 *
 * inner must have fragment_seen == 1. Returns COMPLETE when every payload byte
 * from offset zero through the final fragment is present; on COMPLETE,
 * result->payload is valid until a later add call reuses that slot.
 */
Ipv6ReassemblyStatus ipv6_reassembly_add_at(
    Ipv6Reassembler* reassembler,
    const Ipv6Header* header,
    const Ipv6Payload* inner,
    uint64_t now_usec,
    Ipv6ReassemblyResult* result);

void ipv6_reassembly_print_summary(const Ipv6Reassembler* reassembler);

#endif /* IPV6_REASSEMBLY_H */
