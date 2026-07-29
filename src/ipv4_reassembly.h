#ifndef IPV4_REASSEMBLY_H
#define IPV4_REASSEMBLY_H

/*
 * Bounded IPv4 fragment reassembly for offline packet inspection.
 *
 * Datagrams are keyed by source IP, destination IP, protocol, and ID.
 * Storage is fixed-size: when all slots are occupied, the oldest incomplete
 * datagram is evicted. Identical overlapping bytes are accepted so duplicate
 * fragments are harmless; conflicting overlaps reject the whole datagram.
 */

#include "ipv4.h"

#define IPV4_REASSEMBLY_MAX_ENTRIES  8
#define IPV4_REASSEMBLY_MAX_PAYLOAD  (65535u - IPV4_MIN_HDR_LEN)
#define IPV4_REASSEMBLY_BITMAP_SIZE  ((IPV4_REASSEMBLY_MAX_PAYLOAD + 7u) / 8u)
#define IPV4_REASSEMBLY_TIMEOUT_USEC (30ULL * 1000000ULL)

typedef enum {
    IPV4_REASSEMBLY_ERROR = -1,
    IPV4_REASSEMBLY_INCOMPLETE = 0,
    IPV4_REASSEMBLY_COMPLETE = 1
} Ipv4ReassemblyStatus;

typedef struct {
    const uint8_t* payload;
    size_t         payload_len;
    size_t         fragment_count;
} Ipv4ReassemblyResult;

typedef struct {
    int      in_use;
    uint8_t  src[4];
    uint8_t  dst[4];
    uint8_t  protocol;
    uint16_t id;
    int      first_seen;
    uint8_t  first_hdr_len;
    int      final_seen;
    size_t   total_len;
    size_t   highest_end;
    size_t   received_count;
    size_t   fragment_count;
    uint64_t last_seen_sequence;
    uint64_t last_seen_usec;
    uint8_t  payload[IPV4_REASSEMBLY_MAX_PAYLOAD];
    uint8_t  received[IPV4_REASSEMBLY_BITMAP_SIZE];
} Ipv4ReassemblyEntry;

typedef struct {
    Ipv4ReassemblyEntry entries[IPV4_REASSEMBLY_MAX_ENTRIES];
    uint64_t            next_sequence;
    uint64_t            logical_now_usec;
    size_t              completed_datagrams;
    size_t              expired_datagrams;
    size_t              rejected_datagrams;
    size_t              evicted_datagrams;
} Ipv4Reassembler;

void ipv4_reassembly_init(Ipv4Reassembler* reassembler);

/*
 * Advance capture time and discard incomplete datagrams older than 30 seconds.
 * Call this for every packet so non-fragment traffic also advances lifecycle.
 */
void ipv4_reassembly_expire_idle(Ipv4Reassembler* reassembler,
                                 uint64_t now_usec);

/*
 * Add one fragmented IPv4 payload.
 *
 * Returns COMPLETE only when every payload byte from offset zero through the
 * final fragment is present. On COMPLETE, result->payload remains valid until
 * a later add call reuses that slot.
 */
Ipv4ReassemblyStatus ipv4_reassembly_add(
    Ipv4Reassembler* reassembler,
    const Ipv4Header* header,
    const uint8_t* fragment_payload,
    size_t fragment_len,
    Ipv4ReassemblyResult* result);

Ipv4ReassemblyStatus ipv4_reassembly_add_at(
    Ipv4Reassembler* reassembler,
    const Ipv4Header* header,
    const uint8_t* fragment_payload,
    size_t fragment_len,
    uint64_t now_usec,
    Ipv4ReassemblyResult* result);

void ipv4_reassembly_print_summary(const Ipv4Reassembler* reassembler);

#endif /* IPV4_REASSEMBLY_H */
