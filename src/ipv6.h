#ifndef IPV6_H
#define IPV6_H

/*
 * Minimal IPv6 fixed-header parser for offline packet inspection.
 *
 * This layer validates the 40-byte base header and can locate the upper-layer
 * payload after the common fixed-size and variable-size extension headers.
 */

#include "common.h"

#define IPV6_HDR_LEN 40
#define IPV6_VERSION 6

#ifndef IPPROTO_ICMPV6
#  define IPPROTO_ICMPV6 58u
#endif

typedef struct {
    uint8_t  version;
    uint8_t  traffic_class;
    uint32_t flow_label;
    uint16_t payload_len;
    uint8_t  next_header;
    uint8_t  hop_limit;
    uint8_t  src[16];
    uint8_t  dst[16];
} Ipv6Header;

/* Maximum segment addresses stored for Routing Header display. */
#define IPV6_ROUTING_MAX_SEGS 8

typedef struct {
    uint8_t     final_next_header;
    const uint8_t* payload;
    size_t      payload_len;
    size_t      extension_len;
    int         fragment_seen;
    uint16_t    fragment_offset;
    int         more_fragments;
    uint32_t    fragment_id;
    /* Routing Header (next_header == 43), if present */
    int         has_routing;
    uint8_t     routing_type;
    uint8_t     routing_segments_left;
    uint8_t     routing_segs[IPV6_ROUTING_MAX_SEGS][16];
    int         routing_seg_count;
} Ipv6Payload;

/*
 * Parse an IPv6 fixed header. Ethernet padding after the declared payload is
 * accepted. Returns 0 on success and -1 for malformed or truncated packets.
 */
int ipv6_parse(const uint8_t* data, size_t len, Ipv6Header* out);

/*
 * Locate the upper-layer payload within a parsed IPv6 packet. The packet
 * pointer must point to the start of the IPv6 header. Fragmented packets are
 * reported but not reassembled here; callers should avoid upper-layer dispatch
 * when fragment_seen is true and either fragment_offset or more_fragments is
 * non-zero.
 */
int ipv6_locate_payload(const Ipv6Header* header,
                        const uint8_t* packet, size_t packet_len,
                        Ipv6Payload* out);

/*
 * Traverse extension headers in a fully reassembled Fragmentable Part.
 * next_header is the value carried by the first fragment's Fragment header.
 */
int ipv6_locate_fragmentable_payload(uint8_t next_header,
                                     const uint8_t* payload,
                                     size_t payload_len,
                                     Ipv6Payload* out);

const char* ipv6_next_header_name(uint8_t next_header);
void ipv6_print(const Ipv6Header* header);
void ipv6_routing_print(const Ipv6Payload* inner);

#endif /* IPV6_H */
