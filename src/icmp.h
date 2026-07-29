#ifndef ICMP_H
#define ICMP_H

/*
 * icmp.h — ICMP (Internet Control Message Protocol) parser
 *
 * ICMP Message Layout:
 *
 *  Offset  Size  Field
 *  ──────  ────  ─────────────────────────────────────────────────────────
 *    0      1    Type
 *    1      1    Code
 *    2      2    Checksum          (big-endian, covers header + data)
 *    4      4    Rest of Header    (interpretation depends on type)
 *    8      *    Data              (type-dependent)
 *
 * Echo Request / Reply (type 8 / 0):
 *   Offset 4–5 : Identifier  (big-endian)
 *   Offset 6–7 : Sequence    (big-endian)
 *   Offset 8+  : Echo data
 *
 * Destination Unreachable (type 3):
 *   Offset 4–7 : unused (must be zero)
 *   Offset 8+  : original IP header + first 8 bytes of original datagram
 *
 * Time Exceeded (type 11):
 *   Same layout as Destination Unreachable.
 *
 * The checksum covers the entire ICMP message (no pseudo-header required).
 *
 * Reference: RFC 792
 */

#include "common.h"

#define ICMP_MIN_LEN  8   /* minimum: type + code + checksum + rest-of-hdr */

/* Common type values */
#define ICMP_TYPE_ECHO_REPLY    0u
#define ICMP_TYPE_UNREACH       3u
#define ICMP_TYPE_ECHO_REQ      8u
#define ICMP_TYPE_TIME_EXCEEDED 11u

/* Codes for Destination Unreachable (type 3) */
#define ICMP_UNREACH_NET    0u
#define ICMP_UNREACH_HOST   1u
#define ICMP_UNREACH_PROTO  2u
#define ICMP_UNREACH_PORT   3u
#define ICMP_UNREACH_FRAG   4u   /* fragmentation needed but DF set */

typedef struct {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    int      checksum_valid;  /* 1 = OK, 0 = bad */

    /* Fields valid for Echo Request / Echo Reply */
    uint16_t echo_id;
    uint16_t echo_seq;

    /* Pointer into the original packet buffer (not a copy) */
    const uint8_t* payload;
    size_t         payload_len;

    /* Embedded original datagram (type 3 = Unreachable, type 11 = Time-Exceeded) */
    int     has_embedded;
    uint8_t embedded_proto;       /* IPv4 protocol of original datagram */
    uint8_t embedded_src[4];      /* original source IP */
    uint8_t embedded_dst[4];      /* original destination IP */
    uint16_t embedded_src_port;   /* TCP/UDP only; 0 otherwise */
    uint16_t embedded_dst_port;
} IcmpHeader;

/*
 * icmp_parse — parse raw ICMP bytes (the IPv4 payload for protocol 1).
 *   data     — start of the ICMP message
 *   len      — bytes available (should be ipv4.total_len - ipv4.hdr_len)
 *   out      — filled on success; payload pointer references data[]
 * Returns 0 on success, -1 if len < ICMP_MIN_LEN.
 */
int icmp_parse(const uint8_t* data, size_t len, IcmpHeader* out);

/*
 * icmp_print — pretty-print an ICMP header to stdout.
 */
void icmp_print(const IcmpHeader* hdr);

/*
 * icmp_type_name — return a human-readable string for a type value.
 */
const char* icmp_type_name(uint8_t type);

#endif /* ICMP_H */
