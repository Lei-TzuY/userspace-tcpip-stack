#ifndef IPV4_H
#define IPV4_H

/*
 * ipv4.h — IPv4 header parser
 *
 * IPv4 Header Layout (20 bytes minimum, up to 60 bytes with options):
 *
 *  Offset  Size  Field
 *  ──────  ────  ─────────────────────────────────────────────────────────
 *    0      1    Version (4 bits) + IHL (4 bits, header length in 32-bit words)
 *    1      1    DSCP (6 bits) + ECN (2 bits)
 *    2      2    Total Length            (big-endian)
 *    4      2    Identification          (big-endian)
 *    6      2    Flags (3 bits) + Fragment Offset (13 bits)  (big-endian)
 *    8      1    TTL
 *    9      1    Protocol
 *   10      2    Header Checksum         (big-endian)
 *   12      4    Source IP address       (big-endian)
 *   16      4    Destination IP address  (big-endian)
 *   20      *    Options (if IHL > 5)
 *
 * Flags bits (within the 3-bit flags field):
 *   bit 1 (0x02)  DF — Don't Fragment
 *   bit 0 (0x01)  MF — More Fragments
 *
 * Well-known protocol numbers:
 *   1   ICMP     6   TCP     17  UDP
 *
 * Reference: RFC 791
 */

#include "common.h"

#define IPV4_MIN_HDR_LEN  20
#define IPV4_MAX_HDR_LEN  60
#define IPV4_VERSION       4

/* IP protocol number constants */
#ifndef IPPROTO_ICMP
#  define IPPROTO_ICMP   1u
#endif
#ifndef IPPROTO_TCP
#  define IPPROTO_TCP    6u
#endif
#ifndef IPPROTO_UDP
#  define IPPROTO_UDP   17u
#endif

/* Fragment flags (within the 3-bit flags nibble) */
#define IPV4_FLAG_DF  0x02u   /* Don't Fragment */
#define IPV4_FLAG_MF  0x01u   /* More Fragments */

/* Parsed representation of an IPv4 header */
typedef struct {
    uint8_t  version;
    uint8_t  ihl;           /* header length in 32-bit words (4–15)    */
    uint8_t  hdr_len;       /* header length in bytes  (ihl * 4)        */
    uint8_t  dscp;          /* differentiated services code point       */
    uint8_t  ecn;           /* explicit congestion notification         */
    uint16_t total_len;     /* total packet length including header     */
    uint16_t id;            /* identification for reassembly            */
    uint8_t  flags;         /* DF / MF bits                             */
    uint16_t frag_offset;   /* fragment offset in 8-byte units          */
    uint8_t  ttl;           /* time to live                             */
    uint8_t  protocol;      /* encapsulated protocol (IPPROTO_*)        */
    uint16_t checksum;      /* header checksum (raw, big-endian)        */
    int      checksum_valid; /* 1 = OK, 0 = bad                        */
    uint8_t  src[4];        /* source IP address                        */
    uint8_t  dst[4];        /* destination IP address                   */
    const uint8_t* options; /* points into raw packet; NULL if no options */
    uint8_t  options_len;   /* hdr_len - 20; 0 if no options            */
} Ipv4Header;

/*
 * ipv4_parse — parse raw bytes into an Ipv4Header.
 *   data     — start of the IPv4 header (i.e. Ethernet payload for EtherType 0x0800)
 *   len      — bytes available from data onwards
 *   out      — filled on success
 * Returns 0 on success, -1 on error.
 * The checksum_valid field is set by computing the one's complement checksum
 * over the header bytes and comparing to 0xFFFF.
 */
int ipv4_parse(const uint8_t* data, size_t len, Ipv4Header* out);

/*
 * ipv4_print — pretty-print an IPv4 header to stdout.
 */
void ipv4_print(const Ipv4Header* hdr);

/*
 * ipv4_proto_name — return a human-readable string for a protocol number.
 */
const char* ipv4_proto_name(uint8_t protocol);

#endif /* IPV4_H */
