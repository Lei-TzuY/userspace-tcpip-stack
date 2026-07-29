#ifndef ICMPV6_H
#define ICMPV6_H

/*
 * ICMPv6 parser and checksum verifier.
 *
 * ICMPv6 uses the IPv6 pseudo-header for checksum validation, unlike ICMPv4.
 * This module currently decodes the common header and Echo Request/Reply
 * fields, while still naming common control and Neighbor Discovery messages.
 */

#include "ipv6.h"

#define ICMPV6_MIN_LEN 8

#define ICMPV6_TYPE_DEST_UNREACH  1u
#define ICMPV6_TYPE_PACKET_TOO_BIG 2u
#define ICMPV6_TYPE_TIME_EXCEEDED 3u
#define ICMPV6_TYPE_PARAM_PROBLEM 4u
#define ICMPV6_TYPE_ECHO_REQ     128u
#define ICMPV6_TYPE_ECHO_REPLY   129u
#define ICMPV6_TYPE_ROUTER_SOL   133u
#define ICMPV6_TYPE_ROUTER_ADV   134u
#define ICMPV6_TYPE_NEIGHBOR_SOL 135u
#define ICMPV6_TYPE_NEIGHBOR_ADV 136u
#define ICMPV6_TYPE_REDIRECT     137u

/* NDP option types (RFC 4861 §4.6) */
#define ICMPV6_OPT_SRC_LLADDR   1u
#define ICMPV6_OPT_TGT_LLADDR   2u
#define ICMPV6_OPT_PREFIX_INFO  3u
#define ICMPV6_OPT_MTU          5u

#define ICMPV6_NDP_MAX_OPTS     8

/* NA flags (in the first reserved word) */
#define ICMPV6_NA_ROUTER    0x80000000u
#define ICMPV6_NA_SOLICITED 0x40000000u
#define ICMPV6_NA_OVERRIDE  0x20000000u

typedef struct {
    uint8_t  type;
    uint8_t  length;     /* in 8-byte units */
    union {
        uint8_t  lladdr[6];   /* type 1 or 2 */
        struct {
            uint8_t  prefix_len;
            uint8_t  flags;
            uint32_t valid_lifetime;
            uint32_t preferred_lifetime;
            uint8_t  prefix[16];
        } prefix;
        uint32_t mtu;         /* type 5 */
    } u;
} Icmpv6NdpOption;

typedef struct {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;

    /* Echo Request/Reply */
    uint16_t echo_id;
    uint16_t echo_seq;

    /* NDP (RS/RA/NS/NA/Redirect) */
    uint8_t  target[16];     /* NS / NA / Redirect */
    uint8_t  dest[16];       /* Redirect only */
    uint32_t na_flags;       /* NA: R/S/O bits */
    uint8_t  ra_hop_limit;   /* RA */
    uint8_t  ra_flags;       /* RA: M/O bits */
    uint16_t ra_router_lifetime; /* RA */
    uint32_t ra_reachable_time;  /* RA */
    uint32_t ra_retrans_timer;   /* RA */

    /* NDP options */
    Icmpv6NdpOption ndp_opts[ICMPV6_NDP_MAX_OPTS];
    int             ndp_opt_count;

    const uint8_t* payload;
    size_t payload_len;

    /* Error body: embedded original IPv6 header (types 1/2/3/4) */
    int      has_embedded;
    uint8_t  embedded_next_header;
    uint8_t  embedded_src[16];
    uint8_t  embedded_dst[16];
    uint16_t embedded_src_port;
    uint16_t embedded_dst_port;
    uint32_t packet_too_big_mtu;  /* type 2 only */
} Icmpv6Header;

int icmpv6_parse(const uint8_t* data, size_t len, Icmpv6Header* out);
int icmpv6_checksum_ok(const Ipv6Header* ip,
                       const uint8_t* message, size_t message_len);
const char* icmpv6_type_name(uint8_t type);
void icmpv6_print(const Icmpv6Header* header, int checksum_valid);

#endif /* ICMPV6_H */
