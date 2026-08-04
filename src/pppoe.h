#ifndef PPPOE_H
#define PPPOE_H

/*
 * pppoe.h — PPP over Ethernet (RFC 2516)
 *
 * The link layer of most DSL and some fibre connections. Two EtherTypes carry
 * it: 0x8863 for the discovery exchange that sets up a session, and 0x8864 for
 * the session itself. Only the session type carries user traffic.
 *
 * Session header, 6 bytes, followed by a PPP protocol field:
 *
 *   0     version (4 bits) + type (4 bits), both 1
 *   1     code, 0x00 for a session packet
 *   2-3   session ID
 *   4-5   payload length, not counting this header
 *   6-7   PPP protocol (0x0021 IPv4, 0x0057 IPv6)
 *
 * The PPP protocol field is technically part of the payload and can be
 * compressed to one byte, but that requires an option negotiated during
 * discovery which is rare in practice and unobservable mid-capture, so the
 * two-byte form is what is parsed.
 */

#include "common.h"

#define PPPOE_HDR_LEN 6

/* PPP protocol numbers we dispatch on */
#define PPP_PROTO_IPV4 0x0021u
#define PPP_PROTO_IPV6 0x0057u
#define PPP_PROTO_LCP  0xC021u
#define PPP_PROTO_IPCP 0x8021u
#define PPP_PROTO_CHAP 0xC223u
#define PPP_PROTO_PAP  0xC023u

typedef struct {
    uint8_t  version;
    uint8_t  type;
    uint8_t  code;
    uint16_t session_id;
    uint16_t length;        /* declared payload length */
    int      is_session;    /* 1 for a session packet carrying traffic */
    uint16_t ppp_protocol;  /* valid when is_session and a payload follows */
    int      has_ppp_protocol;
    const uint8_t* payload; /* after the PPP protocol field; not a copy */
    size_t         payload_len;
} PppoeHeader;

/*
 * pppoe_parse — parse a PPPoE header.
 *   ethertype — ETHERTYPE_PPPOE_SESSION or ETHERTYPE_PPPOE_DISCOVERY
 * Returns 0 on success, -1 if truncated or malformed.
 */
int pppoe_parse(uint16_t ethertype, const uint8_t* data, size_t len,
                PppoeHeader* out);

void pppoe_print(const PppoeHeader* hdr);

/* Name for a PPP protocol number, or "UNKNOWN". */
const char* ppp_protocol_name(uint16_t protocol);

#endif /* PPPOE_H */
