#ifndef DHCPV6_H
#define DHCPV6_H

/*
 * dhcpv6.h — DHCPv6 (Dynamic Host Configuration Protocol for IPv6) parser
 *
 * DHCPv6 client/server message layout (RFC 3315 §6):
 *
 *  Offset  Size  Field
 *  ──────  ────  ─────────────────────────────────────────────────────────
 *    0      1    msg-type
 *    1      3    transaction-id  (24-bit, big-endian)
 *    4      *    options         (type=uint16, length=uint16, value[length])
 *
 * Client uses UDP port 546; server uses 547.
 *
 * Common message types:
 *   1=SOLICIT, 2=ADVERTISE, 3=REQUEST, 4=CONFIRM, 5=RENEW, 6=REBIND,
 *   7=REPLY, 8=RELEASE, 9=DECLINE, 10=RECONFIGURE, 11=INFO-REQUEST
 *
 * Reference: RFC 3315, RFC 8415 (updates)
 */

#include "common.h"

#define DHCPV6_MIN_LEN   4   /* msg-type + transaction-id */

/* Message type values */
#define DHCPV6_SOLICIT        1u
#define DHCPV6_ADVERTISE      2u
#define DHCPV6_REQUEST        3u
#define DHCPV6_CONFIRM        4u
#define DHCPV6_RENEW          5u
#define DHCPV6_REBIND         6u
#define DHCPV6_REPLY          7u
#define DHCPV6_RELEASE        8u
#define DHCPV6_DECLINE        9u
#define DHCPV6_RECONFIGURE   10u
#define DHCPV6_INFO_REQUEST  11u

/* Option codes */
#define DHCPV6_OPT_CLIENTID    1u
#define DHCPV6_OPT_SERVERID    2u
#define DHCPV6_OPT_IA_NA       3u
#define DHCPV6_OPT_IAADDR      5u
#define DHCPV6_OPT_ORO         6u
#define DHCPV6_OPT_ELAPSED_TIME 8u
#define DHCPV6_OPT_DNS_SERVERS 23u

#define DHCPV6_MAX_DNS  4   /* parsed DNS server addresses */

typedef struct {
    uint8_t  msg_type;
    uint32_t transaction_id;  /* 24-bit, stored in low bits */

    /* Client / server DUID length (0 = not present) */
    uint16_t client_duid_len;
    uint16_t server_duid_len;

    /* IA_NA first address (if present) */
    int      has_ia_addr;
    uint8_t  ia_addr[16];
    uint32_t preferred_lifetime;
    uint32_t valid_lifetime;

    /* DNS recursive name servers */
    int      dns_count;
    uint8_t  dns_servers[DHCPV6_MAX_DNS][16];
} Dhcpv6Message;

int  dhcpv6_parse(const uint8_t* data, size_t len, Dhcpv6Message* out);
void dhcpv6_print(const Dhcpv6Message* msg);
const char* dhcpv6_msg_type_name(uint8_t type);

#endif /* DHCPV6_H */
