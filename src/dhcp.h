#ifndef DHCP_H
#define DHCP_H

/*
 * dhcp.h — DHCP (RFC 2131) wire-format parser
 *
 * DHCP uses UDP port 67 (server) and 68 (client).
 * The wire layout is:
 *   op(1) htype(1) hlen(1) hops(1)
 *   xid(4) secs(2) flags(2)
 *   ciaddr(4) yiaddr(4) siaddr(4) giaddr(4)
 *   chaddr(16) sname(64) file(128)
 *   magic cookie(4) = 0x63825363
 *   options (TLV, terminated by 0xFF)
 */

#include "common.h"

#define DHCP_MIN_LEN     236   /* fixed header before options */
#define DHCP_MAGIC       0x63825363u
#define DHCP_OPT_PAD     0u
#define DHCP_OPT_END     255u
#define DHCP_MAX_OPTS    32

typedef struct {
    uint8_t  code;
    uint8_t  len;
    uint8_t  data[64];  /* raw option data (truncated if longer) */
} DhcpOption;

typedef struct {
    uint8_t  op;        /* 1=BOOTREQUEST 2=BOOTREPLY */
    uint8_t  htype;     /* hardware type: 1=Ethernet */
    uint8_t  hlen;      /* hardware address length */
    uint8_t  hops;
    uint32_t xid;       /* transaction ID */
    uint16_t secs;
    uint16_t flags;
    uint8_t  ciaddr[4]; /* client IP address */
    uint8_t  yiaddr[4]; /* 'your' (client) IP address */
    uint8_t  siaddr[4]; /* next server IP address */
    uint8_t  giaddr[4]; /* relay agent IP address */
    uint8_t  chaddr[16];/* client hardware address */
    int      has_magic; /* 1 if magic cookie present */

    /* Parsed options (up to DHCP_MAX_OPTS) */
    DhcpOption options[DHCP_MAX_OPTS];
    int        opt_count;

    /* Convenience fields extracted from options */
    uint8_t  msg_type;  /* option 53: 0=unknown */
    uint8_t  subnet[4]; /* option 1 */
    uint8_t  router[4]; /* option 3 (first) */
    uint8_t  dns[4];    /* option 6 (first) */
    uint32_t lease_time;/* option 51 */
    uint8_t  server_id[4]; /* option 54 */
    char     hostname[64];  /* option 12 */
} DhcpMessage;

int  dhcp_parse(const uint8_t* data, size_t len, DhcpMessage* out);
void dhcp_print(const DhcpMessage* msg);
const char* dhcp_msg_type_name(uint8_t t);

#endif /* DHCP_H */
