#ifndef ARP_H
#define ARP_H

/*
 * arp.h — ARP (Address Resolution Protocol) parser
 *
 * ARP Packet Layout for Ethernet / IPv4 (28 bytes):
 *
 *  Offset  Size  Field
 *  ──────  ────  ─────────────────────────────────────────────────────────
 *    0      2    Hardware type        (1 = Ethernet)
 *    2      2    Protocol type        (0x0800 = IPv4)
 *    4      1    Hardware addr length (6 for Ethernet)
 *    5      1    Protocol addr length (4 for IPv4)
 *    6      2    Operation            (1 = REQUEST, 2 = REPLY)
 *    8      6    Sender hardware address (MAC)
 *   14      4    Sender protocol address (IP)
 *   18      6    Target hardware address (MAC, all-zero in a request)
 *   24      4    Target protocol address (IP)
 *
 * Reference: RFC 826
 */

#include "common.h"

#define ARP_HDR_LEN     28      /* fixed for Ethernet/IPv4 ARP */

#define ARP_HW_ETHERNET  1u
#define ARP_PROTO_IPV4   0x0800u
#define ARP_OP_REQUEST   1u
#define ARP_OP_REPLY     2u

typedef struct {
    uint16_t hw_type;        /* hardware type          (host order) */
    uint16_t proto_type;     /* protocol type          (host order) */
    uint8_t  hw_len;         /* hardware address length             */
    uint8_t  proto_len;      /* protocol address length             */
    uint16_t operation;      /* ARP_OP_REQUEST or ARP_OP_REPLY      */
    uint8_t  sender_mac[6];  /* sender hardware address             */
    uint8_t  sender_ip[4];   /* sender protocol address             */
    uint8_t  target_mac[6];  /* target hardware address             */
    uint8_t  target_ip[4];   /* target protocol address             */
} ArpHeader;

/*
 * arp_parse — parse raw ARP bytes from the Ethernet payload.
 * This fixed-layout parser accepts Ethernet/IPv4 ARP only.
 * Returns 0 on success, -1 if the packet is truncated or has another format.
 */
int  arp_parse(const uint8_t* data, size_t len, ArpHeader* out);

/*
 * arp_print — pretty-print an ARP header to stdout.
 */
void arp_print(const ArpHeader* hdr);

#endif /* ARP_H */
