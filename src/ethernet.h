#ifndef ETHERNET_H
#define ETHERNET_H

/*
 * ethernet.h — Ethernet II frame parser
 *
 * Ethernet II Frame Layout (14 bytes header):
 *
 *  Offset  Size  Field
 *  ──────  ────  ─────────────────────────────────────────────────────────
 *    0      6    Destination MAC address
 *    6      6    Source MAC address
 *   12      2    EtherType  (big-endian)
 *   14      *    Payload (varies)
 *
 * Notable EtherType values:
 *   0x0800  IPv4
 *   0x0806  ARP
 *   0x86DD  IPv6
 *   0x8100  802.1Q VLAN tag
 *   0x88A8  802.1ad provider bridging tag
 *
 * If EtherType <= 1500 the frame is 802.3 and the field is a *length*,
 * not a protocol identifier.  We flag this case but do not yet parse it.
 */

#include "common.h"

#define ETHER_ADDR_LEN   6
#define ETHER_HDR_LEN   14
#define ETHER_VLAN_TAG_LEN  4
#define ETHER_MAX_VLAN_TAGS 2

/* Well-known EtherType constants */
#define ETHERTYPE_IPV4  0x0800u
#define ETHERTYPE_ARP   0x0806u
#define ETHERTYPE_IPV6  0x86DDu
#define ETHERTYPE_VLAN  0x8100u
#define ETHERTYPE_QINQ  0x88A8u

typedef struct {
    uint16_t tpid;  /* tag protocol identifier: 0x8100 or 0x88a8 */
    uint8_t  pcp;   /* priority code point: 0-7                  */
    uint8_t  dei;   /* drop eligible indicator: 0 or 1           */
    uint16_t vid;   /* VLAN identifier: 0-4095                   */
} EtherVlanTag;

/* Parsed representation of an Ethernet II header */
typedef struct {
    uint8_t  dst[ETHER_ADDR_LEN];  /* destination MAC                      */
    uint8_t  src[ETHER_ADDR_LEN];  /* source MAC                           */
    uint16_t outer_ethertype;      /* first EtherType after source MAC      */
    uint16_t ethertype;            /* payload EtherType after VLAN tags     */
    size_t   hdr_len;              /* base header plus parsed VLAN tags     */
    EtherVlanTag vlan_tags[ETHER_MAX_VLAN_TAGS];
    uint8_t  vlan_count;
} EtherHeader;

/*
 * eth_parse — parse raw bytes into an EtherHeader.
 *
 *   data     — pointer to the start of the Ethernet frame
 *   len      — total bytes available in data
 *   out      — filled on success
 *
 * Supports up to ETHER_MAX_VLAN_TAGS nested 802.1Q / 802.1ad tags.
 * Returns 0 on success, -1 if the frame is truncated or nesting is too deep.
 */
int eth_parse(const uint8_t* data, size_t len, EtherHeader* out);

/*
 * eth_print — pretty-print an Ethernet header to stdout.
 * Also shows a human-readable EtherType name where known.
 */
void eth_print(const EtherHeader* hdr);

/*
 * ethertype_name — return a constant string for a known EtherType,
 * or "UNKNOWN" if not recognised.
 */
const char* ethertype_name(uint16_t ethertype);

#endif /* ETHERNET_H */
