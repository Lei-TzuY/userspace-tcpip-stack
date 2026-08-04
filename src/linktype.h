#ifndef LINKTYPE_H
#define LINKTYPE_H

/*
 * linktype.h — link-layer headers other than Ethernet
 *
 * A capture file names its link layer with a LINKTYPE_* value, and Ethernet is
 * only the most common one. A capture from `tcpdump -i any` on Linux uses the
 * cooked header, one from a tunnel or VPN interface usually has no link header
 * at all, and loopback captures on the BSDs carry a four-byte address family.
 * Without these, such a capture parses to nothing.
 *
 * Ethernet is not handled here: it has VLAN stacking and its own header struct
 * in ethernet.h. This module covers the link layers that reduce to "skip a
 * fixed header, then here is the protocol".
 *
 * References:
 *   https://www.tcpdump.org/linktypes.html
 *   https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html
 *   https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL2.html
 */

#include "common.h"

/* How the payload's protocol is identified. */
typedef enum {
    LINK_PAYLOAD_NONE = 0,     /* nothing usable follows the header */
    LINK_PAYLOAD_ETHERTYPE,    /* identified by an EtherType value */
    LINK_PAYLOAD_IPV4,
    LINK_PAYLOAD_IPV6
} LinkPayloadKind;

typedef struct {
    LinkPayloadKind kind;
    uint16_t        ethertype;    /* set when kind is LINK_PAYLOAD_ETHERTYPE */
    size_t          hdr_len;
    const uint8_t*  payload;      /* into the caller's buffer, not a copy */
    size_t          payload_len;

    /* Fields worth printing, per link type. Unset ones stay zero. */
    uint32_t null_family;         /* LINKTYPE_NULL address family */
    uint16_t sll_packet_type;     /* LINKTYPE_LINUX_SLL* packet type */
    uint16_t sll_arphrd_type;
    uint16_t sll_addr_len;
    uint8_t  sll_addr[8];
    uint32_t sll_interface_index; /* LINKTYPE_LINUX_SLL2 only */
} LinkFrame;

/*
 * link_decode — strip the link header for one of the supported link types.
 *
 * Returns 0 on success, -1 if the link type is not handled here (Ethernet
 * included) or the header is truncated.
 */
int link_decode(uint32_t link_type, const uint8_t* data, size_t len,
                LinkFrame* out);

void link_print(uint32_t link_type, const LinkFrame* frame);

/* Human-readable name for a LINKTYPE_* value, or "UNKNOWN". */
const char* link_type_name(uint32_t link_type);

/* 1 if link_decode handles this link type, 0 otherwise. */
int link_type_supported(uint32_t link_type);

#endif /* LINKTYPE_H */
