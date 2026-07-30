#ifndef VXLAN_H
#define VXLAN_H

/*
 * vxlan.h — Virtual eXtensible LAN (RFC 7348)
 *
 * Carries a whole Ethernet frame inside UDP, which is how overlay networks
 * stretch a layer-2 segment across a routed fabric. The default destination
 * port is 4789.
 *
 * Header, 8 bytes:
 *
 *   0     flags; bit 0x08 ("I") must be set for the VNI to be valid
 *   1-3   reserved
 *   4-6   VXLAN Network Identifier, 24 bits
 *   7     reserved
 *
 * Everything after that is an Ethernet frame, complete with its own MAC
 * addresses and EtherType. That makes VXLAN the one encapsulation here that
 * returns the walk to the link layer, so a chain of them nests without bound
 * unless the dispatcher caps the depth.
 */

#include "common.h"

#define VXLAN_HDR_LEN     8
#define VXLAN_DEFAULT_PORT 4789
#define VXLAN_FLAG_VNI_VALID 0x08u

typedef struct {
    uint8_t  flags;
    int      vni_valid;      /* the I bit; without it the VNI means nothing */
    uint32_t vni;            /* 24-bit network identifier */
    const uint8_t* payload;  /* the inner Ethernet frame; not a copy */
    size_t         payload_len;
} VxlanHeader;

/*
 * vxlan_parse — parse a VXLAN header.
 * Returns 0 on success, -1 if the header is truncated.
 */
int vxlan_parse(const uint8_t* data, size_t len, VxlanHeader* out);

void vxlan_print(const VxlanHeader* hdr);

/*
 * vxlan_sniff — 1 if the payload plausibly starts with a VXLAN header.
 *
 * Port 4789 alone is weak evidence, since anything may use a UDP port. The
 * reserved bits give a cheap additional check.
 */
int vxlan_sniff(const uint8_t* data, size_t len);

#endif /* VXLAN_H */
