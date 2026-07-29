/*
 * ethernet.c — Ethernet II frame parser implementation
 *
 * Key concept: MAC addresses are always 6 bytes stored in network order
 * (most-significant byte first).  EtherType is a 16-bit big-endian value
 * that we convert to host order with ntohs() for comparisons.
 */

#include "ethernet.h"

static uint16_t read16(const uint8_t* data) {
    return (uint16_t)((data[0] << 8) | data[1]);
}

static int is_vlan_tpid(uint16_t ethertype) {
    return ethertype == ETHERTYPE_VLAN || ethertype == ETHERTYPE_QINQ;
}

/* ── eth_parse ──────────────────────────────────────────────────────────── */

int eth_parse(const uint8_t* data, size_t len, EtherHeader* out) {
    if (!data || !out) {
        fprintf(stderr, "[eth] Missing frame data or output header\n");
        return -1;
    }
    if (len < ETHER_HDR_LEN) {
        fprintf(stderr, "[eth] Frame too short: %zu bytes (need %d)\n",
                len, ETHER_HDR_LEN);
        return -1;
    }

    memset(out, 0, sizeof(*out));

    /* Destination MAC: bytes 0-5 */
    memcpy(out->dst, data + 0, ETHER_ADDR_LEN);

    /* Source MAC: bytes 6-11 */
    memcpy(out->src, data + 6, ETHER_ADDR_LEN);

    /*
     * EtherType: bytes 12-13, big-endian.
     * We read the two bytes directly instead of casting the pointer because
     * the buffer may not be aligned to a 2-byte boundary.
     */
    out->outer_ethertype = read16(data + 12);
    out->ethertype = out->outer_ethertype;
    out->hdr_len = ETHER_HDR_LEN;

    while (is_vlan_tpid(out->ethertype)) {
        EtherVlanTag* tag;
        uint16_t tci;

        if (out->vlan_count >= ETHER_MAX_VLAN_TAGS) {
            fprintf(stderr, "[eth] Too many nested VLAN tags (max %d)\n",
                    ETHER_MAX_VLAN_TAGS);
            return -1;
        }
        if (len < out->hdr_len + ETHER_VLAN_TAG_LEN) {
            fprintf(stderr, "[eth] Truncated VLAN tag: have %zu, need %zu bytes\n",
                    len, out->hdr_len + ETHER_VLAN_TAG_LEN);
            return -1;
        }

        tag = &out->vlan_tags[out->vlan_count++];
        tag->tpid = out->ethertype;
        tci = read16(data + out->hdr_len);
        tag->pcp = (uint8_t)((tci >> 13) & 0x07);
        tag->dei = (uint8_t)((tci >> 12) & 0x01);
        tag->vid = (uint16_t)(tci & 0x0fff);

        out->ethertype = read16(data + out->hdr_len + 2);
        out->hdr_len += ETHER_VLAN_TAG_LEN;
    }

    return 0;
}

/* ── ethertype_name ─────────────────────────────────────────────────────── */

const char* ethertype_name(uint16_t ethertype) {
    switch (ethertype) {
        case ETHERTYPE_IPV4:  return "IPv4";
        case ETHERTYPE_ARP:   return "ARP";
        case ETHERTYPE_IPV6:  return "IPv6";
        case ETHERTYPE_VLAN:  return "802.1Q VLAN";
        case ETHERTYPE_QINQ:  return "802.1ad VLAN";
        default:
            if (ethertype <= 1500) return "802.3 (length field)";
            return "UNKNOWN";
    }
}

/* ── eth_print ──────────────────────────────────────────────────────────── */

void eth_print(const EtherHeader* hdr) {
    printf("┌─ Ethernet II ──────────────────────────────────────┐\n");

    /* Source MAC */
    printf("│  Src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
           hdr->src[0], hdr->src[1], hdr->src[2],
           hdr->src[3], hdr->src[4], hdr->src[5]);

    /* Destination MAC */
    printf("│  Dst MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
           hdr->dst[0], hdr->dst[1], hdr->dst[2],
           hdr->dst[3], hdr->dst[4], hdr->dst[5]);

    /* EtherType */
    printf("│  EtherType: 0x%04x  (%s)\n",
           hdr->outer_ethertype, ethertype_name(hdr->outer_ethertype));

    for (uint8_t i = 0; i < hdr->vlan_count; i++) {
        const EtherVlanTag* tag = &hdr->vlan_tags[i];
        printf("│  VLAN %u   : TPID=0x%04x PCP=%u DEI=%u VID=%u\n",
               (unsigned)i + 1u, tag->tpid, tag->pcp, tag->dei, tag->vid);
    }

    if (hdr->vlan_count > 0)
        printf("│  Payload   : 0x%04x  (%s)\n",
               hdr->ethertype, ethertype_name(hdr->ethertype));

    printf("└────────────────────────────────────────────────────┘\n");
}
