/*
 * vxlan.c — Virtual eXtensible LAN (RFC 7348)
 */

#include "vxlan.h"

int vxlan_parse(const uint8_t* data, size_t len, VxlanHeader* out) {
    if (!data || !out) {
        fprintf(stderr, "[vxlan] Missing packet data or output header\n");
        return -1;
    }
    if (len < VXLAN_HDR_LEN) {
        fprintf(stderr, "[vxlan] Too short: %zu bytes (need %d)\n",
                len, VXLAN_HDR_LEN);
        return -1;
    }

    memset(out, 0, sizeof(*out));
    out->flags     = data[0];
    out->vni_valid = (data[0] & VXLAN_FLAG_VNI_VALID) != 0;
    out->vni       = ((uint32_t)data[4] << 16)
                   | ((uint32_t)data[5] << 8)
                   |  (uint32_t)data[6];

    out->payload_len = len - VXLAN_HDR_LEN;
    out->payload     = out->payload_len > 0 ? data + VXLAN_HDR_LEN : NULL;
    return 0;
}

int vxlan_sniff(const uint8_t* data, size_t len) {
    if (!data || len < VXLAN_HDR_LEN)
        return 0;

    /* The I bit must be set on a real VXLAN packet, and every other flag bit
       is reserved and sent as zero. Requiring exactly that rejects most
       traffic that merely happens to use the port. */
    if (data[0] != VXLAN_FLAG_VNI_VALID)
        return 0;

    /* Reserved bytes are zero too. */
    if (data[1] || data[2] || data[3] || data[7])
        return 0;

    /* An inner Ethernet frame needs at least a header behind the VXLAN one. */
    return len >= VXLAN_HDR_LEN + 14;
}

void vxlan_print(const VxlanHeader* hdr) {
    printf("┌─ VXLAN ────────────────────────────────────────────┐\n");
    printf("│  Flags     : 0x%02x%s\n", hdr->flags,
           hdr->vni_valid ? "  (VNI valid)" : "  (VNI not valid)");
    if (hdr->vni_valid)
        printf("│  VNI       : %u\n", hdr->vni);
    printf("│  Inner     : %zu byte(s) of Ethernet\n", hdr->payload_len);
    printf("└────────────────────────────────────────────────────┘\n");
}
