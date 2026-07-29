/*
 * arp.c — ARP (Address Resolution Protocol) parser implementation
 */

#include "arp.h"

static uint16_t read16(const uint8_t* data) {
    return (uint16_t)((data[0] << 8) | data[1]);
}

/* ── arp_parse ───────────────────────────────────────────────────────────── */

int arp_parse(const uint8_t* data, size_t len, ArpHeader* out) {
    if (!data || !out) {
        fprintf(stderr, "[arp] Missing packet data or output header\n");
        return -1;
    }
    if (len < ARP_HDR_LEN) {
        fprintf(stderr, "[arp] Packet too short: %zu bytes (need %d)\n",
                len, ARP_HDR_LEN);
        return -1;
    }

    memset(out, 0, sizeof(*out));
    out->hw_type    = read16(data + 0);
    out->proto_type = read16(data + 2);
    out->hw_len     = data[4];
    out->proto_len  = data[5];
    out->operation  = read16(data + 6);

    if (out->hw_type != ARP_HW_ETHERNET
            || out->proto_type != ARP_PROTO_IPV4
            || out->hw_len != 6
            || out->proto_len != 4) {
        fprintf(stderr,
                "[arp] Unsupported format: hw=%u proto=0x%04x hlen=%u plen=%u\n",
                out->hw_type, out->proto_type, out->hw_len, out->proto_len);
        return -1;
    }

    memcpy(out->sender_mac, data +  8, 6);
    memcpy(out->sender_ip,  data + 14, 4);
    memcpy(out->target_mac, data + 18, 6);
    memcpy(out->target_ip,  data + 24, 4);

    return 0;
}

/* ── arp_print ───────────────────────────────────────────────────────────── */

void arp_print(const ArpHeader* hdr) {
    const char* op = hdr->operation == ARP_OP_REQUEST ? "REQUEST"
                   : hdr->operation == ARP_OP_REPLY   ? "REPLY"
                   : "UNKNOWN";

    printf("┌─ ARP ──────────────────────────────────────────────┐\n");
    printf("│  Operation : %s (%u)\n", op, hdr->operation);
    printf("│  Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           hdr->sender_mac[0], hdr->sender_mac[1], hdr->sender_mac[2],
           hdr->sender_mac[3], hdr->sender_mac[4], hdr->sender_mac[5]);
    printf("│  Sender IP : %u.%u.%u.%u\n",
           hdr->sender_ip[0], hdr->sender_ip[1],
           hdr->sender_ip[2], hdr->sender_ip[3]);
    printf("│  Target MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           hdr->target_mac[0], hdr->target_mac[1], hdr->target_mac[2],
           hdr->target_mac[3], hdr->target_mac[4], hdr->target_mac[5]);
    printf("│  Target IP : %u.%u.%u.%u\n",
           hdr->target_ip[0], hdr->target_ip[1],
           hdr->target_ip[2], hdr->target_ip[3]);
    printf("└────────────────────────────────────────────────────┘\n");
}
