/*
 * ipv4.c — IPv4 header parser implementation
 *
 * Checksum algorithm (RFC 791 §3.1):
 *   Compute the one's complement sum of all 16-bit words in the header.
 *   Fold any 32-bit carry back into the lower 16 bits.
 *   The result must equal 0xFFFF for a valid header.
 *   This works because the checksum field itself is included in the sum —
 *   if checksum = ~(sum of other words), then total = 0xFFFF.
 */

#include "ipv4.h"

/* ── helpers ────────────────────────────────────────────────────────────── */

static int hdr_checksum_ok(const uint8_t* data, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2)
        sum += (uint32_t)((data[i] << 8) | data[i + 1]);
    if (len & 1)
        sum += (uint32_t)(data[len - 1] << 8);
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (sum == 0xFFFF);
}

/* ── ipv4_parse ──────────────────────────────────────────────────────────── */

int ipv4_parse(const uint8_t* data, size_t len, Ipv4Header* out) {
    if (len < IPV4_MIN_HDR_LEN) {
        fprintf(stderr, "[ipv4] Too short: %zu bytes\n", len);
        return -1;
    }

    out->version = (data[0] >> 4) & 0x0F;
    out->ihl     = data[0] & 0x0F;
    out->hdr_len = (uint8_t)(out->ihl * 4);

    if (out->version != IPV4_VERSION) {
        fprintf(stderr, "[ipv4] Bad version: %u (expected 4)\n", out->version);
        return -1;
    }
    if (out->hdr_len < IPV4_MIN_HDR_LEN) {
        fprintf(stderr, "[ipv4] IHL too small: %u\n", out->ihl);
        return -1;
    }
    if (len < out->hdr_len) {
        fprintf(stderr, "[ipv4] Truncated header: have %zu, need %u bytes\n",
                len, out->hdr_len);
        return -1;
    }

    out->dscp      = (data[1] >> 2) & 0x3F;
    out->ecn       = data[1] & 0x03;
    out->total_len = (uint16_t)((data[2] << 8) | data[3]);
    out->id        = (uint16_t)((data[4] << 8) | data[5]);

    if (out->total_len < out->hdr_len) {
        fprintf(stderr, "[ipv4] Total length too small: %u (header is %u bytes)\n",
                out->total_len, out->hdr_len);
        return -1;
    }
    if (len < out->total_len) {
        fprintf(stderr, "[ipv4] Truncated packet: have %zu, need %u bytes\n",
                len, out->total_len);
        return -1;
    }

    uint16_t ff      = (uint16_t)((data[6] << 8) | data[7]);
    out->flags       = (uint8_t)((ff >> 13) & 0x07);
    out->frag_offset = (uint16_t)(ff & 0x1FFF);

    out->ttl      = data[8];
    out->protocol = data[9];
    out->checksum = (uint16_t)((data[10] << 8) | data[11]);

    out->checksum_valid = hdr_checksum_ok(data, out->hdr_len);

    memcpy(out->src, data + 12, 4);
    memcpy(out->dst, data + 16, 4);

    if (out->hdr_len > IPV4_MIN_HDR_LEN) {
        out->options     = data + IPV4_MIN_HDR_LEN;
        out->options_len = (uint8_t)(out->hdr_len - IPV4_MIN_HDR_LEN);
    } else {
        out->options     = NULL;
        out->options_len = 0;
    }

    return 0;
}

/* ── ipv4_proto_name ─────────────────────────────────────────────────────── */

const char* ipv4_proto_name(uint8_t p) {
    switch (p) {
        case IPPROTO_ICMP: return "ICMP";
        case IPPROTO_TCP:  return "TCP";
        case IPPROTO_UDP:  return "UDP";
        case 2:            return "IGMP";
        case 89:           return "OSPF";
        default:           return "UNKNOWN";
    }
}

/* ── ipv4_print ──────────────────────────────────────────────────────────── */

void ipv4_print(const Ipv4Header* hdr) {
    printf("┌─ IPv4 ─────────────────────────────────────────────┐\n");
    printf("│  Src IP    : %u.%u.%u.%u\n",
           hdr->src[0], hdr->src[1], hdr->src[2], hdr->src[3]);
    printf("│  Dst IP    : %u.%u.%u.%u\n",
           hdr->dst[0], hdr->dst[1], hdr->dst[2], hdr->dst[3]);
    printf("│  Protocol  : %u  (%s)\n",
           hdr->protocol, ipv4_proto_name(hdr->protocol));
    printf("│  TTL       : %u\n", hdr->ttl);
    printf("│  Total Len : %u bytes  (hdr=%u, payload=%u)\n",
           hdr->total_len, hdr->hdr_len,
           (hdr->total_len >= hdr->hdr_len)
               ? (unsigned)(hdr->total_len - hdr->hdr_len) : 0u);
    printf("│  ID        : 0x%04x\n", hdr->id);

    /* Flags */
    char flags_str[16] = "none";
    if (hdr->flags & IPV4_FLAG_DF) {
        if (hdr->flags & IPV4_FLAG_MF)
            snprintf(flags_str, sizeof(flags_str), "DF MF");
        else
            snprintf(flags_str, sizeof(flags_str), "DF");
    } else if (hdr->flags & IPV4_FLAG_MF) {
        snprintf(flags_str, sizeof(flags_str), "MF");
    }
    printf("│  Flags     : %s\n", flags_str);

    if (hdr->frag_offset)
        printf("│  Frag Offs : %u × 8 = %u bytes\n",
               hdr->frag_offset, hdr->frag_offset * 8u);

    printf("│  Checksum  : 0x%04x  (%s)\n",
           hdr->checksum,
           hdr->checksum_valid ? "OK" : "BAD");

    if (hdr->options && hdr->options_len > 0) {
        const uint8_t* opt = hdr->options;
        size_t rem = hdr->options_len;
        while (rem > 0) {
            uint8_t kind = opt[0];
            if (kind == 0) break;           /* End of Options */
            if (kind == 1) { opt++; rem--; continue; }  /* NOP */
            if (rem < 2) break;
            uint8_t olen = opt[1];
            if (olen < 2 || olen > (uint8_t)rem) break;
            switch (kind) {
                case 7:   printf("│  Option    : Record Route, len=%u\n",    olen); break;
                case 68:  printf("│  Option    : Timestamp, len=%u\n",       olen); break;
                case 148: printf("│  Option    : Router Alert, len=%u\n",    olen); break;
                default:  printf("│  Option    : type=%u len=%u\n", kind, olen);    break;
            }
            opt += olen;
            rem -= olen;
        }
    }

    printf("└────────────────────────────────────────────────────┘\n");
}
