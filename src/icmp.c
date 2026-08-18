/*
 * icmp.c — ICMP parser implementation
 *
 * Unlike TCP and UDP, ICMP does not use a pseudo-header.  The checksum
 * is computed over the entire ICMP message (type through end of data).
 */

#include "icmp.h"

/* ── helpers ────────────────────────────────────────────────────────────── */

static int msg_checksum_ok(const uint8_t* data, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2)
        sum += (uint32_t)((data[i] << 8) | data[i + 1]);
    if (len & 1)
        sum += (uint32_t)(data[len - 1] << 8);
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (sum == 0xFFFF);
}

/* ── icmp_parse ──────────────────────────────────────────────────────────── */

int icmp_parse(const uint8_t* data, size_t len, IcmpHeader* out) {
    if (len < ICMP_MIN_LEN) {
        fprintf(stderr, "[icmp] Too short: %zu bytes (need %d)\n",
                len, ICMP_MIN_LEN);
        return -1;
    }

    out->type     = data[0];
    out->code     = data[1];
    out->checksum = (uint16_t)((data[2] << 8) | data[3]);

    out->checksum_valid = msg_checksum_ok(data, len);

    /* Echo Request / Reply carry an identifier and sequence number */
    if (out->type == ICMP_TYPE_ECHO_REQ || out->type == ICMP_TYPE_ECHO_REPLY) {
        out->echo_id  = (uint16_t)((data[4] << 8) | data[5]);
        out->echo_seq = (uint16_t)((data[6] << 8) | data[7]);
    } else {
        out->echo_id  = 0;
        out->echo_seq = 0;
    }

    /* Point payload at the message-type-specific data (after the 8-byte hdr) */
    if (len > ICMP_MIN_LEN) {
        out->payload     = data + ICMP_MIN_LEN;
        out->payload_len = len - ICMP_MIN_LEN;
    } else {
        out->payload     = NULL;
        out->payload_len = 0;
    }

    /* For Unreachable / Time-Exceeded, decode the embedded original datagram.
     * Layout after ICMP 8-byte header: original IPv4 header + 8 transport bytes.
     * Minimum: 20 (IPv4 min) + 8 = 28 bytes in payload. */
    out->has_embedded = 0;
    if ((out->type == ICMP_TYPE_UNREACH || out->type == ICMP_TYPE_TIME_EXCEEDED)
            && out->payload_len >= 28) {
        const uint8_t* inner = out->payload;
        uint8_t version = (uint8_t)(inner[0] >> 4);
        uint8_t ihl = (uint8_t)((inner[0] & 0x0F) * 4u);
        if (version == 4 && ihl >= 20
                && out->payload_len >= (size_t)(ihl + 8u)) {
            out->has_embedded     = 1;
            out->embedded_proto   = inner[9];
            memcpy(out->embedded_src, inner + 12, 4);
            memcpy(out->embedded_dst, inner + 16, 4);
            const uint8_t* tp = inner + ihl;
            if (out->embedded_proto == 6 || out->embedded_proto == 17) {
                out->embedded_src_port = (uint16_t)((tp[0] << 8) | tp[1]);
                out->embedded_dst_port = (uint16_t)((tp[2] << 8) | tp[3]);
            } else {
                out->embedded_src_port = 0;
                out->embedded_dst_port = 0;
            }
        }
    }

    return 0;
}

/* ── icmp_type_name ──────────────────────────────────────────────────────── */

const char* icmp_type_name(uint8_t type) {
    switch (type) {
        case ICMP_TYPE_ECHO_REPLY:    return "Echo Reply";
        case ICMP_TYPE_UNREACH:       return "Destination Unreachable";
        case ICMP_TYPE_ECHO_REQ:      return "Echo Request";
        case ICMP_TYPE_TIME_EXCEEDED: return "Time Exceeded";
        case 4:  return "Source Quench";
        case 5:  return "Redirect";
        case 9:  return "Router Advertisement";
        case 10: return "Router Solicitation";
        default: return "UNKNOWN";
    }
}

/* ── icmp_print ──────────────────────────────────────────────────────────── */

void icmp_print(const IcmpHeader* hdr) {
    printf("┌─ ICMP ─────────────────────────────────────────────┐\n");
    printf("│  Type      : %u  (%s)\n",
           hdr->type, icmp_type_name(hdr->type));
    printf("│  Code      : %u\n", hdr->code);

    if (hdr->type == ICMP_TYPE_ECHO_REQ ||
        hdr->type == ICMP_TYPE_ECHO_REPLY) {
        printf("│  ID        : %u\n", hdr->echo_id);
        printf("│  Sequence  : %u\n", hdr->echo_seq);
    }

    if (hdr->type == ICMP_TYPE_UNREACH) {
        const char* code_str = "unknown";
        switch (hdr->code) {
            case ICMP_UNREACH_NET:   code_str = "net unreachable";   break;
            case ICMP_UNREACH_HOST:  code_str = "host unreachable";  break;
            case ICMP_UNREACH_PROTO: code_str = "proto unreachable"; break;
            case ICMP_UNREACH_PORT:  code_str = "port unreachable";  break;
            case ICMP_UNREACH_FRAG:  code_str = "frag needed, DF set"; break;
        }
        printf("│  Reason    : %s\n", code_str);
    }

    if (hdr->has_embedded) {
        printf("│  Inner IP  : %u.%u.%u.%u → %u.%u.%u.%u  proto=%u\n",
               hdr->embedded_src[0], hdr->embedded_src[1],
               hdr->embedded_src[2], hdr->embedded_src[3],
               hdr->embedded_dst[0], hdr->embedded_dst[1],
               hdr->embedded_dst[2], hdr->embedded_dst[3],
               hdr->embedded_proto);
        if (hdr->embedded_src_port || hdr->embedded_dst_port)
            printf("│  Inner Port: %u → %u\n",
                   hdr->embedded_src_port, hdr->embedded_dst_port);
    } else if (hdr->payload_len > 0) {
        printf("│  Data Len  : %zu bytes\n", hdr->payload_len);
    }

    printf("│  Checksum  : 0x%04x  (%s)\n",
           hdr->checksum,
           hdr->checksum_valid ? "OK" : "BAD");
    printf("└────────────────────────────────────────────────────┘\n");
}
