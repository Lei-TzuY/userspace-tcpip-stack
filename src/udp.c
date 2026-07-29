/*
 * udp.c — UDP parser implementation
 *
 * Pseudo-header checksum (RFC 768):
 *   The checksum is computed over the concatenation of:
 *     IPv4 pseudo-header  (12 bytes: src IP, dst IP, zero, proto=17, UDP length)
 *     UDP header          (8 bytes)
 *     UDP data            (variable)
 *   An odd-length data section is zero-padded to the next even byte before
 *   computing the sum, but the zero byte is not transmitted.
 */

#include "udp.h"

/* ── helpers ────────────────────────────────────────────────────────────── */

/* ── udp_parse ───────────────────────────────────────────────────────────── */

int udp_parse(const uint8_t* data, size_t len, UdpHeader* out) {
    if (len < UDP_HDR_LEN) {
        fprintf(stderr, "[udp] Too short: %zu bytes (need %d)\n",
                len, UDP_HDR_LEN);
        return -1;
    }

    out->src_port = (uint16_t)((data[0] << 8) | data[1]);
    out->dst_port = (uint16_t)((data[2] << 8) | data[3]);
    out->length   = (uint16_t)((data[4] << 8) | data[5]);
    out->checksum = (uint16_t)((data[6] << 8) | data[7]);

    if (out->length < UDP_HDR_LEN) {
        fprintf(stderr, "[udp] Bad length: %u (need at least %d)\n",
                out->length, UDP_HDR_LEN);
        return -1;
    }
    if (len < out->length) {
        fprintf(stderr, "[udp] Truncated datagram: have %zu, need %u bytes\n",
                len, out->length);
        return -1;
    }

    out->payload_len = out->length - UDP_HDR_LEN;
    out->payload     = out->payload_len > 0 ? data + UDP_HDR_LEN : NULL;

    return 0;
}

/* ── udp_checksum_ok ─────────────────────────────────────────────────────── */

int udp_checksum_ok(const uint8_t* src_ip, const uint8_t* dst_ip,
                    const uint8_t* segment, uint16_t seg_len) {
    if (!src_ip || !dst_ip || !segment || seg_len < UDP_HDR_LEN)
        return 0;

    /* Checksum of 0 means sender disabled it */
    uint16_t stored_ck = (uint16_t)((segment[6] << 8) | segment[7]);
    if (stored_ck == 0) return 1;

    /* Build 12-byte pseudo-header on the stack */
    uint8_t pseudo[12];
    memcpy(pseudo + 0, src_ip, 4);
    memcpy(pseudo + 4, dst_ip, 4);
    pseudo[8]  = 0;       /* zero octet */
    pseudo[9]  = 17;      /* protocol = UDP */
    pseudo[10] = (uint8_t)(seg_len >> 8);
    pseudo[11] = (uint8_t)(seg_len & 0xFF);

    /* Sum pseudo-header and segment together */
    uint32_t sum = 0;
    for (int i = 0; i < 12; i += 2)
        sum += (uint32_t)((pseudo[i] << 8) | pseudo[i + 1]);

    for (size_t i = 0; i + 1 < seg_len; i += 2)
        sum += (uint32_t)((segment[i] << 8) | segment[i + 1]);
    if (seg_len & 1)
        sum += (uint32_t)(segment[seg_len - 1] << 8);

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (sum == 0xFFFF);
}

/* ── udp_checksum_ok_v6 ──────────────────────────────────────────────────── */

int udp_checksum_ok_v6(const uint8_t* src_ip6, const uint8_t* dst_ip6,
                       const uint8_t* segment, uint16_t seg_len) {
    if (!src_ip6 || !dst_ip6 || !segment || seg_len < UDP_HDR_LEN)
        return 0;

    /* IPv6 pseudo-header: src(16) + dst(16) + upper-layer-length(4) +
       zeros(3) + next-header(1) = 40 bytes total (RFC 8200 §8.1). */
    uint8_t pseudo[40];
    memcpy(pseudo,      src_ip6, 16);
    memcpy(pseudo + 16, dst_ip6, 16);
    pseudo[32] = 0;
    pseudo[33] = 0;
    pseudo[34] = (uint8_t)(seg_len >> 8);
    pseudo[35] = (uint8_t)(seg_len & 0xFF);
    pseudo[36] = 0;
    pseudo[37] = 0;
    pseudo[38] = 0;
    pseudo[39] = 17;    /* Next Header = UDP */

    uint32_t sum = 0;
    for (int i = 0; i < 40; i += 2)
        sum += (uint32_t)((pseudo[i] << 8) | pseudo[i + 1]);

    for (size_t i = 0; i + 1 < seg_len; i += 2)
        sum += (uint32_t)((segment[i] << 8) | segment[i + 1]);
    if (seg_len & 1)
        sum += (uint32_t)(segment[seg_len - 1] << 8);

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (sum == 0xFFFF);
}

/* ── udp_port_name ───────────────────────────────────────────────────────── */

const char* udp_port_name(uint16_t port) {
    switch (port) {
        case 53:  return "DNS";
        case 67:  return "DHCP-server";
        case 68:  return "DHCP-client";
        case 69:  return "TFTP";
        case 123: return "NTP";
        case 161: return "SNMP";
        case 162: return "SNMP-trap";
        case 514: return "Syslog";
        case 5353: return "mDNS";
        default:  return NULL;
    }
}

/* ── udp_print ───────────────────────────────────────────────────────────── */

void udp_print(const UdpHeader* hdr, int cksum_valid) {
    const char* sp = udp_port_name(hdr->src_port);
    const char* dp = udp_port_name(hdr->dst_port);

    printf("┌─ UDP ──────────────────────────────────────────────┐\n");
    if (sp)
        printf("│  Src Port  : %u  (%s)\n", hdr->src_port, sp);
    else
        printf("│  Src Port  : %u\n", hdr->src_port);

    if (dp)
        printf("│  Dst Port  : %u  (%s)\n", hdr->dst_port, dp);
    else
        printf("│  Dst Port  : %u\n", hdr->dst_port);

    printf("│  Length    : %u bytes  (hdr=8, data=%u)\n",
           hdr->length,
           (hdr->length >= UDP_HDR_LEN) ? (unsigned)(hdr->length - UDP_HDR_LEN) : 0u);

    const char* ck_str = (cksum_valid < 0) ? "not checked"
                       : (cksum_valid     ) ? "OK"
                       : "BAD";
    if (hdr->checksum == 0)
        printf("│  Checksum  : 0x0000  (disabled)\n");
    else
        printf("│  Checksum  : 0x%04x  (%s)\n", hdr->checksum, ck_str);

    printf("└────────────────────────────────────────────────────┘\n");
}
