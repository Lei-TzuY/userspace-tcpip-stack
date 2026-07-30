/*
 * tcp.c — TCP parser implementation
 *
 * Options parsing:
 *   Options occupy bytes [20, hdr_len) of the TCP segment.
 *   Each option starts with a 1-byte kind:
 *     Kind 0 (EOL) and Kind 1 (NOP) are single-byte with no length field.
 *     All other kinds are followed by a 1-byte length (minimum 2, including
 *     the kind and length bytes themselves) and then (length-2) data bytes.
 *
 * Checksum:
 *   Same one's complement algorithm as UDP, but with protocol = 6 (TCP).
 */

#include "tcp.h"

/* ── helpers ────────────────────────────────────────────────────────────── */

static uint32_t read32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

static uint16_t read16(const uint8_t* p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

/* ── tcp_parse ───────────────────────────────────────────────────────────── */

int tcp_parse(const uint8_t* data, size_t len, TcpHeader* out) {
    if (len < TCP_MIN_HDR_LEN) {
        fprintf(stderr, "[tcp] Too short: %zu bytes (need %d)\n",
                len, TCP_MIN_HDR_LEN);
        return -1;
    }

    out->src_port    = read16(data + 0);
    out->dst_port    = read16(data + 2);
    out->seq_num     = read32(data + 4);
    out->ack_num     = read32(data + 8);
    out->data_offset = (data[12] >> 4) & 0x0F;
    out->hdr_len     = (uint8_t)(out->data_offset * 4);
    out->flags       = data[13];
    out->window      = read16(data + 14);
    out->checksum    = read16(data + 16);
    out->urgent_ptr  = read16(data + 18);

    if (out->hdr_len < TCP_MIN_HDR_LEN || out->hdr_len > TCP_MAX_HDR_LEN) {
        fprintf(stderr, "[tcp] Bad data offset: %u\n", out->data_offset);
        return -1;
    }
    if (len < out->hdr_len) {
        fprintf(stderr, "[tcp] Truncated header: have %zu, need %u bytes\n",
                len, out->hdr_len);
        return -1;
    }

    /* ── Parse options ──────────────────────────────────────────────────── */
    out->opt_count = 0;
    const uint8_t* opt     = data + TCP_MIN_HDR_LEN;
    const uint8_t* opt_end = data + out->hdr_len;

    while (opt < opt_end && out->opt_count < TCP_MAX_OPTS) {
        uint8_t kind = *opt++;

        if (kind == TCP_OPT_EOL) break;       /* End of options list */
        if (kind == TCP_OPT_NOP) {            /* No-Op — single byte, no length */
            TcpOption* o = &out->options[out->opt_count++];
            o->kind     = kind;
            o->data_len = 0;
            continue;
        }

        /* All other options: kind + length + (length-2) data bytes */
        if (opt >= opt_end) {
            fprintf(stderr, "[tcp] Truncated option length\n");
            return -1;
        }
        uint8_t olen = *opt++;
        if (olen < 2) {
            fprintf(stderr, "[tcp] Bad option length: %u\n", olen);
            return -1;
        }
        uint8_t dlen = olen - 2;
        if ((size_t)(opt_end - opt) < dlen) {
            fprintf(stderr, "[tcp] Truncated option data\n");
            return -1;
        }

        TcpOption* o = &out->options[out->opt_count++];
        o->kind     = kind;

        /* Copy option data, clamped to our storage, and report the length that
           was actually stored. Recording the declared length instead would let
           a consumer loop past the end of data[] on an option claiming more
           than fits — the storage is sized for the largest option the header
           can hold, so this only ever trims a malformed one. */
        size_t copy = (dlen <= sizeof(o->data)) ? dlen : sizeof(o->data);
        memcpy(o->data, opt, copy);
        o->data_len = (uint8_t)copy;

        opt += dlen;
    }

    /* ── Payload ────────────────────────────────────────────────────────── */
    if (len > out->hdr_len) {
        out->payload     = data + out->hdr_len;
        out->payload_len = len - out->hdr_len;
    } else {
        out->payload     = NULL;
        out->payload_len = 0;
    }

    return 0;
}

/* ── tcp_checksum_ok ─────────────────────────────────────────────────────── */

int tcp_checksum_ok(const uint8_t* src_ip, const uint8_t* dst_ip,
                    const uint8_t* segment, uint16_t seg_len) {
    if (!src_ip || !dst_ip || !segment || seg_len < TCP_MIN_HDR_LEN)
        return 0;

    uint8_t pseudo[12];
    memcpy(pseudo + 0, src_ip, 4);
    memcpy(pseudo + 4, dst_ip, 4);
    pseudo[8]  = 0;      /* zero */
    pseudo[9]  = 6;      /* protocol = TCP */
    pseudo[10] = (uint8_t)(seg_len >> 8);
    pseudo[11] = (uint8_t)(seg_len & 0xFF);

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

/* ── tcp_checksum_ok_v6 ──────────────────────────────────────────────────── */

int tcp_checksum_ok_v6(const uint8_t* src_ip6, const uint8_t* dst_ip6,
                       const uint8_t* segment, uint16_t seg_len) {
    if (!src_ip6 || !dst_ip6 || !segment || seg_len < TCP_MIN_HDR_LEN)
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
    pseudo[39] = 6;     /* Next Header = TCP */

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

/* ── tcp_flags_str ───────────────────────────────────────────────────────── */

void tcp_flags_str(uint8_t flags, char* buf, size_t buf_len) {
    /* Build a Wireshark-style "[SYN, ACK]" string using pointer arithmetic
       to avoid MSVC's deprecation warning on strcat. */
    static const struct { uint8_t mask; const char* name; } kFlags[] = {
        { TCP_CWR, "CWR" }, { TCP_ECE, "ECE" }, { TCP_URG, "URG" },
        { TCP_ACK, "ACK" }, { TCP_PSH, "PSH" }, { TCP_RST, "RST" },
        { TCP_SYN, "SYN" }, { TCP_FIN, "FIN" },
    };
    static const int kCount = (int)(sizeof(kFlags) / sizeof(kFlags[0]));

    if (!buf || buf_len == 0)
        return;

    char* p   = buf;
    char* end = buf + buf_len - 1;
    int first = 1;

#define SAFE_APPEND(s) \
    do { \
        const char* _s = (s); \
        while (*_s && p < end) *p++ = *_s++; \
    } while (0)

    SAFE_APPEND("[");
    for (int i = 0; i < kCount; i++) {
        if (!(flags & kFlags[i].mask)) continue;
        if (!first) SAFE_APPEND(", ");
        SAFE_APPEND(kFlags[i].name);
        first = 0;
    }
    if (first) SAFE_APPEND("none");
    SAFE_APPEND("]");
    *p = '\0';

#undef SAFE_APPEND
}

/* ── tcp_port_name ───────────────────────────────────────────────────────── */

const char* tcp_port_name(uint16_t port) {
    switch (port) {
        case 20:   return "FTP-data";
        case 21:   return "FTP";
        case 22:   return "SSH";
        case 23:   return "Telnet";
        case 25:   return "SMTP";
        case 53:   return "DNS";
        case 80:   return "HTTP";
        case 110:  return "POP3";
        case 143:  return "IMAP";
        case 443:  return "HTTPS";
        case 465:  return "SMTPS";
        case 587:  return "SMTP-submission";
        case 993:  return "IMAPS";
        case 995:  return "POP3S";
        case 3306: return "MySQL";
        case 5432: return "PostgreSQL";
        case 6379: return "Redis";
        case 8080: return "HTTP-alt";
        default:   return NULL;
    }
}

/* ── tcp_print ───────────────────────────────────────────────────────────── */

void tcp_print(const TcpHeader* hdr, int cksum_valid) {
    char flags_buf[40];
    tcp_flags_str(hdr->flags, flags_buf, sizeof(flags_buf));

    const char* sp = tcp_port_name(hdr->src_port);
    const char* dp = tcp_port_name(hdr->dst_port);

    printf("┌─ TCP ──────────────────────────────────────────────┐\n");
    if (sp)
        printf("│  Src Port  : %u  (%s)\n", hdr->src_port, sp);
    else
        printf("│  Src Port  : %u\n", hdr->src_port);

    if (dp)
        printf("│  Dst Port  : %u  (%s)\n", hdr->dst_port, dp);
    else
        printf("│  Dst Port  : %u\n", hdr->dst_port);

    printf("│  Flags     : 0x%02x  %s\n", hdr->flags, flags_buf);
    printf("│  Seq       : %u\n", hdr->seq_num);

    if (hdr->flags & TCP_ACK)
        printf("│  Ack       : %u\n", hdr->ack_num);

    printf("│  Window    : %u\n", hdr->window);
    printf("│  Hdr Len   : %u bytes\n", hdr->hdr_len);

    if (hdr->flags & TCP_URG)
        printf("│  Urgent    : %u\n", hdr->urgent_ptr);

    /* ── Options ── */
    for (int i = 0; i < hdr->opt_count; i++) {
        const TcpOption* o = &hdr->options[i];
        switch (o->kind) {
            case TCP_OPT_NOP:
                /* skip printing individual NOPs */
                break;
            case TCP_OPT_MSS:
                if (o->data_len >= 2) {
                    uint16_t mss = (uint16_t)((o->data[0] << 8) | o->data[1]);
                    printf("│  Opt MSS   : %u bytes\n", mss);
                }
                break;
            case TCP_OPT_WSCALE:
                if (o->data_len >= 1)
                    printf("│  Opt WScale: %u  (multiply window by %u)\n",
                           o->data[0], 1u << o->data[0]);
                break;
            case TCP_OPT_SACKP:
                printf("│  Opt SACK  : permitted\n");
                break;
            case TCP_OPT_SACK: {
                int blocks = o->data_len / 8;
                printf("│  Opt SACK  : %d block(s)\n", blocks);
                for (int b = 0; b < blocks && b * 8 + 7 < (int)o->data_len; b++) {
                    uint32_t le = read32(o->data + b * 8);
                    uint32_t re = read32(o->data + b * 8 + 4);
                    printf("│    block %d : [%u, %u)\n", b + 1, le, re);
                }
                break;
            }
            case TCP_OPT_TS:
                if (o->data_len >= 8) {
                    uint32_t tsval = read32(o->data + 0);
                    uint32_t tsecr = read32(o->data + 4);
                    printf("│  Opt TS    : TSval=%u  TSecr=%u\n", tsval, tsecr);
                }
                break;
            default:
                printf("│  Opt %3u   : len=%u\n", o->kind, o->data_len);
                break;
        }
    }

    const char* ck_str = (cksum_valid < 0) ? "not checked"
                       : (cksum_valid     ) ? "OK"
                       : "BAD";
    printf("│  Checksum  : 0x%04x  (%s)\n", hdr->checksum, ck_str);

    if (hdr->payload_len > 0)
        printf("│  Data Len  : %zu bytes\n", hdr->payload_len);

    printf("└────────────────────────────────────────────────────┘\n");
}
