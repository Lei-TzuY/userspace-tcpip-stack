/*
 * dns.c — DNS wire-format parser
 *
 * Name decompression follows RFC 1035 §4.1.4: a label starting with 0xC0
 * is a 2-byte pointer (upper 6 bits = 0b110000) into the message buffer.
 * We bound the pointer depth to 16 hops to prevent infinite loops.
 */

#include "dns.h"

/* ── helpers ─────────────────────────────────────────────────────────────── */

static uint16_t read16(const uint8_t* p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t read32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

/*
 * dns_decode_name — decode a DNS name at msg[offset] into dst (NUL-terminated).
 * Returns the number of bytes consumed at the original offset (following the
 * first label sequence or pointer), or -1 on error.
 */
static int dns_decode_name(const uint8_t* msg, size_t msg_len,
                           size_t offset, char* dst, size_t dst_len) {
    size_t out = 0;
    int jumped = 0;
    int consumed = -1;
    int hops = 0;
    size_t initial_offset = offset;

    if (dst_len == 0) return -1;
    dst[0] = '\0';

    for (;;) {
        if (offset >= msg_len) return -1;
        uint8_t label_len = msg[offset];

        if (label_len == 0) {
            /* Root label / end of name. */
            if (!jumped) consumed = (int)(offset + 1 - initial_offset);
            if (out == 0) {
                /* Root label alone → "." */
                if (out + 1 >= dst_len) return -1;
                dst[out++] = '.';
            }
            dst[out] = '\0';
            return consumed;
        }

        if ((label_len & 0xC0) == 0xC0) {
            /* Compression pointer. */
            if (offset + 1 >= msg_len) return -1;
            if (!jumped) consumed = (int)(offset + 2 - initial_offset);
            size_t ptr = ((size_t)(label_len & 0x3F) << 8) | msg[offset + 1];
            if (ptr >= msg_len || ptr == offset) return -1;
            if (++hops > 16) return -1;
            offset = ptr;
            jumped = 1;
            continue;
        }

        if ((label_len & 0xC0) != 0) return -1; /* reserved bits */

        offset++;
        if (offset + label_len > msg_len) return -1;

        /* Append "label." to dst. */
        if (out > 0) {
            if (out + 1 >= dst_len) return -1;
            dst[out++] = '.';
        }
        for (uint8_t i = 0; i < label_len; i++) {
            if (out + 1 >= dst_len) return -1;
            uint8_t ch = msg[offset + i];
            dst[out++] = (ch >= 32 && ch <= 126) ? (char)ch : '?';
        }
        offset += label_len;
    }
}

/* Append text to dst, returning 1 if it fits. */
static int append(char* dst, size_t dst_len, const char* src) {
    size_t dlen = strlen(dst);
    size_t slen = strlen(src);
    if (dlen + slen + 1 > dst_len) return 0;
    memcpy(dst + dlen, src, slen + 1);
    return 1;
}

static void fmt_ipv4(char* buf, size_t buf_len, const uint8_t* p) {
    char tmp[20];
    /* safe manual sprint — no snprintf dependency needed */
    unsigned a = p[0], b = p[1], c = p[2], d = p[3];
    /* fit: max "255.255.255.255\0" = 16 chars */
    size_t n = 0;
#define DIGIT3(x) do { \
    if ((x) >= 100) { if(n<buf_len-1) buf[n++]=(char)('0'+(x)/100); } \
    if ((x) >= 10)  { if(n<buf_len-1) buf[n++]=(char)('0'+((x)/10)%10); } \
    if(n<buf_len-1) buf[n++]=(char)('0'+(x)%10); } while(0)
    DIGIT3(a); if(n<buf_len-1) buf[n++]='.';
    DIGIT3(b); if(n<buf_len-1) buf[n++]='.';
    DIGIT3(c); if(n<buf_len-1) buf[n++]='.';
    DIGIT3(d); if(n<buf_len-1) buf[n]='\0'; else buf[buf_len-1]='\0';
#undef DIGIT3
    (void)tmp;
}

static void fmt_ipv6(char* buf, size_t buf_len, const uint8_t* p) {
    /* Minimal unabbreviated form "xxxx:xxxx:...:xxxx" */
    static const char hex[] = "0123456789abcdef";
    size_t n = 0;
    for (int i = 0; i < 8; i++) {
        uint16_t grp = (uint16_t)((p[i*2] << 8) | p[i*2+1]);
        int leading = 1;
        for (int shift = 12; shift >= 0; shift -= 4) {
            uint8_t nibble = (grp >> shift) & 0xF;
            if (nibble == 0 && leading && shift > 0) continue;
            leading = 0;
            if (n < buf_len - 1) buf[n++] = hex[nibble];
        }
        if (i < 7 && n < buf_len - 1) buf[n++] = ':';
    }
    buf[n < buf_len ? n : buf_len - 1] = '\0';
}

/*
 * parse_rr — parse one resource record starting at msg[*offset].
 * Fills *rr. Returns bytes consumed or -1 on error.
 */
static int parse_rr(const uint8_t* msg, size_t msg_len, size_t offset,
                    DnsRR* rr, int is_question) {
    char name[DNS_MAX_NAME];
    int name_bytes = dns_decode_name(msg, msg_len, offset, name, sizeof(name));
    if (name_bytes < 0) return -1;
    offset += (size_t)name_bytes;

    if (offset + 4 > msg_len) return -1;
    uint16_t type  = read16(msg + offset);     offset += 2;
    uint16_t class_ = read16(msg + offset);    offset += 2;

    /* Copy name */
    strncpy(rr->name, name, DNS_MAX_NAME - 1);
    rr->name[DNS_MAX_NAME - 1] = '\0';
    rr->type   = type;
    rr->class_ = class_;
    rr->ttl    = 0;
    rr->rdata[0] = '\0';

    if (is_question) return (int)(offset - (size_t)name_bytes - 4 + (size_t)name_bytes + 4);

    /* Full RR: TTL + RDLENGTH + RDATA */
    if (offset + 6 > msg_len) return -1;
    uint32_t ttl      = read32(msg + offset); offset += 4;
    uint16_t rdlength = read16(msg + offset); offset += 2;

    rr->ttl = ttl;

    if (offset + rdlength > msg_len) return -1;
    const uint8_t* rd = msg + offset;

    switch (type) {
        case DNS_TYPE_A:
            if (rdlength == 4) fmt_ipv4(rr->rdata, sizeof(rr->rdata), rd);
            break;
        case DNS_TYPE_AAAA:
            if (rdlength == 16) fmt_ipv6(rr->rdata, sizeof(rr->rdata), rd);
            break;
        case DNS_TYPE_NS:
        case DNS_TYPE_CNAME:
        case DNS_TYPE_PTR:
            dns_decode_name(msg, msg_len, offset, rr->rdata, sizeof(rr->rdata));
            break;
        case DNS_TYPE_MX: {
            if (rdlength < 3) break;
            char mx_name[DNS_MAX_NAME];
            dns_decode_name(msg, msg_len, offset + 2, mx_name, sizeof(mx_name));
            uint16_t pref = read16(rd);
            /* format: "10 mail.example.com" */
            char tmp[8]; size_t n = 0;
            uint16_t p2 = pref;
            if (p2 >= 10000) { tmp[n++] = (char)('0' + p2/10000); p2 %= 10000; }
            if (pref >= 1000) { tmp[n++] = (char)('0' + p2/1000); p2 %= 1000; }
            if (pref >= 100)  { tmp[n++] = (char)('0' + p2/100);  p2 %= 100; }
            if (pref >= 10)   { tmp[n++] = (char)('0' + p2/10);   p2 %= 10; }
            tmp[n++] = (char)('0' + p2);
            tmp[n] = '\0';
            append(rr->rdata, sizeof(rr->rdata), tmp);
            append(rr->rdata, sizeof(rr->rdata), " ");
            append(rr->rdata, sizeof(rr->rdata), mx_name);
            break;
        }
        case DNS_TYPE_TXT: {
            size_t pos = 0;
            while (pos < rdlength) {
                uint8_t tlen = rd[pos++];
                if (pos + tlen > rdlength) break;
                if (rr->rdata[0]) append(rr->rdata, sizeof(rr->rdata), " ");
                append(rr->rdata, sizeof(rr->rdata), "\"");
                for (uint8_t k = 0; k < tlen; k++) {
                    char c[2] = { (char)(rd[pos + k] >= 32 && rd[pos + k] <= 126
                                   ? rd[pos + k] : '.'), '\0' };
                    append(rr->rdata, sizeof(rr->rdata), c);
                }
                append(rr->rdata, sizeof(rr->rdata), "\"");
                pos += tlen;
            }
            break;
        }
        case DNS_TYPE_SOA: {
            /* mname + rname + serial(4) + refresh(4) + retry(4) + expire(4) + min(4) */
            char mname[DNS_MAX_NAME], rname[DNS_MAX_NAME];
            int n1 = dns_decode_name(msg, msg_len, offset, mname, sizeof(mname));
            if (n1 < 0) break;
            int n2 = dns_decode_name(msg, msg_len, offset + (size_t)n1,
                                     rname, sizeof(rname));
            if (n2 < 0) break;
            size_t foff = offset + (size_t)n1 + (size_t)n2;
            if (foff + 20 > offset + rdlength) break;
            uint32_t serial = read32(msg + foff);
            char buf[DNS_MAX_NAME * 2 + 32];
            snprintf(buf, sizeof(buf), "%s %s serial=%u", mname, rname,
                     (unsigned)serial);
            append(rr->rdata, sizeof(rr->rdata), buf);
            break;
        }
        case DNS_TYPE_SRV: {
            /* priority(2) + weight(2) + port(2) + target(name) */
            if (rdlength < 7) break;
            uint16_t prio   = read16(rd);
            uint16_t weight = read16(rd + 2);
            uint16_t port   = read16(rd + 4);
            char target[DNS_MAX_NAME];
            dns_decode_name(msg, msg_len, offset + 6, target, sizeof(target));
            char buf[DNS_MAX_NAME + 64];
            snprintf(buf, sizeof(buf), "prio=%u weight=%u port=%u %s",
                     prio, weight, port, target);
            append(rr->rdata, sizeof(rr->rdata), buf);
            break;
        }
        default:
            /* Raw hex for unknown types (first 8 bytes). */
            {
                static const char hex[] = "0123456789abcdef";
                size_t show = rdlength < 8 ? rdlength : 8;
                char hex_buf[32]; size_t h = 0;
                for (size_t i = 0; i < show; i++) {
                    hex_buf[h++] = hex[rd[i] >> 4];
                    hex_buf[h++] = hex[rd[i] & 0xF];
                }
                if (rdlength > 8) { hex_buf[h++] = '.'; hex_buf[h++] = '.'; }
                hex_buf[h] = '\0';
                append(rr->rdata, sizeof(rr->rdata), hex_buf);
            }
            break;
    }

    offset += rdlength;
    return (int)offset;
}

/* ── dns_parse ───────────────────────────────────────────────────────────── */

int dns_parse(const uint8_t* data, size_t len, DnsMessage* out) {
    if (!data || !out || len < DNS_HDR_LEN) return -1;

    memset(out, 0, sizeof(*out));
    out->id      = read16(data + 0);
    out->flags   = read16(data + 2);
    out->qdcount = read16(data + 4);
    out->ancount = read16(data + 6);
    out->nscount = read16(data + 8);
    out->arcount = read16(data + 10);

    size_t offset = DNS_HDR_LEN;

    /* Questions */
    for (uint16_t i = 0; i < out->qdcount; i++) {
        DnsRR scratch;
        DnsRR* rr = i < DNS_MAX_RECS
                  ? &out->questions[out->question_count] : &scratch;
        int consumed = parse_rr(data, len, offset, rr, 1);
        if (consumed < 0) return -1;
        offset = (size_t)consumed;
        if (i < DNS_MAX_RECS)
            out->question_count++;
    }

    /* Answers */
    for (uint16_t i = 0; i < out->ancount; i++) {
        DnsRR scratch;
        DnsRR* rr = i < DNS_MAX_RECS
                  ? &out->answers[out->answer_count] : &scratch;
        int consumed = parse_rr(data, len, offset, rr, 0);
        if (consumed < 0) return -1;
        offset = (size_t)consumed;
        if (i < DNS_MAX_RECS)
            out->answer_count++;
    }

    /* Authority */
    for (uint16_t i = 0; i < out->nscount; i++) {
        DnsRR scratch;
        DnsRR* rr = i < DNS_MAX_RECS
                  ? &out->authority[out->authority_count] : &scratch;
        int consumed = parse_rr(data, len, offset, rr, 0);
        if (consumed < 0) return -1;
        offset = (size_t)consumed;
        if (i < DNS_MAX_RECS)
            out->authority_count++;
    }

    /* Additional */
    for (uint16_t i = 0; i < out->arcount; i++) {
        DnsRR scratch;
        DnsRR* rr = i < DNS_MAX_RECS
                  ? &out->additional[out->additional_count] : &scratch;
        int consumed = parse_rr(data, len, offset, rr, 0);
        if (consumed < 0) return -1;
        offset = (size_t)consumed;
        if (i < DNS_MAX_RECS)
            out->additional_count++;
    }

    return 0;
}

/* ── dns_print ───────────────────────────────────────────────────────────── */

const char* dns_rcode_name(uint8_t rcode) {
    switch (rcode) {
        case 0: return "NOERROR";
        case 1: return "FORMERR";
        case 2: return "SERVFAIL";
        case 3: return "NXDOMAIN";
        case 4: return "NOTIMP";
        case 5: return "REFUSED";
        default: return "UNKNOWN";
    }
}

const char* dns_type_name(uint16_t type) {
    switch (type) {
        case DNS_TYPE_A:     return "A";
        case DNS_TYPE_NS:    return "NS";
        case DNS_TYPE_SOA:   return "SOA";
        case DNS_TYPE_CNAME: return "CNAME";
        case DNS_TYPE_PTR:   return "PTR";
        case DNS_TYPE_MX:    return "MX";
        case DNS_TYPE_TXT:   return "TXT";
        case DNS_TYPE_AAAA:  return "AAAA";
        case DNS_TYPE_SRV:   return "SRV";
        case 255:            return "ANY";
        default:             return NULL;
    }
}

static void print_rr(const DnsRR* rr, int show_ttl) {
    const char* tname = dns_type_name(rr->type);
    char type_buf[8];
    if (!tname) {
        size_t n = 0;
        uint16_t t = rr->type;
        if (t >= 10000) type_buf[n++] = (char)('0' + t / 10000);
        if (t >= 1000)  type_buf[n++] = (char)('0' + (t / 1000) % 10);
        if (t >= 100)   type_buf[n++] = (char)('0' + (t / 100) % 10);
        if (t >= 10)    type_buf[n++] = (char)('0' + (t / 10) % 10);
        type_buf[n++] = (char)('0' + t % 10);
        type_buf[n] = '\0';
        tname = type_buf;
    }

    if (show_ttl)
        printf("|    %-32s  %-6s  TTL=%-6u  %s\n",
               rr->name, tname, rr->ttl,
               rr->rdata[0] ? rr->rdata : "(no rdata)");
    else
        printf("|    %-32s  %s\n", rr->name, tname);
}

void dns_print(const DnsMessage* msg) {
    int is_response = (msg->flags & DNS_QR) != 0;
    uint8_t opcode  = (uint8_t)((msg->flags >> 11) & 0xF);
    uint8_t rcode   = (uint8_t)(msg->flags & DNS_RCODE);

    printf("+-- DNS (%s) -----------------------------------------+\n",
           is_response ? "response" : "query");
    printf("|  ID        : 0x%04x\n", msg->id);
    printf("|  Flags     : 0x%04x  [%s%s%s%s%s]  RCODE=%s\n",
           msg->flags,
           opcode == 0 ? "QUERY" : opcode == 1 ? "IQUERY" : "UNKNOWN",
           (msg->flags & DNS_AA) ? " AA" : "",
           (msg->flags & DNS_TC) ? " TC" : "",
           (msg->flags & DNS_RD) ? " RD" : "",
           (msg->flags & DNS_RA) ? " RA" : "",
           dns_rcode_name(rcode));
    printf("|  Questions : %u  Answers : %u  Auth : %u  Add : %u\n",
           msg->qdcount, msg->ancount, msg->nscount, msg->arcount);

    if (msg->question_count > 0) {
        printf("|  -- Questions --\n");
        for (int i = 0; i < msg->question_count; i++)
            print_rr(&msg->questions[i], 0);
    }
    if (msg->answer_count > 0) {
        printf("|  -- Answers --\n");
        for (int i = 0; i < msg->answer_count; i++)
            print_rr(&msg->answers[i], 1);
    }
    if (msg->authority_count > 0) {
        printf("|  -- Authority --\n");
        for (int i = 0; i < msg->authority_count; i++)
            print_rr(&msg->authority[i], 1);
    }
    if (msg->additional_count > 0) {
        printf("|  -- Additional --\n");
        for (int i = 0; i < msg->additional_count; i++)
            print_rr(&msg->additional[i], 1);
    }
    printf("+------------------------------------------------------------+\n");
}
