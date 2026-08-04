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

/* ── DNSSEC helpers ──────────────────────────────────────────────────────── */

/*
 * Append up to max_bytes of p as lowercase hex, marking the cut with "..".
 * Signature and key material runs to hundreds of bytes and there is nothing to
 * learn from all of it — the first few octets are enough to tell two keys
 * apart by eye.
 */
static void append_hex(char* dst, size_t dst_len,
                       const uint8_t* p, size_t n, size_t max_bytes) {
    static const char hex[] = "0123456789abcdef";
    size_t show = n < max_bytes ? n : max_bytes;
    size_t i;
    char pair[3];

    pair[2] = '\0';
    for (i = 0; i < show; i++) {
        pair[0] = hex[p[i] >> 4];
        pair[1] = hex[p[i] & 0xF];
        if (!append(dst, dst_len, pair)) return;
    }
    if (n > show) append(dst, dst_len, "..");
}

const char* dns_algorithm_name(uint8_t algorithm) {
    switch (algorithm) {
        case 1:  return "RSAMD5";           /* MUST NOT be used (RFC 8624) */
        case 3:  return "DSA";
        case 5:  return "RSASHA1";
        case 6:  return "DSA-NSEC3-SHA1";
        case 7:  return "RSASHA1-NSEC3-SHA1";
        case 8:  return "RSASHA256";
        case 10: return "RSASHA512";
        case 12: return "ECC-GOST";
        case 13: return "ECDSAP256SHA256";
        case 14: return "ECDSAP384SHA384";
        case 15: return "ED25519";
        case 16: return "ED448";
        default: return NULL;
    }
}

static const char* digest_type_name(uint8_t digest_type) {
    switch (digest_type) {
        case 1:  return "SHA-1";
        case 2:  return "SHA-256";
        case 3:  return "GOST R 34.11-94";
        case 4:  return "SHA-384";
        default: return NULL;
    }
}

uint16_t dns_dnskey_key_tag(const uint8_t* rdata, size_t rdlength) {
    /*
     * RFC 4034 Appendix B: sum the RDATA as a sequence of big-endian 16-bit
     * words, fold the carry back in, and keep the low 16 bits. Algorithm 1
     * (RSAMD5) has its own rule using the last two bytes of the key, but that
     * algorithm is MUST NOT under RFC 8624, so treating it like the rest costs
     * nothing real and keeps this a single expression.
     */
    uint32_t ac = 0;
    size_t i;

    if (!rdata) return 0;
    for (i = 0; i < rdlength; i++)
        ac += (i & 1) ? rdata[i] : ((uint32_t)rdata[i] << 8);
    ac += (ac >> 16) & 0xFFFFu;
    return (uint16_t)(ac & 0xFFFFu);
}

/* Write the RR type as a name, or as RFC 3597's TYPE<n> when unassigned. */
static const char* type_text(uint16_t type, char* buf, size_t buf_len) {
    const char* name = dns_type_name(type);
    if (name) return name;
    snprintf(buf, buf_len, "TYPE%u", type);
    return buf;
}

/*
 * Format a POSIX timestamp as RFC 4034 §3.2's presentation form,
 * YYYYMMDDHHMMSS.
 *
 * Written out rather than handed to gmtime(): the wire field is 32 bits
 * unsigned, time_t is signed and still 32 bits in places, so a timestamp past
 * 2038 would arrive as a negative time or a NULL struct tm. The civil-date
 * conversion shifts the epoch to 0000-03-01 so every intermediate stays
 * positive and no negative-division rounding case exists.
 */
static void fmt_dns_time(char* buf, size_t buf_len, uint32_t secs) {
    int64_t days = (int64_t)(secs / 86400u);
    unsigned rem = (unsigned)(secs % 86400u);
    int64_t z, era, doe, yoe, y, doy, mp, d, m;

    z   = days + 719468;          /* days since 0000-03-01, always positive */
    era = z / 146097;             /* 400-year cycle */
    doe = z - era * 146097;
    yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    y   = yoe + era * 400;
    doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    mp  = (5 * doy + 2) / 153;    /* month, counting March as 0 */
    d   = doy - (153 * mp + 2) / 5 + 1;
    m   = mp < 10 ? mp + 3 : mp - 9;
    if (m <= 2) y++;              /* January and February belong to next year */

    snprintf(buf, buf_len, "%04d%02u%02u%02u%02u%02u",
             (int)y, (unsigned)m, (unsigned)d,
             rem / 3600u, (rem / 60u) % 60u, rem % 60u);
}

/*
 * Append an NSEC/NSEC3 type bit map (RFC 4034 §4.1.2): a sequence of
 * {window number, bitmap length, bitmap} blocks, each naming the types whose
 * low byte has a set bit.
 */
static void append_type_bitmap(char* dst, size_t dst_len,
                               const uint8_t* p, size_t len) {
    size_t pos = 0;
    int wrote = 0;

    while (pos + 2 <= len) {
        unsigned window = p[pos];
        size_t bitmap_len = p[pos + 1];
        size_t i;

        pos += 2;
        /*
         * A block declares its own length. RFC 4034 §4.1.2 allows 1 to 32
         * octets, and anything else means the next block's position is a
         * guess — so stop rather than walk on from a position we invented.
         */
        if (bitmap_len == 0 || bitmap_len > 32 || pos + bitmap_len > len) {
            append(dst, dst_len, wrote ? " <malformed bitmap>"
                                       : "<malformed bitmap>");
            return;
        }

        for (i = 0; i < bitmap_len; i++) {
            int bit;
            for (bit = 0; bit < 8; bit++) {
                char name_buf[12];
                uint16_t type;
                if (!(p[pos + i] & (0x80 >> bit))) continue;
                type = (uint16_t)(window * 256u + i * 8u + (unsigned)bit);
                if (wrote && !append(dst, dst_len, " ")) return;
                if (!append(dst, dst_len,
                            type_text(type, name_buf, sizeof(name_buf))))
                    return;
                wrote = 1;
            }
        }
        pos += bitmap_len;
    }

    if (!wrote) append(dst, dst_len, "(no types)");
}

/*
 * parse_rr — parse one resource record starting at msg[*offset].
 * Fills *rr. Returns bytes consumed or -1 on error.
 *
 * rd_out/rdlen_out receive the location of the raw RDATA, which the caller
 * needs for OPT: its contents are transport options rather than data about a
 * name, and are lifted into DnsMessage.edns instead of being rendered here.
 */
static int parse_rr(const uint8_t* msg, size_t msg_len, size_t offset,
                    DnsRR* rr, int is_question,
                    const uint8_t** rd_out, uint16_t* rdlen_out) {
    char name[DNS_MAX_NAME];
    int name_bytes = dns_decode_name(msg, msg_len, offset, name, sizeof(name));

    *rd_out    = NULL;
    *rdlen_out = 0;

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

    *rd_out    = rd;
    *rdlen_out = rdlength;

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
        case DNS_TYPE_DS: {
            /* key tag(2) algorithm(1) digest type(1) digest */
            char buf[96];
            const char* alg;
            const char* dt;
            if (rdlength < 4) break;
            alg = dns_algorithm_name(rd[2]);
            dt  = digest_type_name(rd[3]);
            snprintf(buf, sizeof(buf), "keytag=%u alg=%u (%s) digest=%u (%s) ",
                     read16(rd), rd[2], alg ? alg : "unassigned",
                     rd[3], dt ? dt : "unassigned");
            append(rr->rdata, sizeof(rr->rdata), buf);
            append_hex(rr->rdata, sizeof(rr->rdata),
                       rd + 4, (size_t)(rdlength - 4), 12);
            break;
        }

        case DNS_TYPE_DNSKEY: {
            /* flags(2) protocol(1) algorithm(1) public key */
            char buf[128];
            uint16_t key_flags;
            const char* alg;
            if (rdlength < 4) break;
            key_flags = read16(rd);
            alg = dns_algorithm_name(rd[3]);
            snprintf(buf, sizeof(buf),
                     "keytag=%u flags=0x%04x%s%s%s proto=%u alg=%u (%s) key=",
                     dns_dnskey_key_tag(rd, rdlength), key_flags,
                     (key_flags & DNS_DNSKEY_ZONE)   ? " ZONE"   : "",
                     (key_flags & DNS_DNSKEY_SEP)    ? " SEP"    : "",
                     (key_flags & DNS_DNSKEY_REVOKE) ? " REVOKE" : "",
                     rd[2], rd[3], alg ? alg : "unassigned");
            append(rr->rdata, sizeof(rr->rdata), buf);
            append_hex(rr->rdata, sizeof(rr->rdata),
                       rd + 4, (size_t)(rdlength - 4), 8);
            break;
        }

        case DNS_TYPE_RRSIG: {
            /* type covered(2) alg(1) labels(1) original TTL(4)
               expiration(4) inception(4) key tag(2) signer, signature */
            char buf[DNS_MAX_NAME + 128];
            char expires[20], inception[20], covered[12];
            char signer[DNS_MAX_NAME];
            const char* alg;
            int signer_bytes;

            if (rdlength < 18) break;
            signer_bytes = dns_decode_name(msg, msg_len, offset + 18,
                                           signer, sizeof(signer));
            /* RFC 4034 §3.1.7: the signer's name is not compressed, so it has
               to fit inside this record's own RDATA. A name that runs past
               RDLENGTH means the record is lying about its size. */
            if (signer_bytes < 0 || (size_t)signer_bytes + 18 > rdlength)
                break;

            fmt_dns_time(inception, sizeof(inception), read32(rd + 12));
            fmt_dns_time(expires,   sizeof(expires),   read32(rd + 8));
            alg = dns_algorithm_name(rd[2]);
            snprintf(buf, sizeof(buf),
                     "%s alg=%u (%s) labels=%u origttl=%u %s..%s "
                     "keytag=%u signer=%s sig=",
                     type_text(read16(rd), covered, sizeof(covered)),
                     rd[2], alg ? alg : "unassigned", rd[3],
                     (unsigned)read32(rd + 4), inception, expires,
                     read16(rd + 16), signer);
            append(rr->rdata, sizeof(rr->rdata), buf);
            append_hex(rr->rdata, sizeof(rr->rdata),
                       rd + 18 + signer_bytes,
                       (size_t)(rdlength - 18 - signer_bytes), 6);
            break;
        }

        case DNS_TYPE_NSEC: {
            /* next domain name, then the type bit map */
            char next[DNS_MAX_NAME];
            int next_bytes = dns_decode_name(msg, msg_len, offset,
                                             next, sizeof(next));
            /* RFC 4034 §4.1.1: not compressed, same reasoning as RRSIG. */
            if (next_bytes < 0 || (size_t)next_bytes > rdlength) break;
            append(rr->rdata, sizeof(rr->rdata), next);
            append(rr->rdata, sizeof(rr->rdata), " ");
            append_type_bitmap(rr->rdata, sizeof(rr->rdata),
                               rd + next_bytes,
                               (size_t)(rdlength - next_bytes));
            break;
        }

        case DNS_TYPE_NSEC3: {
            /* hash alg(1) flags(1) iterations(2) salt len(1) salt
               hash len(1) next hashed owner, then the type bit map.
               Both lengths are chosen by whoever wrote the record, so each is
               checked against what is left before it is used to step. */
            char buf[96];
            size_t salt_len, hash_len, pos;

            if (rdlength < 5) break;
            salt_len = rd[4];
            pos = 5;
            if (pos + salt_len + 1 > rdlength) break;
            hash_len = rd[pos + salt_len];
            pos += salt_len + 1;
            if (pos + hash_len > rdlength) break;

            snprintf(buf, sizeof(buf), "hash=%u flags=0x%02x%s iter=%u salt=",
                     rd[0], rd[1], (rd[1] & 0x01) ? " OPTOUT" : "",
                     read16(rd + 2));
            append(rr->rdata, sizeof(rr->rdata), buf);
            if (salt_len == 0)
                append(rr->rdata, sizeof(rr->rdata), "-");
            else
                append_hex(rr->rdata, sizeof(rr->rdata), rd + 5, salt_len, 8);
            append(rr->rdata, sizeof(rr->rdata), " next=");
            append_hex(rr->rdata, sizeof(rr->rdata), rd + pos, hash_len, 8);
            pos += hash_len;
            append(rr->rdata, sizeof(rr->rdata), " ");
            append_type_bitmap(rr->rdata, sizeof(rr->rdata),
                               rd + pos, (size_t)rdlength - pos);
            break;
        }

        case DNS_TYPE_NSEC3PARAM: {
            char buf[96];
            size_t salt_len;

            if (rdlength < 5) break;
            salt_len = rd[4];
            if (5 + salt_len > rdlength) break;
            snprintf(buf, sizeof(buf), "hash=%u flags=0x%02x iter=%u salt=",
                     rd[0], rd[1], read16(rd + 2));
            append(rr->rdata, sizeof(rr->rdata), buf);
            if (salt_len == 0)
                append(rr->rdata, sizeof(rr->rdata), "-");
            else
                append_hex(rr->rdata, sizeof(rr->rdata), rd + 5, salt_len, 8);
            break;
        }

        case DNS_TYPE_OPT:
            /* Not data about a name: the caller lifts this into DnsMessage.edns
               and renders it there. Leaving rdata empty avoids a hex dump of
               option bytes that are about to be decoded properly. */
            break;

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

/* ── EDNS0 (RFC 6891) ────────────────────────────────────────────────────── */

static const char* edns_error_name(uint16_t info_code) {
    switch (info_code) {
        case 0:  return "Other";
        case 1:  return "Unsupported DNSKEY Algorithm";
        case 2:  return "Unsupported DS Digest Type";
        case 3:  return "Stale Answer";
        case 4:  return "Forged Answer";
        case 5:  return "DNSSEC Indeterminate";
        case 6:  return "DNSSEC Bogus";
        case 7:  return "Signature Expired";
        case 8:  return "Signature Not Yet Valid";
        case 9:  return "DNSKEY Missing";
        case 10: return "RRSIGs Missing";
        case 11: return "No Zone Key Bit Set";
        case 12: return "NSEC Missing";
        case 13: return "Cached Error";
        case 14: return "Not Ready";
        case 15: return "Blocked";
        case 16: return "Censored";
        case 17: return "Filtered";
        case 18: return "Prohibited";
        case 19: return "Stale NXDOMAIN Answer";
        case 20: return "Not Authoritative";
        case 21: return "Not Supported";
        case 22: return "No Reachable Authority";
        case 23: return "Network Error";
        case 24: return "Invalid Data";
        default: return NULL;
    }
}

/* Decode one EDNS option's payload into opt->text. data[0..len) is in bounds. */
static void decode_edns_option(DnsEdnsOption* opt,
                               const uint8_t* data, uint16_t len) {
    char tmp[DNS_EDNS_OPT_TEXT];

    opt->text[0] = '\0';

    switch (opt->code) {
        case DNS_EDNS_CLIENT_SUBNET: {
            /* family(2) source prefix-len(1) scope prefix-len(1) address */
            uint16_t family;
            unsigned source, scope;
            size_t addr_bytes, present;
            uint8_t addr[16];
            char ip[48];

            if (len < 4) { append(opt->text, sizeof(opt->text), "<truncated>");
                           break; }
            family  = read16(data);
            source  = data[2];
            scope   = data[3];
            present = (size_t)len - 4u;

            /*
             * RFC 7871 §6: the address is truncated to SOURCE PREFIX-LENGTH
             * bits, rounded up to a whole octet. The prefix length is chosen
             * by the sender, so it is checked against the family's width and
             * against how many bytes actually arrived before it is used to
             * size a copy.
             */
            addr_bytes = ((size_t)source + 7u) / 8u;
            if ((family == 1 && source > 32) || (family == 2 && source > 128)
                    || addr_bytes > present || addr_bytes > sizeof(addr)) {
                snprintf(tmp, sizeof(tmp),
                         "family=%u <source prefix %u does not fit %u byte(s)>",
                         family, source, (unsigned)present);
                append(opt->text, sizeof(opt->text), tmp);
                break;
            }

            memset(addr, 0, sizeof(addr));
            memcpy(addr, data + 4, addr_bytes);
            if (family == 1)
                fmt_ipv4(ip, sizeof(ip), addr);
            else if (family == 2)
                fmt_ipv6(ip, sizeof(ip), addr);
            else {
                snprintf(tmp, sizeof(tmp), "family=%u source=%u scope=%u",
                         family, source, scope);
                append(opt->text, sizeof(opt->text), tmp);
                break;
            }
            snprintf(tmp, sizeof(tmp), "%s/%u scope /%u", ip, source, scope);
            append(opt->text, sizeof(opt->text), tmp);
            break;
        }

        case DNS_EDNS_ERROR: {
            /* info code(2) then UTF-8 extra text, not NUL-terminated */
            uint16_t info;
            const char* name;
            size_t i, text_len;

            if (len < 2) { append(opt->text, sizeof(opt->text), "<truncated>");
                           break; }
            info = read16(data);
            name = edns_error_name(info);
            snprintf(tmp, sizeof(tmp), "%u (%s)", info,
                     name ? name : "unassigned");
            append(opt->text, sizeof(opt->text), tmp);

            text_len = (size_t)len - 2u;
            if (text_len == 0) break;
            append(opt->text, sizeof(opt->text), " \"");
            for (i = 0; i < text_len; i++) {
                uint8_t ch = data[2 + i];
                char c[2];
                c[0] = (ch >= 32 && ch <= 126) ? (char)ch : '.';
                c[1] = '\0';
                if (!append(opt->text, sizeof(opt->text), c)) break;
            }
            append(opt->text, sizeof(opt->text), "\"");
            break;
        }

        case DNS_EDNS_COOKIE:
            /* RFC 7873 §5.2.2: 8 bytes client-only, or 16 to 40 with the
               server's half appended. Any other length is malformed. */
            if (len == 8) {
                append(opt->text, sizeof(opt->text), "client ");
                append_hex(opt->text, sizeof(opt->text), data, 8, 8);
            } else if (len >= 16 && len <= 40) {
                append(opt->text, sizeof(opt->text), "client ");
                append_hex(opt->text, sizeof(opt->text), data, 8, 8);
                snprintf(tmp, sizeof(tmp), " + %u-byte server ", len - 8u);
                append(opt->text, sizeof(opt->text), tmp);
                append_hex(opt->text, sizeof(opt->text),
                           data + 8, (size_t)len - 8u, 8);
            } else {
                snprintf(tmp, sizeof(tmp), "<invalid length %u>", len);
                append(opt->text, sizeof(opt->text), tmp);
            }
            break;

        case DNS_EDNS_TCP_KEEPALIVE:
            /* RFC 7828 §3: absent in a request, 2 bytes in a response,
               counted in 100 ms units. */
            if (len == 0) {
                append(opt->text, sizeof(opt->text), "requested, no timeout");
            } else if (len == 2) {
                unsigned units = read16(data);
                snprintf(tmp, sizeof(tmp), "%u.%u s", units / 10u, units % 10u);
                append(opt->text, sizeof(opt->text), tmp);
            } else {
                snprintf(tmp, sizeof(tmp), "<invalid length %u>", len);
                append(opt->text, sizeof(opt->text), tmp);
            }
            break;

        case DNS_EDNS_NSID:
            append_hex(opt->text, sizeof(opt->text), data, len, 16);
            break;

        default:
            snprintf(tmp, sizeof(tmp), "%u byte(s)", len);
            append(opt->text, sizeof(opt->text), tmp);
            break;
    }
}

/*
 * Lift an OPT record into DnsMessage.edns.
 *
 * Problems are recorded in edns.problems rather than failing the parse: a
 * malformed OPT does not stop the rest of the message from being readable, and
 * naming the rule that was broken is more useful than dropping the packet.
 */
static void parse_edns(DnsMessage* out, const DnsRR* rr,
                       const uint8_t* rd, uint16_t rdlength,
                       int in_additional) {
    DnsEdns* e = &out->edns;
    size_t pos = 0;

    if (e->present) {
        /* RFC 6891 §6.1.1: at most one OPT per message. */
        e->problems |= DNS_EDNS_DUPLICATE;
        return;
    }

    e->present = 1;
    if (!in_additional)
        e->problems |= DNS_EDNS_MISPLACED;
    if (strcmp(rr->name, ".") != 0)
        e->problems |= DNS_EDNS_BAD_OWNER;

    /* The class and TTL fields are reused: class is the requestor's UDP
       payload size, TTL is (extended RCODE, version, flags). */
    e->udp_payload_size = rr->class_;
    e->rcode_high = (uint8_t)((rr->ttl >> 24) & 0xFFu);
    e->version    = (uint8_t)((rr->ttl >> 16) & 0xFFu);
    e->flags      = (uint16_t)(rr->ttl & 0xFFFFu);
    e->dnssec_ok  = (e->flags & 0x8000u) != 0;

    if (!rd) return;

    while (pos + 4 <= rdlength) {
        uint16_t code = read16(rd + pos);
        uint16_t olen = read16(rd + pos + 2);
        pos += 4;
        if (pos + olen > rdlength) {
            e->problems |= DNS_EDNS_BAD_OPTION;
            return;
        }
        if (e->option_count < DNS_EDNS_MAX_OPTS) {
            DnsEdnsOption* opt = &e->options[e->option_count++];
            opt->code   = code;
            opt->length = olen;
            decode_edns_option(opt, rd + pos, olen);
        } else {
            e->problems |= DNS_EDNS_OPTS_FULL;
        }
        pos += olen;
    }

    /* One to three bytes left over is a header that could not start. */
    if (pos != rdlength)
        e->problems |= DNS_EDNS_BAD_OPTION;
}

uint16_t dns_full_rcode(const DnsMessage* msg) {
    uint16_t low = (uint16_t)(msg->flags & DNS_RCODE);
    if (!msg->edns.present) return low;
    return (uint16_t)(((uint16_t)msg->edns.rcode_high << 4) | low);
}

/* ── dns_parse ───────────────────────────────────────────────────────────── */

/*
 * Parse one section's records. OPT is lifted into out->edns instead of being
 * stored, so the slot check is against the stored count rather than the loop
 * index. Returns the new offset, or -1.
 */
static int parse_section(const uint8_t* data, size_t len, size_t offset,
                         DnsMessage* out, uint16_t count,
                         DnsRR* records, int* stored, int in_additional) {
    uint16_t i;

    for (i = 0; i < count; i++) {
        DnsRR scratch;
        int have_slot = *stored < DNS_MAX_RECS;
        DnsRR* rr = have_slot ? &records[*stored] : &scratch;
        const uint8_t* rd = NULL;
        uint16_t rdlen = 0;
        int consumed = parse_rr(data, len, offset, rr, 0, &rd, &rdlen);

        if (consumed < 0) return -1;
        offset = (size_t)consumed;

        if (rr->type == DNS_TYPE_OPT) {
            parse_edns(out, rr, rd, rdlen, in_additional);
            continue;
        }
        if (have_slot) (*stored)++;
    }
    return (int)offset;
}

int dns_parse(const uint8_t* data, size_t len, DnsMessage* out) {
    int section;

    if (!data || !out || len < DNS_HDR_LEN) return -1;

    memset(out, 0, sizeof(*out));
    out->id      = read16(data + 0);
    out->flags   = read16(data + 2);
    out->qdcount = read16(data + 4);
    out->ancount = read16(data + 6);
    out->nscount = read16(data + 8);
    out->arcount = read16(data + 10);

    size_t offset = DNS_HDR_LEN;

    /* Questions carry no RDATA, so there is no OPT to lift out of them. */
    for (uint16_t i = 0; i < out->qdcount; i++) {
        DnsRR scratch;
        DnsRR* rr = i < DNS_MAX_RECS
                  ? &out->questions[out->question_count] : &scratch;
        const uint8_t* rd = NULL;
        uint16_t rdlen = 0;
        int consumed = parse_rr(data, len, offset, rr, 1, &rd, &rdlen);
        if (consumed < 0) return -1;
        offset = (size_t)consumed;
        if (i < DNS_MAX_RECS)
            out->question_count++;
    }

    section = parse_section(data, len, offset, out, out->ancount,
                            out->answers, &out->answer_count, 0);
    if (section < 0) return -1;
    offset = (size_t)section;

    section = parse_section(data, len, offset, out, out->nscount,
                            out->authority, &out->authority_count, 0);
    if (section < 0) return -1;
    offset = (size_t)section;

    section = parse_section(data, len, offset, out, out->arcount,
                            out->additional, &out->additional_count, 1);
    if (section < 0) return -1;

    return 0;
}

/* ── dns_print ───────────────────────────────────────────────────────────── */

const char* dns_rcode_name(uint16_t rcode) {
    switch (rcode) {
        case 0:  return "NOERROR";
        case 1:  return "FORMERR";
        case 2:  return "SERVFAIL";
        case 3:  return "NXDOMAIN";
        case 4:  return "NOTIMP";
        case 5:  return "REFUSED";
        case 6:  return "YXDOMAIN";
        case 7:  return "YXRRSET";
        case 8:  return "NXRRSET";
        case 9:  return "NOTAUTH";
        case 10: return "NOTZONE";
        case 11: return "DSOTYPENI";
        /* Everything from here up needs the OPT record's extra eight bits. */
        case 16: return "BADVERS";
        case 17: return "BADKEY";
        case 18: return "BADTIME";
        case 19: return "BADMODE";
        case 20: return "BADNAME";
        case 21: return "BADALG";
        case 22: return "BADTRUNC";
        case 23: return "BADCOOKIE";
        default: return "UNKNOWN";
    }
}

const char* dns_type_name(uint16_t type) {
    switch (type) {
        case DNS_TYPE_A:          return "A";
        case DNS_TYPE_NS:         return "NS";
        case DNS_TYPE_SOA:        return "SOA";
        case DNS_TYPE_CNAME:      return "CNAME";
        case DNS_TYPE_PTR:        return "PTR";
        case DNS_TYPE_MX:         return "MX";
        case DNS_TYPE_TXT:        return "TXT";
        case DNS_TYPE_AAAA:       return "AAAA";
        case DNS_TYPE_SRV:        return "SRV";
        case DNS_TYPE_OPT:        return "OPT";
        case DNS_TYPE_DS:         return "DS";
        case DNS_TYPE_RRSIG:      return "RRSIG";
        case DNS_TYPE_NSEC:       return "NSEC";
        case DNS_TYPE_DNSKEY:     return "DNSKEY";
        case DNS_TYPE_NSEC3:      return "NSEC3";
        case DNS_TYPE_NSEC3PARAM: return "NSEC3PARAM";
        case 255:                 return "ANY";
        default:                  return NULL;
    }
}

static void print_rr(const DnsRR* rr, int show_ttl) {
    char type_buf[12];
    const char* tname = type_text(rr->type, type_buf, sizeof(type_buf));

    if (show_ttl)
        printf("|    %-32s  %-6s  TTL=%-6u  %s\n",
               rr->name, tname, rr->ttl,
               rr->rdata[0] ? rr->rdata : "(no rdata)");
    else
        printf("|    %-32s  %s\n", rr->name, tname);
}

static const char* edns_option_name(uint16_t code) {
    switch (code) {
        case DNS_EDNS_NSID:           return "NSID";
        case 5:                       return "DAU";
        case 6:                       return "DHU";
        case 7:                       return "N3U";
        case DNS_EDNS_CLIENT_SUBNET:  return "Client Subnet";
        case DNS_EDNS_EXPIRE:         return "EXPIRE";
        case DNS_EDNS_COOKIE:         return "Cookie";
        case DNS_EDNS_TCP_KEEPALIVE:  return "TCP Keepalive";
        case DNS_EDNS_PADDING:        return "Padding";
        case 13:                      return "CHAIN";
        case 14:                      return "Key Tag";
        case DNS_EDNS_ERROR:          return "Extended Error";
        default:                      return "unassigned";
    }
}

static void print_edns(const DnsEdns* edns) {
    int i;

    printf("|  -- EDNS0 (RFC 6891) --\n");
    printf("|    UDP size : %u  version=%u  flags=0x%04x%s\n",
           edns->udp_payload_size, edns->version, edns->flags,
           edns->dnssec_ok ? "  [DO]" : "");

    /* RFC 6891 §6.2.5: a requestor advertising less than 512 has asked for
       something the protocol does not allow, so say so rather than repeat it. */
    if (edns->udp_payload_size < 512)
        printf("|    [edns] advertised UDP size below the 512-byte minimum\n");
    if (edns->version != 0)
        printf("|    [edns] version %u is not one we know (0 is the only one "
               "defined)\n", edns->version);

    if (edns->problems & DNS_EDNS_DUPLICATE)
        printf("|    [edns] more than one OPT record — only the first is shown\n");
    if (edns->problems & DNS_EDNS_MISPLACED)
        printf("|    [edns] OPT outside the additional section\n");
    if (edns->problems & DNS_EDNS_BAD_OWNER)
        printf("|    [edns] OPT owner name is not the root\n");
    if (edns->problems & DNS_EDNS_BAD_OPTION)
        printf("|    [edns] an option ran past the end of the RDATA\n");
    if (edns->problems & DNS_EDNS_OPTS_FULL)
        printf("|    [edns] more than %d options — the rest are not shown\n",
               DNS_EDNS_MAX_OPTS);

    for (i = 0; i < edns->option_count; i++) {
        const DnsEdnsOption* opt = &edns->options[i];
        printf("|    option %-5u %-14s  %s\n",
               opt->code, edns_option_name(opt->code), opt->text);
    }
}

void dns_print(const DnsMessage* msg) {
    int is_response = (msg->flags & DNS_QR) != 0;
    uint8_t opcode  = (uint8_t)((msg->flags >> 11) & 0xF);
    uint16_t rcode  = dns_full_rcode(msg);

    printf("+-- DNS (%s) -----------------------------------------+\n",
           is_response ? "response" : "query");
    printf("|  ID        : 0x%04x\n", msg->id);
    printf("|  Flags     : 0x%04x  [%s%s%s%s%s%s%s]  RCODE=%u (%s)\n",
           msg->flags,
           opcode == 0 ? "QUERY" : opcode == 1 ? "IQUERY" : "UNKNOWN",
           (msg->flags & DNS_AA) ? " AA" : "",
           (msg->flags & DNS_TC) ? " TC" : "",
           (msg->flags & DNS_RD) ? " RD" : "",
           (msg->flags & DNS_RA) ? " RA" : "",
           (msg->flags & DNS_AD) ? " AD" : "",
           (msg->flags & DNS_CD) ? " CD" : "",
           rcode, dns_rcode_name(rcode));
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
    if (msg->edns.present)
        print_edns(&msg->edns);
    printf("+------------------------------------------------------------+\n");
}
