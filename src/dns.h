#ifndef DNS_H
#define DNS_H

/*
 * dns.h — DNS message parser (RFC 1035).
 *
 * Parses the DNS wire format carried in UDP (or TCP) port 53 payloads.
 * Supports:
 *   - Header fields (ID, QR, opcode, flags, RCODE)
 *   - Question section: QNAME, QTYPE, QCLASS
 *   - Answer/Authority/Additional resource records:
 *       A (1), NS (2), CNAME (5), PTR (12), MX (15), AAAA (28), TXT (16)
 *   - Message compression pointers (RFC 1035 §4.1.4)
 *
 * The parser stores decoded records as printable strings to keep the struct
 * self-contained (no external allocations needed).
 */

#include "common.h"

#define DNS_HDR_LEN      12
#define DNS_MAX_NAME    256      /* encoded label sequence, decoded */
#define DNS_MAX_RECS     16      /* questions + RRs shown per section */

/* ── RR types ───────────────────────────────────────────────────────────── */
#define DNS_TYPE_A      1
#define DNS_TYPE_NS     2
#define DNS_TYPE_CNAME  5
#define DNS_TYPE_PTR    12
#define DNS_TYPE_SOA    6
#define DNS_TYPE_MX     15
#define DNS_TYPE_TXT    16
#define DNS_TYPE_AAAA   28
#define DNS_TYPE_SRV    33

/* ── Flags bits ─────────────────────────────────────────────────────────── */
#define DNS_QR      0x8000u   /* 1 = response */
#define DNS_AA      0x0400u   /* authoritative answer */
#define DNS_TC      0x0200u   /* truncated */
#define DNS_RD      0x0100u   /* recursion desired */
#define DNS_RA      0x0080u   /* recursion available */
#define DNS_RCODE   0x000Fu   /* response code mask */

typedef struct {
    char name[DNS_MAX_NAME];
    uint16_t type;
    uint16_t class_;
    uint32_t ttl;
    char     rdata[DNS_MAX_NAME + 32];  /* decoded rdata as text */
} DnsRR;

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;

    /* Decoded question entries (up to DNS_MAX_RECS) */
    DnsRR    questions[DNS_MAX_RECS];
    int      question_count;

    /* Decoded answer entries (up to DNS_MAX_RECS) */
    DnsRR    answers[DNS_MAX_RECS];
    int      answer_count;

    /* Decoded authority entries (up to DNS_MAX_RECS) */
    DnsRR    authority[DNS_MAX_RECS];
    int      authority_count;

    /* Decoded additional entries (up to DNS_MAX_RECS) */
    DnsRR    additional[DNS_MAX_RECS];
    int      additional_count;
} DnsMessage;

/*
 * dns_parse — parse a DNS message from raw UDP/TCP payload bytes.
 * Returns 0 on success, -1 if truncated or malformed.
 */
int dns_parse(const uint8_t* data, size_t len, DnsMessage* out);

/*
 * dns_print — pretty-print a decoded DNS message to stdout.
 */
void dns_print(const DnsMessage* msg);

/*
 * dns_rcode_name — human-readable response code string.
 */
const char* dns_rcode_name(uint8_t rcode);

/*
 * dns_type_name — human-readable RR type name or NULL.
 */
const char* dns_type_name(uint16_t type);

#endif /* DNS_H */
