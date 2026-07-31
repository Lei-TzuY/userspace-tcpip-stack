#ifndef DNS_H
#define DNS_H

/*
 * dns.h — DNS message parser (RFC 1035, 4034, 6891)
 *
 * Parses the DNS wire format carried in UDP (or TCP) port 53 payloads.
 * Supports:
 *   - Header fields (ID, QR, opcode, flags, RCODE)
 *   - Question section: QNAME, QTYPE, QCLASS
 *   - Answer/Authority/Additional resource records:
 *       A (1), NS (2), CNAME (5), PTR (12), MX (15), AAAA (28), TXT (16),
 *       SOA (6), SRV (33)
 *   - DNSSEC records, reported structurally and never validated:
 *       DS (43), RRSIG (46), NSEC (47), DNSKEY (48), NSEC3 (50),
 *       NSEC3PARAM (51)
 *   - EDNS0 (RFC 6891): the OPT pseudo-record, hoisted out of the additional
 *     section into DnsMessage.edns
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

/* ── EDNS0 and DNSSEC RR types ──────────────────────────────────────────── */
#define DNS_TYPE_OPT        41   /* pseudo-record; see DnsEdns below */
#define DNS_TYPE_DS         43
#define DNS_TYPE_RRSIG      46
#define DNS_TYPE_NSEC       47
#define DNS_TYPE_DNSKEY     48
#define DNS_TYPE_NSEC3      50
#define DNS_TYPE_NSEC3PARAM 51

/* ── Flags bits ─────────────────────────────────────────────────────────── */
#define DNS_QR      0x8000u   /* 1 = response */
#define DNS_AA      0x0400u   /* authoritative answer */
#define DNS_TC      0x0200u   /* truncated */
#define DNS_RD      0x0100u   /* recursion desired */
#define DNS_RA      0x0080u   /* recursion available */
#define DNS_AD      0x0020u   /* authentic data (RFC 4035 §3.2.3) */
#define DNS_CD      0x0010u   /* checking disabled (RFC 4035 §3.2.2) */
#define DNS_RCODE   0x000Fu   /* low 4 bits of the response code */

/* ── DNSKEY flags (RFC 4034 §2.1.1) ─────────────────────────────────────── */
#define DNS_DNSKEY_ZONE  0x0100u   /* the key signs a zone            */
#define DNS_DNSKEY_SEP   0x0001u   /* secure entry point (a KSK)      */
#define DNS_DNSKEY_REVOKE 0x0080u  /* revoked (RFC 5011 §2.1)         */

/* ── EDNS0 ──────────────────────────────────────────────────────────────── */

#define DNS_EDNS_MAX_OPTS   8
#define DNS_EDNS_OPT_TEXT  96

/* EDNS option codes we name (IANA "DNS EDNS0 Option Codes"). */
#define DNS_EDNS_NSID        3
#define DNS_EDNS_CLIENT_SUBNET 8
#define DNS_EDNS_EXPIRE      9
#define DNS_EDNS_COOKIE     10
#define DNS_EDNS_TCP_KEEPALIVE 11
#define DNS_EDNS_PADDING    12
#define DNS_EDNS_ERROR      15   /* Extended DNS Errors, RFC 8914 */

/*
 * Things wrong with the OPT record. These are recorded rather than made fatal:
 * a malformed OPT does not stop the rest of the message from being readable,
 * and saying which rule was broken is more useful than dropping the packet.
 */
#define DNS_EDNS_DUPLICATE   0x01u  /* more than one OPT (RFC 6891 §6.1.1) */
#define DNS_EDNS_MISPLACED   0x02u  /* OPT outside the additional section  */
#define DNS_EDNS_BAD_OWNER   0x04u  /* owner name is not the root          */
#define DNS_EDNS_BAD_OPTION  0x08u  /* an option ran past the RDATA        */
#define DNS_EDNS_OPTS_FULL   0x10u  /* more options than we keep           */

typedef struct {
    uint16_t code;
    uint16_t length;                  /* length the sender declared */
    char     text[DNS_EDNS_OPT_TEXT]; /* decoded, or a byte count */
} DnsEdnsOption;

/*
 * The OPT record is not a resource record about a name — it carries transport
 * parameters for this one message, with its class field reused as a UDP
 * payload size and its TTL field reused as flags. Printing it as an ordinary
 * additional-section RR (owner ".", "TTL=32768") actively misleads, so it is
 * lifted out here instead.
 */
typedef struct {
    int      present;
    uint8_t  problems;          /* DNS_EDNS_* bits above; 0 when well-formed */
    uint16_t udp_payload_size;  /* OPT class field (RFC 6891 §6.1.2)         */
    uint8_t  version;           /* 0 is the only version defined             */
    uint8_t  rcode_high;        /* upper 8 bits of the 12-bit RCODE          */
    uint16_t flags;             /* OPT TTL low half                          */
    int      dnssec_ok;         /* the DO bit (RFC 3225)                     */
    DnsEdnsOption options[DNS_EDNS_MAX_OPTS];
    int      option_count;
} DnsEdns;

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

    /*
     * Decoded additional entries (up to DNS_MAX_RECS). The OPT record, if any,
     * is not stored here — see edns.
     */
    DnsRR    additional[DNS_MAX_RECS];
    int      additional_count;

    DnsEdns  edns;
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
 * dns_full_rcode — the complete response code.
 *
 * Without EDNS0 the RCODE is the header's low 4 bits. An OPT record supplies
 * eight more significant bits in its TTL field, extending the space to 12 bits
 * (RFC 6891 §6.1.3) — which is the only way BADVERS (16) or BADCOOKIE (23) can
 * be expressed at all. Reading just the header would report those as 0
 * (NOERROR) and 7 (YXRRSET) respectively.
 */
uint16_t dns_full_rcode(const DnsMessage* msg);

/*
 * dns_rcode_name — human-readable response code string. Takes the full 12-bit
 * code from dns_full_rcode(), not the header nibble.
 */
const char* dns_rcode_name(uint16_t rcode);

/*
 * dns_type_name — human-readable RR type name or NULL.
 */
const char* dns_type_name(uint16_t type);

/*
 * dns_algorithm_name — DNSSEC algorithm number to name (RFC 8624 §3.1),
 * or NULL when unassigned.
 */
const char* dns_algorithm_name(uint8_t algorithm);

/*
 * dns_dnskey_key_tag — the key tag of a DNSKEY, computed over its RDATA
 * (RFC 4034 Appendix B). This is what lets a DNSKEY be matched to the DS and
 * RRSIG records that reference it, so it is worth computing even though
 * nothing here validates a signature.
 */
uint16_t dns_dnskey_key_tag(const uint8_t* rdata, size_t rdlength);

#endif /* DNS_H */
