#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "dns.h"

static void write16(uint8_t* p, uint16_t value) {
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)(value & 0xff);
}

static void write32(uint8_t* p, uint32_t value) {
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)((value >> 16) & 0xff);
    p[2] = (uint8_t)((value >> 8) & 0xff);
    p[3] = (uint8_t)(value & 0xff);
}

static void test_parses_authority_and_additional_records(void) {
    static const uint8_t message[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x01, 0x00, 0x01,
        0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',
        0x03, 'c',  'o',  'm',  0x00, 0x00, 0x01, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x01, 0x2c, 0x00, 0x04, 0xc0, 0x00, 0x02, 0x01,
        0xc0, 0x0c, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00,
        0x01, 0x2c, 0x00, 0x06, 0x03, 'n',  's',  '1',  0xc0, 0x0c,
        0x03, 'n',  's',  '1',  0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0xc0, 0x00, 0x02, 0x35,
    };
    DnsMessage dns;

    assert(dns_parse(message, sizeof(message), &dns) == 0);
    assert(dns.id == 0x1234);
    assert(dns.qdcount == 1);
    assert(dns.ancount == 1);
    assert(dns.nscount == 1);
    assert(dns.arcount == 1);

    assert(dns.question_count == 1);
    assert(strcmp(dns.questions[0].name, "example.com") == 0);
    assert(dns.questions[0].type == DNS_TYPE_A);

    assert(dns.answer_count == 1);
    assert(strcmp(dns.answers[0].name, "example.com") == 0);
    assert(strcmp(dns.answers[0].rdata, "192.0.2.1") == 0);

    assert(dns.authority_count == 1);
    assert(dns.authority[0].type == DNS_TYPE_NS);
    assert(strcmp(dns.authority[0].rdata, "ns1.example.com") == 0);

    assert(dns.additional_count == 1);
    assert(strcmp(dns.additional[0].name, "ns1.example.com") == 0);
    assert(dns.additional[0].type == DNS_TYPE_A);
    assert(strcmp(dns.additional[0].rdata, "192.0.2.53") == 0);
}

static void test_rejects_truncated_additional_record(void) {
    static const uint8_t message[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x01, 0x00,
    };
    DnsMessage dns;

    assert(dns_parse(message, sizeof(message), &dns) == -1);
}

static void test_skips_records_beyond_storage_limit(void) {
    uint8_t message[12 + ((DNS_MAX_RECS + 1) * 5) + 15];
    size_t offset = 0;
    DnsMessage dns;

    memset(message, 0, sizeof(message));
    write16(message + 0, 0x2222);
    write16(message + 2, 0x8180);
    write16(message + 4, DNS_MAX_RECS + 1);
    write16(message + 6, 1);
    offset = 12;

    for (int i = 0; i < DNS_MAX_RECS + 1; i++) {
        message[offset++] = 0; /* root label */
        write16(message + offset, DNS_TYPE_A); offset += 2;
        write16(message + offset, 1); offset += 2;
    }

    message[offset++] = 0; /* root label */
    write16(message + offset, DNS_TYPE_A); offset += 2;
    write16(message + offset, 1); offset += 2;
    write32(message + offset, 60); offset += 4;
    write16(message + offset, 4); offset += 2;
    message[offset++] = 203;
    message[offset++] = 0;
    message[offset++] = 113;
    message[offset++] = 9;

    assert(offset == sizeof(message));
    assert(dns_parse(message, sizeof(message), &dns) == 0);
    assert(dns.question_count == DNS_MAX_RECS);
    assert(dns.answer_count == 1);
    assert(strcmp(dns.answers[0].rdata, "203.0.113.9") == 0);
}

/* ── a small message builder, so the EDNS0/DNSSEC cases stay readable ────── */

typedef struct {
    uint8_t buf[512];
    size_t  len;
} Builder;

static void put8(Builder* b, uint8_t v) {
    assert(b->len + 1 <= sizeof(b->buf));
    b->buf[b->len++] = v;
}

static void put16(Builder* b, uint16_t v) {
    assert(b->len + 2 <= sizeof(b->buf));
    write16(b->buf + b->len, v);
    b->len += 2;
}

static void put32(Builder* b, uint32_t v) {
    assert(b->len + 4 <= sizeof(b->buf));
    write32(b->buf + b->len, v);
    b->len += 4;
}

static void putn(Builder* b, const void* p, size_t n) {
    assert(b->len + n <= sizeof(b->buf));
    memcpy(b->buf + b->len, p, n);
    b->len += n;
}

static void header(Builder* b, uint16_t flags, uint16_t qd, uint16_t an,
                   uint16_t ns, uint16_t ar) {
    b->len = 0;
    put16(b, 0x1234);
    put16(b, flags);
    put16(b, qd);
    put16(b, an);
    put16(b, ns);
    put16(b, ar);
}

/* Reserve the RDLENGTH field; end_rdata patches in what was actually written. */
static size_t begin_rdata(Builder* b) {
    size_t at = b->len;
    put16(b, 0);
    return at;
}

static void end_rdata(Builder* b, size_t at) {
    write16(b->buf + at, (uint16_t)(b->len - at - 2));
}

/* An OPT record: root owner, class = UDP payload size, TTL = flags. */
static size_t begin_opt(Builder* b, uint16_t udp_size, uint8_t rcode_high,
                        uint8_t version, uint16_t opt_flags) {
    put8(b, 0);                    /* root owner name */
    put16(b, DNS_TYPE_OPT);
    put16(b, udp_size);
    put32(b, ((uint32_t)rcode_high << 24) | ((uint32_t)version << 16)
             | opt_flags);
    return begin_rdata(b);
}

/* ── EDNS0 ───────────────────────────────────────────────────────────────── */

static void test_opt_is_hoisted_out_of_the_additional_section(void) {
    Builder b;
    DnsMessage dns;
    size_t rd;

    /* One ordinary A record, then the OPT. arcount counts both. */
    header(&b, 0x8180, 0, 0, 0, 2);
    put8(&b, 0);
    put16(&b, DNS_TYPE_A);
    put16(&b, 1);
    put32(&b, 60);
    rd = begin_rdata(&b);
    put8(&b, 192); put8(&b, 0); put8(&b, 2); put8(&b, 1);
    end_rdata(&b, rd);

    rd = begin_opt(&b, 1232, 0, 0, 0x8000);   /* DO set */
    end_rdata(&b, rd);

    assert(dns_parse(b.buf, b.len, &dns) == 0);
    assert(dns.arcount == 2);
    /* The OPT is not a record about a name, so it is not listed as one. */
    assert(dns.additional_count == 1);
    assert(strcmp(dns.additional[0].rdata, "192.0.2.1") == 0);

    assert(dns.edns.present);
    assert(dns.edns.problems == 0);
    assert(dns.edns.udp_payload_size == 1232);
    assert(dns.edns.version == 0);
    assert(dns.edns.dnssec_ok);
}

static void test_extended_rcode_combines_header_and_opt(void) {
    Builder b;
    DnsMessage dns;
    size_t rd;

    /* BADVERS is 16: the header's four bits are 0 and the OPT supplies 1 in
       the next eight. Reading only the header would report NOERROR. */
    header(&b, 0x8180, 0, 0, 0, 1);
    rd = begin_opt(&b, 4096, 1, 0, 0);
    end_rdata(&b, rd);

    assert(dns_parse(b.buf, b.len, &dns) == 0);
    assert((dns.flags & DNS_RCODE) == 0);
    assert(dns.edns.rcode_high == 1);
    assert(dns_full_rcode(&dns) == 16);
    assert(strcmp(dns_rcode_name(dns_full_rcode(&dns)), "BADVERS") == 0);
}

static void test_rcode_without_opt_is_the_header_nibble(void) {
    Builder b;
    DnsMessage dns;

    header(&b, 0x8183, 0, 0, 0, 0);   /* NXDOMAIN */
    assert(dns_parse(b.buf, b.len, &dns) == 0);
    assert(!dns.edns.present);
    assert(dns_full_rcode(&dns) == 3);
    assert(strcmp(dns_rcode_name(dns_full_rcode(&dns)), "NXDOMAIN") == 0);
}

static void test_second_opt_record_is_reported(void) {
    Builder b;
    DnsMessage dns;
    size_t rd;

    header(&b, 0x8180, 0, 0, 0, 2);
    rd = begin_opt(&b, 1232, 0, 0, 0);
    end_rdata(&b, rd);
    rd = begin_opt(&b, 512, 0, 0, 0);
    end_rdata(&b, rd);

    assert(dns_parse(b.buf, b.len, &dns) == 0);
    assert(dns.edns.present);
    assert(dns.edns.problems & DNS_EDNS_DUPLICATE);
    /* The first one still stands; the second must not overwrite it. */
    assert(dns.edns.udp_payload_size == 1232);
}

static void test_opt_outside_the_additional_section_is_reported(void) {
    Builder b;
    DnsMessage dns;
    size_t rd;

    header(&b, 0x8180, 0, 1, 0, 0);
    rd = begin_opt(&b, 1232, 0, 0, 0);
    end_rdata(&b, rd);

    assert(dns_parse(b.buf, b.len, &dns) == 0);
    assert(dns.edns.present);
    assert(dns.edns.problems & DNS_EDNS_MISPLACED);
    assert(dns.answer_count == 0);
}

static void test_option_running_past_the_rdata_is_reported(void) {
    Builder b;
    DnsMessage dns;
    size_t rd;

    header(&b, 0x8180, 0, 0, 0, 1);
    rd = begin_opt(&b, 1232, 0, 0, 0);
    put16(&b, DNS_EDNS_COOKIE);
    put16(&b, 64);            /* claims 64 bytes */
    put8(&b, 0xaa);           /* supplies one */
    end_rdata(&b, rd);

    /* The rest of the message stays readable; only the OPT is suspect. */
    assert(dns_parse(b.buf, b.len, &dns) == 0);
    assert(dns.edns.present);
    assert(dns.edns.problems & DNS_EDNS_BAD_OPTION);
    assert(dns.edns.option_count == 0);
}

static void test_client_subnet_is_decoded(void) {
    Builder b;
    DnsMessage dns;
    size_t rd;

    header(&b, 0x0100, 0, 0, 0, 1);
    rd = begin_opt(&b, 1232, 0, 0, 0);
    put16(&b, DNS_EDNS_CLIENT_SUBNET);
    put16(&b, 7);
    put16(&b, 1);             /* family: IPv4     */
    put8(&b, 24);             /* source prefix    */
    put8(&b, 0);              /* scope prefix     */
    put8(&b, 192); put8(&b, 0); put8(&b, 2);
    end_rdata(&b, rd);

    assert(dns_parse(b.buf, b.len, &dns) == 0);
    assert(dns.edns.option_count == 1);
    assert(dns.edns.options[0].code == DNS_EDNS_CLIENT_SUBNET);
    assert(strcmp(dns.edns.options[0].text, "192.0.2.0/24 scope /0") == 0);
}

static void test_client_subnet_prefix_longer_than_the_family(void) {
    Builder b;
    DnsMessage dns;
    size_t rd;

    /* A source prefix of 255 bits describes 32 octets of IPv4 address. The
       option carries three. Neither number may be allowed to drive a copy. */
    header(&b, 0x0100, 0, 0, 0, 1);
    rd = begin_opt(&b, 1232, 0, 0, 0);
    put16(&b, DNS_EDNS_CLIENT_SUBNET);
    put16(&b, 7);
    put16(&b, 1);
    put8(&b, 255);
    put8(&b, 0);
    put8(&b, 192); put8(&b, 0); put8(&b, 2);
    end_rdata(&b, rd);

    assert(dns_parse(b.buf, b.len, &dns) == 0);
    assert(dns.edns.option_count == 1);
    assert(strstr(dns.edns.options[0].text, "does not fit") != NULL);
}

static void test_extended_error_carries_its_text(void) {
    Builder b;
    DnsMessage dns;
    static const char extra[] = "no SEP matching the DS found";
    size_t rd;

    header(&b, 0x8182, 0, 0, 0, 1);
    rd = begin_opt(&b, 1232, 0, 0, 0);
    put16(&b, DNS_EDNS_ERROR);
    put16(&b, (uint16_t)(2 + sizeof(extra) - 1));
    put16(&b, 6);                              /* DNSSEC Bogus */
    putn(&b, extra, sizeof(extra) - 1);        /* not NUL-terminated on the wire */
    end_rdata(&b, rd);

    assert(dns_parse(b.buf, b.len, &dns) == 0);
    assert(dns.edns.option_count == 1);
    assert(strstr(dns.edns.options[0].text, "DNSSEC Bogus") != NULL);
    assert(strstr(dns.edns.options[0].text, "no SEP matching") != NULL);
}

/* ── DNSSEC ──────────────────────────────────────────────────────────────── */

static void test_dnskey_key_tag_matches_rfc_4034_appendix_b(void) {
    /* flags=0x0100 (ZONE) protocol=3 algorithm=8, then four key bytes.
       Summed as big-endian 16-bit words with the carry folded back in. */
    static const uint8_t rdata[] = {
        0x01, 0x00, 0x03, 0x08, 0xab, 0xcd, 0xef, 0x01
    };
    assert(dns_dnskey_key_tag(rdata, sizeof(rdata)) == 0x9ed7);
    /* Empty RDATA must not read anything. */
    assert(dns_dnskey_key_tag(rdata, 0) == 0);
}

static void test_dnskey_record_reports_tag_and_flags(void) {
    Builder b;
    DnsMessage dns;
    size_t rd;

    header(&b, 0x8180, 0, 1, 0, 0);
    put8(&b, 0);
    put16(&b, DNS_TYPE_DNSKEY);
    put16(&b, 1);
    put32(&b, 3600);
    rd = begin_rdata(&b);
    put16(&b, DNS_DNSKEY_ZONE | DNS_DNSKEY_SEP);
    put8(&b, 3);
    put8(&b, 8);
    put8(&b, 0xab); put8(&b, 0xcd); put8(&b, 0xef); put8(&b, 0x01);
    end_rdata(&b, rd);

    assert(dns_parse(b.buf, b.len, &dns) == 0);
    assert(dns.answer_count == 1);
    assert(dns.answers[0].type == DNS_TYPE_DNSKEY);
    assert(strstr(dns.answers[0].rdata, "ZONE") != NULL);
    assert(strstr(dns.answers[0].rdata, "SEP") != NULL);
    assert(strstr(dns.answers[0].rdata, "RSASHA256") != NULL);
}

static void test_rrsig_timestamps_survive_2038(void) {
    Builder b;
    DnsMessage dns;
    size_t rd;

    header(&b, 0x8180, 0, 1, 0, 0);
    put8(&b, 0);
    put16(&b, DNS_TYPE_RRSIG);
    put16(&b, 1);
    put32(&b, 3600);
    rd = begin_rdata(&b);
    put16(&b, DNS_TYPE_A);        /* type covered   */
    put8(&b, 8);                  /* algorithm      */
    put8(&b, 2);                  /* labels         */
    put32(&b, 3600);              /* original TTL   */
    put32(&b, 4102444800u);       /* expires 2100-01-01, past a 32-bit time_t */
    put32(&b, 0);                 /* inception at the epoch */
    put16(&b, 0x9ed7);            /* key tag        */
    put8(&b, 0);                  /* signer: root, uncompressed */
    put8(&b, 0xde); put8(&b, 0xad);
    end_rdata(&b, rd);

    assert(dns_parse(b.buf, b.len, &dns) == 0);
    assert(dns.answer_count == 1);
    assert(strstr(dns.answers[0].rdata, "19700101000000..21000101000000")
           != NULL);
    assert(strstr(dns.answers[0].rdata, "keytag=40663") != NULL);
}

static void test_rrsig_signer_must_fit_inside_its_rdata(void) {
    Builder b;
    DnsMessage dns;

    /* RDLENGTH covers the fixed 18 bytes and nothing else, but a signer name
       follows. Believing the name over the length would read past the record. */
    header(&b, 0x8180, 0, 1, 0, 0);
    put8(&b, 0);
    put16(&b, DNS_TYPE_RRSIG);
    put16(&b, 1);
    put32(&b, 3600);
    put16(&b, 18);
    put16(&b, DNS_TYPE_A);
    put8(&b, 8); put8(&b, 2);
    put32(&b, 3600); put32(&b, 0); put32(&b, 0);
    put16(&b, 1);
    put8(&b, 3); putn(&b, "com", 3); put8(&b, 0);   /* beyond RDLENGTH */

    assert(dns_parse(b.buf, b.len, &dns) == 0);
    assert(dns.answer_count == 1);
    assert(dns.answers[0].rdata[0] == '\0');
}

static void test_nsec_lists_the_types_in_its_bitmap(void) {
    Builder b;
    DnsMessage dns;
    size_t rd;

    header(&b, 0x8180, 0, 1, 0, 0);
    put8(&b, 0);
    put16(&b, DNS_TYPE_NSEC);
    put16(&b, 1);
    put32(&b, 3600);
    rd = begin_rdata(&b);
    put8(&b, 4); putn(&b, "next", 4); put8(&b, 0);   /* next domain name */
    put8(&b, 0);                                     /* window 0          */
    put8(&b, 6);                                     /* bitmap length     */
    /* A (1) and NS (2) in the first octet; RRSIG (46) and NSEC (47) in the
       sixth. */
    put8(&b, 0x60); put8(&b, 0); put8(&b, 0);
    put8(&b, 0);    put8(&b, 0); put8(&b, 0x03);
    end_rdata(&b, rd);

    assert(dns_parse(b.buf, b.len, &dns) == 0);
    assert(strcmp(dns.answers[0].rdata, "next A NS RRSIG NSEC") == 0);
}

static void test_nsec_bitmap_length_is_bounded(void) {
    Builder b;
    DnsMessage dns;
    size_t rd;

    /* RFC 4034 §4.1.2 caps a window's bitmap at 32 octets. A block claiming
       33 puts the next window's position beyond anything we can trust. */
    header(&b, 0x8180, 0, 1, 0, 0);
    put8(&b, 0);
    put16(&b, DNS_TYPE_NSEC);
    put16(&b, 1);
    put32(&b, 3600);
    rd = begin_rdata(&b);
    put8(&b, 0);              /* root next-domain name */
    put8(&b, 0);              /* window 0              */
    put8(&b, 33);             /* over the limit        */
    put8(&b, 0x40);
    end_rdata(&b, rd);

    assert(dns_parse(b.buf, b.len, &dns) == 0);
    assert(strstr(dns.answers[0].rdata, "malformed bitmap") != NULL);
}

static void test_nsec3_lengths_are_checked_before_use(void) {
    Builder b;
    DnsMessage dns;
    size_t rd;

    /* A salt length of 200 inside a record carrying six bytes of RDATA. */
    header(&b, 0x8180, 0, 1, 0, 0);
    put8(&b, 0);
    put16(&b, DNS_TYPE_NSEC3);
    put16(&b, 1);
    put32(&b, 3600);
    rd = begin_rdata(&b);
    put8(&b, 1);              /* hash algorithm  */
    put8(&b, 1);              /* flags: opt-out  */
    put16(&b, 10);            /* iterations      */
    put8(&b, 200);            /* salt length     */
    put8(&b, 0xaa);
    end_rdata(&b, rd);

    assert(dns_parse(b.buf, b.len, &dns) == 0);
    assert(dns.answers[0].rdata[0] == '\0');
}

static void test_nsec3_well_formed(void) {
    Builder b;
    DnsMessage dns;
    size_t rd;

    header(&b, 0x8180, 0, 1, 0, 0);
    put8(&b, 0);
    put16(&b, DNS_TYPE_NSEC3);
    put16(&b, 1);
    put32(&b, 3600);
    rd = begin_rdata(&b);
    put8(&b, 1);                          /* SHA-1          */
    put8(&b, 1);                          /* opt-out        */
    put16(&b, 12);                        /* iterations     */
    put8(&b, 2); put8(&b, 0xaa); put8(&b, 0xbb);        /* salt */
    put8(&b, 4); put32(&b, 0x11223344);                 /* next hashed owner */
    put8(&b, 0); put8(&b, 1); put8(&b, 0x40);           /* bitmap: A */
    end_rdata(&b, rd);

    assert(dns_parse(b.buf, b.len, &dns) == 0);
    assert(strstr(dns.answers[0].rdata, "OPTOUT") != NULL);
    assert(strstr(dns.answers[0].rdata, "salt=aabb") != NULL);
    assert(strstr(dns.answers[0].rdata, "next=11223344") != NULL);
    assert(strstr(dns.answers[0].rdata, " A") != NULL);
}

static void test_ds_record_names_its_algorithms(void) {
    Builder b;
    DnsMessage dns;
    size_t rd;

    header(&b, 0x8180, 0, 0, 1, 0);
    put8(&b, 0);
    put16(&b, DNS_TYPE_DS);
    put16(&b, 1);
    put32(&b, 3600);
    rd = begin_rdata(&b);
    put16(&b, 40663);         /* key tag      */
    put8(&b, 8);              /* RSASHA256    */
    put8(&b, 2);              /* SHA-256      */
    put32(&b, 0xdeadbeef);
    end_rdata(&b, rd);

    assert(dns_parse(b.buf, b.len, &dns) == 0);
    assert(dns.authority_count == 1);
    assert(strstr(dns.authority[0].rdata, "keytag=40663") != NULL);
    assert(strstr(dns.authority[0].rdata, "RSASHA256") != NULL);
    assert(strstr(dns.authority[0].rdata, "SHA-256") != NULL);
    assert(strstr(dns.authority[0].rdata, "deadbeef") != NULL);
}

static void test_unassigned_type_uses_rfc_3597_presentation(void) {
    assert(dns_type_name(65280) == NULL);
    assert(strcmp(dns_type_name(DNS_TYPE_NSEC3PARAM), "NSEC3PARAM") == 0);
}

int main(void) {
    test_parses_authority_and_additional_records();
    test_rejects_truncated_additional_record();
    test_skips_records_beyond_storage_limit();

    test_opt_is_hoisted_out_of_the_additional_section();
    test_extended_rcode_combines_header_and_opt();
    test_rcode_without_opt_is_the_header_nibble();
    test_second_opt_record_is_reported();
    test_opt_outside_the_additional_section_is_reported();
    test_option_running_past_the_rdata_is_reported();
    test_client_subnet_is_decoded();
    test_client_subnet_prefix_longer_than_the_family();
    test_extended_error_carries_its_text();

    test_dnskey_key_tag_matches_rfc_4034_appendix_b();
    test_dnskey_record_reports_tag_and_flags();
    test_rrsig_timestamps_survive_2038();
    test_rrsig_signer_must_fit_inside_its_rdata();
    test_nsec_lists_the_types_in_its_bitmap();
    test_nsec_bitmap_length_is_bounded();
    test_nsec3_lengths_are_checked_before_use();
    test_nsec3_well_formed();
    test_ds_record_names_its_algorithms();
    test_unassigned_type_uses_rfc_3597_presentation();

    printf("dns_parse tests passed\n");
    return 0;
}
