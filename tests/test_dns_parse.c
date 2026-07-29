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

int main(void) {
    test_parses_authority_and_additional_records();
    test_rejects_truncated_additional_record();
    test_skips_records_beyond_storage_limit();
    printf("dns_parse tests passed\n");
    return 0;
}
