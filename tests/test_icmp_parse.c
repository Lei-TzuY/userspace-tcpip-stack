#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "icmp.h"

static void init_error_quote(uint8_t* message, uint8_t version_ihl) {
    uint8_t* inner;

    memset(message, 0, 36);
    message[0] = ICMP_TYPE_UNREACH;
    message[1] = ICMP_UNREACH_PORT;
    inner = message + ICMP_MIN_LEN;
    inner[0] = version_ihl;
    inner[9] = 17; /* UDP */
    inner[12] = 192;
    inner[13] = 0;
    inner[14] = 2;
    inner[15] = 1;
    inner[16] = 198;
    inner[17] = 51;
    inner[18] = 100;
    inner[19] = 2;
    inner[20] = 0x12;
    inner[21] = 0x34;
    inner[22] = 0x00;
    inner[23] = 0x35;
}

static void test_decodes_quoted_ipv4_transport(void) {
    uint8_t message[36];
    IcmpHeader header;

    init_error_quote(message, 0x45);
    assert(icmp_parse(message, sizeof(message), &header) == 0);
    assert(header.has_embedded);
    assert(header.embedded_proto == 17);
    assert(header.embedded_src_port == 0x1234);
    assert(header.embedded_dst_port == 53);
}

static void test_rejects_non_ipv4_error_quote(void) {
    uint8_t message[36];
    IcmpHeader header;

    /* The low nibble still claims a 20-byte header; only the version differs. */
    init_error_quote(message, 0x65);
    assert(icmp_parse(message, sizeof(message), &header) == 0);
    assert(!header.has_embedded);
}

int main(void) {
    test_decodes_quoted_ipv4_transport();
    test_rejects_non_ipv4_error_quote();
    printf("icmp_parse tests passed\n");
    return 0;
}
