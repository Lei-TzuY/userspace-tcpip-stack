#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "tcp.h"

static void init_segment(uint8_t* segment, size_t len) {
    memset(segment, 0, len);
    segment[0] = 0x12;
    segment[1] = 0x34;
    segment[2] = 0x00;
    segment[3] = 0x50;
    segment[12] = 0x60; /* 24-byte TCP header */
    segment[13] = TCP_SYN;
}

static void test_valid_mss_option(void) {
    uint8_t segment[24];
    TcpHeader header;
    init_segment(segment, sizeof(segment));
    segment[20] = TCP_OPT_MSS;
    segment[21] = 4;
    segment[22] = 0x05;
    segment[23] = 0xb4;

    assert(tcp_parse(segment, sizeof(segment), &header) == 0);
    assert(header.hdr_len == 24);
    assert(header.opt_count == 1);
    assert(header.options[0].kind == TCP_OPT_MSS);
    assert(header.options[0].data_len == 2);
    assert(header.options[0].data[0] == 0x05);
    assert(header.options[0].data[1] == 0xb4);
}

static void test_bad_option_length(void) {
    uint8_t segment[24];
    TcpHeader header;
    init_segment(segment, sizeof(segment));
    segment[20] = TCP_OPT_MSS;
    segment[21] = 1;

    assert(tcp_parse(segment, sizeof(segment), &header) == -1);
}

static void test_truncated_option_data(void) {
    uint8_t segment[24];
    TcpHeader header;
    init_segment(segment, sizeof(segment));
    segment[20] = TCP_OPT_MSS;
    segment[21] = 6;

    assert(tcp_parse(segment, sizeof(segment), &header) == -1);
}

static void test_max_length_option_fits(void) {
    /* 60-byte header: 20 fixed plus the full 40 bytes of option space, spent on
       a single option. Its data section is 38 bytes, the largest that can
       occur, and all of it has to be stored. */
    uint8_t segment[60];
    TcpHeader header;
    int i;

    init_segment(segment, sizeof(segment));
    segment[12] = 0x0F << 4;      /* data offset = 15 words = 60 bytes */
    segment[20] = TCP_OPT_SACK;
    segment[21] = 40;
    for (i = 0; i < 38; i++)
        segment[22 + i] = (uint8_t)(i + 1);

    assert(tcp_parse(segment, sizeof(segment), &header) == 0);
    assert(header.opt_count == 1);
    assert(header.options[0].data_len == TCP_OPT_MAX_DATA);
    assert(header.options[0].data[0] == 1);
    assert(header.options[0].data[37] == 38);
}

static void test_option_length_never_exceeds_storage(void) {
    /* An option declaring more data than the header can hold is truncated by
       the length check, so tcp_parse rejects it. The point of the assertion is
       the invariant that follows: whatever a caller is handed, data_len
       describes bytes that are really in data[]. */
    uint8_t segment[60];
    TcpHeader header;
    int i;

    init_segment(segment, sizeof(segment));
    segment[12] = 0x0F << 4;
    segment[20] = TCP_OPT_SACK;
    segment[21] = 0xFF;           /* claims 253 bytes of data */

    assert(tcp_parse(segment, sizeof(segment), &header) == -1);

    /* Now a header full of options that do fit, to confirm every stored
       data_len stays inside the array. A consumer looping to data_len must not
       be able to walk off the end. */
    init_segment(segment, sizeof(segment));
    segment[12] = 0x0F << 4;
    for (i = 0; i < 40; i += 4) {
        segment[20 + i]     = TCP_OPT_MSS;
        segment[20 + i + 1] = 4;
        segment[20 + i + 2] = 0x05;
        segment[20 + i + 3] = 0xb4;
    }
    assert(tcp_parse(segment, sizeof(segment), &header) == 0);
    for (i = 0; i < header.opt_count; i++)
        assert(header.options[i].data_len <= TCP_OPT_MAX_DATA);
}

static void test_checksum_rejects_short_segment(void) {
    static const uint8_t ip[4] = { 192, 0, 2, 1 };
    uint8_t segment[TCP_MIN_HDR_LEN - 1] = { 0 };

    assert(tcp_checksum_ok(ip, ip, segment, sizeof(segment)) == 0);
}

static void test_flags_string_ignores_empty_buffer(void) {
    char buf = 'x';

    tcp_flags_str(TCP_SYN, NULL, 0);
    tcp_flags_str(TCP_SYN, &buf, 0);
    assert(buf == 'x');
}

int main(void) {
    test_valid_mss_option();
    test_bad_option_length();
    test_truncated_option_data();
    test_max_length_option_fits();
    test_option_length_never_exceeds_storage();
    test_checksum_rejects_short_segment();
    test_flags_string_ignores_empty_buffer();
    printf("tcp_parse tests passed\n");
    return 0;
}
