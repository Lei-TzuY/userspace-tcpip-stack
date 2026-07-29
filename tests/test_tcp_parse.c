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
    test_checksum_rejects_short_segment();
    test_flags_string_ignores_empty_buffer();
    printf("tcp_parse tests passed\n");
    return 0;
}
