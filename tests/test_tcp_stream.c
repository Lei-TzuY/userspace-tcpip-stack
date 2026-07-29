#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "tcp_stream.h"

typedef struct {
    uint8_t data[128];
    size_t  len;
} Collector;

static void collect(const uint8_t* data, size_t len, void* context) {
    Collector* collector = (Collector*)context;
    assert(collector->len + len <= sizeof(collector->data));
    memcpy(collector->data + collector->len, data, len);
    collector->len += len;
}

static void test_reassembles_gap(void) {
    TcpStream stream;
    Collector collector = { { 0 }, 0 };
    size_t emitted;
    tcp_stream_reset(&stream, 100);

    assert(tcp_stream_add(
        &stream, 103, (const uint8_t*)"def", 3,
        collect, &collector, &emitted) == TCP_STREAM_OK);
    assert(emitted == 0);
    assert(stream.buffered_bytes == 3);
    assert(stream.next_seq == 100);

    assert(tcp_stream_add(
        &stream, 100, (const uint8_t*)"abc", 3,
        collect, &collector, &emitted) == TCP_STREAM_OK);
    assert(emitted == 6);
    assert(stream.buffered_bytes == 0);
    assert(stream.next_seq == 106);
    assert(collector.len == 6);
    assert(memcmp(collector.data, "abcdef", 6) == 0);
}

static void test_accepts_retransmission_with_new_tail(void) {
    TcpStream stream;
    Collector collector = { { 0 }, 0 };
    size_t emitted;
    tcp_stream_reset(&stream, 100);

    assert(tcp_stream_add(
        &stream, 100, (const uint8_t*)"abcdef", 6,
        collect, &collector, &emitted) == TCP_STREAM_OK);
    assert(emitted == 6);

    assert(tcp_stream_add(
        &stream, 104, (const uint8_t*)"efgh", 4,
        collect, &collector, &emitted) == TCP_STREAM_OK);
    assert(emitted == 2);
    assert(stream.next_seq == 108);
    assert(collector.len == 8);
    assert(memcmp(collector.data, "abcdefgh", 8) == 0);
}

static void test_rejects_conflicting_pending_overlap(void) {
    TcpStream stream;
    Collector collector = { { 0 }, 0 };
    size_t emitted;
    tcp_stream_reset(&stream, 100);

    assert(tcp_stream_add(
        &stream, 103, (const uint8_t*)"def", 3,
        collect, &collector, &emitted) == TCP_STREAM_OK);
    assert(tcp_stream_add(
        &stream, 103, (const uint8_t*)"dxf", 3,
        collect, &collector, &emitted) == TCP_STREAM_CONFLICT);
    assert(stream.buffered_bytes == 3);
    assert(stream.next_seq == 100);
}

static void test_rejects_data_beyond_window(void) {
    TcpStream stream;
    size_t emitted;
    tcp_stream_reset(&stream, 100);

    assert(tcp_stream_add(
        &stream, 100 + TCP_STREAM_WINDOW_SIZE, (const uint8_t*)"x", 1,
        NULL, NULL, &emitted) == TCP_STREAM_WINDOW_EXCEEDED);
    assert(stream.buffered_bytes == 0);
    assert(stream.next_seq == 100);
}

static void test_sequence_wraparound(void) {
    TcpStream stream;
    Collector collector = { { 0 }, 0 };
    size_t emitted;
    tcp_stream_reset(&stream, UINT32_MAX - 1u);

    assert(tcp_stream_add(
        &stream, UINT32_MAX, (const uint8_t*)"bc", 2,
        collect, &collector, &emitted) == TCP_STREAM_OK);
    assert(emitted == 0);
    assert(tcp_stream_add(
        &stream, UINT32_MAX - 1u, (const uint8_t*)"a", 1,
        collect, &collector, &emitted) == TCP_STREAM_OK);
    assert(emitted == 3);
    assert(stream.next_seq == 1);
    assert(memcmp(collector.data, "abc", 3) == 0);
}

static void test_control_byte_advance(void) {
    TcpStream stream;
    tcp_stream_reset(&stream, 100);

    assert(tcp_stream_advance(&stream, 1) == 0);
    assert(stream.next_seq == 101);
}

int main(void) {
    test_reassembles_gap();
    test_accepts_retransmission_with_new_tail();
    test_rejects_conflicting_pending_overlap();
    test_rejects_data_beyond_window();
    test_sequence_wraparound();
    test_control_byte_advance();
    printf("tcp_stream tests passed\n");
    return 0;
}
