#ifndef TCP_STREAM_H
#define TCP_STREAM_H

/*
 * Bounded passive TCP byte-stream reassembly.
 *
 * The buffer stores payload bytes that arrived ahead of the next expected
 * sequence number. Once a gap is filled, contiguous bytes are emitted in
 * order through a callback. Sequence-space bytes consumed by SYN and FIN are
 * advanced separately by the tracker with tcp_stream_advance().
 */

#include "common.h"

#define TCP_STREAM_WINDOW_SIZE 4096
#define TCP_STREAM_BITMAP_SIZE ((TCP_STREAM_WINDOW_SIZE + 7u) / 8u)

typedef enum {
    TCP_STREAM_OK = 0,
    TCP_STREAM_WINDOW_EXCEEDED,
    TCP_STREAM_CONFLICT
} TcpStreamStatus;

typedef void (*TcpStreamEmitFn)(const uint8_t* data, size_t len, void* context);

typedef struct {
    uint32_t next_seq;
    int      next_seq_valid;
    size_t   base_slot;
    size_t   buffered_bytes;
    uint64_t delivered_bytes;
    uint8_t  data[TCP_STREAM_WINDOW_SIZE];
    uint8_t  received[TCP_STREAM_BITMAP_SIZE];
} TcpStream;

void tcp_stream_init(TcpStream* stream);
void tcp_stream_reset(TcpStream* stream, uint32_t next_seq);

/*
 * Advance sequence space for an in-order SYN or FIN control byte.
 * Returns 0 on success, -1 if buffered payload already occupies that slot.
 */
int tcp_stream_advance(TcpStream* stream, uint32_t count);

/*
 * Add TCP payload bytes at an absolute sequence number.
 *
 * Old bytes that were already emitted are accepted as retransmissions.
 * Pending overlaps must contain identical bytes. Bytes beyond the bounded
 * receive window are rejected without modifying the stream.
 */
TcpStreamStatus tcp_stream_add(
    TcpStream* stream,
    uint32_t seq,
    const uint8_t* data,
    size_t len,
    TcpStreamEmitFn emit,
    void* context,
    size_t* emitted_bytes);

const char* tcp_stream_status_name(TcpStreamStatus status);

#endif /* TCP_STREAM_H */
