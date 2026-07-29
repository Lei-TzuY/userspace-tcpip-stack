#include "tcp_stream.h"

static int32_t seq_delta(uint32_t value, uint32_t expected) {
    return (int32_t)(value - expected);
}

static size_t slot_for(const TcpStream* stream, size_t offset) {
    return (stream->base_slot + offset) % TCP_STREAM_WINDOW_SIZE;
}

static int slot_received(const TcpStream* stream, size_t slot) {
    return (stream->received[slot / 8u] & (uint8_t)(1u << (slot % 8u))) != 0;
}

static void mark_slot_received(TcpStream* stream, size_t slot) {
    stream->received[slot / 8u] |= (uint8_t)(1u << (slot % 8u));
}

static void clear_slot_received(TcpStream* stream, size_t slot) {
    stream->received[slot / 8u] &= (uint8_t)~(1u << (slot % 8u));
}

void tcp_stream_init(TcpStream* stream) {
    memset(stream, 0, sizeof(*stream));
}

void tcp_stream_reset(TcpStream* stream, uint32_t next_seq) {
    tcp_stream_init(stream);
    stream->next_seq = next_seq;
    stream->next_seq_valid = 1;
}

int tcp_stream_advance(TcpStream* stream, uint32_t count) {
    if (!stream || !stream->next_seq_valid)
        return -1;

    for (uint32_t i = 0; i < count; i++) {
        if (slot_received(stream, slot_for(stream, i)))
            return -1;
    }

    stream->next_seq += count;
    stream->base_slot = (stream->base_slot + count) % TCP_STREAM_WINDOW_SIZE;
    return 0;
}

TcpStreamStatus tcp_stream_add(
    TcpStream* stream,
    uint32_t seq,
    const uint8_t* data,
    size_t len,
    TcpStreamEmitFn emit,
    void* context,
    size_t* emitted_bytes) {
    size_t emitted = 0;

    if (emitted_bytes)
        *emitted_bytes = 0;
    if (!stream || !stream->next_seq_valid || (!data && len > 0))
        return TCP_STREAM_CONFLICT;

    for (size_t i = 0; i < len; i++) {
        int32_t delta = seq_delta(seq + (uint32_t)i, stream->next_seq);
        size_t slot;

        if (delta < 0)
            continue;
        if ((uint32_t)delta >= TCP_STREAM_WINDOW_SIZE)
            return TCP_STREAM_WINDOW_EXCEEDED;

        slot = slot_for(stream, (size_t)delta);
        if (slot_received(stream, slot) && stream->data[slot] != data[i])
            return TCP_STREAM_CONFLICT;
    }

    for (size_t i = 0; i < len; i++) {
        int32_t delta = seq_delta(seq + (uint32_t)i, stream->next_seq);
        size_t slot;

        if (delta < 0)
            continue;

        slot = slot_for(stream, (size_t)delta);
        if (!slot_received(stream, slot)) {
            stream->data[slot] = data[i];
            mark_slot_received(stream, slot);
            stream->buffered_bytes++;
        }
    }

    while (slot_received(stream, stream->base_slot)) {
        size_t run = 0;

        while (run < TCP_STREAM_WINDOW_SIZE - stream->base_slot
                && slot_received(stream, stream->base_slot + run))
            run++;

        if (emit)
            emit(stream->data + stream->base_slot, run, context);

        for (size_t i = 0; i < run; i++)
            clear_slot_received(stream, stream->base_slot + i);
        stream->buffered_bytes -= run;
        stream->delivered_bytes += run;
        stream->next_seq += (uint32_t)run;
        stream->base_slot = (stream->base_slot + run) % TCP_STREAM_WINDOW_SIZE;
        emitted += run;
    }

    if (emitted_bytes)
        *emitted_bytes = emitted;
    return TCP_STREAM_OK;
}

const char* tcp_stream_status_name(TcpStreamStatus status) {
    switch (status) {
        case TCP_STREAM_OK:              return "OK";
        case TCP_STREAM_WINDOW_EXCEEDED: return "window exceeded";
        case TCP_STREAM_CONFLICT:        return "conflicting overlap";
        default:                         return "unknown";
    }
}
