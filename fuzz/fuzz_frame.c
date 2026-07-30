/*
 * fuzz_frame.c — drive the full dispatch pipeline with a sequence of frames
 *
 * A single frame cannot reach the interesting state: IP reassembly only
 * completes across fragments, the TCP state machine only moves across
 * segments, and the ARP cache only reports a change on the second sighting of
 * an address. So one input encodes several frames:
 *
 *   byte 0            time step selector
 *   then, repeated:   u16 big-endian frame length, followed by that many bytes
 *
 * A length that overruns the remaining input is clamped rather than rejected,
 * which keeps truncated tails useful to the mutator.
 *
 * The capture clock advances by a fixed step per frame. The step comes from
 * byte 0 so that the fuzzer can choose between packing frames close enough to
 * stay in the trackers and spacing them far enough apart to trigger the idle
 * expiry paths.
 */

#include "fuzz_target.h"
#include "dispatch.h"

#define FUZZ_MAX_FRAMES_PER_INPUT 64

static StackContext* g_stack;

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    uint64_t step_usec;
    uint64_t now_usec = 0;
    size_t   offset;
    unsigned frames = 0;

    fuzz_silence_stdout();

    if (size < 1) return 0;

    if (!g_stack) {
        g_stack = stack_create();
        if (!g_stack) return 0;
    }
    /* Every tracker's init is a memset, so this is a complete reset and each
       input is reproducible on its own. */
    stack_init(g_stack);

    /* 1 ms .. 256 ms per frame; the tracker idle timeout is minutes, so the
       upper end still needs many frames to trip expiry. That is intentional —
       we want the fuzzer to have to work for it, not to expire on frame two. */
    step_usec = ((uint64_t)data[0] + 1u) * 1000u;
    offset = 1;

    while (offset + 2 <= size && frames < FUZZ_MAX_FRAMES_PER_INPUT) {
        size_t frame_len = ((size_t)data[offset] << 8) | (size_t)data[offset + 1];
        size_t available;

        offset += 2;
        available = size - offset;
        if (frame_len > available) frame_len = available;

        now_usec += step_usec;
        stack_expire_idle(g_stack, now_usec);
        stack_dispatch_frame(g_stack, data + offset, frame_len, now_usec);

        offset += frame_len;
        frames++;
    }

    /* The summary walks every tracker table, so it is worth reaching. */
    stack_print_summary(g_stack);
    return 0;
}
