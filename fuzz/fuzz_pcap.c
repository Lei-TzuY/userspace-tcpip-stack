/*
 * fuzz_pcap.c — treat the whole input as a capture file
 *
 * This is the only target that exercises the pcap/pcapng reader, which is the
 * part of the stack that does the most length arithmetic on untrusted input:
 * block totals, option padding, per-interface timestamp resolution, and the
 * byte-order swap paths.
 *
 * The reader opens captures by path, so the input has to be written to a
 * temporary file first. That makes this target much slower than the others;
 * when running a long campaign, give it its own process rather than sharing
 * time with fuzz_frame.
 */

#include "fuzz_target.h"
#include "pcap.h"
#include "dispatch.h"

#define FUZZ_PCAP_BUF_SIZE   (64u * 1024u)
#define FUZZ_PCAP_MAX_PACKETS 4096u

static StackContext* g_stack;
static uint8_t       g_pkt_buf[FUZZ_PCAP_BUF_SIZE];

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    char        path[512];
    PcapReader* reader;
    PcapPacketHeader pkt_hdr;
    unsigned    packets = 0;

    fuzz_silence_stdout();

    if (fuzz_temp_file_write(data, size, path, sizeof(path)) != 0)
        return 0;

    reader = pcap_open(path);
    if (!reader) {
        fuzz_temp_file_remove(path);
        return 0;
    }

    if (!g_stack) {
        g_stack = stack_create();
        if (!g_stack) {
            pcap_close(reader);
            fuzz_temp_file_remove(path);
            return 0;
        }
    }
    stack_init(g_stack);

    while (packets < FUZZ_PCAP_MAX_PACKETS) {
        size_t pkt_len = pcap_next(reader, &pkt_hdr, g_pkt_buf,
                                   sizeof(g_pkt_buf));
        uint64_t timestamp_usec;
        if (pkt_len == 0) break;

        packets++;
        timestamp_usec = ((uint64_t)pkt_hdr.ts_sec * 1000000u) + pkt_hdr.ts_usec;
        stack_expire_idle(g_stack, timestamp_usec);

        /* Dispatch by whatever link type the file declared, not just Ethernet:
           the cooked, raw-IP, and loopback headers are parsed from the same
           untrusted bytes and are only reachable this way. */
        {
            /* Hand the packet to the dispatcher in an allocation sized exactly
               to pkt_len. The reader has to fill a snaplen-sized buffer, but
               dispatching straight out of it would leave any read past
               pkt_len inside a valid object, where the sanitizer cannot see
               it. The copy puts a redzone right after the last valid byte. */
            uint8_t* frame = (uint8_t*)malloc(pkt_len);
            if (frame) {
                memcpy(frame, g_pkt_buf, pkt_len);
                stack_dispatch_link(g_stack,
                                    reader->global.network,
                                    frame, pkt_len, timestamp_usec);
                free(frame);
            }
        }
    }

    stack_print_summary(g_stack);

    pcap_close(reader);
    fuzz_temp_file_remove(path);
    return 0;
}
