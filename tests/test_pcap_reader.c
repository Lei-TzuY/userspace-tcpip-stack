#include <assert.h>
#include <stdio.h>

#include "pcap.h"

static void assert_capture(const char* path, PcapFormat expected_format,
                           size_t expected_packets,
                           uint32_t expected_last_sec,
                           uint32_t expected_last_usec) {
    PcapReader* reader = pcap_open(path);
    PcapPacketHeader header = {0};
    uint8_t packet[65536];
    size_t packets = 0;

    assert(reader != NULL);
    assert(reader->format == expected_format);

    while (pcap_next(reader, &header, packet, sizeof(packet)) > 0) {
        packets++;
        assert(reader->global.network == LINKTYPE_ETHERNET);
        assert(header.incl_len > 0);
        assert(header.orig_len >= header.incl_len);
    }

    assert(packets == expected_packets);
    assert(header.ts_sec == expected_last_sec);
    assert(header.ts_usec == expected_last_usec);
    pcap_close(reader);
}

int main(int argc, char** argv) {
    assert(argc == 5);
    assert_capture(argv[1], PCAP_FORMAT_CLASSIC, 52, 1000005, 100000);
    assert_capture(argv[2], PCAP_FORMAT_PCAPNG, 52, 1000005, 100000);
    assert_capture(argv[3], PCAP_FORMAT_PCAPNG, 52, 1000005, 100000);
    assert_capture(argv[4], PCAP_FORMAT_PCAPNG, 1, 0, 0);
    printf("pcap reader tests passed\n");
    return 0;
}
