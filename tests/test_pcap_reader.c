#include <assert.h>
#include <stdio.h>

#include "pcap.h"

static void write_bytes(FILE* fp, const uint8_t* data, size_t len) {
    assert(fwrite(data, 1, len, fp) == len);
}

static void write16le(FILE* fp, uint16_t value) {
    uint8_t data[2] = {
        (uint8_t)value,
        (uint8_t)(value >> 8)
    };
    write_bytes(fp, data, sizeof(data));
}

static void write32le(FILE* fp, uint32_t value) {
    uint8_t data[4] = {
        (uint8_t)value,
        (uint8_t)(value >> 8),
        (uint8_t)(value >> 16),
        (uint8_t)(value >> 24)
    };
    write_bytes(fp, data, sizeof(data));
}

static void write_invalid_classic_capture(const char* path) {
    static const uint8_t packet[2] = {0xaa, 0xbb};
    FILE* fp;

    (void)remove(path);
    fp = fopen(path, "wb");
    assert(fp != NULL);
    write32le(fp, PCAP_MAGIC_LE);
    write16le(fp, 2);
    write16le(fp, 4);
    write32le(fp, 0);
    write32le(fp, 0);
    write32le(fp, 65535);
    write32le(fp, LINKTYPE_ETHERNET);
    write32le(fp, 0);
    write32le(fp, 0);
    write32le(fp, (uint32_t)sizeof(packet));
    write32le(fp, 1); /* Captured length cannot exceed original length. */
    write_bytes(fp, packet, sizeof(packet));
    assert(fclose(fp) == 0);
}

static void write_invalid_pcapng_capture(const char* path) {
    static const uint8_t packet_and_padding[4] = {0xaa, 0xbb, 0, 0};
    FILE* fp;

    (void)remove(path);
    fp = fopen(path, "wb");
    assert(fp != NULL);

    write32le(fp, PCAPNG_BLOCK_SHB);
    write32le(fp, 28);
    write32le(fp, PCAPNG_BYTE_ORDER_MAGIC);
    write16le(fp, 1);
    write16le(fp, 0);
    write32le(fp, UINT32_MAX);
    write32le(fp, UINT32_MAX);
    write32le(fp, 28);

    write32le(fp, PCAPNG_BLOCK_IDB);
    write32le(fp, 20);
    write16le(fp, LINKTYPE_ETHERNET);
    write16le(fp, 0);
    write32le(fp, 65535);
    write32le(fp, 20);

    write32le(fp, PCAPNG_BLOCK_EPB);
    write32le(fp, 36);
    write32le(fp, 0);
    write32le(fp, 0);
    write32le(fp, 0);
    write32le(fp, 2);
    write32le(fp, 1); /* Captured length cannot exceed original length. */
    write_bytes(fp, packet_and_padding, sizeof(packet_and_padding));
    write32le(fp, 36);
    assert(fclose(fp) == 0);
}

static void assert_invalid_length_rejected(const char* path,
                                           PcapFormat expected_format) {
    PcapPacketHeader header = {0};
    uint8_t packet[8];
    PcapReader* reader = pcap_open(path);

    assert(reader != NULL);
    assert(reader->format == expected_format);
    assert(pcap_next(reader, &header, packet, sizeof(packet)) == 0);
    pcap_close(reader);
    assert(remove(path) == 0);
}

static void test_rejects_captured_length_above_original(void) {
    const char* classic_path = "tcpip_invalid_lengths.pcap";
    const char* pcapng_path = "tcpip_invalid_lengths.pcapng";

    write_invalid_pcapng_capture(pcapng_path);
    assert_invalid_length_rejected(pcapng_path, PCAP_FORMAT_PCAPNG);

    write_invalid_classic_capture(classic_path);
    assert_invalid_length_rejected(classic_path, PCAP_FORMAT_CLASSIC);
}

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
    test_rejects_captured_length_above_original();
    assert_capture(argv[1], PCAP_FORMAT_CLASSIC, 52, 1000005, 100000);
    assert_capture(argv[2], PCAP_FORMAT_PCAPNG, 52, 1000005, 100000);
    assert_capture(argv[3], PCAP_FORMAT_PCAPNG, 52, 1000005, 100000);
    assert_capture(argv[4], PCAP_FORMAT_PCAPNG, 1, 0, 0);
    printf("pcap reader tests passed\n");
    return 0;
}
