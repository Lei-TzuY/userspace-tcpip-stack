#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "sctp.h"

/* ── CRC-32C ─────────────────────────────────────────────────────────────── */

static void test_crc32c_matches_the_published_check_values(void) {
    /* The check value every CRC-32C description carries, and the all-zero
       vector from RFC 3720 Appendix B. Checking against these rather than
       against this implementation's own output is what makes the nibble table
       in sctp.c verified rather than merely self-consistent. */
    const uint8_t nine[] = "123456789";
    uint8_t zeros[32];

    memset(zeros, 0, sizeof(zeros));
    assert(sctp_crc32c(nine, 9) == 0xE3069283u);
    assert(sctp_crc32c(zeros, sizeof(zeros)) == 0x8A9136AAu);
    assert(sctp_crc32c(nine, 0) == 0x00000000u);
}

/* Write the CRC-32C into the checksum field the way a sender does: computed
   over the packet with that field zeroed, and stored least significant byte
   first. */
static void set_checksum(uint8_t* packet, size_t len) {
    uint32_t crc;

    packet[8] = packet[9] = packet[10] = packet[11] = 0;
    crc = sctp_crc32c(packet, len);
    packet[8]  = (uint8_t)(crc & 0xFFu);
    packet[9]  = (uint8_t)((crc >> 8) & 0xFFu);
    packet[10] = (uint8_t)((crc >> 16) & 0xFFu);
    packet[11] = (uint8_t)((crc >> 24) & 0xFFu);
}

/* A minimal packet: common header plus one COOKIE ACK chunk. */
static void build_cookie_ack(uint8_t* packet) {
    static const uint8_t base[16] = {
        0x26, 0xab, 0x26, 0xac,              /* ports 9899 -> 9900 */
        0x11, 0x22, 0x33, 0x44,              /* verification tag */
        0x00, 0x00, 0x00, 0x00,              /* checksum, filled in below */
        0x0b, 0x00, 0x00, 0x04               /* COOKIE ACK, length 4 */
    };
    memcpy(packet, base, sizeof(base));
    set_checksum(packet, sizeof(base));
}

static void test_checksum_field_is_little_endian(void) {
    uint8_t packet[16];
    uint8_t swapped[16];

    build_cookie_ack(packet);
    assert(sctp_checksum_ok(packet, sizeof(packet)) == 1);

    /* The same four bytes the other way round. Every other field in an SCTP
       packet is big endian, so reading this one that way would make a valid
       checksum read as broken — which is the mistake this asserts against. */
    memcpy(swapped, packet, sizeof(packet));
    swapped[8]  = packet[11];
    swapped[9]  = packet[10];
    swapped[10] = packet[9];
    swapped[11] = packet[8];
    assert(sctp_checksum_ok(swapped, sizeof(swapped)) == 0);
}

static void test_checksum_covers_a_zeroed_field(void) {
    uint8_t packet[16];

    build_cookie_ack(packet);
    /* Flip a byte anywhere else and the CRC must reject it. */
    packet[6] ^= 0x01u;
    assert(sctp_checksum_ok(packet, sizeof(packet)) == 0);

    build_cookie_ack(packet);
    assert(sctp_checksum_ok(packet, 8) == 0);       /* shorter than a header */
    assert(sctp_checksum_ok(NULL, 16) == 0);
}

static void test_checksum_uses_the_length_it_is_given(void) {
    uint8_t padded[24];

    /* Ethernet pads short frames, so a buffer can be longer than the packet.
       Summing the padding in would fail every checksum on a small packet. */
    memset(padded, 0xAA, sizeof(padded));
    build_cookie_ack(padded);
    assert(sctp_checksum_ok(padded, 16) == 1);
    assert(sctp_checksum_ok(padded, sizeof(padded)) == 0);
}

/* ── the common header ───────────────────────────────────────────────────── */

static void test_common_header(void) {
    uint8_t packet[16];
    SctpPacket sctp;

    build_cookie_ack(packet);
    assert(sctp_parse(packet, sizeof(packet), &sctp) == 0);
    assert(sctp.src_port == 9899);
    assert(sctp.dst_port == 9900);
    assert(sctp.vtag == 0x11223344u);
    assert(sctp.chunk_count == 1);
    assert(sctp.chunks_seen == 1);
    assert(sctp.chunks[0].type == SCTP_CHUNK_COOKIE_ACK);
    assert(sctp.chunks[0].length == 4);
    assert(sctp.chunks[0].value_len == 0);
    assert(sctp.chunks[0].value == NULL);
    assert(sctp.walk_stopped == 0);
    assert(sctp.trailing_bytes == 0);
}

static void test_too_short(void) {
    uint8_t packet[16] = { 0 };
    SctpPacket sctp;

    assert(sctp_parse(packet, 11, &sctp) == -1);
    assert(sctp_parse(NULL, 16, &sctp) == -1);
    assert(sctp_parse(packet, 16, NULL) == -1);

    /* A common header with no chunk behind it is a valid parse of nothing. */
    assert(sctp_parse(packet, 12, &sctp) == 0);
    assert(sctp.chunk_count == 0);
}

/* ── the chunk walk ──────────────────────────────────────────────────────── */

static void test_data_chunk_and_padding(void) {
    /* DATA carrying three bytes: length 19, so the next chunk starts at the
       20-byte boundary and one pad byte sits between them. */
    uint8_t packet[12 + 20 + 4] = {
        0x26, 0xab, 0x26, 0xac,
        0x11, 0x22, 0x33, 0x44,
        0x00, 0x00, 0x00, 0x00,

        0x00, 0x03, 0x00, 0x13,              /* DATA, flags B|E, length 19 */
        0x00, 0x00, 0x03, 0xe8,              /* TSN 1000 */
        0x00, 0x01, 0x00, 0x02,              /* stream 1, sequence 2 */
        0x00, 0x00, 0x00, 0x33,              /* PPID 51 */
        'h',  'i',  '!',
        0x00,                                /* the pad byte */

        0x0b, 0x00, 0x00, 0x04               /* COOKIE ACK */
    };
    SctpPacket sctp;

    assert(sctp_parse(packet, sizeof(packet), &sctp) == 0);
    assert(sctp.chunks_seen == 2);
    assert(sctp.chunk_count == 2);

    assert(sctp.chunks[0].type == SCTP_CHUNK_DATA);
    assert(sctp.chunks[0].flags == (SCTP_DATA_FLAG_B | SCTP_DATA_FLAG_E));
    assert(sctp.chunks[0].detail_valid == 1);
    assert(sctp.chunks[0].u.data.tsn == 1000);
    assert(sctp.chunks[0].u.data.stream_id == 1);
    assert(sctp.chunks[0].u.data.stream_seq == 2);
    assert(sctp.chunks[0].u.data.ppid == 51);
    assert(sctp.chunks[0].u.data.user_data_len == 3);

    /* The pad byte is not part of the declared length but is on the wire, so
       the second chunk is only found if the walk rounds up. */
    assert(sctp.chunks[1].type == SCTP_CHUNK_COOKIE_ACK);
    assert(sctp.walk_stopped == 0);
}

static void test_length_below_the_chunk_header_stops_the_walk(void) {
    /* Length 0 describes something smaller than the four-byte header that
       declared it. Advancing by it would leave the walk exactly where it was,
       so it has to stop instead. */
    uint8_t packet[12 + 4 + 4] = {
        0x26, 0xab, 0x26, 0xac,
        0x11, 0x22, 0x33, 0x44,
        0x00, 0x00, 0x00, 0x00,
        0x0b, 0x00, 0x00, 0x00,              /* COOKIE ACK, length 0 */
        0x0b, 0x00, 0x00, 0x04
    };
    SctpPacket sctp;

    assert(sctp_parse(packet, sizeof(packet), &sctp) == 0);
    assert(sctp.chunk_count == 1);
    assert(sctp.chunks[0].length_invalid == 1);
    assert(sctp.walk_stopped == 1);

    /* Length 3 is the same problem one byte higher up. */
    packet[15] = 0x03;
    assert(sctp_parse(packet, sizeof(packet), &sctp) == 0);
    assert(sctp.chunks[0].length_invalid == 1);
    assert(sctp.walk_stopped == 1);
}

static void test_declared_length_beyond_the_packet(void) {
    uint8_t packet[12 + 8] = {
        0x26, 0xab, 0x26, 0xac,
        0x11, 0x22, 0x33, 0x44,
        0x00, 0x00, 0x00, 0x00,
        0x07, 0x00, 0xff, 0xff,              /* SHUTDOWN claiming 65535 bytes */
        0x00, 0x00, 0x00, 0x2a               /* four bytes actually arrived */
    };
    SctpPacket sctp;

    assert(sctp_parse(packet, sizeof(packet), &sctp) == 0);
    assert(sctp.chunk_count == 1);
    assert(sctp.chunks[0].truncated == 1);
    assert(sctp.chunks[0].length == 0xFFFFu);
    /* value_len is what arrived, never what was declared. A consumer walking
       the declared length would read 65 KB past the packet. */
    assert(sctp.chunks[0].value_len == 4);
    assert(sctp.chunks[0].detail_valid == 1);
    assert(sctp.chunks[0].u.shutdown.cum_tsn_ack == 42);
    assert(sctp.walk_stopped == 1);
}

static void test_more_chunks_than_are_stored(void) {
    uint8_t packet[12 + 4 * 20];
    SctpPacket sctp;
    size_t index;

    memset(packet, 0, sizeof(packet));
    packet[0] = 0x26; packet[1] = 0xab;
    for (index = 12; index < sizeof(packet); index += 4) {
        packet[index] = SCTP_CHUNK_COOKIE_ACK;
        packet[index + 3] = 0x04;
    }

    assert(sctp_parse(packet, sizeof(packet), &sctp) == 0);
    assert(sctp.chunks_seen == 20);
    assert(sctp.chunk_count == SCTP_MAX_CHUNKS);
    assert(sctp.walk_stopped == 0);
}

static void test_trailing_bytes(void) {
    uint8_t packet[12 + 4 + 3] = {
        0x26, 0xab, 0x26, 0xac,
        0x11, 0x22, 0x33, 0x44,
        0x00, 0x00, 0x00, 0x00,
        0x0b, 0x00, 0x00, 0x04,
        0xde, 0xad, 0xbe
    };
    SctpPacket sctp;

    /* Three bytes cannot be a chunk header, so they are reported rather than
       silently dropped. */
    assert(sctp_parse(packet, sizeof(packet), &sctp) == 0);
    assert(sctp.chunk_count == 1);
    assert(sctp.trailing_bytes == 3);
}

/* ── INIT parameters, the walk inside the walk ───────────────────────────── */

static void test_init_parameters(void) {
    uint8_t packet[12 + 4 + 16 + 8 + 4] = {
        0x26, 0xab, 0x26, 0xac,
        0x11, 0x22, 0x33, 0x44,
        0x00, 0x00, 0x00, 0x00,

        0x01, 0x00, 0x00, 0x20,              /* INIT, length 32 */
        0xaa, 0xbb, 0xcc, 0xdd,              /* initiate tag */
        0x00, 0x01, 0x00, 0x00,              /* a_rwnd 65536 */
        0x00, 0x0a, 0x00, 0x05,              /* out 10, in 5 */
        0x00, 0x00, 0x27, 0x10,              /* initial TSN 10000 */

        0x00, 0x05, 0x00, 0x08,              /* IPv4 Address parameter */
        0xc0, 0xa8, 0x01, 0x01,
        0xc0, 0x00, 0x00, 0x04               /* Forward-TSN Supported */
    };
    SctpPacket sctp;
    const SctpChunk* chunk;

    assert(sctp_parse(packet, sizeof(packet), &sctp) == 0);
    chunk = &sctp.chunks[0];
    assert(chunk->type == SCTP_CHUNK_INIT);
    assert(chunk->detail_valid == 1);
    assert(chunk->u.init.initiate_tag == 0xaabbccddu);
    assert(chunk->u.init.a_rwnd == 65536u);
    assert(chunk->u.init.out_streams == 10);
    assert(chunk->u.init.in_streams == 5);
    assert(chunk->u.init.initial_tsn == 10000u);
    assert(chunk->u.init.params_seen == 2);
    assert(chunk->u.init.param_count == 2);
    assert(chunk->u.init.params[0].type == 5);
    assert(chunk->u.init.params[0].stored_len == 4);
    assert(chunk->u.init.params[1].type == 0xC000u);
    assert(chunk->u.init.params[1].stored_len == 0);
    assert(chunk->u.init.param_overrun == 0);
}

static void test_init_parameter_length_below_its_header(void) {
    uint8_t packet[12 + 4 + 16 + 4] = {
        0x26, 0xab, 0x26, 0xac,
        0x11, 0x22, 0x33, 0x44,
        0x00, 0x00, 0x00, 0x00,

        0x01, 0x00, 0x00, 0x18,              /* INIT, length 24 */
        0xaa, 0xbb, 0xcc, 0xdd,
        0x00, 0x01, 0x00, 0x00,
        0x00, 0x0a, 0x00, 0x05,
        0x00, 0x00, 0x27, 0x10,

        0x00, 0x05, 0x00, 0x00               /* a parameter of length 0 */
    };
    SctpPacket sctp;

    assert(sctp_parse(packet, sizeof(packet), &sctp) == 0);
    assert(sctp.chunks[0].u.init.param_overrun == 1);
    assert(sctp.chunks[0].u.init.params_seen == 1);
    assert(sctp.chunks[0].u.init.param_count == 0);
}

static void test_init_parameter_running_past_the_chunk(void) {
    uint8_t packet[12 + 4 + 16 + 6] = {
        0x26, 0xab, 0x26, 0xac,
        0x11, 0x22, 0x33, 0x44,
        0x00, 0x00, 0x00, 0x00,

        0x01, 0x00, 0x00, 0x1a,              /* INIT, length 26 */
        0xaa, 0xbb, 0xcc, 0xdd,
        0x00, 0x01, 0x00, 0x00,
        0x00, 0x0a, 0x00, 0x05,
        0x00, 0x00, 0x27, 0x10,

        0x00, 0x07, 0xff, 0xff,              /* State Cookie, 65535 bytes */
        0x01, 0x02
    };
    SctpPacket sctp;
    const SctpChunk* chunk;

    assert(sctp_parse(packet, sizeof(packet), &sctp) == 0);
    chunk = &sctp.chunks[0];
    assert(chunk->u.init.param_overrun == 1);
    assert(chunk->u.init.param_count == 1);
    /* Two bytes arrived, whatever the parameter claimed. */
    assert(chunk->u.init.params[0].length == 0xFFFFu);
    assert(chunk->u.init.params[0].stored_len == 2);
}

/* ── SACK ────────────────────────────────────────────────────────────────── */

static void test_sack_gap_blocks(void) {
    uint8_t packet[12 + 4 + 12 + 8] = {
        0x26, 0xab, 0x26, 0xac,
        0x11, 0x22, 0x33, 0x44,
        0x00, 0x00, 0x00, 0x00,

        0x03, 0x00, 0x00, 0x18,              /* SACK, length 24 */
        0x00, 0x00, 0x03, 0xe8,              /* cumulative TSN 1000 */
        0x00, 0x01, 0x00, 0x00,              /* a_rwnd */
        0x00, 0x02, 0x00, 0x00,              /* 2 gap blocks, 0 duplicates */
        0x00, 0x02, 0x00, 0x03,              /* TSN 1002..1003 */
        0x00, 0x05, 0x00, 0x07               /* TSN 1005..1007 */
    };
    SctpPacket sctp;
    const SctpChunk* chunk;

    assert(sctp_parse(packet, sizeof(packet), &sctp) == 0);
    chunk = &sctp.chunks[0];
    assert(chunk->type == SCTP_CHUNK_SACK);
    assert(chunk->u.sack.cum_tsn_ack == 1000);
    assert(chunk->u.sack.gap_count == 2);
    assert(chunk->u.sack.dup_count == 0);
    assert(chunk->u.sack.gaps_stored == 2);
    assert(chunk->u.sack.gaps[0].start == 2 && chunk->u.sack.gaps[0].end == 3);
    assert(chunk->u.sack.gaps[1].start == 5 && chunk->u.sack.gaps[1].end == 7);
    assert(chunk->u.sack.counts_overrun == 0);
}

static void test_sack_counts_that_do_not_fit(void) {
    /* Both counts are the sender's, and each entry is four bytes, so the
       product is what would drive a reader off the end of the chunk. */
    uint8_t packet[12 + 4 + 12] = {
        0x26, 0xab, 0x26, 0xac,
        0x11, 0x22, 0x33, 0x44,
        0x00, 0x00, 0x00, 0x00,

        0x03, 0x00, 0x00, 0x10,              /* SACK, length 16 */
        0x00, 0x00, 0x03, 0xe8,
        0x00, 0x01, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff               /* 65535 gaps, 65535 duplicates */
    };
    SctpPacket sctp;

    assert(sctp_parse(packet, sizeof(packet), &sctp) == 0);
    assert(sctp.chunks[0].u.sack.gap_count == 0xFFFFu);
    assert(sctp.chunks[0].u.sack.counts_overrun == 1);
    assert(sctp.chunks[0].u.sack.gaps_stored == 0);
}

/* ── ABORT causes and unknown types ──────────────────────────────────────── */

static void test_abort_error_causes(void) {
    uint8_t packet[12 + 4 + 8] = {
        0x26, 0xab, 0x26, 0xac,
        0x11, 0x22, 0x33, 0x44,
        0x00, 0x00, 0x00, 0x00,

        0x06, 0x00, 0x00, 0x0c,              /* ABORT, length 12 */
        0x00, 0x0c, 0x00, 0x08,              /* User Initiated Abort */
        'b',  'y',  'e',  0x00
    };
    SctpPacket sctp;

    assert(sctp_parse(packet, sizeof(packet), &sctp) == 0);
    assert(sctp.chunks[0].type == SCTP_CHUNK_ABORT);
    assert(sctp.chunks[0].u.error.causes_seen == 1);
    assert(sctp.chunks[0].u.error.causes[0].type == 12);
    assert(sctp.chunks[0].u.error.causes[0].stored_len == 4);
}

static void test_unknown_chunk_action_bits(void) {
    /* RFC 9260 §3.2 puts the handling rule for an unrecognised chunk in the
       top two bits of the type, so a receiver knows what to do without
       knowing the chunk. */
    assert(sctp_unknown_action(0x3F) == SCTP_UNKNOWN_STOP);
    assert(sctp_unknown_action(0x7F) == SCTP_UNKNOWN_STOP_REPORT);
    assert(sctp_unknown_action(0xBF) == SCTP_UNKNOWN_SKIP);
    assert(sctp_unknown_action(0xFF) == SCTP_UNKNOWN_SKIP_REPORT);
    assert(sctp_unknown_action(SCTP_CHUNK_FORWARD_TSN) == SCTP_UNKNOWN_SKIP_REPORT);
}

static void test_type_names(void) {
    assert(strcmp(sctp_chunk_type_name(SCTP_CHUNK_DATA), "DATA") == 0);
    assert(strcmp(sctp_chunk_type_name(SCTP_CHUNK_INIT_ACK), "INIT ACK") == 0);
    assert(strcmp(sctp_chunk_type_name(0x3F), "UNKNOWN") == 0);
    assert(strcmp(sctp_param_type_name(7), "State Cookie") == 0);
    assert(strcmp(sctp_param_type_name(0x1234), "unknown") == 0);
    assert(strcmp(sctp_cause_code_name(13), "Protocol Violation") == 0);
    assert(strcmp(sctp_cause_code_name(0x1234), "unknown") == 0);
}

int main(void) {
    test_crc32c_matches_the_published_check_values();
    test_checksum_field_is_little_endian();
    test_checksum_covers_a_zeroed_field();
    test_checksum_uses_the_length_it_is_given();

    test_common_header();
    test_too_short();

    test_data_chunk_and_padding();
    test_length_below_the_chunk_header_stops_the_walk();
    test_declared_length_beyond_the_packet();
    test_more_chunks_than_are_stored();
    test_trailing_bytes();

    test_init_parameters();
    test_init_parameter_length_below_its_header();
    test_init_parameter_running_past_the_chunk();

    test_sack_gap_blocks();
    test_sack_counts_that_do_not_fit();

    test_abort_error_causes();
    test_unknown_chunk_action_bits();
    test_type_names();

    printf("sctp tests passed\n");
    return 0;
}
