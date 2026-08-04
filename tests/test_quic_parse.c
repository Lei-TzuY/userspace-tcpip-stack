#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "quic.h"

/* A version 1 Initial: 8-byte DCID, 4-byte SCID, no token, and a Length of 20
   encoded as a two-byte variable-length integer. */
static const uint8_t k_initial_v1[] = {
    0xc0,                                    /* long header, fixed bit, type 0 */
    0x00, 0x00, 0x00, 0x01,                  /* version 1 */
    0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x04, 0xaa, 0xbb, 0xcc, 0xdd,
    0x00,                                    /* token length 0 */
    0x40, 0x14,                              /* length 20 */
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x01, 0x02, 0x03, 0x04
};

static void test_initial_long_header(void) {
    QuicDatagram datagram;
    const QuicPacket* packet;

    assert(quic_parse(k_initial_v1, sizeof(k_initial_v1), &datagram) == 0);
    assert(datagram.count == 1);
    packet = &datagram.packets[0];

    assert(packet->long_header == 1);
    assert(packet->fixed_bit == 1);
    assert(packet->version == QUIC_VERSION_1);
    assert(packet->kind == QUIC_PACKET_INITIAL);
    assert(packet->dcid_len == 8 && packet->dcid_stored == 8);
    assert(packet->dcid[0] == 0x01 && packet->dcid[7] == 0x08);
    assert(packet->scid_len == 4 && packet->scid_stored == 4);
    assert(packet->has_token == 1 && packet->token_len == 0);
    assert(packet->has_length == 1 && packet->length == 20);
    assert(packet->header_len == 22);
    assert(packet->packet_len == sizeof(k_initial_v1));
    assert(packet->truncated == 0);
}

static void test_coalesced_packets(void) {
    /* RFC 9000 §12.2: several QUIC packets may share one datagram, and the
       Length field of each is the only thing saying where the next starts. */
    uint8_t datagram_bytes[sizeof(k_initial_v1) + 13];
    static const uint8_t handshake[] = {
        0xe0,                                /* type 2 in version 1 */
        0x00, 0x00, 0x00, 0x01,
        0x00,                                /* no DCID */
        0x00,                                /* no SCID */
        0x05,                                /* length 5 */
        0x01, 0x02, 0x03, 0x04, 0x05
    };
    QuicDatagram datagram;

    memcpy(datagram_bytes, k_initial_v1, sizeof(k_initial_v1));
    memcpy(datagram_bytes + sizeof(k_initial_v1), handshake, sizeof(handshake));

    assert(quic_parse(datagram_bytes, sizeof(datagram_bytes), &datagram) == 0);
    assert(datagram.count == 2);
    assert(datagram.packets[0].kind == QUIC_PACKET_INITIAL);
    assert(datagram.packets[1].kind == QUIC_PACKET_HANDSHAKE);
    assert(datagram.packets[1].length == 5);
    assert(datagram.more == 0);
}

static void test_coalescing_is_capped(void) {
    uint8_t datagram_bytes[8 * 5];
    static const uint8_t empty_handshake[8] = {
        0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00
    };
    QuicDatagram datagram;
    unsigned index;

    /* A zero Length is legal on the wire and would be a step of zero if the
       loop walked payloads rather than whole packets. */
    for (index = 0; index < 5; index++)
        memcpy(datagram_bytes + index * 8, empty_handshake, 8);

    assert(quic_parse(datagram_bytes, sizeof(datagram_bytes), &datagram) == 0);
    assert(datagram.count == QUIC_MAX_COALESCED);
    assert(datagram.more == 1);
}

static void test_version_2_renumbers_the_packet_types(void) {
    /* RFC 9369 gives the same two bits different meanings, so that a v2
       packet cannot be mistaken for a v1 one by anything that ignores the
       version field. Type 1 is Initial in v2 and 0-RTT in v1. */
    uint8_t packet[] = {
        0xd0,                                /* type bits = 1 */
        0x6b, 0x33, 0x43, 0xcf,              /* version 2 */
        0x00, 0x00,
        0x00,                                /* token length 0 */
        0x02, 0x01, 0x02
    };
    QuicDatagram datagram;

    assert(quic_parse(packet, sizeof(packet), &datagram) == 0);
    assert(datagram.packets[0].version == QUIC_VERSION_2);
    assert(datagram.packets[0].kind == QUIC_PACKET_INITIAL);

    packet[1] = 0x00; packet[2] = 0x00; packet[3] = 0x00; packet[4] = 0x01;
    assert(quic_parse(packet, sizeof(packet), &datagram) == 0);
    assert(datagram.packets[0].kind == QUIC_PACKET_0RTT);
}

static void test_version_negotiation(void) {
    uint8_t packet[] = {
        0xc0,
        0x00, 0x00, 0x00, 0x00,              /* version 0 */
        0x04, 0xd0, 0xd1, 0xd2, 0xd3,
        0x04, 0x50, 0x51, 0x52, 0x53,
        0x00, 0x00, 0x00, 0x01,              /* v1 */
        0x6b, 0x33, 0x43, 0xcf               /* v2 */
    };
    QuicDatagram datagram;

    assert(quic_parse(packet, sizeof(packet), &datagram) == 0);
    assert(datagram.packets[0].kind == QUIC_PACKET_VERSION_NEGOTIATION);
    assert(datagram.packets[0].version_count == 2);
    assert(datagram.packets[0].versions_stored == 2);
    assert(datagram.packets[0].versions[0] == QUIC_VERSION_1);
    assert(datagram.packets[0].versions[1] == QUIC_VERSION_2);
    assert(datagram.packets[0].version_list_ragged == 0);
    /* No Length field, so nothing may follow it in the datagram. */
    assert(datagram.count == 1);
}

static void test_version_negotiation_with_a_ragged_list(void) {
    uint8_t packet[] = {
        0xc0,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
        0xff                                 /* one byte of a second version */
    };
    QuicDatagram datagram;

    assert(quic_parse(packet, sizeof(packet), &datagram) == 0);
    assert(datagram.packets[0].version_count == 1);
    assert(datagram.packets[0].version_list_ragged == 1);
}

static void test_retry_reserves_its_integrity_tag(void) {
    uint8_t packet[1 + 4 + 1 + 1 + 4 + 4 + 16];
    QuicDatagram datagram;

    memset(packet, 0x5a, sizeof(packet));
    packet[0] = 0xf0;                        /* type 3 in version 1 */
    packet[1] = 0x00; packet[2] = 0x00; packet[3] = 0x00; packet[4] = 0x01;
    packet[5] = 0x00;                        /* no DCID */
    packet[6] = 0x04;                        /* 4-byte SCID */

    assert(quic_parse(packet, sizeof(packet), &datagram) == 0);
    assert(datagram.packets[0].kind == QUIC_PACKET_RETRY);
    assert(datagram.packets[0].has_token == 1);
    /* The trailing 16 bytes are the integrity tag, not token bytes. */
    assert(datagram.packets[0].token_len == 4);
    assert(datagram.packets[0].has_length == 0);
}

static void test_retry_shorter_than_its_tag(void) {
    uint8_t packet[] = {
        0xf0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x02
    };
    QuicDatagram datagram;

    assert(quic_parse(packet, sizeof(packet), &datagram) == 0);
    assert(datagram.packets[0].kind == QUIC_PACKET_RETRY);
    assert(datagram.packets[0].truncated == 1);
    assert(datagram.packets[0].token_len == 0);
}

static void test_short_header_is_not_guessed_at(void) {
    /* Without knowing how long the connection IDs of this connection are,
       nothing after the first byte of a short header can be located. */
    uint8_t packet[] = { 0x40, 0x01, 0x02, 0x03, 0x04, 0x05 };
    QuicDatagram datagram;

    assert(quic_parse(packet, sizeof(packet), &datagram) == 0);
    assert(datagram.packets[0].long_header == 0);
    assert(datagram.packets[0].kind == QUIC_PACKET_SHORT_HEADER);
    assert(datagram.packets[0].dcid_len == 0);
    assert(datagram.count == 1);
}

static void test_unknown_version_stops_at_the_connection_ids(void) {
    /* RFC 9000 §15 reserves 0x?a?a?a?a to force version negotiation. RFC 8999
       defines the connection IDs for every version, and nothing beyond them,
       so this is exactly as far as the parse may go. */
    uint8_t packet[] = {
        0xc0,
        0x0a, 0x0a, 0x0a, 0x0a,
        0x02, 0xab, 0xcd,
        0x00,
        0x00, 0x40, 0x14                     /* would be a token and a length */
    };
    QuicDatagram datagram;

    assert(quic_parse(packet, sizeof(packet), &datagram) == 0);
    assert(datagram.packets[0].kind == QUIC_PACKET_UNKNOWN);
    assert(datagram.packets[0].dcid_len == 2);
    assert(datagram.packets[0].dcid_stored == 2);
    assert(datagram.packets[0].has_token == 0);
    assert(datagram.packets[0].has_length == 0);
}

/* ── lengths the sender chose ────────────────────────────────────────────── */

static void test_connection_id_beyond_the_version_1_limit(void) {
    uint8_t packet[1 + 4 + 1 + 25 + 1 + 1 + 1 + 2];
    QuicDatagram datagram;

    memset(packet, 0x77, sizeof(packet));
    packet[0] = 0xc0;
    packet[1] = 0x00; packet[2] = 0x00; packet[3] = 0x00; packet[4] = 0x01;
    packet[5] = 25;                          /* five more than v1 permits */
    packet[31] = 0x00;                       /* SCID length */
    packet[32] = 0x00;                       /* token length */
    packet[33] = 0x02;                       /* length 2 */

    assert(quic_parse(packet, sizeof(packet), &datagram) == 0);
    assert(datagram.packets[0].dcid_len == 25);
    /* dcid_stored is what the struct really holds, never what was declared. */
    assert(datagram.packets[0].dcid_stored == QUIC_MAX_CID_LEN);
    assert(datagram.packets[0].cid_over_limit == 1);
    assert(datagram.packets[0].truncated == 0);
    assert(datagram.packets[0].kind == QUIC_PACKET_INITIAL);
}

static void test_connection_id_longer_than_the_datagram(void) {
    uint8_t packet[] = {
        0xc0, 0x00, 0x00, 0x00, 0x01,
        0xff,                                /* 255 bytes of DCID promised */
        0x01, 0x02, 0x03
    };
    QuicDatagram datagram;

    assert(quic_parse(packet, sizeof(packet), &datagram) == 0);
    assert(datagram.packets[0].dcid_len == 255);
    assert(datagram.packets[0].dcid_stored == 3);
    assert(datagram.packets[0].truncated == 1);
    assert(datagram.packets[0].has_length == 0);
}

static void test_token_length_beyond_the_datagram(void) {
    uint8_t packet[] = {
        0xc0, 0x00, 0x00, 0x00, 0x01,
        0x00,                                /* no DCID */
        0x00,                                /* no SCID */
        0x80, 0x00, 0x00, 0x64,              /* token length 100, 4-byte varint */
        0x01, 0x02, 0x03                     /* three bytes actually present */
    };
    QuicDatagram datagram;

    assert(quic_parse(packet, sizeof(packet), &datagram) == 0);
    assert(datagram.packets[0].has_token == 1);
    assert(datagram.packets[0].token_len == 100);
    assert(datagram.packets[0].token_present == 3);
    assert(datagram.packets[0].truncated == 1);
    assert(datagram.packets[0].has_length == 0);
}

static void test_length_beyond_the_datagram(void) {
    uint8_t packet[] = {
        0xc0, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00,
        0x00,                                /* token length 0 */
        0x44, 0x00,                          /* length 1024 */
        0x01, 0x02, 0x03, 0x04
    };
    QuicDatagram datagram;

    assert(quic_parse(packet, sizeof(packet), &datagram) == 0);
    assert(datagram.packets[0].length == 1024);
    assert(datagram.packets[0].truncated == 1);
    /* The next coalesced packet would start past the datagram, so the walk has
       to stop here rather than following the declared length. */
    assert(datagram.packets[0].packet_len == sizeof(packet));
    assert(datagram.count == 1);
}

static void test_varint_announcing_more_bytes_than_arrived(void) {
    /* 0xc0 in the length position selects the eight-byte encoding, and only
       two bytes follow it. */
    uint8_t packet[] = {
        0xc0, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00,
        0x00,
        0xc0, 0x00
    };
    QuicDatagram datagram;

    assert(quic_parse(packet, sizeof(packet), &datagram) == 0);
    assert(datagram.packets[0].has_length == 0);
    assert(datagram.packets[0].truncated == 1);
}

static void test_varint_widths(void) {
    /* The same value, 0, in each of the four encodings the token length may
       use. All four must consume their own width and no more. */
    static const uint8_t widths[4][8] = {
        { 0x00 },
        { 0x40, 0x00 },
        { 0x80, 0x00, 0x00, 0x00 },
        { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
    };
    static const size_t sizes[4] = { 1, 2, 4, 8 };
    unsigned index;

    for (index = 0; index < 4; index++) {
        uint8_t packet[8 + 8 + 2];
        QuicDatagram datagram;
        size_t offset = 7;

        packet[0] = 0xc0;
        packet[1] = 0x00; packet[2] = 0x00; packet[3] = 0x00; packet[4] = 0x01;
        packet[5] = 0x00;
        packet[6] = 0x00;
        memcpy(packet + offset, widths[index], sizes[index]);
        offset += sizes[index];
        packet[offset++] = 0x02;             /* length 2 */
        packet[offset++] = 0xaa;
        packet[offset++] = 0xbb;

        assert(quic_parse(packet, offset, &datagram) == 0);
        assert(datagram.packets[0].token_len == 0);
        assert(datagram.packets[0].has_length == 1);
        assert(datagram.packets[0].length == 2);
        assert(datagram.packets[0].truncated == 0);
    }
}

static void test_parse_rejects_nothing_to_parse(void) {
    QuicDatagram datagram;
    uint8_t packet[1] = { 0xc0 };

    assert(quic_parse(NULL, 8, &datagram) == -1);
    assert(quic_parse(packet, 0, &datagram) == -1);
    assert(quic_parse(packet, 1, NULL) == -1);

    /* One byte is enough to say it is a long header and nothing more. */
    assert(quic_parse(packet, 1, &datagram) == 0);
    assert(datagram.packets[0].truncated == 1);
}

/* ── the sniff, and why the dispatcher does not trust it alone ───────────── */

static void test_sniff_accepts_a_long_header(void) {
    assert(quic_sniff(k_initial_v1, sizeof(k_initial_v1)) == 1);
    assert(quic_sniff(NULL, 64) == 0);
    assert(quic_sniff(k_initial_v1, 6) == 0);
}

static void test_sniff_requires_a_version_it_knows(void) {
    uint8_t packet[sizeof(k_initial_v1)];

    memcpy(packet, k_initial_v1, sizeof(packet));
    packet[1] = 0x12; packet[2] = 0x34; packet[3] = 0x56; packet[4] = 0x78;
    assert(quic_sniff(packet, sizeof(packet)) == 0);

    /* An IETF draft version is one we know how to read. */
    packet[1] = 0xff; packet[2] = 0x00; packet[3] = 0x00; packet[4] = 0x1d;
    assert(quic_sniff(packet, sizeof(packet)) == 1);
}

static void test_sniff_requires_the_header_form_and_fixed_bits(void) {
    uint8_t packet[sizeof(k_initial_v1)];

    memcpy(packet, k_initial_v1, sizeof(packet));
    packet[0] = 0x40;                        /* short header */
    assert(quic_sniff(packet, sizeof(packet)) == 0);

    packet[0] = 0x80;                        /* long header, fixed bit clear */
    assert(quic_sniff(packet, sizeof(packet)) == 0);
}

static void test_sniff_rejects_connection_ids_that_do_not_fit(void) {
    uint8_t packet[sizeof(k_initial_v1)];

    memcpy(packet, k_initial_v1, sizeof(packet));
    packet[5] = 21;                          /* over the version 1 limit */
    assert(quic_sniff(packet, sizeof(packet)) == 0);

    memcpy(packet, k_initial_v1, sizeof(packet));
    assert(quic_sniff(packet, 8) == 0);      /* the DCID runs off the end */
}

static void test_short_header_predicate(void) {
    uint8_t packet[] = { 0x41, 0x01, 0x02, 0x03 };

    assert(quic_is_short_header(packet, sizeof(packet)) == 1);
    packet[0] = 0x01;                        /* fixed bit clear */
    assert(quic_is_short_header(packet, sizeof(packet)) == 0);
    packet[0] = 0xc1;                        /* a long header */
    assert(quic_is_short_header(packet, sizeof(packet)) == 0);
    assert(quic_is_short_header(NULL, 4) == 0);
    assert(quic_is_short_header(packet, 0) == 0);
}

static void test_sniff_alone_would_claim_a_dns_query(void) {
    /*
     * This is why dispatch.c requires a QUIC port as well as this sniff.
     *
     * An ordinary iterative DNS query — recursion-desired clear, one question,
     * no answers — whose transaction ID happens to end in 0xff reads as a
     * long header announcing an IETF draft version with a one-byte connection
     * ID. Nothing structural distinguishes them, so around one query in a
     * thousand would be taken away from the DNS parser if the sniff were
     * trusted on its own.
     */
    static const uint8_t dns_query[] = {
        0xc0, 0xff,                          /* transaction ID */
        0x00, 0x00,                          /* flags: a query, RD clear */
        0x00, 0x01,                          /* one question */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  /* no answers, authority, extra */
        0x01, 'a', 0x00, 0x00, 0x01, 0x00, 0x01
    };

    assert(quic_sniff(dns_query, sizeof(dns_query)) == 1);
}

static void test_version_names(void) {
    assert(strcmp(quic_version_name(QUIC_VERSION_1), "v1, RFC 9000") == 0);
    assert(strcmp(quic_version_name(QUIC_VERSION_2), "v2, RFC 9369") == 0);
    assert(strcmp(quic_version_name(0xff00001du), "IETF draft") == 0);
    assert(strcmp(quic_version_name(0x1a2a3a4au),
                  "reserved to force version negotiation") == 0);
    assert(strcmp(quic_version_name(0x12345678u), "unknown") == 0);
    assert(quic_version_is_known(0x12345678u) == 0);
    assert(strcmp(quic_packet_kind_name(QUIC_PACKET_RETRY), "Retry") == 0);
}

int main(void) {
    test_initial_long_header();
    test_coalesced_packets();
    test_coalescing_is_capped();
    test_version_2_renumbers_the_packet_types();
    test_version_negotiation();
    test_version_negotiation_with_a_ragged_list();
    test_retry_reserves_its_integrity_tag();
    test_retry_shorter_than_its_tag();
    test_short_header_is_not_guessed_at();
    test_unknown_version_stops_at_the_connection_ids();

    test_connection_id_beyond_the_version_1_limit();
    test_connection_id_longer_than_the_datagram();
    test_token_length_beyond_the_datagram();
    test_length_beyond_the_datagram();
    test_varint_announcing_more_bytes_than_arrived();
    test_varint_widths();
    test_parse_rejects_nothing_to_parse();

    test_sniff_accepts_a_long_header();
    test_sniff_requires_a_version_it_knows();
    test_sniff_requires_the_header_form_and_fixed_bits();
    test_sniff_rejects_connection_ids_that_do_not_fit();
    test_short_header_predicate();
    test_sniff_alone_would_claim_a_dns_query();
    test_version_names();

    printf("quic tests passed\n");
    return 0;
}
