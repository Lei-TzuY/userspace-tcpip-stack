#ifndef QUIC_H
#define QUIC_H

/*
 * quic.h — QUIC long headers (RFC 8999 invariants, RFC 9000 v1, RFC 9369 v2)
 *
 * Only the part of a QUIC packet that is *not* encrypted can be read here, and
 * that is deliberate. Everything from the packet number onward is protected by
 * keys derived from the Initial secret, and even the packet number's own
 * length bits are masked by header protection — so this parser reports what is
 * on the wire in clear and stops, rather than printing a packet number it
 * cannot actually know.
 *
 * The long header, per RFC 8999 §5.1, is the same in every QUIC version:
 *
 *   byte 0    1 (long header) | version-specific bits
 *   version   4 bytes; 0 means Version Negotiation
 *   DCID Len  1 byte, then that many bytes
 *   SCID Len  1 byte, then that many bytes
 *
 * Everything after that is version-specific. For v1 and v2 the type is in bits
 * 5-4 of byte 0, and Initial / 0-RTT / Handshake carry a Length field that
 * says where the next coalesced packet in the same datagram begins.
 *
 * A short header (bit 7 clear) cannot be parsed from the packet alone: the
 * destination connection ID has no length prefix there, because the receiver
 * is expected to know how long the IDs it handed out are. It is reported as
 * such rather than guessed at.
 */

#include "common.h"

/* RFC 9000 §17.2 caps a connection ID at 20 bytes and requires a version 1
   endpoint to drop anything longer. RFC 8999 allows up to 255, so a longer one
   is recorded and reported rather than treated as a parse failure. */
#define QUIC_MAX_CID_LEN    20
#define QUIC_MAX_COALESCED   4
#define QUIC_MAX_VERSIONS    8

#define QUIC_VERSION_NEGOTIATION 0x00000000u
#define QUIC_VERSION_1           0x00000001u  /* RFC 9000 */
#define QUIC_VERSION_2           0x6b3343cfu  /* RFC 9369 */

typedef enum {
    QUIC_PACKET_UNKNOWN = 0,
    QUIC_PACKET_INITIAL,
    QUIC_PACKET_0RTT,
    QUIC_PACKET_HANDSHAKE,
    QUIC_PACKET_RETRY,
    QUIC_PACKET_VERSION_NEGOTIATION,
    QUIC_PACKET_SHORT_HEADER
} QuicPacketKind;

typedef struct {
    uint8_t  first_byte;
    int      long_header;
    int      fixed_bit;          /* RFC 9000 §17.2; may be greased (RFC 9287) */
    uint32_t version;
    uint8_t  type_bits;          /* bits 5-4 of byte 0, meaning is per version */
    QuicPacketKind kind;

    uint8_t  dcid[QUIC_MAX_CID_LEN];
    uint8_t  dcid_len;           /* as declared */
    uint8_t  dcid_stored;        /* bytes actually kept, which is what dcid
                                    holds — they differ past 20 bytes */
    uint8_t  scid[QUIC_MAX_CID_LEN];
    uint8_t  scid_len;
    uint8_t  scid_stored;
    int      cid_over_limit;     /* longer than version 1 permits */

    int      has_token;          /* Initial and Retry carry one */
    uint64_t token_len;          /* as declared */
    size_t   token_present;      /* bytes of it that arrived */

    int      has_length;
    uint64_t length;             /* declared payload length, packet number
                                    included (RFC 9000 §17.2) */

    uint32_t versions[QUIC_MAX_VERSIONS];
    unsigned version_count;      /* versions the server offered */
    unsigned versions_stored;
    int      version_list_ragged;/* not a whole number of 32-bit versions */

    size_t   header_len;         /* clear-text header bytes decoded */
    size_t   packet_len;         /* bytes this packet occupies in the datagram */
    int      truncated;          /* a declared length ran past the datagram */
} QuicPacket;

/* One UDP datagram, which may carry several QUIC packets back to back
   (RFC 9000 §12.2). */
typedef struct {
    QuicPacket packets[QUIC_MAX_COALESCED];
    unsigned   count;
    int        more;             /* bytes remained after the cap */
    size_t     total_len;
} QuicDatagram;

/*
 * Decide whether a UDP payload looks like QUIC.
 *
 * This is structural only — it requires a long header, a version this build
 * names, and connection ID lengths that fit inside the datagram. It is not
 * enough on its own: an ordinary DNS query can satisfy every one of those
 * tests, which is why the dispatcher also requires a QUIC port. See the
 * comment at the call site in dispatch.c.
 */
int quic_sniff(const uint8_t* data, size_t len);

/*
 * Does this look like a 1-RTT packet?
 *
 * There is nothing structural to test — a short header is one byte of flags
 * followed by a connection ID of a length only the endpoints know — so this
 * checks the two bits that are fixed and no more. It is only meaningful on a
 * port where QUIC is expected, which is where the dispatcher applies it.
 */
int quic_is_short_header(const uint8_t* data, size_t len);

int  quic_parse(const uint8_t* data, size_t len, QuicDatagram* out);
void quic_print(const QuicDatagram* datagram);

int         quic_version_is_known(uint32_t version);
const char* quic_version_name(uint32_t version);
const char* quic_packet_kind_name(QuicPacketKind kind);

#endif /* QUIC_H */
