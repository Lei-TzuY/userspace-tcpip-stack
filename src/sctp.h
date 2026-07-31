#ifndef SCTP_H
#define SCTP_H

/*
 * sctp.h — Stream Control Transmission Protocol (RFC 9260, was RFC 4960)
 *
 * Common header, 12 bytes, followed by one or more chunks:
 *
 *   Src Port (2)  Dst Port (2)  Verification Tag (4)  Checksum (4)
 *
 * Each chunk is a TLV:
 *
 *   Type (1)  Flags (1)  Length (2)  Value (Length - 4)
 *
 * with the length counting its own four-byte header and *excluding* the
 * padding that aligns the next chunk to a four-byte boundary. A chunk
 * declaring a length below 4 therefore describes something smaller than its
 * own header; walking by the declared length without rejecting that never
 * advances, which is the shape this parser is most careful about.
 *
 * The checksum is CRC-32C (RFC 3309), not the one's-complement sum the rest of
 * the stack uses, and it is the one field of an SCTP packet that is *not* big
 * endian — see sctp_checksum_ok().
 */

#include "common.h"

#define SCTP_COMMON_HDR_LEN 12
#define SCTP_CHUNK_HDR_LEN   4

/* Storage caps. A packet can carry more than these; the counts below record
   what arrived, and the arrays hold what is shown. */
#define SCTP_MAX_CHUNKS      16
#define SCTP_MAX_PARAMS       8
#define SCTP_MAX_GAP_BLOCKS   8
#define SCTP_MAX_CAUSES       4

/* Chunk types. The top two bits are not part of the identity — they tell a
   receiver what to do with a type it does not know (RFC 9260 §3.2). */
#define SCTP_CHUNK_DATA              0u
#define SCTP_CHUNK_INIT              1u
#define SCTP_CHUNK_INIT_ACK          2u
#define SCTP_CHUNK_SACK              3u
#define SCTP_CHUNK_HEARTBEAT         4u
#define SCTP_CHUNK_HEARTBEAT_ACK     5u
#define SCTP_CHUNK_ABORT             6u
#define SCTP_CHUNK_SHUTDOWN          7u
#define SCTP_CHUNK_SHUTDOWN_ACK      8u
#define SCTP_CHUNK_ERROR             9u
#define SCTP_CHUNK_COOKIE_ECHO      10u
#define SCTP_CHUNK_COOKIE_ACK       11u
#define SCTP_CHUNK_ECNE             12u
#define SCTP_CHUNK_CWR              13u
#define SCTP_CHUNK_SHUTDOWN_COMPLETE 14u
#define SCTP_CHUNK_AUTH             15u
#define SCTP_CHUNK_I_DATA           64u
#define SCTP_CHUNK_ASCONF_ACK      128u
#define SCTP_CHUNK_RE_CONFIG       130u
#define SCTP_CHUNK_PAD             132u
#define SCTP_CHUNK_FORWARD_TSN     192u
#define SCTP_CHUNK_ASCONF          193u

/* DATA chunk flags (RFC 9260 §3.3.1). */
#define SCTP_DATA_FLAG_E 0x01u   /* last fragment of a message */
#define SCTP_DATA_FLAG_B 0x02u   /* first fragment of a message */
#define SCTP_DATA_FLAG_U 0x04u   /* unordered */
#define SCTP_DATA_FLAG_I 0x08u   /* SACK immediately (RFC 7053) */

/* What a receiver is meant to do with a chunk type it does not recognise. */
typedef enum {
    SCTP_UNKNOWN_STOP = 0,        /* 00 — discard the rest of the packet */
    SCTP_UNKNOWN_STOP_REPORT,     /* 01 — the same, and report it */
    SCTP_UNKNOWN_SKIP,            /* 10 — skip this chunk, keep going */
    SCTP_UNKNOWN_SKIP_REPORT      /* 11 — the same, and report it */
} SctpUnknownAction;

/* One variable parameter of an INIT / INIT ACK, or one error cause of an
   ABORT / ERROR. Both are the same {type, length, value} shape. */
typedef struct {
    uint16_t type;
    uint16_t length;       /* as declared, header included */
    uint16_t stored_len;   /* value bytes actually present, not what was
                              declared — they differ for a truncated parameter */
} SctpParam;

typedef struct {
    uint16_t start;        /* offsets from the cumulative TSN, inclusive */
    uint16_t end;
} SctpGapBlock;

typedef struct {
    uint8_t  type;
    uint8_t  flags;
    uint16_t length;             /* as declared, header included */
    const uint8_t* value;        /* NULL when nothing followed the header */
    size_t   value_len;          /* bytes actually present, not what the
                                    sender declared */
    int      length_invalid;     /* declared below the 4-byte chunk header */
    int      truncated;          /* declared more than the packet held */
    int      detail_valid;       /* the union below was filled in */

    union {
        struct {
            uint32_t tsn;
            uint16_t stream_id;
            uint16_t stream_seq;
            uint32_t ppid;
            size_t   user_data_len;
        } data;
        struct {
            uint32_t initiate_tag;
            uint32_t a_rwnd;
            uint16_t out_streams;
            uint16_t in_streams;
            uint32_t initial_tsn;
            SctpParam params[SCTP_MAX_PARAMS];
            unsigned param_count;      /* stored */
            unsigned params_seen;      /* walked, which can exceed the above */
            int      param_overrun;    /* a parameter ran past the chunk */
        } init;
        struct {
            uint32_t cum_tsn_ack;
            uint32_t a_rwnd;
            uint16_t gap_count;        /* as declared */
            uint16_t dup_count;        /* as declared */
            SctpGapBlock gaps[SCTP_MAX_GAP_BLOCKS];
            unsigned gaps_stored;
            int      counts_overrun;   /* the declared counts do not fit */
        } sack;
        struct {
            uint32_t cum_tsn_ack;
        } shutdown;
        struct {
            SctpParam causes[SCTP_MAX_CAUSES];
            unsigned  cause_count;     /* stored */
            unsigned  causes_seen;
            int       cause_overrun;
        } error;
        struct {
            uint32_t new_cum_tsn;
        } forward_tsn;
    } u;
} SctpChunk;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t vtag;
    uint32_t checksum;           /* as it appeared, host order */

    SctpChunk chunks[SCTP_MAX_CHUNKS];
    unsigned  chunk_count;       /* stored */
    unsigned  chunks_seen;       /* walked */
    int       walk_stopped;      /* a chunk's length made the walk unsafe */
    size_t    trailing_bytes;    /* left over after the last complete chunk */
} SctpPacket;

int sctp_parse(const uint8_t* data, size_t len, SctpPacket* out);

/*
 * Verify the CRC-32C over the whole SCTP packet. `len` must be the length of
 * the SCTP packet as the IP layer reports it, not the size of whatever buffer
 * happens to hold it: trailing Ethernet padding would otherwise be summed in
 * and every checksum would read as wrong.
 */
int sctp_checksum_ok(const uint8_t* data, size_t len);

/* Exposed for the unit test, which checks it against the published CRC-32C
   check value rather than against whatever this implementation produces. */
uint32_t sctp_crc32c(const uint8_t* data, size_t len);

void sctp_print(const SctpPacket* pkt, int checksum_ok);

const char*       sctp_chunk_type_name(uint8_t type);
const char*       sctp_param_type_name(uint16_t type);
const char*       sctp_cause_code_name(uint16_t code);
SctpUnknownAction sctp_unknown_action(uint8_t type);

#endif /* SCTP_H */
