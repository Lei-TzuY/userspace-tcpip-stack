/*
 * sctp.c — Stream Control Transmission Protocol (RFC 9260)
 *
 * See sctp.h for the wire format. Three things here are worth knowing before
 * reading the code:
 *
 *   - A chunk declares its own length, and that length drives the walk to the
 *     next chunk. Anything below the four-byte chunk header would make the
 *     walk stand still, so it stops the walk instead.
 *   - Everything an INIT, an ABORT or an ERROR carries is a second TLV walk
 *     nested inside the first, with the same hazard.
 *   - The checksum is CRC-32C, and it is the one field of the packet that is
 *     not big endian.
 */

#include "sctp.h"

/*
 * Reflected CRC-32C (Castagnoli, polynomial 0x1EDC6F41; 0x82F63B78 reversed),
 * four bits at a time. A nibble table is 64 bytes rather than the usual
 * kilobyte and still costs only two lookups per byte, which is far more than
 * an offline analyser needs.
 *
 * tests/test_sctp_parse.c checks this against the published check value for
 * "123456789" and the all-zero vector from RFC 3720 Appendix B, so the table
 * is verified against something other than itself.
 */
static const uint32_t k_crc32c_nibble[16] = {
    0x00000000u, 0x105EC76Fu, 0x20BD8EDEu, 0x30E349B1u,
    0x417B1DBCu, 0x5125DAD3u, 0x61C69362u, 0x7198540Du,
    0x82F63B78u, 0x92A8FC17u, 0xA24BB5A6u, 0xB21572C9u,
    0xC38D26C4u, 0xD3D3E1ABu, 0xE330A81Au, 0xF36E6F75u,
};

static uint32_t crc32c_update(uint32_t crc, const uint8_t* data, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        crc ^= data[i];
        crc = (crc >> 4) ^ k_crc32c_nibble[crc & 0x0Fu];
        crc = (crc >> 4) ^ k_crc32c_nibble[crc & 0x0Fu];
    }
    return crc;
}

uint32_t sctp_crc32c(const uint8_t* data, size_t len) {
    if (!data) return 0;
    return crc32c_update(0xFFFFFFFFu, data, len) ^ 0xFFFFFFFFu;
}

int sctp_checksum_ok(const uint8_t* data, size_t len) {
    static const uint8_t zeros[4] = { 0, 0, 0, 0 };
    uint32_t crc, declared;

    if (!data || len < SCTP_COMMON_HDR_LEN)
        return 0;

    /* The sender computed this with the checksum field zeroed, so the field
       itself is replaced with four zero bytes rather than skipped — the CRC
       is position-dependent and skipping would shift everything after it. */
    crc = crc32c_update(0xFFFFFFFFu, data, 8);
    crc = crc32c_update(crc, zeros, sizeof(zeros));
    crc = crc32c_update(crc, data + SCTP_COMMON_HDR_LEN,
                        len - SCTP_COMMON_HDR_LEN);
    crc ^= 0xFFFFFFFFu;

    /* RFC 9260 Appendix A byte-swaps the result before storing it, so this one
       field reads little-endian while every other field in the packet is big
       endian. Reading it the usual way makes every checksum look wrong. */
    declared = (uint32_t)data[8]
             | ((uint32_t)data[9] << 8)
             | ((uint32_t)data[10] << 16)
             | ((uint32_t)data[11] << 24);

    return crc == declared;
}

/* ── field readers ───────────────────────────────────────────────────────── */

static uint16_t rd16(const uint8_t* p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t rd32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

/* Round a chunk or parameter length up to the next four-byte boundary. The
   padding is not counted in the declared length but does sit on the wire. */
static size_t pad4(size_t n) {
    return (n + 3u) & ~(size_t)3u;
}

/* ── the TLV walk shared by INIT parameters and error causes ─────────────── */

/*
 * Walk a {type, length, value} list, storing up to `capacity` entries.
 *
 * Returns the number walked, which can exceed what was stored. *overrun is set
 * when an entry declares a length the enclosing chunk cannot hold, or one
 * below the four-byte header — either way the walk stops there, because the
 * declared length is the only thing that says where the next entry begins.
 */
static unsigned walk_tlv(const uint8_t* value, size_t value_len, size_t start,
                         SctpParam* out, unsigned capacity,
                         unsigned* stored, int* overrun) {
    unsigned seen = 0;
    size_t offset = start;

    *stored = 0;
    *overrun = 0;

    while (offset + 4u <= value_len) {
        uint16_t type = rd16(value + offset);
        uint16_t length = rd16(value + offset + 2);
        size_t available = value_len - offset - 4u;
        size_t declared;

        seen++;

        if (length < 4u) {
            *overrun = 1;
            break;
        }
        declared = (size_t)length - 4u;

        if (*stored < capacity) {
            SctpParam* param = &out[*stored];
            param->type = type;
            param->length = length;
            param->stored_len = (uint16_t)(declared < available
                                           ? declared : available);
            (*stored)++;
        }

        if (declared > available) {
            *overrun = 1;
            break;
        }
        offset += pad4(4u + declared);
    }

    return seen;
}

/* ── per-chunk detail ────────────────────────────────────────────────────── */

static void decode_data(SctpChunk* chunk) {
    if (chunk->value_len < 12u) return;
    chunk->u.data.tsn           = rd32(chunk->value);
    chunk->u.data.stream_id     = rd16(chunk->value + 4);
    chunk->u.data.stream_seq    = rd16(chunk->value + 6);
    chunk->u.data.ppid          = rd32(chunk->value + 8);
    chunk->u.data.user_data_len = chunk->value_len - 12u;
    chunk->detail_valid = 1;
}

static void decode_init(SctpChunk* chunk) {
    if (chunk->value_len < 16u) return;
    chunk->u.init.initiate_tag = rd32(chunk->value);
    chunk->u.init.a_rwnd       = rd32(chunk->value + 4);
    chunk->u.init.out_streams  = rd16(chunk->value + 8);
    chunk->u.init.in_streams   = rd16(chunk->value + 10);
    chunk->u.init.initial_tsn  = rd32(chunk->value + 12);
    chunk->u.init.params_seen  = walk_tlv(chunk->value, chunk->value_len, 16u,
                                          chunk->u.init.params,
                                          SCTP_MAX_PARAMS,
                                          &chunk->u.init.param_count,
                                          &chunk->u.init.param_overrun);
    chunk->detail_valid = 1;
}

static void decode_sack(SctpChunk* chunk) {
    size_t needed;
    unsigned index;

    if (chunk->value_len < 12u) return;
    chunk->u.sack.cum_tsn_ack = rd32(chunk->value);
    chunk->u.sack.a_rwnd      = rd32(chunk->value + 4);
    chunk->u.sack.gap_count   = rd16(chunk->value + 8);
    chunk->u.sack.dup_count   = rd16(chunk->value + 10);
    chunk->detail_valid = 1;

    /* Both counts are the sender's, and each block is four bytes. The product
       is what decides how far a reader walks, so it is checked against the
       chunk before any of it is read. */
    needed = 12u + (size_t)chunk->u.sack.gap_count * 4u
                 + (size_t)chunk->u.sack.dup_count * 4u;
    chunk->u.sack.counts_overrun = needed > chunk->value_len;

    for (index = 0; index < chunk->u.sack.gap_count
                    && index < SCTP_MAX_GAP_BLOCKS; index++) {
        size_t offset = 12u + (size_t)index * 4u;
        if (offset + 4u > chunk->value_len) break;
        chunk->u.sack.gaps[index].start = rd16(chunk->value + offset);
        chunk->u.sack.gaps[index].end   = rd16(chunk->value + offset + 2);
        chunk->u.sack.gaps_stored++;
    }
}

static void decode_error(SctpChunk* chunk) {
    chunk->u.error.causes_seen = walk_tlv(chunk->value, chunk->value_len, 0u,
                                          chunk->u.error.causes,
                                          SCTP_MAX_CAUSES,
                                          &chunk->u.error.cause_count,
                                          &chunk->u.error.cause_overrun);
    chunk->detail_valid = 1;
}

static void decode_chunk_detail(SctpChunk* chunk) {
    switch (chunk->type) {
        case SCTP_CHUNK_DATA:
            decode_data(chunk);
            break;
        case SCTP_CHUNK_INIT:
        case SCTP_CHUNK_INIT_ACK:
            decode_init(chunk);
            break;
        case SCTP_CHUNK_SACK:
            decode_sack(chunk);
            break;
        case SCTP_CHUNK_SHUTDOWN:
            if (chunk->value_len >= 4u) {
                chunk->u.shutdown.cum_tsn_ack = rd32(chunk->value);
                chunk->detail_valid = 1;
            }
            break;
        case SCTP_CHUNK_ABORT:
        case SCTP_CHUNK_ERROR:
            decode_error(chunk);
            break;
        case SCTP_CHUNK_FORWARD_TSN:
            if (chunk->value_len >= 4u) {
                chunk->u.forward_tsn.new_cum_tsn = rd32(chunk->value);
                chunk->detail_valid = 1;
            }
            break;
        default:
            break;
    }
}

/* ── parse ───────────────────────────────────────────────────────────────── */

int sctp_parse(const uint8_t* data, size_t len, SctpPacket* out) {
    SctpChunk discarded;   /* somewhere to decode into past SCTP_MAX_CHUNKS */
    size_t offset;

    if (!data || !out) {
        fprintf(stderr, "[sctp] Missing packet data or output header\n");
        return -1;
    }
    if (len < SCTP_COMMON_HDR_LEN) {
        fprintf(stderr, "[sctp] Too short: %zu bytes (need %d)\n",
                len, SCTP_COMMON_HDR_LEN);
        return -1;
    }

    memset(out, 0, sizeof(*out));
    out->src_port = rd16(data);
    out->dst_port = rd16(data + 2);
    out->vtag     = rd32(data + 4);
    out->checksum = (uint32_t)data[8]
                  | ((uint32_t)data[9] << 8)
                  | ((uint32_t)data[10] << 16)
                  | ((uint32_t)data[11] << 24);

    offset = SCTP_COMMON_HDR_LEN;
    while (offset + SCTP_CHUNK_HDR_LEN <= len) {
        SctpChunk* chunk;
        size_t available, declared;

        chunk = out->chunk_count < SCTP_MAX_CHUNKS
              ? &out->chunks[out->chunk_count] : &discarded;
        memset(chunk, 0, sizeof(*chunk));

        chunk->type   = data[offset];
        chunk->flags  = data[offset + 1];
        chunk->length = rd16(data + offset + 2);
        out->chunks_seen++;

        /* A chunk shorter than its own header cannot say where the next one
           starts, and advancing by it would not advance at all. */
        if (chunk->length < SCTP_CHUNK_HDR_LEN) {
            chunk->length_invalid = 1;
            out->walk_stopped = 1;
            if (chunk != &discarded) out->chunk_count++;
            break;
        }

        available = len - offset - SCTP_CHUNK_HDR_LEN;
        declared  = (size_t)chunk->length - SCTP_CHUNK_HDR_LEN;

        /* value_len is what is really there. Storing the declared length here
           would hand every consumer a number it could walk off the end of. */
        chunk->value_len = declared < available ? declared : available;
        chunk->value     = chunk->value_len > 0
                         ? data + offset + SCTP_CHUNK_HDR_LEN : NULL;
        chunk->truncated = declared > available;

        decode_chunk_detail(chunk);

        if (chunk != &discarded) out->chunk_count++;

        if (chunk->truncated) {
            /* Whatever the sender meant to follow this chunk did not arrive. */
            out->walk_stopped = 1;
            break;
        }

        offset += pad4(SCTP_CHUNK_HDR_LEN + declared);
    }

    if (!out->walk_stopped && offset < len)
        out->trailing_bytes = len - offset;

    return 0;
}

/* ── names ───────────────────────────────────────────────────────────────── */

const char* sctp_chunk_type_name(uint8_t type) {
    switch (type) {
        case SCTP_CHUNK_DATA:              return "DATA";
        case SCTP_CHUNK_INIT:              return "INIT";
        case SCTP_CHUNK_INIT_ACK:          return "INIT ACK";
        case SCTP_CHUNK_SACK:              return "SACK";
        case SCTP_CHUNK_HEARTBEAT:         return "HEARTBEAT";
        case SCTP_CHUNK_HEARTBEAT_ACK:     return "HEARTBEAT ACK";
        case SCTP_CHUNK_ABORT:             return "ABORT";
        case SCTP_CHUNK_SHUTDOWN:          return "SHUTDOWN";
        case SCTP_CHUNK_SHUTDOWN_ACK:      return "SHUTDOWN ACK";
        case SCTP_CHUNK_ERROR:             return "ERROR";
        case SCTP_CHUNK_COOKIE_ECHO:       return "COOKIE ECHO";
        case SCTP_CHUNK_COOKIE_ACK:        return "COOKIE ACK";
        case SCTP_CHUNK_ECNE:              return "ECNE";
        case SCTP_CHUNK_CWR:               return "CWR";
        case SCTP_CHUNK_SHUTDOWN_COMPLETE: return "SHUTDOWN COMPLETE";
        case SCTP_CHUNK_AUTH:              return "AUTH";
        /* I-DATA is a DATA chunk with a different layout (RFC 8260), so it is
           named but not decoded as one — its message identifier sits where
           DATA's stream sequence number does. */
        case SCTP_CHUNK_I_DATA:            return "I-DATA";
        case SCTP_CHUNK_ASCONF_ACK:        return "ASCONF ACK";
        case SCTP_CHUNK_RE_CONFIG:         return "RE-CONFIG";
        case SCTP_CHUNK_PAD:               return "PAD";
        case SCTP_CHUNK_FORWARD_TSN:       return "FORWARD TSN";
        case SCTP_CHUNK_ASCONF:            return "ASCONF";
        default:                           return "UNKNOWN";
    }
}

const char* sctp_param_type_name(uint16_t type) {
    switch (type) {
        case 1:      return "Heartbeat Info";
        case 5:      return "IPv4 Address";
        case 6:      return "IPv6 Address";
        case 7:      return "State Cookie";
        case 8:      return "Unrecognized Parameter";
        case 9:      return "Cookie Preservative";
        case 11:     return "Host Name Address";
        case 12:     return "Supported Address Types";
        case 13:     return "Outgoing SSN Reset Request";
        case 0x8000: return "ECN Capable";
        case 0x8002: return "Random";
        case 0x8003: return "Chunk List";
        case 0x8004: return "Requested HMAC Algorithm";
        case 0x8008: return "Supported Extensions";
        case 0xC000: return "Forward-TSN Supported";
        case 0xC001: return "Add IP Address";
        case 0xC002: return "Delete IP Address";
        default:     return "unknown";
    }
}

const char* sctp_cause_code_name(uint16_t code) {
    switch (code) {
        case 1:  return "Invalid Stream Identifier";
        case 2:  return "Missing Mandatory Parameter";
        case 3:  return "Stale Cookie Error";
        case 4:  return "Out of Resource";
        case 5:  return "Unresolvable Address";
        case 6:  return "Unrecognized Chunk Type";
        case 7:  return "Invalid Mandatory Parameter";
        case 8:  return "Unrecognized Parameters";
        case 9:  return "No User Data";
        case 10: return "Cookie Received While Shutting Down";
        case 11: return "Restart of an Association with New Addresses";
        case 12: return "User Initiated Abort";
        case 13: return "Protocol Violation";
        default: return "unknown";
    }
}

SctpUnknownAction sctp_unknown_action(uint8_t type) {
    return (SctpUnknownAction)((type >> 6) & 0x03u);
}

/* ── print ───────────────────────────────────────────────────────────────── */

static void print_data_flags(uint8_t flags) {
    printf("  [%s%s%s%s]",
           (flags & SCTP_DATA_FLAG_B) ? "B" : "",
           (flags & SCTP_DATA_FLAG_E) ? "E" : "",
           (flags & SCTP_DATA_FLAG_U) ? "U" : "",
           (flags & SCTP_DATA_FLAG_I) ? "I" : "");
}

static void print_params(const SctpParam* params, unsigned stored,
                         unsigned seen, int overrun, const char* label,
                         const char* (*name_of)(uint16_t)) {
    unsigned index;

    for (index = 0; index < stored; index++)
        printf("│      %s %-5u %-28s %u byte(s)\n", label, params[index].type,
               name_of(params[index].type), params[index].stored_len);

    if (seen > stored)
        printf("│    [sctp] %u further %s(s) not shown\n", seen - stored, label);
    if (overrun)
        printf("│    [sctp] a %s ran past the end of the chunk\n", label);
}

/* The name table answers "UNKNOWN" for a type it does not carry, and that
   answer is what decides whether the RFC 9260 §3.2 handling note is printed. */
static int chunk_type_known(uint8_t type) {
    return strcmp(sctp_chunk_type_name(type), "UNKNOWN") != 0;
}

static void print_chunk(unsigned index, const SctpChunk* chunk) {
    printf("│  chunk %-2u  : %-17s len=%u flags=0x%02x",
           index, sctp_chunk_type_name(chunk->type), chunk->length,
           chunk->flags);
    if (chunk->type == SCTP_CHUNK_DATA)
        print_data_flags(chunk->flags);
    printf("\n");

    if (chunk->length_invalid) {
        printf("│    [sctp] declared length %u is below the %d-byte chunk "
               "header\n", chunk->length, SCTP_CHUNK_HDR_LEN);
        return;
    }
    if (chunk->truncated)
        printf("│    [sctp] declared %u bytes, %zu arrived\n",
               chunk->length, chunk->value_len + SCTP_CHUNK_HDR_LEN);

    if (!chunk_type_known(chunk->type)) {
        static const char* action[] = {
            "stop", "stop and report", "skip", "skip and report"
        };
        printf("│    unknown type — a receiver should %s (RFC 9260 §3.2)\n",
               action[sctp_unknown_action(chunk->type)]);
        return;
    }

    if (!chunk->detail_valid)
        return;

    switch (chunk->type) {
        case SCTP_CHUNK_DATA:
            printf("│      TSN=%u stream=%u seq=%u ppid=%u  payload=%zu byte(s)\n",
                   chunk->u.data.tsn, chunk->u.data.stream_id,
                   chunk->u.data.stream_seq, chunk->u.data.ppid,
                   chunk->u.data.user_data_len);
            break;
        case SCTP_CHUNK_INIT:
        case SCTP_CHUNK_INIT_ACK:
            printf("│      tag=0x%08x a_rwnd=%u out=%u in=%u initial TSN=%u\n",
                   chunk->u.init.initiate_tag, chunk->u.init.a_rwnd,
                   chunk->u.init.out_streams, chunk->u.init.in_streams,
                   chunk->u.init.initial_tsn);
            print_params(chunk->u.init.params, chunk->u.init.param_count,
                         chunk->u.init.params_seen,
                         chunk->u.init.param_overrun,
                         "param", sctp_param_type_name);
            break;
        case SCTP_CHUNK_SACK: {
            unsigned gap;
            printf("│      cum TSN=%u a_rwnd=%u gaps=%u dups=%u\n",
                   chunk->u.sack.cum_tsn_ack, chunk->u.sack.a_rwnd,
                   chunk->u.sack.gap_count, chunk->u.sack.dup_count);
            for (gap = 0; gap < chunk->u.sack.gaps_stored; gap++)
                printf("│      gap %u: TSN %u..%u\n", gap,
                       chunk->u.sack.cum_tsn_ack
                           + chunk->u.sack.gaps[gap].start,
                       chunk->u.sack.cum_tsn_ack
                           + chunk->u.sack.gaps[gap].end);
            if (chunk->u.sack.counts_overrun)
                printf("│    [sctp] the declared gap and duplicate counts do "
                       "not fit in the chunk\n");
            break;
        }
        case SCTP_CHUNK_SHUTDOWN:
            printf("│      cum TSN=%u\n", chunk->u.shutdown.cum_tsn_ack);
            break;
        case SCTP_CHUNK_ABORT:
        case SCTP_CHUNK_ERROR:
            print_params(chunk->u.error.causes, chunk->u.error.cause_count,
                         chunk->u.error.causes_seen,
                         chunk->u.error.cause_overrun,
                         "cause", sctp_cause_code_name);
            break;
        case SCTP_CHUNK_FORWARD_TSN:
            printf("│      new cum TSN=%u\n", chunk->u.forward_tsn.new_cum_tsn);
            break;
        default:
            break;
    }
}

void sctp_print(const SctpPacket* pkt, int checksum_ok) {
    unsigned index;

    printf("┌─ SCTP ─────────────────────────────────────────────┐\n");
    printf("│  Src Port  : %u\n", pkt->src_port);
    printf("│  Dst Port  : %u\n", pkt->dst_port);
    printf("│  Ver Tag   : 0x%08x\n", pkt->vtag);
    printf("│  Checksum  : 0x%08x  (CRC-32C %s)\n", pkt->checksum,
           checksum_ok ? "valid" : "INVALID");
    printf("│  Chunks    : %u\n", pkt->chunks_seen);

    for (index = 0; index < pkt->chunk_count; index++)
        print_chunk(index, &pkt->chunks[index]);

    if (pkt->chunks_seen > pkt->chunk_count)
        printf("│    [sctp] %u further chunk(s) not shown\n",
               pkt->chunks_seen - pkt->chunk_count);
    if (pkt->walk_stopped)
        printf("│    [sctp] chunk walk stopped early\n");
    if (pkt->trailing_bytes)
        printf("│    [sctp] %zu byte(s) after the last chunk\n",
               pkt->trailing_bytes);

    printf("└────────────────────────────────────────────────────┘\n");
}
