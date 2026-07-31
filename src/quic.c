/*
 * quic.c — QUIC long headers (RFC 8999, RFC 9000, RFC 9369)
 *
 * See quic.h for what is and is not readable here. Two shapes in this file are
 * the ones worth being careful about:
 *
 *   - The variable-length integer of RFC 9000 §16 encodes its own width in its
 *     top two bits, so a two-byte buffer can announce an eight-byte field. The
 *     width is checked against what arrived before any of it is read.
 *   - One UDP datagram may carry several QUIC packets back to back, and the
 *     Length field of each is what says where the next begins. That is a
 *     sender-controlled offset driving a loop, so the walk is capped and every
 *     step is required to advance.
 */

#include "quic.h"

static uint32_t rd32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

/*
 * RFC 9000 §16: the two most significant bits of the first byte give the
 * length of the encoding — 1, 2, 4 or 8 bytes — and the remaining 62 bits are
 * the value.
 */
static int read_varint(const uint8_t* data, size_t len, size_t offset,
                       uint64_t* value, size_t* width) {
    size_t bytes, index;
    uint64_t result;

    if (offset >= len)
        return -1;

    bytes = (size_t)1u << (data[offset] >> 6);
    if (bytes > len - offset)
        return -1;

    result = (uint64_t)(data[offset] & 0x3Fu);
    for (index = 1; index < bytes; index++)
        result = (result << 8) | data[offset + index];

    *value = result;
    *width = bytes;
    return 0;
}

/* The drafts that became version 1 share its packet-type numbering. */
static int version_is_v1_like(uint32_t version) {
    return version == QUIC_VERSION_1
        || (version & 0xFFFFFF00u) == 0xFF000000u;
}

/* RFC 9000 §15 reserves every version of the form 0x?a?a?a?a to make sure
   implementations really do fall back to version negotiation. */
static int version_is_reserved(uint32_t version) {
    return (version & 0x0F0F0F0Fu) == 0x0A0A0A0Au;
}

int quic_version_is_known(uint32_t version) {
    return version == QUIC_VERSION_NEGOTIATION
        || version == QUIC_VERSION_2
        || version_is_v1_like(version)
        || version_is_reserved(version);
}

const char* quic_version_name(uint32_t version) {
    if (version == QUIC_VERSION_NEGOTIATION) return "version negotiation";
    if (version == QUIC_VERSION_1)           return "v1, RFC 9000";
    if (version == QUIC_VERSION_2)           return "v2, RFC 9369";
    if ((version & 0xFFFFFF00u) == 0xFF000000u) return "IETF draft";
    if (version_is_reserved(version))
        return "reserved to force version negotiation";
    return "unknown";
}

const char* quic_packet_kind_name(QuicPacketKind kind) {
    switch (kind) {
        case QUIC_PACKET_INITIAL:      return "Initial";
        case QUIC_PACKET_0RTT:         return "0-RTT";
        case QUIC_PACKET_HANDSHAKE:    return "Handshake";
        case QUIC_PACKET_RETRY:        return "Retry";
        case QUIC_PACKET_VERSION_NEGOTIATION: return "Version Negotiation";
        case QUIC_PACKET_SHORT_HEADER: return "1-RTT (short header)";
        default:                       return "unknown";
    }
}

/*
 * The two type bits mean different things in different versions: RFC 9369
 * renumbered them precisely so that a v2 packet cannot be mistaken for a v1
 * one by an implementation that ignores the version.
 */
static QuicPacketKind kind_of(uint32_t version, uint8_t type_bits) {
    if (version == QUIC_VERSION_NEGOTIATION)
        return QUIC_PACKET_VERSION_NEGOTIATION;

    if (version == QUIC_VERSION_2) {
        switch (type_bits) {
            case 0:  return QUIC_PACKET_RETRY;
            case 1:  return QUIC_PACKET_INITIAL;
            case 2:  return QUIC_PACKET_0RTT;
            default: return QUIC_PACKET_HANDSHAKE;
        }
    }

    if (version_is_v1_like(version)) {
        switch (type_bits) {
            case 0:  return QUIC_PACKET_INITIAL;
            case 1:  return QUIC_PACKET_0RTT;
            case 2:  return QUIC_PACKET_HANDSHAKE;
            default: return QUIC_PACKET_RETRY;
        }
    }

    /* RFC 8999 stops at the connection IDs. Everything past them, the packet
       type included, is defined by a version we do not know. */
    return QUIC_PACKET_UNKNOWN;
}

/*
 * Copy one connection ID. The declared length can exceed both what arrived and
 * what this struct holds, so `*stored` is the number of bytes really in `dest`
 * — never the number the sender claimed.
 */
static size_t take_cid(const uint8_t* data, size_t len, size_t offset,
                       uint8_t declared, uint8_t* dest, uint8_t* stored,
                       int* truncated) {
    size_t available = len - offset;
    size_t present = declared;
    size_t keep;

    if (present > available) {
        present = available;
        *truncated = 1;
    }
    keep = present > QUIC_MAX_CID_LEN ? QUIC_MAX_CID_LEN : present;
    if (keep > 0)
        memcpy(dest, data + offset, keep);
    *stored = (uint8_t)keep;
    return present;
}

static void parse_one(const uint8_t* data, size_t len, QuicPacket* out) {
    size_t offset;
    size_t width;
    uint64_t available;

    memset(out, 0, sizeof(*out));
    out->first_byte  = data[0];
    out->long_header = (data[0] & 0x80u) != 0;
    out->fixed_bit   = (data[0] & 0x40u) != 0;

    /* Unless a Length field says otherwise, a packet runs to the end of the
       datagram. Setting that first keeps every early return from leaving a
       zero here, which the coalescing loop would read as no progress. */
    out->packet_len = len;
    out->header_len = len;

    if (!out->long_header) {
        /* The destination connection ID has no length prefix in a short
           header — the receiver is meant to know how long the IDs it issued
           are. Guessing would produce a plausible-looking wrong answer. */
        out->kind = QUIC_PACKET_SHORT_HEADER;
        return;
    }

    if (len < 5) {
        out->truncated = 1;
        return;
    }
    out->version   = rd32(data + 1);
    out->type_bits = (uint8_t)((data[0] >> 4) & 0x03u);
    offset = 5;

    if (offset >= len) {
        out->truncated = 1;
        return;
    }
    out->dcid_len = data[offset++];
    offset += take_cid(data, len, offset, out->dcid_len,
                       out->dcid, &out->dcid_stored, &out->truncated);
    if (out->dcid_len > QUIC_MAX_CID_LEN)
        out->cid_over_limit = 1;
    if (out->truncated || offset >= len) {
        out->truncated = 1;
        out->header_len = offset;
        return;
    }

    out->scid_len = data[offset++];
    offset += take_cid(data, len, offset, out->scid_len,
                       out->scid, &out->scid_stored, &out->truncated);
    if (out->scid_len > QUIC_MAX_CID_LEN)
        out->cid_over_limit = 1;
    out->header_len = offset;
    if (out->truncated)
        return;

    out->kind = kind_of(out->version, out->type_bits);

    if (out->kind == QUIC_PACKET_VERSION_NEGOTIATION) {
        /* A server's list of what it does support. RFC 9000 §17.2.1: this is
           the whole rest of the datagram, four bytes per version. */
        size_t rest = len - offset;
        unsigned index;
        out->version_count = (unsigned)(rest / 4u);
        out->version_list_ragged = (rest % 4u) != 0;
        for (index = 0; index < out->version_count
                        && index < QUIC_MAX_VERSIONS; index++) {
            out->versions[index] = rd32(data + offset + (size_t)index * 4u);
            out->versions_stored++;
        }
        return;
    }

    if (out->kind == QUIC_PACKET_UNKNOWN)
        return;   /* past the invariants, in a version we cannot read */

    if (out->kind == QUIC_PACKET_RETRY) {
        /* No Length field: a Retry runs to the end of the datagram, and its
           last 16 bytes are the integrity tag rather than token bytes. */
        size_t rest = len - offset;
        out->has_token = 1;
        if (rest >= 16u) {
            out->token_len = (uint64_t)(rest - 16u);
            out->token_present = rest - 16u;
        } else {
            out->truncated = 1;
        }
        return;
    }

    if (out->kind == QUIC_PACKET_INITIAL) {
        if (read_varint(data, len, offset, &out->token_len, &width) != 0) {
            out->truncated = 1;
            return;
        }
        offset += width;
        out->has_token = 1;

        available = (uint64_t)(len - offset);
        if (out->token_len > available) {
            out->token_present = len - offset;
            out->truncated = 1;
            out->header_len = offset;
            return;
        }
        out->token_present = (size_t)out->token_len;
        offset += (size_t)out->token_len;
    }

    if (read_varint(data, len, offset, &out->length, &width) != 0) {
        out->truncated = 1;
        out->header_len = offset;
        return;
    }
    offset += width;
    out->has_length = 1;
    out->header_len = offset;

    available = (uint64_t)(len - offset);
    if (out->length > available) {
        out->truncated = 1;
        return;                 /* packet_len already spans what arrived */
    }
    out->packet_len = offset + (size_t)out->length;
}

int quic_sniff(const uint8_t* data, size_t len) {
    uint32_t version;
    size_t offset;
    uint8_t cid_len;

    /* One byte of flags, four of version, and a length byte for each
       connection ID is the least a long header can be. */
    if (!data || len < 7)
        return 0;
    if ((data[0] & 0x80u) == 0)
        return 0;

    version = rd32(data + 1);
    if (!quic_version_is_known(version))
        return 0;

    /* Every version but Version Negotiation sets the fixed bit, unless the
       peers have agreed to grease it (RFC 9287) — which they cannot have
       done in a handshake this parser is watching from the outside. */
    if (version != QUIC_VERSION_NEGOTIATION && (data[0] & 0x40u) == 0)
        return 0;

    offset = 5;
    cid_len = data[offset++];
    if (cid_len > QUIC_MAX_CID_LEN || cid_len >= len - offset)
        return 0;               /* the SCID length byte has to fit too */
    offset += cid_len;

    cid_len = data[offset++];
    if (cid_len > QUIC_MAX_CID_LEN || cid_len > len - offset)
        return 0;

    return 1;
}

int quic_is_short_header(const uint8_t* data, size_t len) {
    if (!data || len < 1)
        return 0;
    /* Header form clear, fixed bit set (RFC 9000 §17.3). That is the whole of
       what a short header says about itself in clear. */
    return (data[0] & 0x80u) == 0 && (data[0] & 0x40u) != 0;
}

int quic_parse(const uint8_t* data, size_t len, QuicDatagram* out) {
    size_t offset = 0;

    if (!data || !out) {
        fprintf(stderr, "[quic] Missing packet data or output header\n");
        return -1;
    }
    if (len < 1) {
        fprintf(stderr, "[quic] Too short: %zu bytes\n", len);
        return -1;
    }

    memset(out, 0, sizeof(*out));
    out->total_len = len;

    while (offset < len) {
        QuicPacket* packet;

        if (out->count >= QUIC_MAX_COALESCED) {
            out->more = 1;
            break;
        }

        packet = &out->packets[out->count++];
        parse_one(data + offset, len - offset, packet);

        /* Only the three packet types carrying a Length can be followed by
           another packet in the same datagram (RFC 9000 §12.2), and a step of
           zero would make this loop stand still. */
        if (!packet->has_length || packet->packet_len == 0
                || packet->packet_len > len - offset)
            break;
        offset += packet->packet_len;
    }

    return 0;
}

/* ── print ───────────────────────────────────────────────────────────────── */

static void print_cid(const char* label, const uint8_t* cid,
                      uint8_t declared, uint8_t stored) {
    unsigned index;

    printf("│      %-6s: %u byte(s)", label, declared);
    if (stored > 0) {
        printf("  ");
        for (index = 0; index < stored; index++)
            printf("%02x", cid[index]);
    }
    if (stored < declared)
        printf("  (first %u shown)", stored);
    printf("\n");
}

static void print_packet(unsigned index, const QuicPacket* packet) {
    printf("│  packet %-2u : %s", index, quic_packet_kind_name(packet->kind));
    if (packet->long_header)
        printf("  version=0x%08x (%s)", packet->version,
               quic_version_name(packet->version));
    printf("\n");

    if (!packet->long_header) {
        printf("│      the connection ID has no length prefix here, so its "
               "size is not readable\n");
        return;
    }

    if (!packet->fixed_bit)
        printf("│    [quic] the fixed bit is clear (RFC 9000 §17.2)\n");

    print_cid("DCID", packet->dcid, packet->dcid_len, packet->dcid_stored);
    print_cid("SCID", packet->scid, packet->scid_len, packet->scid_stored);
    if (packet->cid_over_limit)
        printf("│    [quic] a connection ID is longer than the %d bytes "
               "version 1 allows\n", QUIC_MAX_CID_LEN);

    if (packet->kind == QUIC_PACKET_VERSION_NEGOTIATION) {
        unsigned version;
        printf("│      %-6s: %u version(s)\n", "Offers", packet->version_count);
        for (version = 0; version < packet->versions_stored; version++)
            printf("│        0x%08x  (%s)\n", packet->versions[version],
                   quic_version_name(packet->versions[version]));
        if (packet->versions_stored < packet->version_count)
            printf("│    [quic] %u further version(s) not shown\n",
                   packet->version_count - packet->versions_stored);
        if (packet->version_list_ragged)
            printf("│    [quic] the version list is not a whole number of "
                   "4-byte versions\n");
        return;
    }

    if (packet->kind == QUIC_PACKET_UNKNOWN) {
        printf("│      nothing past the connection IDs is readable without "
               "knowing this version\n");
        return;
    }

    if (packet->has_token)
        printf("│      %-6s: %llu byte(s)%s\n", "Token",
               (unsigned long long)packet->token_len,
               packet->kind == QUIC_PACKET_RETRY
                   ? "  (plus a 16-byte integrity tag)" : "");

    if (packet->has_length)
        printf("│      %-6s: %llu byte(s) of packet number and payload, "
               "encrypted\n", "Length", (unsigned long long)packet->length);

    if (packet->truncated)
        printf("│    [quic] a declared length ran past the end of the "
               "datagram\n");
}

void quic_print(const QuicDatagram* datagram) {
    unsigned index;

    printf("┌─ QUIC ─────────────────────────────────────────────┐\n");
    printf("│  Packets   : %u in %zu byte(s)\n",
           datagram->count, datagram->total_len);

    for (index = 0; index < datagram->count; index++)
        print_packet(index, &datagram->packets[index]);

    if (datagram->more)
        printf("│    [quic] more than %d coalesced packets — the rest are "
               "not shown\n", QUIC_MAX_COALESCED);

    printf("└────────────────────────────────────────────────────┘\n");
}
