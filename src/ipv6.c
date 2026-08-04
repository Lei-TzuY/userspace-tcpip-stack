#include "ipv6.h"

static uint16_t read16(const uint8_t* data) {
    return (uint16_t)((data[0] << 8) | data[1]);
}

static uint32_t read32(const uint8_t* data) {
    return ((uint32_t)data[0] << 24)
         | ((uint32_t)data[1] << 16)
         | ((uint32_t)data[2] << 8)
         | data[3];
}

static int is_extension_header(uint8_t next_header) {
    return next_header == 0
        || next_header == 43
        || next_header == 44
        || next_header == 51
        || next_header == 60;
}

static void print_address(const uint8_t* address) {
    for (size_t i = 0; i < 8; i++) {
        if (i > 0)
            putchar(':');
        printf("%x", read16(address + (i * 2)));
    }
}

int ipv6_parse(const uint8_t* data, size_t len, Ipv6Header* out) {
    uint32_t first_word;
    size_t total_len;

    if (!data || !out) {
        fprintf(stderr, "[ipv6] Missing packet data or output header\n");
        return -1;
    }
    if (len < IPV6_HDR_LEN) {
        fprintf(stderr, "[ipv6] Too short: %zu bytes (need %d)\n",
                len, IPV6_HDR_LEN);
        return -1;
    }

    first_word = ((uint32_t)data[0] << 24)
               | ((uint32_t)data[1] << 16)
               | ((uint32_t)data[2] << 8)
               | data[3];
    memset(out, 0, sizeof(*out));
    out->version = (uint8_t)(first_word >> 28);
    if (out->version != IPV6_VERSION) {
        fprintf(stderr, "[ipv6] Bad version: %u (expected 6)\n", out->version);
        return -1;
    }

    out->traffic_class = (uint8_t)((first_word >> 20) & 0xffu);
    out->flow_label = first_word & 0x000fffffu;
    out->payload_len = read16(data + 4);
    out->next_header = data[6];
    out->hop_limit = data[7];
    memcpy(out->src, data + 8, sizeof(out->src));
    memcpy(out->dst, data + 24, sizeof(out->dst));

    total_len = IPV6_HDR_LEN + (size_t)out->payload_len;
    if (len < total_len) {
        fprintf(stderr, "[ipv6] Truncated packet: have %zu, need %zu bytes\n",
                len, total_len);
        return -1;
    }
    return 0;
}

int ipv6_locate_payload(const Ipv6Header* header,
                        const uint8_t* packet, size_t packet_len,
                        Ipv6Payload* out) {
    size_t declared_end;
    size_t offset = IPV6_HDR_LEN;
    uint8_t next_header;
    unsigned depth = 0;

    if (!header || !packet || !out) {
        fprintf(stderr, "[ipv6] Missing payload traversal input\n");
        return -1;
    }
    declared_end = IPV6_HDR_LEN + (size_t)header->payload_len;
    if (packet_len < declared_end) {
        fprintf(stderr, "[ipv6] Truncated packet while locating payload\n");
        return -1;
    }

    memset(out, 0, sizeof(*out));
    next_header = header->next_header;

    while (is_extension_header(next_header)) {
        uint8_t current = next_header;
        size_t ext_len;

        if (++depth > 8) {
            fprintf(stderr, "[ipv6] Too many extension headers\n");
            return -1;
        }
        if (declared_end - offset < 8) {
            fprintf(stderr, "[ipv6] Truncated extension header\n");
            return -1;
        }

        next_header = packet[offset];

        /* Work out how long this header claims to be, but read nothing that
           the claim points at yet. The length is a single attacker-controlled
           byte, so it has to be checked against the packet before it is used
           as a bound — a Routing Header declaring hdr_ext_len=0x3a would
           otherwise have us copying addresses from 400 bytes past the end. */
        if (current == 44) {
            ext_len = 8;   /* Fragment headers are a fixed size */
        } else if (current == 51) {
            ext_len = ((size_t)packet[offset + 1] + 2u) * 4u;
        } else {
            ext_len = ((size_t)packet[offset + 1] + 1u) * 8u;
        }

        if (ext_len == 0 || ext_len > declared_end - offset) {
            fprintf(stderr, "[ipv6] Invalid extension header length\n");
            return -1;
        }

        /* Past this point ext_len is known to fit, so offset + ext_len is a
           safe upper bound for anything read out of this header. */
        if (current == 44) {
            uint16_t frag = read16(packet + offset + 2);
            out->fragment_seen = 1;
            out->fragment_offset = (uint16_t)(frag >> 3);
            out->more_fragments = (frag & 0x1u) != 0;
            out->fragment_id = read32(packet + offset + 4);
        } else if (current == 43 && !out->has_routing) {
            /* Routing Header */
            out->has_routing = 1;
            out->routing_type          = packet[offset + 2];
            out->routing_segments_left = packet[offset + 3];
            /* Extract up to IPV6_ROUTING_MAX_SEGS 16-byte addresses
               beginning at byte 8 of the routing header. */
            size_t addr_bytes = ext_len - 8u;
            int n = (int)(addr_bytes / 16u);
            if (n > IPV6_ROUTING_MAX_SEGS) n = IPV6_ROUTING_MAX_SEGS;
            for (int i = 0; i < n; i++)
                memcpy(out->routing_segs[i], packet + offset + 8 + i * 16, 16);
            out->routing_seg_count = n;
        }

        offset += ext_len;
    }

    out->final_next_header = next_header;
    out->extension_len = offset - IPV6_HDR_LEN;
    if (next_header == 59) {
        out->payload = NULL;
        out->payload_len = 0;
    } else {
        out->payload = packet + offset;
        out->payload_len = declared_end - offset;
    }
    return 0;
}

const char* ipv6_next_header_name(uint8_t next_header) {
    switch (next_header) {
        case 0:            return "Hop-by-Hop Options";
        case 6:            return "TCP";
        case 17:           return "UDP";
        case 43:           return "Routing";
        case 44:           return "Fragment";
        case 51:           return "AH";
        case IPPROTO_ICMPV6: return "ICMPv6";
        case 59:           return "No Next Header";
        case 60:           return "Destination Options";
        default:           return "UNKNOWN";
    }
}

void ipv6_routing_print(const Ipv6Payload* inner) {
    static const char* rtype_name[] = { "Type0(deprecated)", NULL, "MIPv6", NULL, "SRv6" };
    const char* tname = (inner->routing_type < 5 && rtype_name[inner->routing_type])
                      ? rtype_name[inner->routing_type] : "UNKNOWN";

    printf("+-- IPv6 Routing Header ------------------------------------+\n");
    printf("|  Type      : %u  (%s)\n", inner->routing_type, tname);
    printf("|  Segs Left : %u\n", inner->routing_segments_left);
    for (int i = 0; i < inner->routing_seg_count; i++) {
        printf("|  Seg[%d]    : ", i);
        print_address(inner->routing_segs[i]);
        printf("\n");
    }
    printf("+------------------------------------------------------------+\n");
}

void ipv6_print(const Ipv6Header* header) {
    printf("+-- IPv6 ----------------------------------------------------+\n");
    printf("|  Src IP    : ");
    print_address(header->src);
    printf("\n");
    printf("|  Dst IP    : ");
    print_address(header->dst);
    printf("\n");
    printf("|  Next Hdr  : %u  (%s)\n",
           header->next_header, ipv6_next_header_name(header->next_header));
    printf("|  Hop Limit : %u\n", header->hop_limit);
    printf("|  Payload   : %u bytes\n", header->payload_len);
    printf("|  Traffic   : class=%u flow-label=0x%05x\n",
           header->traffic_class, header->flow_label);
    printf("+------------------------------------------------------------+\n");
}
