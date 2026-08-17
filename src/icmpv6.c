#include "icmpv6.h"

static uint16_t read16(const uint8_t* data) {
    return (uint16_t)((data[0] << 8) | data[1]);
}

static uint32_t read32(const uint8_t* data) {
    return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16)
         | ((uint32_t)data[2] <<  8) |  (uint32_t)data[3];
}

static void add_bytes(uint32_t* sum, const uint8_t* data, size_t len) {
    for (size_t i = 0; i + 1 < len; i += 2)
        *sum += (uint32_t)((data[i] << 8) | data[i + 1]);
    if (len & 1)
        *sum += (uint32_t)(data[len - 1] << 8);
}

static uint32_t fold_sum(uint32_t sum) {
    while (sum >> 16)
        sum = (sum & 0xffffu) + (sum >> 16);
    return sum;
}

/* ── NDP option parser ───────────────────────────────────────────────────── */

static int parse_ndp_options(const uint8_t* data, size_t len,
                             Icmpv6Header* out) {
    size_t offset = 0;

    /* Validate every option, including entries beyond the bounded number we
       retain for display. A zero length cannot advance, and a partial option
       makes the entire list malformed. */
    while (offset < len) {
        if (len - offset < 2) {
            fprintf(stderr, "[icmpv6] Truncated NDP option header\n");
            return -1;
        }
        uint8_t opt_len = data[offset + 1]; /* in 8-byte units */
        size_t opt_bytes = (size_t)opt_len * 8u;
        if (opt_len == 0 || opt_bytes > len - offset) {
            fprintf(stderr, "[icmpv6] Invalid NDP option length\n");
            return -1;
        }
        offset += opt_bytes;
    }

    offset = 0;
    while (offset < len && out->ndp_opt_count < ICMPV6_NDP_MAX_OPTS) {
        uint8_t opt_type  = data[offset];
        uint8_t opt_len   = data[offset + 1];
        size_t opt_bytes  = (size_t)opt_len * 8u;
        Icmpv6NdpOption* opt = &out->ndp_opts[out->ndp_opt_count];
        opt->type   = opt_type;
        opt->length = opt_len;

        switch (opt_type) {
            case ICMPV6_OPT_SRC_LLADDR:
            case ICMPV6_OPT_TGT_LLADDR:
                if (opt_bytes >= 8)
                    memcpy(opt->u.lladdr, data + offset + 2, 6);
                break;

            case ICMPV6_OPT_PREFIX_INFO:
                /* RFC 4861 §4.6.2: total 32 bytes */
                if (opt_bytes >= 32) {
                    opt->u.prefix.prefix_len        = data[offset + 2];
                    opt->u.prefix.flags             = data[offset + 3];
                    opt->u.prefix.valid_lifetime     = read32(data + offset + 4);
                    opt->u.prefix.preferred_lifetime = read32(data + offset + 8);
                    memcpy(opt->u.prefix.prefix, data + offset + 16, 16);
                }
                break;

            case ICMPV6_OPT_MTU:
                if (opt_bytes >= 8)
                    opt->u.mtu = read32(data + offset + 4);
                break;

            default:
                break;
        }

        out->ndp_opt_count++;
        offset += opt_bytes;
    }

    return 0;
}

/* ── icmpv6_parse ────────────────────────────────────────────────────────── */

int icmpv6_parse(const uint8_t* data, size_t len, Icmpv6Header* out) {
    if (!data || !out) {
        fprintf(stderr, "[icmpv6] Missing message data or output header\n");
        return -1;
    }
    if (len < ICMPV6_MIN_LEN) {
        fprintf(stderr, "[icmpv6] Too short: %zu bytes (need %d)\n",
                len, ICMPV6_MIN_LEN);
        return -1;
    }

    memset(out, 0, sizeof(*out));
    out->type     = data[0];
    out->code     = data[1];
    out->checksum = read16(data + 2);

    switch (out->type) {
        case ICMPV6_TYPE_ECHO_REQ:
        case ICMPV6_TYPE_ECHO_REPLY:
            if (len >= 8) {
                out->echo_id  = read16(data + 4);
                out->echo_seq = read16(data + 6);
            }
            if (len > 8) {
                out->payload     = data + 8;
                out->payload_len = len - 8;
            }
            break;

        case ICMPV6_TYPE_NEIGHBOR_SOL:
            /* 4 bytes reserved + 16-byte target + options */
            if (len >= 24) {
                memcpy(out->target, data + 8, 16);
                if (len > 24
                        && parse_ndp_options(data + 24, len - 24, out) != 0)
                    return -1;
            }
            break;

        case ICMPV6_TYPE_NEIGHBOR_ADV:
            /* 4 bytes R/S/O flags + 16-byte target + options */
            if (len >= 24) {
                out->na_flags = read32(data + 4);
                memcpy(out->target, data + 8, 16);
                if (len > 24
                        && parse_ndp_options(data + 24, len - 24, out) != 0)
                    return -1;
            }
            break;

        case ICMPV6_TYPE_ROUTER_SOL:
            /* 4 bytes reserved + options */
            if (len > 8
                    && parse_ndp_options(data + 8, len - 8, out) != 0)
                return -1;
            break;

        case ICMPV6_TYPE_ROUTER_ADV:
            /* Cur Hop Limit(1) + M/O flags(1) + Router Lifetime(2) +
               Reachable Time(4) + Retrans Timer(4) + options */
            if (len >= 16) {
                out->ra_hop_limit       = data[4];
                out->ra_flags           = data[5];
                out->ra_router_lifetime = read16(data + 6);
                out->ra_reachable_time  = read32(data + 8);
                out->ra_retrans_timer   = read32(data + 12);
                if (len > 16
                        && parse_ndp_options(data + 16, len - 16, out) != 0)
                    return -1;
            }
            break;

        case ICMPV6_TYPE_REDIRECT:
            /* 4 bytes reserved + 16-byte target + 16-byte destination + options */
            if (len >= 40) {
                memcpy(out->target, data + 8,  16);
                memcpy(out->dest,   data + 24, 16);
                if (len > 40
                        && parse_ndp_options(data + 40, len - 40, out) != 0)
                    return -1;
            }
            break;

        case ICMPV6_TYPE_DEST_UNREACH:
        case ICMPV6_TYPE_PACKET_TOO_BIG:
        case ICMPV6_TYPE_TIME_EXCEEDED:
        case ICMPV6_TYPE_PARAM_PROBLEM:
            if (out->type == ICMPV6_TYPE_PACKET_TOO_BIG && len >= 8)
                out->packet_too_big_mtu = read32(data + 4);
            /* Embedded IPv6 header starts at offset 8 (after 4-byte type/code/cksum
               + 4 bytes type-specific field).  Fixed IPv6 header = 40 bytes. */
            if (len >= ICMPV6_MIN_LEN + 40) {
                const uint8_t* inner = data + ICMPV6_MIN_LEN;
                out->has_embedded         = 1;
                out->embedded_next_header = inner[6];
                memcpy(out->embedded_src, inner + 8,  16);
                memcpy(out->embedded_dst, inner + 24, 16);
                if (len >= ICMPV6_MIN_LEN + 40 + 8) {
                    const uint8_t* tp = inner + 40;
                    uint8_t nh = out->embedded_next_header;
                    if (nh == 6 || nh == 17) { /* TCP or UDP */
                        out->embedded_src_port =
                            (uint16_t)((tp[0] << 8) | tp[1]);
                        out->embedded_dst_port =
                            (uint16_t)((tp[2] << 8) | tp[3]);
                    }
                }
            }
            if (len > ICMPV6_MIN_LEN) {
                out->payload     = data + ICMPV6_MIN_LEN;
                out->payload_len = len - ICMPV6_MIN_LEN;
            }
            break;
        default:
            if (len > ICMPV6_MIN_LEN) {
                out->payload     = data + ICMPV6_MIN_LEN;
                out->payload_len = len - ICMPV6_MIN_LEN;
            }
            break;
    }
    return 0;
}

/* ── icmpv6_checksum_ok ──────────────────────────────────────────────────── */

int icmpv6_checksum_ok(const Ipv6Header* ip,
                       const uint8_t* message, size_t message_len) {
    uint8_t pseudo_tail[8];
    uint32_t sum = 0;

    if (!ip || !message || message_len < ICMPV6_MIN_LEN
            || message_len > UINT32_MAX)
        return 0;

    add_bytes(&sum, ip->src, sizeof(ip->src));
    add_bytes(&sum, ip->dst, sizeof(ip->dst));
    pseudo_tail[0] = (uint8_t)((message_len >> 24) & 0xffu);
    pseudo_tail[1] = (uint8_t)((message_len >> 16) & 0xffu);
    pseudo_tail[2] = (uint8_t)((message_len >> 8) & 0xffu);
    pseudo_tail[3] = (uint8_t)(message_len & 0xffu);
    pseudo_tail[4] = 0;
    pseudo_tail[5] = 0;
    pseudo_tail[6] = 0;
    pseudo_tail[7] = IPPROTO_ICMPV6;
    add_bytes(&sum, pseudo_tail, sizeof(pseudo_tail));
    add_bytes(&sum, message, message_len);

    return fold_sum(sum) == 0xffffu;
}

/* ── helpers ─────────────────────────────────────────────────────────────── */

const char* icmpv6_type_name(uint8_t type) {
    switch (type) {
        case ICMPV6_TYPE_DEST_UNREACH:   return "Destination Unreachable";
        case ICMPV6_TYPE_PACKET_TOO_BIG: return "Packet Too Big";
        case ICMPV6_TYPE_TIME_EXCEEDED:  return "Time Exceeded";
        case ICMPV6_TYPE_PARAM_PROBLEM:  return "Parameter Problem";
        case ICMPV6_TYPE_ECHO_REQ:       return "Echo Request";
        case ICMPV6_TYPE_ECHO_REPLY:     return "Echo Reply";
        case ICMPV6_TYPE_ROUTER_SOL:     return "Router Solicitation";
        case ICMPV6_TYPE_ROUTER_ADV:     return "Router Advertisement";
        case ICMPV6_TYPE_NEIGHBOR_SOL:   return "Neighbor Solicitation";
        case ICMPV6_TYPE_NEIGHBOR_ADV:   return "Neighbor Advertisement";
        case ICMPV6_TYPE_REDIRECT:       return "Redirect";
        default:                         return "UNKNOWN";
    }
}

static void print_ipv6_addr(const uint8_t* addr) {
    for (int i = 0; i < 8; i++) {
        if (i > 0) putchar(':');
        printf("%x", (unsigned)((addr[i*2] << 8) | addr[i*2+1]));
    }
}

static void print_mac(const uint8_t* mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void print_ndp_options(const Icmpv6Header* header) {
    for (int i = 0; i < header->ndp_opt_count; i++) {
        const Icmpv6NdpOption* opt = &header->ndp_opts[i];
        switch (opt->type) {
            case ICMPV6_OPT_SRC_LLADDR:
                printf("|  Src LLAddr: ");
                print_mac(opt->u.lladdr);
                printf("\n");
                break;
            case ICMPV6_OPT_TGT_LLADDR:
                printf("|  Tgt LLAddr: ");
                print_mac(opt->u.lladdr);
                printf("\n");
                break;
            case ICMPV6_OPT_PREFIX_INFO:
                printf("|  Prefix    : ");
                print_ipv6_addr(opt->u.prefix.prefix);
                printf("/%u  L=%u A=%u  valid=%u  pref=%u\n",
                       opt->u.prefix.prefix_len,
                       (opt->u.prefix.flags >> 7) & 1,
                       (opt->u.prefix.flags >> 6) & 1,
                       opt->u.prefix.valid_lifetime,
                       opt->u.prefix.preferred_lifetime);
                break;
            case ICMPV6_OPT_MTU:
                printf("|  MTU       : %u\n", opt->u.mtu);
                break;
            default:
                printf("|  NDP opt   : type=%u len=%u\n",
                       opt->type, opt->length);
                break;
        }
    }
}

/* ── icmpv6_print ────────────────────────────────────────────────────────── */

void icmpv6_print(const Icmpv6Header* header, int checksum_valid) {
    const char* ck_str = checksum_valid ? "OK" : "BAD";

    printf("+-- ICMPv6 --------------------------------------------------+\n");
    printf("|  Type      : %u  (%s)\n",
           header->type, icmpv6_type_name(header->type));
    printf("|  Code      : %u\n", header->code);
    printf("|  Checksum  : 0x%04x  (%s)\n", header->checksum, ck_str);

    switch (header->type) {
        case ICMPV6_TYPE_ECHO_REQ:
        case ICMPV6_TYPE_ECHO_REPLY:
            printf("|  ID        : %u\n", header->echo_id);
            printf("|  Sequence  : %u\n", header->echo_seq);
            if (header->payload_len > 0)
                printf("|  Data Len  : %zu bytes\n", header->payload_len);
            break;

        case ICMPV6_TYPE_NEIGHBOR_SOL:
            printf("|  Target    : ");
            print_ipv6_addr(header->target);
            printf("\n");
            print_ndp_options(header);
            break;

        case ICMPV6_TYPE_NEIGHBOR_ADV:
            printf("|  Target    : ");
            print_ipv6_addr(header->target);
            printf("\n");
            printf("|  Flags     : %s%s%s\n",
                   (header->na_flags & ICMPV6_NA_ROUTER)    ? "R" : "-",
                   (header->na_flags & ICMPV6_NA_SOLICITED) ? "S" : "-",
                   (header->na_flags & ICMPV6_NA_OVERRIDE)  ? "O" : "-");
            print_ndp_options(header);
            break;

        case ICMPV6_TYPE_ROUTER_SOL:
            print_ndp_options(header);
            break;

        case ICMPV6_TYPE_ROUTER_ADV:
            printf("|  Hop Limit : %u\n", header->ra_hop_limit);
            printf("|  Flags     : %s%s\n",
                   (header->ra_flags & 0x80) ? "M" : "-",
                   (header->ra_flags & 0x40) ? "O" : "-");
            printf("|  Lifetime  : %u s\n", header->ra_router_lifetime);
            printf("|  Reach Time: %u ms\n", header->ra_reachable_time);
            printf("|  Retrans   : %u ms\n", header->ra_retrans_timer);
            print_ndp_options(header);
            break;

        case ICMPV6_TYPE_REDIRECT:
            printf("|  Target    : ");
            print_ipv6_addr(header->target);
            printf("\n");
            printf("|  Dest      : ");
            print_ipv6_addr(header->dest);
            printf("\n");
            print_ndp_options(header);
            break;

        case ICMPV6_TYPE_DEST_UNREACH:
        case ICMPV6_TYPE_PACKET_TOO_BIG:
        case ICMPV6_TYPE_TIME_EXCEEDED:
        case ICMPV6_TYPE_PARAM_PROBLEM:
            if (header->type == ICMPV6_TYPE_PACKET_TOO_BIG)
                printf("|  MTU       : %u\n", header->packet_too_big_mtu);
            if (header->has_embedded) {
                printf("|  Inner IPv6 Src: ");
                print_ipv6_addr(header->embedded_src);
                printf("\n");
                printf("|  Inner IPv6 Dst: ");
                print_ipv6_addr(header->embedded_dst);
                printf("\n");
                printf("|  Inner Proto   : %u\n", header->embedded_next_header);
                if (header->embedded_src_port || header->embedded_dst_port)
                    printf("|  Inner Ports   : %u -> %u\n",
                           header->embedded_src_port, header->embedded_dst_port);
            } else if (header->payload_len > 0) {
                printf("|  Data Len  : %zu bytes\n", header->payload_len);
            }
            break;
        default:
            if (header->payload_len > 0)
                printf("|  Data Len  : %zu bytes\n", header->payload_len);
            break;
    }

    printf("+------------------------------------------------------------+\n");
}
