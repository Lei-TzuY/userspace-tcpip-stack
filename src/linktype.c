/*
 * linktype.c — link-layer headers other than Ethernet
 */

#include "linktype.h"
#include "pcap.h"
#include "ethernet.h"

#define SLL_HDR_LEN   16
#define SLL2_HDR_LEN  20
#define NULL_HDR_LEN   4

static uint16_t read16be(const uint8_t* data) {
    return (uint16_t)((data[0] << 8) | data[1]);
}

static uint32_t read32be(const uint8_t* data) {
    return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16)
         | ((uint32_t)data[2] << 8)  |  (uint32_t)data[3];
}

static uint32_t read32le(const uint8_t* data) {
    return ((uint32_t)data[3] << 24) | ((uint32_t)data[2] << 16)
         | ((uint32_t)data[1] << 8)  |  (uint32_t)data[0];
}

/* ── LINKTYPE_NULL ───────────────────────────────────────────────────────── */

/*
 * The BSD loopback header is a four-byte address family written in the
 * *capturing host's* byte order, with no marker saying which that was. The
 * value is small either way, so the orientation that yields a recognised
 * family is the right one; only a corrupt header matches neither.
 *
 * The IPv6 constant is not portable between systems — 24 on NetBSD and
 * OpenBSD, 28 on FreeBSD, 30 on macOS, 10 on Linux — so all of them are
 * accepted. That is what libpcap's own readers do, for the same reason.
 */
static int null_family_kind(uint32_t family, LinkPayloadKind* kind) {
    switch (family) {
        case 2:
            *kind = LINK_PAYLOAD_IPV4;
            return 1;
        case 10: case 24: case 28: case 30:
            *kind = LINK_PAYLOAD_IPV6;
            return 1;
        default:
            return 0;
    }
}

static int decode_null(const uint8_t* data, size_t len, LinkFrame* out) {
    uint32_t native;
    uint32_t swapped;
    LinkPayloadKind kind;

    if (len < NULL_HDR_LEN)
        return -1;

    native  = read32le(data);
    swapped = read32be(data);

    if (null_family_kind(native, &kind)) {
        out->null_family = native;
    } else if (null_family_kind(swapped, &kind)) {
        out->null_family = swapped;
    } else {
        /* Report the header we could not make sense of rather than guessing. */
        out->null_family = native;
        out->kind        = LINK_PAYLOAD_NONE;
        out->hdr_len     = NULL_HDR_LEN;
        out->payload     = data + NULL_HDR_LEN;
        out->payload_len = len - NULL_HDR_LEN;
        return 0;
    }

    out->kind        = kind;
    out->hdr_len     = NULL_HDR_LEN;
    out->payload     = data + NULL_HDR_LEN;
    out->payload_len = len - NULL_HDR_LEN;
    return 0;
}

/* ── LINKTYPE_RAW ────────────────────────────────────────────────────────── */

/*
 * No link header at all: the packet begins with the IP header, and the version
 * nibble is the only thing that says which. Common on tunnel and VPN
 * interfaces, where there is no link layer to record.
 */
static int decode_raw(const uint8_t* data, size_t len, LinkFrame* out) {
    if (len < 1)
        return -1;

    out->hdr_len     = 0;
    out->payload     = data;
    out->payload_len = len;

    switch (data[0] >> 4) {
        case 4:  out->kind = LINK_PAYLOAD_IPV4; break;
        case 6:  out->kind = LINK_PAYLOAD_IPV6; break;
        default: out->kind = LINK_PAYLOAD_NONE; break;
    }
    return 0;
}

/* ── LINKTYPE_LINUX_SLL ──────────────────────────────────────────────────── */

/*
 * Linux "cooked" capture, produced when capturing on the `any` pseudo-device
 * or on an interface with no usable link header.
 *
 *   0-1   packet type (to us, broadcast, outgoing, ...)
 *   2-3   ARPHRD_ hardware type
 *   4-5   link-layer address length
 *   6-13  link-layer address, padded to 8 bytes
 *   14-15 protocol, as an EtherType
 */
static int decode_sll(const uint8_t* data, size_t len, LinkFrame* out) {
    uint16_t addr_len;

    if (len < SLL_HDR_LEN)
        return -1;

    out->sll_packet_type = read16be(data);
    out->sll_arphrd_type = read16be(data + 2);
    addr_len             = read16be(data + 4);
    /* The address field is a fixed 8 bytes; the length says how much of it is
       meaningful, and a larger value describes an address that was truncated
       to fit. Clamp rather than reading past the field. */
    out->sll_addr_len = addr_len > sizeof(out->sll_addr)
                      ? (uint16_t)sizeof(out->sll_addr) : addr_len;
    memcpy(out->sll_addr, data + 6, sizeof(out->sll_addr));

    out->ethertype   = read16be(data + 14);
    out->kind        = LINK_PAYLOAD_ETHERTYPE;
    out->hdr_len     = SLL_HDR_LEN;
    out->payload     = data + SLL_HDR_LEN;
    out->payload_len = len - SLL_HDR_LEN;
    return 0;
}

/*
 * Cooked v2, which moves the protocol to the front and adds the interface
 * index.
 *
 *   0-1   protocol, as an EtherType
 *   2-3   reserved
 *   4-7   interface index
 *   8-9   ARPHRD_ hardware type
 *   10    packet type
 *   11    link-layer address length
 *   12-19 link-layer address, padded to 8 bytes
 */
static int decode_sll2(const uint8_t* data, size_t len, LinkFrame* out) {
    uint8_t addr_len;

    if (len < SLL2_HDR_LEN)
        return -1;

    out->ethertype           = read16be(data);
    out->sll_interface_index = read32be(data + 4);
    out->sll_arphrd_type     = read16be(data + 8);
    out->sll_packet_type     = data[10];
    addr_len                 = data[11];
    out->sll_addr_len = addr_len > sizeof(out->sll_addr)
                      ? (uint16_t)sizeof(out->sll_addr) : addr_len;
    memcpy(out->sll_addr, data + 12, sizeof(out->sll_addr));

    out->kind        = LINK_PAYLOAD_ETHERTYPE;
    out->hdr_len     = SLL2_HDR_LEN;
    out->payload     = data + SLL2_HDR_LEN;
    out->payload_len = len - SLL2_HDR_LEN;
    return 0;
}

/* ── entry points ────────────────────────────────────────────────────────── */

int link_type_supported(uint32_t link_type) {
    switch (link_type) {
        case LINKTYPE_NULL:
        case LINKTYPE_RAW:
        case LINKTYPE_LINUX_SLL:
        case LINKTYPE_LINUX_SLL2:
            return 1;
        default:
            return 0;
    }
}

int link_decode(uint32_t link_type, const uint8_t* data, size_t len,
                LinkFrame* out) {
    if (!data || !out)
        return -1;

    memset(out, 0, sizeof(*out));

    switch (link_type) {
        case LINKTYPE_NULL:       return decode_null(data, len, out);
        case LINKTYPE_RAW:        return decode_raw(data, len, out);
        case LINKTYPE_LINUX_SLL:  return decode_sll(data, len, out);
        case LINKTYPE_LINUX_SLL2: return decode_sll2(data, len, out);
        default:                  return -1;
    }
}

const char* link_type_name(uint32_t link_type) {
    switch (link_type) {
        case LINKTYPE_NULL:       return "BSD loopback";
        case LINKTYPE_ETHERNET:   return "Ethernet";
        case LINKTYPE_RAW:        return "Raw IP";
        case LINKTYPE_LINUX_SLL:  return "Linux cooked v1";
        case LINKTYPE_LINUX_SLL2: return "Linux cooked v2";
        default:                  return "UNKNOWN";
    }
}

static const char* sll_packet_type_name(uint16_t packet_type) {
    switch (packet_type) {
        case 0:  return "to us";
        case 1:  return "broadcast";
        case 2:  return "multicast";
        case 3:  return "to another host";
        case 4:  return "outgoing";
        default: return "unknown";
    }
}

void link_print(uint32_t link_type, const LinkFrame* frame) {
    if (!frame)
        return;

    switch (link_type) {
        case LINKTYPE_NULL:
            printf("┌─ Loopback ─────────────────────────────────────────┐\n");
            printf("│  Family    : %u  (%s)\n", frame->null_family,
                   frame->kind == LINK_PAYLOAD_IPV4 ? "AF_INET"
                 : frame->kind == LINK_PAYLOAD_IPV6 ? "AF_INET6"
                 : "unrecognised");
            printf("└────────────────────────────────────────────────────┘\n");
            break;

        case LINKTYPE_RAW:
            printf("┌─ Raw IP ───────────────────────────────────────────┐\n");
            printf("│  Version   : %s\n",
                   frame->kind == LINK_PAYLOAD_IPV4 ? "4"
                 : frame->kind == LINK_PAYLOAD_IPV6 ? "6"
                 : "unrecognised");
            printf("└────────────────────────────────────────────────────┘\n");
            break;

        case LINKTYPE_LINUX_SLL:
        case LINKTYPE_LINUX_SLL2: {
            size_t i;
            printf("┌─ Linux cooked v%d ──────────────────────────────────┐\n",
                   link_type == LINKTYPE_LINUX_SLL ? 1 : 2);
            printf("│  Direction : %u  (%s)\n", frame->sll_packet_type,
                   sll_packet_type_name(frame->sll_packet_type));
            printf("│  Hardware  : type=%u addr-len=%u\n",
                   frame->sll_arphrd_type, frame->sll_addr_len);
            if (frame->sll_addr_len > 0) {
                printf("│  Address   : ");
                for (i = 0; i < frame->sll_addr_len; i++)
                    printf("%s%02x", i ? ":" : "", frame->sll_addr[i]);
                printf("\n");
            }
            if (link_type == LINKTYPE_LINUX_SLL2)
                printf("│  Interface : index=%u\n", frame->sll_interface_index);
            printf("│  Protocol  : 0x%04x  (%s)\n", frame->ethertype,
                   ethertype_name(frame->ethertype));
            printf("└────────────────────────────────────────────────────┘\n");
            break;
        }

        default:
            break;
    }
}
