/*
 * dhcp.c — DHCP wire-format parser (RFC 2131)
 */

#include "dhcp.h"

static uint16_t read16(const uint8_t* p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}
static uint32_t read32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

int dhcp_parse(const uint8_t* data, size_t len, DhcpMessage* out) {
    if (!data || !out || len < DHCP_MIN_LEN) return -1;

    memset(out, 0, sizeof(*out));
    out->op    = data[0];
    out->htype = data[1];
    out->hlen  = data[2];
    out->hops  = data[3];
    out->xid   = read32(data + 4);
    out->secs  = read16(data + 8);
    out->flags = read16(data + 10);
    memcpy(out->ciaddr, data + 12, 4);
    memcpy(out->yiaddr, data + 16, 4);
    memcpy(out->siaddr, data + 20, 4);
    memcpy(out->giaddr, data + 24, 4);
    memcpy(out->chaddr, data + 28, 16);
    /* sname[64] at 44, file[128] at 108 — skipped for brevity */

    /* Check magic cookie */
    if (len < DHCP_MIN_LEN + 4) return 0;  /* no options section */
    if (read32(data + DHCP_MIN_LEN) != DHCP_MAGIC) return 0;
    out->has_magic = 1;

    size_t offset = DHCP_MIN_LEN + 4;
    while (offset < len && out->opt_count < DHCP_MAX_OPTS) {
        uint8_t code = data[offset++];
        if (code == DHCP_OPT_PAD) continue;
        if (code == DHCP_OPT_END) break;
        if (offset >= len) break;
        uint8_t olen = data[offset++];
        if (offset + olen > len) break;

        DhcpOption* opt = &out->options[out->opt_count++];
        opt->code = code;
        opt->len  = olen;
        size_t copy = olen < sizeof(opt->data) ? olen : sizeof(opt->data);
        memcpy(opt->data, data + offset, copy);

        /* Extract common fields */
        switch (code) {
            case 53: if (olen >= 1) out->msg_type  = data[offset];    break;
            case 1:  if (olen >= 4) memcpy(out->subnet,    data + offset, 4); break;
            case 3:  if (olen >= 4) memcpy(out->router,    data + offset, 4); break;
            case 6:  if (olen >= 4) memcpy(out->dns,       data + offset, 4); break;
            case 51: if (olen >= 4) out->lease_time = read32(data + offset); break;
            case 54: if (olen >= 4) memcpy(out->server_id, data + offset, 4); break;
            case 12: {
                size_t n = olen < sizeof(out->hostname) - 1 ? olen : sizeof(out->hostname) - 1;
                memcpy(out->hostname, data + offset, n);
                out->hostname[n] = '\0';
                break;
            }
            default: break;
        }
        offset += olen;
    }
    return 0;
}

const char* dhcp_msg_type_name(uint8_t t) {
    switch (t) {
        case 1: return "DISCOVER";
        case 2: return "OFFER";
        case 3: return "REQUEST";
        case 4: return "DECLINE";
        case 5: return "ACK";
        case 6: return "NAK";
        case 7: return "RELEASE";
        case 8: return "INFORM";
        default: return "UNKNOWN";
    }
}

static void fmt_ip(const uint8_t* ip) {
    printf("%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}
static int is_zero(const uint8_t* p, size_t n) {
    for (size_t i = 0; i < n; i++) if (p[i]) return 0;
    return 1;
}

void dhcp_print(const DhcpMessage* msg) {
    printf("+-- DHCP (%s) ", msg->op == 1 ? "REQUEST" : "REPLY");
    if (msg->msg_type)
        printf("type=%s ", dhcp_msg_type_name(msg->msg_type));
    printf("---------------------------------------+\n");
    printf("|  XID       : 0x%08x\n", msg->xid);
    if (!is_zero(msg->ciaddr, 4)) { printf("|  ciaddr    : "); fmt_ip(msg->ciaddr); printf("\n"); }
    if (!is_zero(msg->yiaddr, 4)) { printf("|  yiaddr    : "); fmt_ip(msg->yiaddr); printf("\n"); }
    if (!is_zero(msg->siaddr, 4)) { printf("|  siaddr    : "); fmt_ip(msg->siaddr); printf("\n"); }
    if (!is_zero(msg->giaddr, 4)) { printf("|  giaddr    : "); fmt_ip(msg->giaddr); printf("\n"); }

    /* chaddr as MAC (first hlen bytes) */
    if (msg->htype == 1 && msg->hlen == 6) {
        printf("|  chaddr    : %02x:%02x:%02x:%02x:%02x:%02x\n",
               msg->chaddr[0], msg->chaddr[1], msg->chaddr[2],
               msg->chaddr[3], msg->chaddr[4], msg->chaddr[5]);
    }

    if (msg->hostname[0])
        printf("|  Hostname  : %s\n", msg->hostname);
    if (!is_zero(msg->subnet,    4)) { printf("|  Subnet    : "); fmt_ip(msg->subnet);    printf("\n"); }
    if (!is_zero(msg->router,    4)) { printf("|  Router    : "); fmt_ip(msg->router);    printf("\n"); }
    if (!is_zero(msg->dns,       4)) { printf("|  DNS       : "); fmt_ip(msg->dns);       printf("\n"); }
    if (!is_zero(msg->server_id, 4)) { printf("|  Server    : "); fmt_ip(msg->server_id); printf("\n"); }
    if (msg->lease_time)
        printf("|  Lease     : %u s\n", msg->lease_time);

    printf("+------------------------------------------------------------+\n");
}
