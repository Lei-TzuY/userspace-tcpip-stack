/*
 * dhcpv6.c — DHCPv6 parser implementation
 */

#include "dhcpv6.h"

static uint16_t read_u16_be(const uint8_t* p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t read_u32_be(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] <<  8) | (uint32_t)p[3];
}

const char* dhcpv6_msg_type_name(uint8_t type) {
    switch (type) {
        case DHCPV6_SOLICIT:       return "SOLICIT";
        case DHCPV6_ADVERTISE:     return "ADVERTISE";
        case DHCPV6_REQUEST:       return "REQUEST";
        case DHCPV6_CONFIRM:       return "CONFIRM";
        case DHCPV6_RENEW:         return "RENEW";
        case DHCPV6_REBIND:        return "REBIND";
        case DHCPV6_REPLY:         return "REPLY";
        case DHCPV6_RELEASE:       return "RELEASE";
        case DHCPV6_DECLINE:       return "DECLINE";
        case DHCPV6_RECONFIGURE:   return "RECONFIGURE";
        case DHCPV6_INFO_REQUEST:  return "INFO-REQUEST";
        default:                   return "UNKNOWN";
    }
}

int dhcpv6_parse(const uint8_t* data, size_t len, Dhcpv6Message* out) {
    if (len < DHCPV6_MIN_LEN) {
        fprintf(stderr, "[dhcpv6] Too short: %zu bytes (need %d)\n",
                len, DHCPV6_MIN_LEN);
        return -1;
    }

    memset(out, 0, sizeof(*out));
    out->msg_type      = data[0];
    out->transaction_id = ((uint32_t)data[1] << 16)
                        | ((uint32_t)data[2] <<  8)
                        | (uint32_t)data[3];

    /* Walk options (TLV: type=2, len=2, value) */
    size_t pos = 4;
    while (pos + 4 <= len) {
        uint16_t opt_type = read_u16_be(data + pos);
        uint16_t opt_len  = read_u16_be(data + pos + 2);
        pos += 4;
        if (pos + opt_len > len)
            break;

        switch (opt_type) {
            case DHCPV6_OPT_CLIENTID:
                out->client_duid_len = opt_len;
                break;
            case DHCPV6_OPT_SERVERID:
                out->server_duid_len = opt_len;
                break;
            case DHCPV6_OPT_IA_NA:
                /* IA_NA: IAID(4) + T1(4) + T2(4) + sub-options */
                if (opt_len >= 12) {
                    const uint8_t* sub = data + pos + 12;
                    size_t sub_len = opt_len - 12;
                    size_t spos = 0;
                    while (spos + 4 <= sub_len) {
                        uint16_t stype = read_u16_be(sub + spos);
                        uint16_t slen  = read_u16_be(sub + spos + 2);
                        spos += 4;
                        if (spos + slen > sub_len) break;
                        if (stype == DHCPV6_OPT_IAADDR && slen >= 24
                                && !out->has_ia_addr) {
                            out->has_ia_addr = 1;
                            memcpy(out->ia_addr, sub + spos, 16);
                            out->preferred_lifetime = read_u32_be(sub + spos + 16);
                            out->valid_lifetime     = read_u32_be(sub + spos + 20);
                        }
                        spos += slen;
                    }
                }
                break;
            case DHCPV6_OPT_DNS_SERVERS:
                {
                    int n = (int)(opt_len / 16);
                    if (n > DHCPV6_MAX_DNS) n = DHCPV6_MAX_DNS;
                    out->dns_count = n;
                    for (int i = 0; i < n; i++)
                        memcpy(out->dns_servers[i], data + pos + i * 16, 16);
                }
                break;
            default:
                break;
        }
        pos += opt_len;
    }
    return 0;
}

void dhcpv6_print(const Dhcpv6Message* msg) {
    printf("┌─ DHCPv6 ───────────────────────────────────────────┐\n");
    printf("│  Type      : %s\n", dhcpv6_msg_type_name(msg->msg_type));
    printf("│  XID       : 0x%06x\n", msg->transaction_id);
    if (msg->client_duid_len)
        printf("│  Client ID : %u bytes\n", msg->client_duid_len);
    if (msg->server_duid_len)
        printf("│  Server ID : %u bytes\n", msg->server_duid_len);
    if (msg->has_ia_addr) {
        const uint8_t* a = msg->ia_addr;
        printf("│  IA Addr   : %x:%x:%x:%x:%x:%x:%x:%x\n",
               (unsigned)((a[0]<<8)|a[1]),  (unsigned)((a[2]<<8)|a[3]),
               (unsigned)((a[4]<<8)|a[5]),  (unsigned)((a[6]<<8)|a[7]),
               (unsigned)((a[8]<<8)|a[9]),  (unsigned)((a[10]<<8)|a[11]),
               (unsigned)((a[12]<<8)|a[13]),(unsigned)((a[14]<<8)|a[15]));
        printf("│  Valid LT  : %u s\n", msg->valid_lifetime);
    }
    if (msg->dns_count > 0) {
        printf("│  DNS Srv   : %d server(s)\n", msg->dns_count);
    }
    printf("└────────────────────────────────────────────────────┘\n");
}
