/*
 * ntp.c — NTP parser implementation
 */

#include "ntp.h"

static uint64_t read_u64_be(const uint8_t* p) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48)
         | ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32)
         | ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16)
         | ((uint64_t)p[6] <<  8) | (uint64_t)p[7];
}

static uint32_t read_u32_be(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] <<  8) | (uint32_t)p[3];
}

int ntp_parse(const uint8_t* data, size_t len, NtpMessage* out) {
    if (len < NTP_MIN_LEN) {
        fprintf(stderr, "[ntp] Too short: %zu bytes (need %d)\n",
                len, NTP_MIN_LEN);
        return -1;
    }
    out->li        = (data[0] >> 6) & 0x03u;
    out->version   = (data[0] >> 3) & 0x07u;
    out->mode      = data[0] & 0x07u;
    out->stratum   = data[1];
    out->poll      = (int8_t)data[2];
    out->precision = (int8_t)data[3];
    out->root_delay       = read_u32_be(data + 4);
    out->root_dispersion  = read_u32_be(data + 8);
    memcpy(out->ref_id, data + 12, 4);
    out->ref_ts  = read_u64_be(data + 16);
    out->orig_ts = read_u64_be(data + 24);
    out->recv_ts = read_u64_be(data + 32);
    out->xmit_ts = read_u64_be(data + 40);
    return 0;
}

const char* ntp_mode_name(uint8_t mode) {
    switch (mode) {
        case 1: return "Symmetric Active";
        case 2: return "Symmetric Passive";
        case 3: return "Client";
        case 4: return "Server";
        case 5: return "Broadcast";
        case 6: return "NTP Control";
        case 7: return "Private";
        default: return "Reserved";
    }
}

static const char* li_name(uint8_t li) {
    switch (li) {
        case 0: return "no warning";
        case 1: return "last min has 61s";
        case 2: return "last min has 59s";
        case 3: return "not synchronized";
        default: return "unknown";
    }
}

/* Convert NTP 64-bit timestamp to Unix seconds (NTP epoch is 1 Jan 1900). */
static uint32_t ntp_to_unix_sec(uint64_t ntp) {
    uint32_t sec = (uint32_t)(ntp >> 32);
    /* NTP epoch offset from Unix: 70 years = 2208988800 seconds */
    return (sec > 2208988800u) ? sec - 2208988800u : 0u;
}

uint32_t ntp_poll_interval_seconds(int8_t poll) {
    /* Shifting a 32-bit value by 32 or more is undefined in C. */
    return (poll >= 0 && poll < 32) ? (1u << (uint8_t)poll) : 0u;
}

void ntp_print(const NtpMessage* msg) {
    printf("┌─ NTP ──────────────────────────────────────────────┐\n");
    printf("│  Mode      : %u  (%s)\n", msg->mode, ntp_mode_name(msg->mode));
    printf("│  Version   : %u\n", msg->version);
    printf("│  LI        : %u  (%s)\n", msg->li, li_name(msg->li));
    printf("│  Stratum   : %u\n", msg->stratum);
    if (msg->stratum >= 2) {
        printf("│  Ref ID    : %u.%u.%u.%u\n",
               msg->ref_id[0], msg->ref_id[1],
               msg->ref_id[2], msg->ref_id[3]);
    } else if (msg->stratum == 1) {
        printf("│  Ref ID    : %.4s\n", (const char*)msg->ref_id);
    }
    printf("│  Poll      : %d  (%u s)\n",
           msg->poll, ntp_poll_interval_seconds(msg->poll));
    uint32_t xmit_unix = ntp_to_unix_sec(msg->xmit_ts);
    if (xmit_unix)
        printf("│  Xmit TS   : %u (Unix)\n", xmit_unix);
    printf("└────────────────────────────────────────────────────┘\n");
}
