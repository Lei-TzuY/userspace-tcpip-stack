#ifndef NTP_H
#define NTP_H

/*
 * ntp.h — NTP (Network Time Protocol) v3/v4 parser
 *
 * Fixed 48-byte wire format (RFC 5905):
 *
 *  Offset  Size  Field
 *  ──────  ────  ─────────────────────────────────────────────────────────
 *    0      1    LI (2 bits) | VN (3 bits) | Mode (3 bits)
 *    1      1    Stratum
 *    2      1    Poll  (signed log2 seconds)
 *    3      1    Precision (signed log2 seconds)
 *    4      4    Root Delay        (signed 16.16 fixed-point, seconds)
 *    8      4    Root Dispersion   (unsigned 16.16 fixed-point, seconds)
 *   12      4    Reference ID      (IP address or ASCII code)
 *   16      8    Reference Timestamp
 *   24      8    Originate Timestamp
 *   32      8    Receive Timestamp
 *   40      8    Transmit Timestamp
 *
 * Each 64-bit timestamp: high 32 bits = seconds since 1 Jan 1900,
 * low 32 bits = sub-second fraction.
 *
 * Mode values: 1=symmetric-active, 2=symmetric-passive, 3=client,
 *              4=server, 5=broadcast, 6=NTP-ctrl, 7=private.
 */

#include "common.h"

#define NTP_MIN_LEN  48

typedef struct {
    uint8_t  li;         /* leap indicator */
    uint8_t  version;    /* protocol version (3 or 4) */
    uint8_t  mode;       /* mode */
    uint8_t  stratum;
    int8_t   poll;       /* log2 of poll interval (seconds) */
    int8_t   precision;  /* log2 of clock precision (seconds) */
    uint32_t root_delay;       /* signed 16.16 */
    uint32_t root_dispersion;  /* unsigned 16.16 */
    uint8_t  ref_id[4];
    uint64_t ref_ts;
    uint64_t orig_ts;
    uint64_t recv_ts;
    uint64_t xmit_ts;
} NtpMessage;

int  ntp_parse(const uint8_t* data, size_t len, NtpMessage* out);
void ntp_print(const NtpMessage* msg);
const char* ntp_mode_name(uint8_t mode);

#endif /* NTP_H */
