#ifndef GRE_H
#define GRE_H

/*
 * gre.h — GRE (Generic Routing Encapsulation) header parser
 *
 * GRE header layout (RFC 2784 / RFC 2890):
 *
 *  Bits 0-15 (16-bit flags word, big-endian):
 *    Bit 15 (MSB): C — Checksum Present
 *    Bit 13:       K — Key Present (RFC 2890)
 *    Bit 12:       S — Sequence Number Present (RFC 2890)
 *    Bits 0-2:     Version (must be 0)
 *  Bits 16-31: Protocol Type (same encoding as EtherType)
 *
 * Optional fields follow in order:
 *    Checksum + Reserved1 (4 bytes total, if C=1)
 *    Key (4 bytes, if K=1)
 *    Sequence Number (4 bytes, if S=1)
 *
 * IP protocol number for GRE: 47.
 * Reference: RFC 2784, RFC 2890
 */

#include "common.h"

#define GRE_MIN_LEN  4   /* flags/ver (2) + protocol (2) */

typedef struct {
    int      has_checksum;   /* C flag */
    int      has_key;        /* K flag */
    int      has_seq;        /* S flag */
    uint8_t  version;        /* should be 0 */
    uint16_t proto;          /* EtherType of encapsulated payload */
    uint32_t key;            /* valid only when has_key */
    uint32_t seq_num;        /* valid only when has_seq */

    const uint8_t* payload;
    size_t         payload_len;
} GreHeader;

/*
 * gre_parse — parse a raw GRE datagram (IPv4 payload for protocol 47).
 * Returns 0 on success, -1 on error.
 */
int  gre_parse(const uint8_t* data, size_t len, GreHeader* out);
void gre_print(const GreHeader* hdr);

#endif /* GRE_H */
