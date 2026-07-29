#ifndef UDP_H
#define UDP_H

/*
 * udp.h — UDP (User Datagram Protocol) parser
 *
 * UDP Header Layout (8 bytes, fixed):
 *
 *  Offset  Size  Field
 *  ──────  ────  ─────────────────────────────────────────────────────────
 *    0      2    Source Port       (big-endian)
 *    2      2    Destination Port  (big-endian)
 *    4      2    Length            (big-endian, header + data)
 *    6      2    Checksum          (big-endian; 0 means not computed)
 *    8      *    Data
 *
 * The UDP checksum (RFC 768) is computed over an IPv4 pseudo-header:
 *
 *   Source IP (4) | Dest IP (4) | zero (1) | Protocol=17 (1) | UDP length (2)
 *
 * followed by the UDP header and data.  A checksum of 0x0000 in the header
 * means the sender chose not to compute it.
 *
 * Well-known port numbers (examples):
 *   53   DNS       67/68  DHCP      123  NTP      161  SNMP
 *
 * Reference: RFC 768
 */

#include "common.h"

#define UDP_HDR_LEN  8

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;      /* header + data in bytes */
    uint16_t checksum;
    /* Payload pointer (into caller's buffer — not a copy) */
    const uint8_t* payload;
    size_t         payload_len;
} UdpHeader;

/*
 * udp_parse — parse raw UDP bytes (IPv4 payload for protocol 17).
 * Returns 0 on success, -1 if the datagram is truncated or has a bad length.
 */
int udp_parse(const uint8_t* data, size_t len, UdpHeader* out);

/*
 * udp_checksum_ok — verify the UDP checksum using the IPv4 pseudo-header.
 *   src_ip   — 4-byte source IP from the enclosing IPv4 header
 *   dst_ip   — 4-byte destination IP
 *   segment  — start of the UDP segment (header + data)
 *   seg_len  — length of the UDP segment in bytes
 * Returns 1 if valid, 0 if bad or shorter than UDP_HDR_LEN.  Returns 1
 * unconditionally when checksum = 0 (sender disabled checksum).
 */
int udp_checksum_ok(const uint8_t* src_ip, const uint8_t* dst_ip,
                    const uint8_t* segment, uint16_t seg_len);

/*
 * udp_checksum_ok_v6 — verify the UDP checksum using the IPv6 pseudo-header
 * (RFC 8200 §8.1). The checksum is mandatory over IPv6 (a stored 0 is invalid).
 *   src_ip6  — 16-byte source IPv6 address
 *   dst_ip6  — 16-byte destination IPv6 address
 */
int udp_checksum_ok_v6(const uint8_t* src_ip6, const uint8_t* dst_ip6,
                       const uint8_t* segment, uint16_t seg_len);

/*
 * udp_print — pretty-print a UDP header to stdout.
 * cksum_valid: result from udp_checksum_ok (or -1 if not computed).
 */
void udp_print(const UdpHeader* hdr, int cksum_valid);

/*
 * udp_port_name — return a service name for well-known UDP ports, or NULL.
 */
const char* udp_port_name(uint16_t port);

#endif /* UDP_H */
