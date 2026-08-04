#ifndef TCP_H
#define TCP_H

/*
 * tcp.h — TCP (Transmission Control Protocol) parser
 *
 * TCP Segment Layout (20 bytes minimum):
 *
 *  Offset  Size  Field
 *  ──────  ────  ─────────────────────────────────────────────────────────
 *    0      2    Source Port          (big-endian)
 *    2      2    Destination Port     (big-endian)
 *    4      4    Sequence Number      (big-endian)
 *    8      4    Acknowledgment Num.  (big-endian)
 *   12      1    Data Offset (4 bits, header length in 32-bit words) +
 *                Reserved   (3 bits) + NS flag (1 bit)
 *   13      1    Control flags: CWR ECE URG ACK PSH RST SYN FIN
 *   14      2    Window Size          (big-endian)
 *   16      2    Checksum             (big-endian)
 *   18      2    Urgent Pointer       (big-endian)
 *   20      *    Options (if Data Offset > 5)
 *   20+opts *    Data
 *
 * TCP Options (kind-length-value encoding):
 *   Kind 0  — End of Options List (no length, no data)
 *   Kind 1  — No-Operation / padding (no length, no data)
 *   Kind 2  — Maximum Segment Size  (len=4, value=uint16)
 *   Kind 3  — Window Scale          (len=3, shift_count=uint8)
 *   Kind 4  — SACK Permitted        (len=2, no data)
 *   Kind 5  — SACK                  (len=variable, pairs of uint32 edges)
 *   Kind 8  — Timestamps            (len=10, TSval=uint32, TSecr=uint32)
 *
 * The TCP checksum uses the same IPv4 pseudo-header as UDP
 * (RFC 793), with protocol = 6 and length = TCP segment length.
 *
 * Reference: RFC 793, RFC 2018 (SACK), RFC 7323 (Timestamps + WScale)
 */

#include "common.h"

#define TCP_MIN_HDR_LEN  20
#define TCP_MAX_HDR_LEN  60   /* IHL can be at most 15 × 4 = 60 bytes */

/* ── Flag bits (in the flags byte at offset 13) ─────────────────────────── */
#define TCP_FIN  0x01u
#define TCP_SYN  0x02u
#define TCP_RST  0x04u
#define TCP_PSH  0x08u
#define TCP_ACK  0x10u
#define TCP_URG  0x20u
#define TCP_ECE  0x40u
#define TCP_CWR  0x80u

/* ── Option kind constants ──────────────────────────────────────────────── */
#define TCP_OPT_EOL    0u
#define TCP_OPT_NOP    1u
#define TCP_OPT_MSS    2u
#define TCP_OPT_WSCALE 3u
#define TCP_OPT_SACKP  4u   /* SACK Permitted */
#define TCP_OPT_SACK   5u   /* Selective Acknowledgment */
#define TCP_OPT_TS     8u   /* Timestamps */

#define TCP_MAX_OPTS  20    /* maximum distinct option entries to store */

/*
 * The largest option data section that can fit. The header is at most 60 bytes,
 * leaving 40 for options; an option spends two of those on its kind and length,
 * so 38 bytes of data is the most any single option can carry.
 */
#define TCP_OPT_MAX_DATA 38

typedef struct {
    uint8_t  kind;
    /*
     * Bytes of option-specific data present in data[] (0 for EOL/NOP).
     *
     * This is the length of what was actually stored, not the length the
     * sender claimed. The two can differ — a malformed option may declare more
     * than fits — and a consumer looping to data_len must not be able to walk
     * off the end of the array.
     */
    uint8_t  data_len;
    uint8_t  data[TCP_OPT_MAX_DATA];
} TcpOption;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  data_offset;  /* header length in 32-bit words */
    uint8_t  hdr_len;      /* header length in bytes (data_offset * 4) */
    uint8_t  flags;        /* combination of TCP_SYN, TCP_ACK, … */
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;

    /* Parsed options */
    TcpOption options[TCP_MAX_OPTS];
    int       opt_count;

    /* Payload (pointer into caller's buffer, not a copy) */
    const uint8_t* payload;
    size_t         payload_len;
} TcpHeader;

/*
 * tcp_parse — parse raw TCP bytes (IPv4 payload for protocol 6).
 * Returns 0 on success, -1 on error.
 */
int tcp_parse(const uint8_t* data, size_t len, TcpHeader* out);

/*
 * tcp_checksum_ok — verify the TCP checksum with the IPv4 pseudo-header.
 *   src_ip   — 4-byte source IP
 *   dst_ip   — 4-byte destination IP
 *   segment  — start of the TCP segment (header + options + data)
 *   seg_len  — total length of the TCP segment in bytes
 * Returns 1 if valid, 0 if bad or shorter than TCP_MIN_HDR_LEN.
 */
int tcp_checksum_ok(const uint8_t* src_ip, const uint8_t* dst_ip,
                    const uint8_t* segment, uint16_t seg_len);

/*
 * tcp_checksum_ok_v6 — verify the TCP checksum with the IPv6 pseudo-header
 * (RFC 8200 §8.1).
 *   src_ip6  — 16-byte source IPv6 address
 *   dst_ip6  — 16-byte destination IPv6 address
 */
int tcp_checksum_ok_v6(const uint8_t* src_ip6, const uint8_t* dst_ip6,
                       const uint8_t* segment, uint16_t seg_len);

/*
 * tcp_flags_str — write a human-readable flags string (e.g. "[SYN, ACK]")
 * into buf (which must be at least 40 bytes).
 */
void tcp_flags_str(uint8_t flags, char* buf, size_t buf_len);

/*
 * tcp_print — pretty-print a TCP header to stdout.
 * cksum_valid: result from tcp_checksum_ok (or -1 if not computed).
 */
void tcp_print(const TcpHeader* hdr, int cksum_valid);

/*
 * tcp_port_name — return a service name for well-known TCP ports, or NULL.
 */
const char* tcp_port_name(uint16_t port);

#endif /* TCP_H */
