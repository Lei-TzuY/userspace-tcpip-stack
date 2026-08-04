#ifndef PCAP_H
#define PCAP_H

/*
 * pcap.h — Minimal pcap / pcapng file reader (offline mode)
 *
 * A pcap file has a simple binary layout:
 *
 *   [Global Header 24 bytes]
 *   [Packet Record Header 16 bytes] [Packet Data …]
 *   [Packet Record Header 16 bytes] [Packet Data …]
 *   …
 *
 * Classic pcap is a flat record stream. pcapng is block-based; this reader
 * supports Section Header, Interface Description, Enhanced Packet, and Simple
 * Packet blocks. Unknown pcapng block types are skipped safely.
 *
 * Reference: https://wiki.wireshark.org/Development/LibpcapFileFormat
 * Reference: https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-05.html
 */

#include "common.h"

/* ── pcap global header (24 bytes) ─────────────────────────────────────── */
#define PCAP_MAGIC_LE  0xa1b2c3d4u  /* native byte order                    */
#define PCAP_MAGIC_BE  0xd4c3b2a1u  /* byte-swapped — we must flip fields   */
#define PCAP_NSEC_MAGIC_LE  0xa1b23c4du
#define PCAP_NSEC_MAGIC_BE  0x4d3cb2a1u

/* pcapng constants */
#define PCAPNG_BLOCK_SHB  0x0a0d0d0au
#define PCAPNG_BLOCK_IDB  0x00000001u
#define PCAPNG_BLOCK_SPB  0x00000003u
#define PCAPNG_BLOCK_EPB  0x00000006u
#define PCAPNG_BYTE_ORDER_MAGIC  0x1a2b3c4du
#define PCAPNG_MAX_INTERFACES    16

/* Link-layer type constants (https://www.tcpdump.org/linktypes.html) */
#define LINKTYPE_NULL        0    /* BSD loopback: 4-byte address family     */
#define LINKTYPE_ETHERNET    1
#define LINKTYPE_RAW       101    /* no link header; starts at the IP header */
#define LINKTYPE_LINUX_SLL 113    /* Linux "cooked" capture, 16-byte header  */
#define LINKTYPE_LINUX_SLL2 276   /* cooked v2, 20-byte header               */

typedef struct {
    uint32_t magic_number;   /* 0xa1b2c3d4                                 */
    uint16_t version_major;  /* currently 2                                 */
    uint16_t version_minor;  /* currently 4                                 */
    int32_t  thiszone;       /* GMT to local correction (usually 0)         */
    uint32_t sigfigs;        /* accuracy of timestamps (usually 0)          */
    uint32_t snaplen;        /* max length saved portion of each packet      */
    uint32_t network;        /* link-layer header type (LINKTYPE_*)          */
} PcapGlobalHeader;

/* ── pcap per-packet record header (16 bytes) ──────────────────────────── */
typedef struct {
    uint32_t ts_sec;         /* timestamp seconds                           */
    uint32_t ts_usec;        /* timestamp microseconds                      */
    uint32_t incl_len;       /* number of octets of packet saved in file    */
    uint32_t orig_len;       /* actual length of packet                     */
} PcapPacketHeader;

typedef enum {
    PCAP_FORMAT_CLASSIC = 0,
    PCAP_FORMAT_PCAPNG
} PcapFormat;

typedef struct {
    uint16_t link_type;
    uint32_t snaplen;
    uint64_t timestamp_units_per_second;
} PcapngInterface;

/* ── Reader handle ──────────────────────────────────────────────────────── */
typedef struct {
    FILE*            fp;
    PcapGlobalHeader global;
    PcapFormat       format;
    int              swapped;   /* 1 if file is byte-swapped relative to host */
    int              timestamp_is_nsec;
    PcapngInterface  interfaces[PCAPNG_MAX_INTERFACES];
    size_t           interface_count;
} PcapReader;

/* ── API ────────────────────────────────────────────────────────────────── */

/*
 * pcap_open — open a classic pcap or pcapng file for reading.
 * Returns a heap-allocated PcapReader on success, NULL on failure.
 * The caller must call pcap_close() when done.
 */
PcapReader* pcap_open(const char* path);

/*
 * pcap_next — read the next packet from the file.
 *
 *   hdr_out  — filled with the packet record header (host byte order)
 *   buf      — caller-supplied buffer to receive raw packet bytes
 *   buf_size — size of buf
 *
 * Returns the number of bytes placed in buf, or 0 on EOF / error.
 */
size_t pcap_next(PcapReader* reader, PcapPacketHeader* hdr_out,
                 uint8_t* buf, size_t buf_size);

/*
 * pcap_close — close the file and free the reader.
 */
void pcap_close(PcapReader* reader);

#endif /* PCAP_H */
