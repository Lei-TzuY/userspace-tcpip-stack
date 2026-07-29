/*
 * Minimal classic pcap and pcapng reader implementation.
 *
 * The public API intentionally stays small: open a capture, read one packet,
 * and close it. For pcapng, global.network is updated to the packet's interface
 * link type before pcap_next() returns so existing dispatch code can remain
 * format-agnostic.
 */

#include "pcap.h"

#define PCAPNG_MAX_BLOCK_LEN (16u * 1024u * 1024u)
#define PCAPNG_OPT_END       0u
#define PCAPNG_OPT_TSRESOL   9u

static uint32_t swap32(uint32_t value) {
    return ((value & 0x000000ffu) << 24)
         | ((value & 0x0000ff00u) << 8)
         | ((value & 0x00ff0000u) >> 8)
         | ((value & 0xff000000u) >> 24);
}

static uint16_t swap16(uint16_t value) {
    return (uint16_t)(((value & 0x00ffu) << 8)
                    | ((value & 0xff00u) >> 8));
}

static uint16_t decode16(const PcapReader* reader, uint16_t value) {
    return reader->swapped ? swap16(value) : value;
}

static uint32_t decode32(const PcapReader* reader, uint32_t value) {
    return reader->swapped ? swap32(value) : value;
}

static int read_exact(FILE* fp, void* out, size_t len) {
    return fread(out, 1, len, fp) == len;
}

static int skip_bytes(FILE* fp, size_t len) {
    uint8_t scratch[512];

    while (len > 0) {
        size_t chunk = len < sizeof(scratch) ? len : sizeof(scratch);
        if (!read_exact(fp, scratch, chunk))
            return -1;
        len -= chunk;
    }
    return 0;
}

static size_t padded4(size_t len) {
    return (len + 3u) & ~(size_t)3u;
}

static int valid_pcapng_block_len(uint32_t len, uint32_t minimum) {
    return len >= minimum && len <= PCAPNG_MAX_BLOCK_LEN && (len % 4u) == 0;
}

static int read_pcapng_trailer(PcapReader* reader, uint32_t expected_len) {
    uint32_t raw_len;
    if (!read_exact(reader->fp, &raw_len, sizeof(raw_len)))
        return -1;
    if (decode32(reader, raw_len) != expected_len) {
        fprintf(stderr, "[pcapng] Block length trailer mismatch\n");
        return -1;
    }
    return 0;
}

static uint64_t decimal_power(unsigned exponent) {
    uint64_t value = 1;
    for (unsigned i = 0; i < exponent; i++) {
        if (value > UINT64_MAX / 10u)
            return 0;
        value *= 10u;
    }
    return value;
}

static uint64_t timestamp_units_from_option(uint8_t value) {
    unsigned exponent = value & 0x7fu;
    if (value & 0x80u) {
        if (exponent >= 64)
            return 0;
        return (uint64_t)1u << exponent;
    }
    return decimal_power(exponent);
}

static int parse_idb_options(PcapReader* reader, const uint8_t* options,
                             size_t options_len, uint64_t* timestamp_units) {
    size_t offset = 0;

    while (offset < options_len) {
        uint16_t raw_code;
        uint16_t raw_len;
        uint16_t code;
        uint16_t len;
        size_t padded_len;

        if (options_len - offset < 4)
            return -1;
        memcpy(&raw_code, options + offset, sizeof(raw_code));
        memcpy(&raw_len, options + offset + 2, sizeof(raw_len));
        code = decode16(reader, raw_code);
        len = decode16(reader, raw_len);
        offset += 4;

        if (code == PCAPNG_OPT_END)
            return len == 0 ? 0 : -1;

        padded_len = padded4(len);
        if (padded_len > options_len - offset)
            return -1;
        if (code == PCAPNG_OPT_TSRESOL && len == 1) {
            uint64_t units = timestamp_units_from_option(options[offset]);
            if (!units)
                return -1;
            *timestamp_units = units;
        }
        offset += padded_len;
    }
    return 0;
}

static int read_pcapng_section(PcapReader* reader, uint32_t raw_total_len) {
    uint32_t raw_bom;
    uint32_t total_len;
    uint16_t raw_major;
    uint16_t raw_minor;

    if (!read_exact(reader->fp, &raw_bom, sizeof(raw_bom)))
        return -1;
    if (raw_bom == PCAPNG_BYTE_ORDER_MAGIC)
        reader->swapped = 0;
    else if (swap32(raw_bom) == PCAPNG_BYTE_ORDER_MAGIC)
        reader->swapped = 1;
    else {
        fprintf(stderr, "[pcapng] Invalid section byte-order magic\n");
        return -1;
    }

    total_len = decode32(reader, raw_total_len);
    if (!valid_pcapng_block_len(total_len, 28)) {
        fprintf(stderr, "[pcapng] Invalid section header length: %u\n", total_len);
        return -1;
    }

    if (!read_exact(reader->fp, &raw_major, sizeof(raw_major))
            || !read_exact(reader->fp, &raw_minor, sizeof(raw_minor))
            || skip_bytes(reader->fp, total_len - 20u) != 0
            || read_pcapng_trailer(reader, total_len) != 0)
        return -1;

    memset(reader->interfaces, 0, sizeof(reader->interfaces));
    reader->interface_count = 0;
    reader->global.version_major = decode16(reader, raw_major);
    reader->global.version_minor = decode16(reader, raw_minor);
    reader->global.network = 0;
    reader->global.snaplen = 0;
    return 0;
}

static int read_pcapng_idb(PcapReader* reader, uint32_t total_len) {
    uint16_t raw_link_type;
    uint16_t reserved;
    uint32_t raw_snaplen;
    size_t options_len;
    uint8_t* options = NULL;
    uint64_t timestamp_units = 1000000u;
    int result = -1;

    if (!valid_pcapng_block_len(total_len, 20)) {
        fprintf(stderr, "[pcapng] Invalid interface block length: %u\n", total_len);
        return -1;
    }

    options_len = total_len - 20u;
    if (!read_exact(reader->fp, &raw_link_type, sizeof(raw_link_type))
            || !read_exact(reader->fp, &reserved, sizeof(reserved))
            || !read_exact(reader->fp, &raw_snaplen, sizeof(raw_snaplen)))
        return -1;

    if (options_len > 0) {
        options = (uint8_t*)malloc(options_len);
        if (!options || !read_exact(reader->fp, options, options_len))
            goto cleanup;
        if (parse_idb_options(reader, options, options_len, &timestamp_units) != 0) {
            fprintf(stderr, "[pcapng] Invalid interface options\n");
            goto cleanup;
        }
    }
    if (read_pcapng_trailer(reader, total_len) != 0)
        goto cleanup;
    if (reader->interface_count >= PCAPNG_MAX_INTERFACES) {
        fprintf(stderr, "[pcapng] Too many interfaces (max %d)\n",
                PCAPNG_MAX_INTERFACES);
        goto cleanup;
    }

    PcapngInterface* iface =
        &reader->interfaces[reader->interface_count++];
    iface->link_type = decode16(reader, raw_link_type);
    iface->snaplen = decode32(reader, raw_snaplen);
    iface->timestamp_units_per_second = timestamp_units;
    result = 0;

cleanup:
    free(options);
    return result;
}

static void split_timestamp(uint64_t timestamp, uint64_t units_per_second,
                            uint32_t* sec_out, uint32_t* usec_out) {
    uint64_t seconds = timestamp / units_per_second;
    uint64_t remainder = timestamp % units_per_second;
    long double usec = ((long double)remainder * 1000000.0L)
                     / (long double)units_per_second;

    *sec_out = (uint32_t)seconds;
    *usec_out = (uint32_t)usec;
}

static size_t read_pcapng_epb(PcapReader* reader, uint32_t total_len,
                              PcapPacketHeader* hdr_out,
                              uint8_t* buf, size_t buf_size) {
    uint32_t raw_interface_id;
    uint32_t raw_ts_high;
    uint32_t raw_ts_low;
    uint32_t raw_incl_len;
    uint32_t raw_orig_len;
    uint32_t interface_id;
    uint32_t incl_len;
    size_t padded_len;
    size_t options_len;
    size_t to_read;

    if (!valid_pcapng_block_len(total_len, 32))
        return 0;
    if (!read_exact(reader->fp, &raw_interface_id, sizeof(raw_interface_id))
            || !read_exact(reader->fp, &raw_ts_high, sizeof(raw_ts_high))
            || !read_exact(reader->fp, &raw_ts_low, sizeof(raw_ts_low))
            || !read_exact(reader->fp, &raw_incl_len, sizeof(raw_incl_len))
            || !read_exact(reader->fp, &raw_orig_len, sizeof(raw_orig_len)))
        return 0;

    interface_id = decode32(reader, raw_interface_id);
    incl_len = decode32(reader, raw_incl_len);
    padded_len = padded4(incl_len);
    if (interface_id >= reader->interface_count
            || padded_len > total_len - 32u)
        return 0;
    options_len = total_len - 32u - padded_len;

    PcapngInterface* iface = &reader->interfaces[interface_id];
    reader->global.network = iface->link_type;
    reader->global.snaplen = iface->snaplen;
    hdr_out->incl_len = incl_len;
    hdr_out->orig_len = decode32(reader, raw_orig_len);
    split_timestamp(((uint64_t)decode32(reader, raw_ts_high) << 32)
                        | decode32(reader, raw_ts_low),
                    iface->timestamp_units_per_second,
                    &hdr_out->ts_sec, &hdr_out->ts_usec);

    to_read = incl_len < buf_size ? incl_len : buf_size;
    if (to_read < incl_len)
        fprintf(stderr, "[pcapng] Packet truncated from %u to %zu bytes "
                        "(increase buffer)\n", incl_len, buf_size);

    if (!read_exact(reader->fp, buf, to_read)
            || skip_bytes(reader->fp, padded_len - to_read + options_len) != 0
            || read_pcapng_trailer(reader, total_len) != 0)
        return 0;
    return to_read;
}

static size_t read_pcapng_spb(PcapReader* reader, uint32_t total_len,
                              PcapPacketHeader* hdr_out,
                              uint8_t* buf, size_t buf_size) {
    uint32_t raw_orig_len;
    uint32_t orig_len;
    size_t captured_len;
    size_t padded_len;
    size_t to_read;

    if (!valid_pcapng_block_len(total_len, 16)
            || reader->interface_count == 0
            || !read_exact(reader->fp, &raw_orig_len, sizeof(raw_orig_len)))
        return 0;

    orig_len = decode32(reader, raw_orig_len);
    captured_len = orig_len < reader->interfaces[0].snaplen
                 ? orig_len : reader->interfaces[0].snaplen;
    padded_len = padded4(captured_len);
    if (padded_len != total_len - 16u)
        return 0;

    reader->global.network = reader->interfaces[0].link_type;
    reader->global.snaplen = reader->interfaces[0].snaplen;
    memset(hdr_out, 0, sizeof(*hdr_out));
    hdr_out->incl_len = (uint32_t)captured_len;
    hdr_out->orig_len = orig_len;
    to_read = captured_len < buf_size ? captured_len : buf_size;

    if (!read_exact(reader->fp, buf, to_read)
            || skip_bytes(reader->fp, padded_len - to_read) != 0
            || read_pcapng_trailer(reader, total_len) != 0)
        return 0;
    return to_read;
}

static int skip_pcapng_block(PcapReader* reader, uint32_t total_len) {
    if (!valid_pcapng_block_len(total_len, 12)
            || skip_bytes(reader->fp, total_len - 12u) != 0)
        return -1;
    return read_pcapng_trailer(reader, total_len);
}

static size_t read_pcapng_packet(PcapReader* reader,
                                 PcapPacketHeader* hdr_out,
                                 uint8_t* buf, size_t buf_size) {
    while (1) {
        uint32_t raw_type;
        uint32_t raw_total_len;
        uint32_t type;
        uint32_t total_len;

        if (!read_exact(reader->fp, &raw_type, sizeof(raw_type)))
            return 0;
        if (!read_exact(reader->fp, &raw_total_len, sizeof(raw_total_len)))
            return 0;

        if (raw_type == PCAPNG_BLOCK_SHB) {
            if (read_pcapng_section(reader, raw_total_len) != 0)
                return 0;
            continue;
        }

        type = decode32(reader, raw_type);
        total_len = decode32(reader, raw_total_len);
        switch (type) {
            case PCAPNG_BLOCK_IDB:
                if (read_pcapng_idb(reader, total_len) != 0)
                    return 0;
                break;
            case PCAPNG_BLOCK_EPB:
                return read_pcapng_epb(reader, total_len, hdr_out, buf, buf_size);
            case PCAPNG_BLOCK_SPB:
                return read_pcapng_spb(reader, total_len, hdr_out, buf, buf_size);
            default:
                if (skip_pcapng_block(reader, total_len) != 0)
                    return 0;
                break;
        }
    }
}

static int open_classic_pcap(PcapReader* reader) {
    if (!read_exact(reader->fp, &reader->global, sizeof(reader->global))) {
        fprintf(stderr, "[pcap] File too short for global header\n");
        return -1;
    }

    switch (reader->global.magic_number) {
        case PCAP_MAGIC_LE:
            break;
        case PCAP_MAGIC_BE:
            reader->swapped = 1;
            break;
        case PCAP_NSEC_MAGIC_LE:
            reader->timestamp_is_nsec = 1;
            break;
        case PCAP_NSEC_MAGIC_BE:
            reader->swapped = 1;
            reader->timestamp_is_nsec = 1;
            break;
        default:
            fprintf(stderr, "[pcap] Unrecognised magic number: 0x%08x\n",
                    reader->global.magic_number);
            return -1;
    }

    if (reader->swapped) {
        reader->global.version_major = swap16(reader->global.version_major);
        reader->global.version_minor = swap16(reader->global.version_minor);
        reader->global.thiszone =
            (int32_t)swap32((uint32_t)reader->global.thiszone);
        reader->global.sigfigs = swap32(reader->global.sigfigs);
        reader->global.snaplen = swap32(reader->global.snaplen);
        reader->global.network = swap32(reader->global.network);
    }
    return 0;
}

static size_t read_classic_packet(PcapReader* reader,
                                  PcapPacketHeader* hdr_out,
                                  uint8_t* buf, size_t buf_size) {
    PcapPacketHeader raw;
    size_t to_read;

    if (!read_exact(reader->fp, &raw, sizeof(raw)))
        return 0;
    if (reader->swapped) {
        raw.ts_sec = swap32(raw.ts_sec);
        raw.ts_usec = swap32(raw.ts_usec);
        raw.incl_len = swap32(raw.incl_len);
        raw.orig_len = swap32(raw.orig_len);
    }
    if (reader->timestamp_is_nsec)
        raw.ts_usec /= 1000u;
    *hdr_out = raw;

    to_read = raw.incl_len < buf_size ? raw.incl_len : buf_size;
    if (to_read < raw.incl_len)
        fprintf(stderr, "[pcap] Packet truncated from %u to %zu bytes "
                        "(increase buffer)\n", raw.incl_len, buf_size);

    if (!read_exact(reader->fp, buf, to_read)
            || skip_bytes(reader->fp, raw.incl_len - to_read) != 0)
        return 0;
    return to_read;
}

PcapReader* pcap_open(const char* path) {
    uint32_t magic;
    PcapReader* reader;
    FILE* fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "[pcap] Cannot open file: %s\n", path);
        return NULL;
    }

    reader = (PcapReader*)calloc(1, sizeof(*reader));
    if (!reader) {
        fclose(fp);
        return NULL;
    }
    reader->fp = fp;

    if (!read_exact(fp, &magic, sizeof(magic)) || fseek(fp, 0, SEEK_SET) != 0)
        goto fail;

    if (magic == PCAPNG_BLOCK_SHB) {
        uint32_t raw_type;
        uint32_t raw_total_len;
        reader->format = PCAP_FORMAT_PCAPNG;
        if (!read_exact(fp, &raw_type, sizeof(raw_type))
                || !read_exact(fp, &raw_total_len, sizeof(raw_total_len))
                || read_pcapng_section(reader, raw_total_len) != 0)
            goto fail;
        printf("[pcapng] Opened '%s'  v%u.%u\n", path,
               reader->global.version_major, reader->global.version_minor);
    } else {
        reader->format = PCAP_FORMAT_CLASSIC;
        if (open_classic_pcap(reader) != 0)
            goto fail;
        printf("[pcap] Opened '%s'  link-type=%u  snaplen=%u  v%u.%u\n",
               path, reader->global.network, reader->global.snaplen,
               reader->global.version_major, reader->global.version_minor);
    }
    return reader;

fail:
    fprintf(stderr, "[pcap] Cannot parse capture file: %s\n", path);
    fclose(fp);
    free(reader);
    return NULL;
}

size_t pcap_next(PcapReader* reader, PcapPacketHeader* hdr_out,
                 uint8_t* buf, size_t buf_size) {
    if (!reader || !hdr_out || !buf || buf_size == 0)
        return 0;
    if (reader->format == PCAP_FORMAT_PCAPNG)
        return read_pcapng_packet(reader, hdr_out, buf, buf_size);
    return read_classic_packet(reader, hdr_out, buf, buf_size);
}

void pcap_close(PcapReader* reader) {
    if (reader) {
        fclose(reader->fp);
        free(reader);
    }
}
