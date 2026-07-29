/*
 * gre.c — GRE header parser implementation
 */

#include "gre.h"

int gre_parse(const uint8_t* data, size_t len, GreHeader* out) {
    if (len < GRE_MIN_LEN) {
        fprintf(stderr, "[gre] Too short: %zu bytes (need %d)\n",
                len, GRE_MIN_LEN);
        return -1;
    }

    uint16_t flags = (uint16_t)((data[0] << 8) | data[1]);
    out->proto       = (uint16_t)((data[2] << 8) | data[3]);
    out->has_checksum = (flags >> 15) & 1;
    out->has_key      = (flags >> 13) & 1;
    out->has_seq      = (flags >> 12) & 1;
    out->version      = (uint8_t)(flags & 0x07u);
    out->key          = 0;
    out->seq_num      = 0;

    size_t offset = 4;

    if (out->has_checksum) {
        if (offset + 4 > len) return -1;
        offset += 4;  /* skip checksum(2) + reserved(2) */
    }
    if (out->has_key) {
        if (offset + 4 > len) return -1;
        out->key = ((uint32_t)data[offset]   << 24)
                 | ((uint32_t)data[offset+1] << 16)
                 | ((uint32_t)data[offset+2] <<  8)
                 |  (uint32_t)data[offset+3];
        offset += 4;
    }
    if (out->has_seq) {
        if (offset + 4 > len) return -1;
        out->seq_num = ((uint32_t)data[offset]   << 24)
                     | ((uint32_t)data[offset+1] << 16)
                     | ((uint32_t)data[offset+2] <<  8)
                     |  (uint32_t)data[offset+3];
        offset += 4;
    }

    out->payload     = data + offset;
    out->payload_len = len - offset;
    return 0;
}

void gre_print(const GreHeader* hdr) {
    printf("┌─ GRE ──────────────────────────────────────────────┐\n");
    printf("│  Proto     : 0x%04x\n", hdr->proto);
    if (hdr->has_key)
        printf("│  Key       : 0x%08x\n", hdr->key);
    if (hdr->has_seq)
        printf("│  Seq       : %u\n", hdr->seq_num);
    printf("│  Payload   : %zu bytes\n", hdr->payload_len);
    printf("└────────────────────────────────────────────────────┘\n");
}
