/*
 * tls.c — TLS record layer parser
 */

#include "tls.h"

static uint16_t read16(const uint8_t* p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

static int valid_version(uint16_t v) {
    return v == 0x0300 || v == 0x0301 || v == 0x0302 || v == 0x0303 || v == 0x0304;
}

int tls_sniff(const uint8_t* payload, size_t len) {
    if (!payload || len < 5) return 0;
    uint8_t ct  = payload[0];
    uint16_t ver = read16(payload + 1);
    uint16_t rlen = read16(payload + 3);
    return (ct >= 20 && ct <= 24) && valid_version(ver) && rlen > 0 && rlen <= 16384;
}

/* Parse SNI from a ClientHello extension block.
   ext_data points to the extensions length field onward. */
static void parse_sni(const uint8_t* ext_data, size_t ext_bytes,
                      char* sni, size_t sni_max) {
    if (ext_bytes < 2) return;
    uint16_t total = read16(ext_data);
    size_t off = 2;
    while (off + 4 <= ext_bytes && off + 2 <= (size_t)(total + 2)) {
        uint16_t etype = read16(ext_data + off);
        uint16_t elen  = read16(ext_data + off + 2);
        off += 4;
        if (off + elen > ext_bytes) break;
        if (etype == 0 && elen >= 5) {
            /* SNI extension: list_len(2) type(1) name_len(2) name */
            uint16_t name_len = read16(ext_data + off + 3);
            if (name_len + 5 <= elen && name_len < sni_max) {
                memcpy(sni, ext_data + off + 5, name_len);
                sni[name_len] = '\0';
            }
            return;
        }
        off += elen;
    }
}

int tls_parse(const uint8_t* payload, size_t len, TlsMessage* out) {
    if (!tls_sniff(payload, len)) return -1;
    memset(out, 0, sizeof(*out));

    size_t offset = 0;
    while (offset + 5 <= len && out->record_count < TLS_MAX_RECORDS) {
        uint8_t  ct   = payload[offset];
        uint16_t ver  = read16(payload + offset + 1);
        uint16_t rlen = read16(payload + offset + 3);

        if (!((ct >= 20 && ct <= 24) && valid_version(ver) && rlen > 0))
            break;
        if (offset + 5 + rlen > len) break;

        TlsRecord* rec = &out->records[out->record_count++];
        rec->content_type = ct;
        rec->version       = ver;
        rec->length        = rlen;

        const uint8_t* rdata = payload + offset + 5;

        if (ct == TLS_CT_HANDSHAKE && rlen >= 4) {
            rec->has_handshake    = 1;
            rec->handshake_type   = rdata[0];
            rec->handshake_length = ((uint32_t)rdata[1] << 16)
                                  | ((uint32_t)rdata[2] << 8)
                                  |  (uint32_t)rdata[3];
            /* ClientHello / ServerHello: random(32) + session_id_len(1) + ... */
            uint8_t ht = rec->handshake_type;
            if ((ht == TLS_HT_CLIENT_HELLO || ht == TLS_HT_SERVER_HELLO)
                    && rlen >= 4 + 2 + 32 + 1) {
                size_t h = 4; /* skip handshake header */
                rec->hello_version = read16(rdata + h); h += 2;
                h += 32; /* random */
                uint8_t sid_len = rdata[h++];
                h += sid_len;
                if (ht == TLS_HT_CLIENT_HELLO && h + 2 <= rlen) {
                    /* cipher suites */
                    uint16_t cs_len = read16(rdata + h); h += 2 + cs_len;
                    /* compression methods */
                    if (h + 1 <= rlen) { uint8_t cm_len = rdata[h]; h += 1 + cm_len; }
                    /* extensions */
                    if (h + 2 <= rlen)
                        parse_sni(rdata + h, rlen - h, rec->sni, sizeof(rec->sni));
                } else if (ht == TLS_HT_SERVER_HELLO && h + 2 <= rlen) {
                    rec->selected_cipher_suite = read16(rdata + h);
                }
            }
            /* Certificate: count certs in chain */
            if (ht == TLS_HT_CERTIFICATE && rlen >= 7) {
                uint32_t list_len = ((uint32_t)rdata[4] << 16)
                                  | ((uint32_t)rdata[5] <<  8)
                                  |  (uint32_t)rdata[6];
                size_t pos = 7;
                int cnt = 0;
                while (pos + 3 <= 4 + list_len && pos + 3 <= rlen) {
                    uint32_t clen = ((uint32_t)rdata[pos]   << 16)
                                  | ((uint32_t)rdata[pos+1] <<  8)
                                  |  (uint32_t)rdata[pos+2];
                    pos += 3 + clen;
                    cnt++;
                }
                rec->cert_count = cnt;
            }
        } else if (ct == TLS_CT_ALERT && rlen >= 2) {
            rec->alert_level = rdata[0];
            rec->alert_desc  = rdata[1];
        }

        offset += 5 + rlen;
    }
    return out->record_count > 0 ? 0 : -1;
}

const char* tls_content_type_name(uint8_t ct) {
    switch (ct) {
        case TLS_CT_CHANGE_CIPHER_SPEC: return "ChangeCipherSpec";
        case TLS_CT_ALERT:              return "Alert";
        case TLS_CT_HANDSHAKE:          return "Handshake";
        case TLS_CT_APPLICATION_DATA:   return "AppData";
        case TLS_CT_HEARTBEAT:          return "Heartbeat";
        default:                        return "UNKNOWN";
    }
}

const char* tls_handshake_type_name(uint8_t ht) {
    switch (ht) {
        case TLS_HT_CLIENT_HELLO:        return "ClientHello";
        case TLS_HT_SERVER_HELLO:        return "ServerHello";
        case TLS_HT_NEW_SESSION_TICKET:  return "NewSessionTicket";
        case TLS_HT_CERTIFICATE:         return "Certificate";
        case TLS_HT_SERVER_KEY_EXCHANGE: return "ServerKeyExchange";
        case TLS_HT_SERVER_HELLO_DONE:   return "ServerHelloDone";
        case TLS_HT_CLIENT_KEY_EXCHANGE: return "ClientKeyExchange";
        case TLS_HT_FINISHED:            return "Finished";
        default:                         return "UNKNOWN";
    }
}

const char* tls_version_name(uint16_t v) {
    switch (v) {
        case 0x0300: return "SSL 3.0";
        case 0x0301: return "TLS 1.0";
        case 0x0302: return "TLS 1.1";
        case 0x0303: return "TLS 1.2";
        case 0x0304: return "TLS 1.3";
        default:     return "UNKNOWN";
    }
}

void tls_print(const TlsMessage* msg) {
    printf("+-- TLS ----------------------------------------------------+\n");
    for (int i = 0; i < msg->record_count; i++) {
        const TlsRecord* r = &msg->records[i];
        printf("|  [%d] %-18s  ver=%-7s  len=%u\n", i,
               tls_content_type_name(r->content_type),
               tls_version_name(r->version),
               r->length);
        if (r->has_handshake) {
            printf("|      -> %-16s  (%u bytes)\n",
                   tls_handshake_type_name(r->handshake_type),
                   r->handshake_length);
            if (r->hello_version)
                printf("|         hello_ver=%s\n",
                       tls_version_name(r->hello_version));
            if (r->sni[0])
                printf("|         SNI=%s\n", r->sni);
            if (r->handshake_type == TLS_HT_SERVER_HELLO
                    && r->selected_cipher_suite)
                printf("|         cipher=0x%04x\n", r->selected_cipher_suite);
            if (r->handshake_type == TLS_HT_CERTIFICATE && r->cert_count > 0)
                printf("|         certs=%d\n", r->cert_count);
        }
        if (r->content_type == TLS_CT_ALERT)
            printf("|      -> alert level=%u desc=%u\n",
                   r->alert_level, r->alert_desc);
    }
    printf("+------------------------------------------------------------+\n");
}
