#ifndef TLS_H
#define TLS_H

/*
 * tls.h — TLS/SSL record layer parser (header only, no decryption)
 *
 * Parses TLS record headers and ClientHello/ServerHello handshake messages.
 * RFC 5246 (TLS 1.2), RFC 8446 (TLS 1.3).
 *
 * Record layout (5-byte header):
 *   ContentType (1)  Version (2)  Length (2)
 *
 * Handshake sub-header (4 bytes, inside a Handshake record):
 *   HandshakeType (1)  Length (3)
 */

#include "common.h"

/* ContentType values */
#define TLS_CT_CHANGE_CIPHER_SPEC  20u
#define TLS_CT_ALERT               21u
#define TLS_CT_HANDSHAKE           22u
#define TLS_CT_APPLICATION_DATA    23u
#define TLS_CT_HEARTBEAT           24u

/* HandshakeType values */
#define TLS_HT_CLIENT_HELLO        1u
#define TLS_HT_SERVER_HELLO        2u
#define TLS_HT_NEW_SESSION_TICKET  4u
#define TLS_HT_CERTIFICATE         11u
#define TLS_HT_SERVER_KEY_EXCHANGE 12u
#define TLS_HT_SERVER_HELLO_DONE   14u
#define TLS_HT_CLIENT_KEY_EXCHANGE 16u
#define TLS_HT_FINISHED            20u

#define TLS_MAX_RECORDS  8   /* max records parsed from one TCP payload */
#define TLS_MAX_SNI      256 /* max Server Name Indication length */

typedef struct {
    uint8_t  content_type;
    uint16_t version;           /* record layer version */
    uint16_t length;
    /* Set when content_type == TLS_CT_HANDSHAKE */
    int      has_handshake;
    uint8_t  handshake_type;
    uint32_t handshake_length;  /* 3-byte field */
    /* ClientHello / ServerHello fields */
    uint16_t hello_version;     /* version field inside Hello */
    char     sni[TLS_MAX_SNI];  /* Server Name (from ClientHello extension) */
    /* Alert fields */
    uint8_t  alert_level;
    uint8_t  alert_desc;
    /* ServerHello selected cipher suite */
    uint16_t selected_cipher_suite;
    /* Certificate message: number of certs in chain */
    int      cert_count;
} TlsRecord;

typedef struct {
    TlsRecord records[TLS_MAX_RECORDS];
    int       record_count;
} TlsMessage;

/*
 * tls_sniff — returns 1 if the payload looks like a TLS record, 0 otherwise.
 */
int tls_sniff(const uint8_t* payload, size_t len);

/*
 * tls_parse — parse TLS records from payload.
 * Returns 0 on success (≥1 record parsed), -1 if not TLS or malformed.
 */
int tls_parse(const uint8_t* payload, size_t len, TlsMessage* out);

void tls_print(const TlsMessage* msg);
const char* tls_content_type_name(uint8_t ct);
const char* tls_handshake_type_name(uint8_t ht);
const char* tls_version_name(uint16_t version);

#endif /* TLS_H */
