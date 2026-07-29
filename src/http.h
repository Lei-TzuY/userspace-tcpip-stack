#ifndef HTTP_H
#define HTTP_H

/*
 * http.h — HTTP/1.x request/response header parser (best-effort, single segment)
 *
 * Detects whether a TCP payload is an HTTP/1.x message, then parses the
 * first line and up to HTTP_MAX_HEADERS header fields.
 */

#include "common.h"

#define HTTP_MAX_HEADERS  20
#define HTTP_MAX_FIELD    128  /* max chars per header name or value */

typedef enum {
    HTTP_MSG_REQUEST,
    HTTP_MSG_RESPONSE
} HttpMsgType;

typedef struct {
    char name[HTTP_MAX_FIELD];
    char value[HTTP_MAX_FIELD];
} HttpHeader;

typedef struct {
    HttpMsgType type;
    /* Request fields */
    char method[16];
    char request_uri[256];
    char version[12];     /* e.g. "HTTP/1.1" */
    /* Response fields */
    int  status_code;
    char reason[64];
    /* Common headers */
    HttpHeader headers[HTTP_MAX_HEADERS];
    int        header_count;
    /* Body (pointer into caller's buffer, not owned) */
    const uint8_t* body;
    size_t         body_len;
} HttpMessage;

/*
 * http_sniff — returns 1 if the payload looks like an HTTP/1.x message,
 * 0 otherwise. Does not parse.
 */
int http_sniff(const uint8_t* payload, size_t len);

/*
 * http_parse — parse an HTTP/1.x message from raw bytes.
 * Returns 0 on success, -1 if not HTTP or malformed.
 */
int http_parse(const uint8_t* payload, size_t len, HttpMessage* out);

void http_print(const HttpMessage* msg);

#endif /* HTTP_H */
