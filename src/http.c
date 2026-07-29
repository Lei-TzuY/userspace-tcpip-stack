/*
 * http.c — HTTP/1.x request/response header parser
 */

#include "http.h"

/* Known HTTP request methods. */
static const char* METHODS[] = {
    "GET", "POST", "PUT", "DELETE", "HEAD",
    "OPTIONS", "PATCH", "CONNECT", "TRACE", NULL
};

/* Copy at most dst_max-1 bytes from src up to 'end', NUL-terminate. */
static size_t copy_until(char* dst, size_t dst_max,
                         const char* src, const char* end) {
    size_t n = 0;
    while (src < end && n + 1 < dst_max) dst[n++] = *src++;
    dst[n] = '\0';
    return n;
}

/* Find needle in [haystack, end). Returns pointer or NULL. */
static const char* mem_find(const char* haystack, const char* end,
                            const char* needle, size_t needle_len) {
    for (const char* p = haystack; p + needle_len <= end; p++) {
        if (memcmp(p, needle, needle_len) == 0) return p;
    }
    return NULL;
}

int http_sniff(const uint8_t* payload, size_t len) {
    if (!payload || len < 4) return 0;
    const char* p = (const char*)payload;
    /* Response */
    if (len >= 7 && memcmp(p, "HTTP/1.", 7) == 0) return 1;
    /* Request: check for method prefix */
    for (int i = 0; METHODS[i]; i++) {
        size_t mlen = strlen(METHODS[i]);
        if (len > mlen && memcmp(p, METHODS[i], mlen) == 0 && p[mlen] == ' ')
            return 1;
    }
    return 0;
}

int http_parse(const uint8_t* payload, size_t len, HttpMessage* out) {
    if (!http_sniff(payload, len)) return -1;

    memset(out, 0, sizeof(*out));
    const char* data = (const char*)payload;
    const char* end  = data + len;

    /* Find end of first line (\r\n or \n). */
    const char* crlf = mem_find(data, end, "\r\n", 2);
    const char* lf   = mem_find(data, end, "\n",   1);
    const char* eol  = (crlf && (!lf || crlf <= lf)) ? crlf : lf;
    if (!eol) return -1;
    size_t lf_len = (eol == crlf) ? 2u : 1u;

    /* Parse first line */
    const char* p = data;
    if (memcmp(p, "HTTP/1.", 7) == 0) {
        /* Response: "HTTP/1.x NNN Reason" */
        out->type = HTTP_MSG_RESPONSE;
        /* version */
        const char* sp1 = mem_find(p, eol, " ", 1);
        if (!sp1) return -1;
        copy_until(out->version, sizeof(out->version), p, sp1);
        /* status code */
        p = sp1 + 1;
        while (p < eol && *p == ' ') p++;
        out->status_code = 0;
        while (p < eol && *p >= '0' && *p <= '9')
            out->status_code = out->status_code * 10 + (*p++ - '0');
        /* reason */
        while (p < eol && *p == ' ') p++;
        copy_until(out->reason, sizeof(out->reason), p, eol);
    } else {
        /* Request: "METHOD URI HTTP/1.x" */
        out->type = HTTP_MSG_REQUEST;
        const char* sp1 = mem_find(p, eol, " ", 1);
        if (!sp1) return -1;
        copy_until(out->method, sizeof(out->method), p, sp1);
        p = sp1 + 1;
        const char* sp2 = mem_find(p, eol, " ", 1);
        if (sp2) {
            copy_until(out->request_uri, sizeof(out->request_uri), p, sp2);
            copy_until(out->version, sizeof(out->version), sp2 + 1, eol);
        } else {
            copy_until(out->request_uri, sizeof(out->request_uri), p, eol);
        }
    }

    /* Parse headers (lines until blank line) */
    p = eol + lf_len;
    while (p < end && out->header_count < HTTP_MAX_HEADERS) {
        /* Find next line end */
        const char* ecrlf = mem_find(p, end, "\r\n", 2);
        const char* elf   = mem_find(p, end, "\n",   1);
        const char* el    = (ecrlf && (!elf || ecrlf <= elf)) ? ecrlf : elf;
        size_t el_len     = (el == ecrlf) ? 2u : 1u;
        if (!el) break;
        if (el == p) { /* blank line → start of body */
            p = el + el_len;
            break;
        }
        /* Split "Name: Value" */
        const char* colon = mem_find(p, el, ":", 1);
        if (colon) {
            HttpHeader* h = &out->headers[out->header_count++];
            copy_until(h->name,  sizeof(h->name),  p, colon);
            const char* val = colon + 1;
            while (val < el && (*val == ' ' || *val == '\t')) val++;
            copy_until(h->value, sizeof(h->value), val, el);
        }
        p = el + el_len;
    }

    /* Remaining bytes are the body */
    if (p < end) {
        out->body     = (const uint8_t*)p;
        out->body_len = (size_t)(end - p);
    }
    return 0;
}

void http_print(const HttpMessage* msg) {
    printf("+-- HTTP/1.x ------------------------------------------------+\n");
    if (msg->type == HTTP_MSG_REQUEST) {
        printf("|  %s %s %s\n", msg->method, msg->request_uri, msg->version);
    } else {
        printf("|  %s %d %s\n", msg->version, msg->status_code, msg->reason);
    }
    for (int i = 0; i < msg->header_count; i++)
        printf("|  %s: %s\n", msg->headers[i].name, msg->headers[i].value);
    if (msg->body_len > 0)
        printf("|  [body: %zu bytes]\n", msg->body_len);
    printf("+------------------------------------------------------------+\n");
}
