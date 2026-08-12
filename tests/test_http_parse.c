#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "http.h"

static void test_short_request_line(void) {
    static const uint8_t request[] = "GET 1\n";
    HttpMessage message;

    assert(http_parse(request, sizeof(request) - 1u, &message) == 0);
    assert(message.type == HTTP_MSG_REQUEST);
    assert(strcmp(message.method, "GET") == 0);
    assert(strcmp(message.request_uri, "1") == 0);
}

static void test_status_code_digit_bounds(void) {
    static const uint8_t valid[] = "HTTP/1.1 200 OK\r\n\r\n";
    static const uint8_t oversized[] = "HTTP/1.1 24777777777777777777 OK\n";
    HttpMessage message;

    assert(http_parse(valid, sizeof(valid) - 1u, &message) == 0);
    assert(message.status_code == 200);
    assert(http_parse(oversized, sizeof(oversized) - 1u, &message) == -1);
}

int main(void) {
    test_short_request_line();
    test_status_code_digit_bounds();
    printf("http_parse tests passed\n");
    return 0;
}
