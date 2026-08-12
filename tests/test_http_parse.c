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

int main(void) {
    test_short_request_line();
    printf("http_parse tests passed\n");
    return 0;
}
