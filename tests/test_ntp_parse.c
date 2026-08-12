#include <assert.h>
#include <stdio.h>

#include "ntp.h"

static void test_poll_interval_bounds(void) {
    assert(ntp_poll_interval_seconds(-1) == 0u);
    assert(ntp_poll_interval_seconds(0) == 1u);
    assert(ntp_poll_interval_seconds(31) == 0x80000000u);
    assert(ntp_poll_interval_seconds(32) == 0u);
    assert(ntp_poll_interval_seconds(127) == 0u);
}

int main(void) {
    test_poll_interval_bounds();
    printf("ntp_parse tests passed\n");
    return 0;
}
