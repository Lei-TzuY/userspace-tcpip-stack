/*
 * fuzz_util.c — helpers shared by every fuzz target and driver
 */

#include "fuzz_target.h"

#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <process.h>   /* _getpid */
#  define FUZZ_NULL_DEVICE "NUL"
#  define fuzz_getpid _getpid
#else
#  include <unistd.h>    /* getpid */
#  define FUZZ_NULL_DEVICE "/dev/null"
#  define fuzz_getpid getpid
#endif

void fuzz_silence_stdout(void) {
    static int silenced = 0;
    if (silenced) return;
    silenced = 1;
    if (!freopen(FUZZ_NULL_DEVICE, "wb", stdout)) {
        /* Keep going: noisy output is slow, not incorrect. */
        fprintf(stderr, "[fuzz] warning: could not silence stdout\n");
    }
}

/* Pick a writable directory for scratch files. */
static const char* fuzz_temp_dir(void) {
    const char* candidates[] = { "TMPDIR", "TMP", "TEMP" };
    size_t i;
    for (i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        const char* dir = getenv(candidates[i]);
        if (dir && dir[0] != '\0') return dir;
    }
    return ".";
}

int fuzz_temp_file_write(const uint8_t* data, size_t size,
                         char* path_out, size_t path_cap) {
    static unsigned long counter = 0;
    const char* dir = fuzz_temp_dir();
    FILE* fp;
    int written;

    written = snprintf(path_out, path_cap, "%s/tcpip_fuzz_%ld_%lu.tmp",
                       dir, (long)fuzz_getpid(), counter++);
    if (written < 0 || (size_t)written >= path_cap)
        return -1;

    fp = fopen(path_out, "wb");
    if (!fp) return -1;

    if (size > 0 && fwrite(data, 1, size, fp) != size) {
        fclose(fp);
        fuzz_temp_file_remove(path_out);
        return -1;
    }
    if (fclose(fp) != 0) {
        fuzz_temp_file_remove(path_out);
        return -1;
    }
    return 0;
}

void fuzz_temp_file_remove(const char* path) {
    if (path && path[0] != '\0')
        remove(path);
}
