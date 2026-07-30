/*
 * standalone_main.c — compiler-agnostic driver for the fuzz targets
 *
 * Two modes:
 *
 *   replay (default)   Run every input named on the command line through
 *                      LLVMFuzzerTestOneInput() once. A directory argument
 *                      replays the regular files directly inside it. This is
 *                      what CTest uses on the checked-in corpus, so a crash
 *                      found once stays found.
 *
 *   --mutate=N         Load those inputs as seeds, then run N mutated
 *                      candidates derived from them. This is a dumb fuzzer: no
 *                      coverage feedback, no corpus growth. It exists because
 *                      libFuzzer needs Clang, and this way the parsers can
 *                      still be hammered under whatever sanitizer the local
 *                      compiler offers — including MSVC's AddressSanitizer.
 *                      For real campaigns, build with -DTCPIP_FUZZ=ON under
 *                      Clang and use the libFuzzer targets instead.
 *
 * Mutation is deterministic given --seed, so a crash is reproducible: re-run
 * with the same --seed and --save-current=PATH, and PATH holds the candidate
 * that was executing when the process died.
 *
 * A crash, an out-of-bounds access, or a UBSan trap aborts the process, which
 * is what makes either mode useful: the caller sees the nonzero exit.
 */

#include "fuzz_target.h"

#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <windows.h>
#else
#  include <dirent.h>
#  include <sys/stat.h>
#endif

#define FUZZ_MAX_INPUT_BYTES (1024u * 1024u)
#define FUZZ_MAX_PATH        1024u
#define FUZZ_MAX_SEEDS       4096u

typedef struct {
    uint8_t* data;
    size_t   len;
} FuzzInput;

static FuzzInput g_seeds[FUZZ_MAX_SEEDS];
static size_t    g_seed_count;
static const char* g_save_current;   /* NULL unless --save-current was given */

/* ── input loading ───────────────────────────────────────────────────────── */

/*
 * Read a file into an allocation sized exactly to its contents.
 *
 * The exact size is the point, not an economy: under AddressSanitizer the
 * redzone then sits immediately after the last valid byte, so a parser that
 * reads one byte past the length it was given is caught. Reading into an
 * oversized buffer would leave those overreads inside a valid allocation, and
 * this driver would report success on code libFuzzer flags immediately.
 */
static int read_exact_size(const char* path, FuzzInput* out) {
    FILE* fp = fopen(path, "rb");
    long size;

    if (!fp) {
        fprintf(stderr, "[fuzz] cannot open %s\n", path);
        return -1;
    }

    if (fseek(fp, 0, SEEK_END) != 0
            || (size = ftell(fp)) < 0
            || fseek(fp, 0, SEEK_SET) != 0) {
        fprintf(stderr, "[fuzz] cannot size %s\n", path);
        fclose(fp);
        return -1;
    }

    if ((unsigned long)size > FUZZ_MAX_INPUT_BYTES)
        size = (long)FUZZ_MAX_INPUT_BYTES;

    /* malloc(0) may legitimately return NULL, so ask for one byte and still
       report a length of zero: the empty input is a case worth testing. */
    out->data = (uint8_t*)malloc(size > 0 ? (size_t)size : 1u);
    if (!out->data) {
        fprintf(stderr, "[fuzz] out of memory reading %s\n", path);
        fclose(fp);
        return -1;
    }

    out->len = fread(out->data, 1, (size_t)size, fp);
    fclose(fp);
    return 0;
}

static int collect_file(const char* path) {
    FuzzInput input;
    if (g_seed_count >= FUZZ_MAX_SEEDS) {
        fprintf(stderr, "[fuzz] seed limit %u reached, ignoring %s\n",
                (unsigned)FUZZ_MAX_SEEDS, path);
        return -1;
    }
    if (read_exact_size(path, &input) != 0)
        return -1;
    g_seeds[g_seed_count++] = input;
    return 0;
}

/*
 * Collect the regular files directly inside a directory. Returns the number
 * collected, or -1 if the path is not a directory we can read. Subdirectories
 * are ignored; the corpus layout is flat.
 */
#ifdef _WIN32
static int collect_directory(const char* path, int* failures) {
    char pattern[FUZZ_MAX_PATH];
    char child[FUZZ_MAX_PATH];
    WIN32_FIND_DATAA entry;
    HANDLE find;
    int collected = 0;

    if (snprintf(pattern, sizeof(pattern), "%s\\*", path) < 0)
        return -1;

    find = FindFirstFileA(pattern, &entry);
    if (find == INVALID_HANDLE_VALUE)
        return -1;

    do {
        if (entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;
        if (snprintf(child, sizeof(child), "%s\\%s", path, entry.cFileName) < 0)
            continue;
        if (collect_file(child) != 0) (*failures)++;
        else collected++;
    } while (FindNextFileA(find, &entry));

    FindClose(find);
    return collected;
}
#else
static int collect_directory(const char* path, int* failures) {
    char child[FUZZ_MAX_PATH];
    struct dirent* entry;
    DIR* dir = opendir(path);
    int collected = 0;

    if (!dir) return -1;

    while ((entry = readdir(dir)) != NULL) {
        struct stat st;
        if (snprintf(child, sizeof(child), "%s/%s", path, entry->d_name) < 0)
            continue;
        if (stat(child, &st) != 0 || !S_ISREG(st.st_mode))
            continue;
        if (collect_file(child) != 0) (*failures)++;
        else collected++;
    }

    closedir(dir);
    return collected;
}
#endif

/* ── mutation ────────────────────────────────────────────────────────────── */

/* xorshift64*: small, deterministic, and good enough to pick offsets with. */
static uint64_t g_rng_state = 0x2545F4914F6CDD1DULL;

static uint64_t rng_next(void) {
    g_rng_state ^= g_rng_state >> 12;
    g_rng_state ^= g_rng_state << 25;
    g_rng_state ^= g_rng_state >> 27;
    return g_rng_state * 0x2545F4914F6CDD1DULL;
}

static size_t rng_below(size_t bound) {
    return bound == 0 ? 0 : (size_t)(rng_next() % bound);
}

/* Boundary values that length and count fields tend to be checked against. */
static const uint8_t k_interesting8[] = {
    0x00, 0x01, 0x02, 0x07, 0x08, 0x0F, 0x10, 0x1F, 0x20, 0x3F, 0x40,
    0x7E, 0x7F, 0x80, 0x81, 0xFE, 0xFF
};

/*
 * Derive one candidate from a seed. Returns the new length, and writes into
 * buf, which must have room for FUZZ_MAX_INPUT_BYTES.
 */
static size_t mutate(uint8_t* buf, size_t len) {
    unsigned rounds = 1u + (unsigned)rng_below(8);
    unsigned round;

    for (round = 0; round < rounds; round++) {
        switch (rng_next() % 8u) {
            case 0:  /* flip one bit */
                if (len) buf[rng_below(len)] ^= (uint8_t)(1u << rng_below(8));
                break;
            case 1:  /* overwrite one byte with a random value */
                if (len) buf[rng_below(len)] = (uint8_t)rng_next();
                break;
            case 2:  /* overwrite one byte with a boundary value */
                if (len)
                    buf[rng_below(len)] =
                        k_interesting8[rng_below(sizeof(k_interesting8))];
                break;
            case 3:  /* fill two bytes, hitting 16-bit length fields */
                if (len >= 2) {
                    size_t at = rng_below(len - 1);
                    buf[at]     = k_interesting8[rng_below(sizeof(k_interesting8))];
                    buf[at + 1] = k_interesting8[rng_below(sizeof(k_interesting8))];
                }
                break;
            case 4:  /* insert a byte */
                if (len < FUZZ_MAX_INPUT_BYTES) {
                    size_t at = rng_below(len + 1);
                    memmove(buf + at + 1, buf + at, len - at);
                    buf[at] = (uint8_t)rng_next();
                    len++;
                }
                break;
            case 5:  /* delete a byte */
                if (len) {
                    size_t at = rng_below(len);
                    memmove(buf + at, buf + at + 1, len - at - 1);
                    len--;
                }
                break;
            case 6:  /* truncate — the shape most likely to walk off the end */
                if (len > 1) len = 1u + rng_below(len - 1);
                break;
            default: /* splice a chunk in from another seed */
                if (g_seed_count > 0) {
                    const FuzzInput* other = &g_seeds[rng_below(g_seed_count)];
                    if (other->len > 0) {
                        size_t take = 1u + rng_below(other->len);
                        size_t from = rng_below(other->len - take + 1);
                        size_t at   = rng_below(len + 1);
                        if (at + take > FUZZ_MAX_INPUT_BYTES)
                            take = FUZZ_MAX_INPUT_BYTES - at;
                        memcpy(buf + at, other->data + from, take);
                        if (at + take > len) len = at + take;
                    }
                }
                break;
        }
    }
    return len;
}

static void save_current(const uint8_t* data, size_t len) {
    FILE* fp;
    if (!g_save_current) return;
    fp = fopen(g_save_current, "wb");
    if (!fp) return;
    if (len) fwrite(data, 1, len, fp);
    fclose(fp);
}

static int run_campaign(unsigned long runs) {
    /* One oversized scratch buffer to mutate in, and one exact-size copy per
       candidate so the sanitizer's redzone lands right after the input. */
    uint8_t* scratch = (uint8_t*)malloc(FUZZ_MAX_INPUT_BYTES);
    unsigned long iteration;

    if (!scratch) {
        fprintf(stderr, "[fuzz] out of memory allocating scratch buffer\n");
        return -1;
    }

    for (iteration = 0; iteration < runs; iteration++) {
        const FuzzInput* seed = &g_seeds[rng_below(g_seed_count)];
        uint8_t* candidate;
        size_t len;

        memcpy(scratch, seed->data, seed->len);
        len = mutate(scratch, seed->len);

        candidate = (uint8_t*)malloc(len > 0 ? len : 1u);
        if (!candidate) {
            fprintf(stderr, "[fuzz] out of memory at iteration %lu\n", iteration);
            break;
        }
        memcpy(candidate, scratch, len);

        save_current(candidate, len);
        LLVMFuzzerTestOneInput(candidate, len);
        free(candidate);

        if ((iteration % 20000u) == 0u)
            fprintf(stderr, "[fuzz] %lu/%lu\n", iteration, runs);
    }

    free(scratch);
    fprintf(stderr, "[fuzz] campaign finished: %lu run(s)\n", iteration);
    return 0;
}

/* ── entry point ─────────────────────────────────────────────────────────── */

static void usage(const char* argv0) {
    fprintf(stderr,
            "Usage: %s [options] <file-or-directory> [more...]\n"
            "  --mutate=N            run N mutated candidates instead of\n"
            "                        replaying the inputs once each\n"
            "  --seed=S              PRNG seed for --mutate (default 1)\n"
            "  --save-current=PATH   write each candidate to PATH before\n"
            "                        running it, so a crash leaves a\n"
            "                        reproducer behind\n",
            argv0);
}

int main(int argc, char* argv[]) {
    int i;
    int failures = 0;
    unsigned long runs = 0;
    size_t index;

    if (argc < 2) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    fuzz_silence_stdout();

    for (i = 1; i < argc; i++) {
        const char* arg = argv[i];

        if (strncmp(arg, "--mutate=", 9) == 0) {
            runs = strtoul(arg + 9, NULL, 10);
            continue;
        }
        if (strncmp(arg, "--seed=", 7) == 0) {
            /* Any nonzero state works; xorshift must never start at zero. */
            g_rng_state = strtoul(arg + 7, NULL, 10) * 0x9E3779B97F4A7C15ULL;
            if (g_rng_state == 0) g_rng_state = 0x2545F4914F6CDD1DULL;
            continue;
        }
        if (strncmp(arg, "--save-current=", 15) == 0) {
            g_save_current = arg + 15;
            continue;
        }
        if (arg[0] == '-' && arg[1] == '-') {
            fprintf(stderr, "[fuzz] unknown option %s\n", arg);
            usage(argv[0]);
            return EXIT_FAILURE;
        }

        if (collect_directory(arg, &failures) < 0 && collect_file(arg) != 0)
            failures++;
    }

    /* An empty corpus must not look like a pass. */
    if (g_seed_count == 0) {
        fprintf(stderr, "[fuzz] no inputs loaded\n");
        return EXIT_FAILURE;
    }

    fprintf(stderr, "[fuzz] loaded %lu input(s), %d unreadable\n",
            (unsigned long)g_seed_count, failures);

    if (runs > 0) {
        if (run_campaign(runs) != 0)
            failures++;
    } else {
        for (index = 0; index < g_seed_count; index++)
            LLVMFuzzerTestOneInput(g_seeds[index].data, g_seeds[index].len);
        fprintf(stderr, "[fuzz] replayed %lu input(s)\n",
                (unsigned long)g_seed_count);
    }

    for (index = 0; index < g_seed_count; index++)
        free(g_seeds[index].data);

    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
