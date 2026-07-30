/*
 * main.c — Toy TCP/IP Stack
 *
 * Usage:
 *   tcpip [options] <file.pcap|file.pcapng>
 *
 * Protocol stack layers implemented:
 *
 *   ┌──────────────────────────────────────────────────────────┐
 *   │  Layer 7 — DNS  (query/answer, A/AAAA/CNAME/MX/TXT/NS) │
 *   │  Layer 7 — HTTP / TLS / DHCP / NTP (sniffed payloads)     │
 *   │  Layer 4 — TCP  (segments, options, checksum, analysis)  │
 *   │  Layer 4 — UDP  (datagrams, pseudo-header checksum)      │
 *   │  Layer 3 — ICMPv6 (echo, NDP RS/RA/NS/NA, options)      │
 *   │  Layer 3 — ICMP (echo, unreachable, time-exceeded)       │
 *   │  Layer 3 — IPv6 (fixed header + reassembly)              │
 *   │  Layer 3 — IPv4 (header, reassembly, checksum)           │
 *   │  Layer 2 — ARP  (request / reply)                        │
 *   │  Layer 2 — Ethernet II / VLAN (MAC, dispatch)            │
 *   │  pcap file reader (offline mode, endian-aware)           │
 *   └──────────────────────────────────────────────────────────┘
 *
 * This file owns the command line and the capture-reading loop only. The
 * per-frame protocol walk lives in dispatch.c so that test and fuzz drivers
 * can exercise the same code path the CLI uses.
 */

#include "common.h"
#include "pcap.h"
#include "dispatch.h"
#include "report.h"

#ifdef _WIN32
#  include <io.h>
#  define os_dup   _dup
#  define os_dup2  _dup2
#  define os_close  _close
#  define os_fileno _fileno
#  define OS_NULL_DEVICE "NUL"
#else
#  include <unistd.h>
#  define os_dup   dup
#  define os_dup2  dup2
#  define os_close  close
#  define os_fileno fileno
#  define OS_NULL_DEVICE "/dev/null"
#endif

#define PKT_BUF_SIZE (64 * 1024)

/* ── options ─────────────────────────────────────────────────────────────── */

typedef struct {
    const char* capture_path;
    int         quiet;        /* suppress the per-packet walk */
    int         no_summary;   /* suppress the human-readable summaries */
    int         want_json;
    const char* json_path;    /* NULL means stdout */
    int         want_csv;
    const char* csv_path;
} Options;

static void print_usage(const char* argv0) {
    printf("Usage: %s [options] <file.pcap|file.pcapng>\n"
           "\n"
           "Options:\n"
           "  -q, --quiet         suppress the per-packet output; print only\n"
           "                      the end-of-capture summaries\n"
           "      --no-summary    suppress the human-readable summaries\n"
           "      --json[=PATH]   write the analysis as JSON (default stdout)\n"
           "      --csv[=PATH]    write the conversation table as CSV\n"
           "                      (default stdout)\n"
           "  -h, --help          show this help and exit\n"
           "\n"
           "Writing both JSON and CSV to stdout at once is refused, since the\n"
           "result would parse as neither.\n",
           argv0);
}

/*
 * Parse the command line. Returns 0 on success, -1 on a usage error (already
 * reported), and 1 when help was requested and the caller should just exit.
 */
static int parse_options(int argc, char* argv[], Options* options) {
    int i;

    memset(options, 0, sizeof(*options));

    for (i = 1; i < argc; i++) {
        const char* arg = argv[i];

        if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
            print_usage(argv[0]);
            return 1;
        }
        if (strcmp(arg, "-q") == 0 || strcmp(arg, "--quiet") == 0) {
            options->quiet = 1;
            continue;
        }
        if (strcmp(arg, "--no-summary") == 0) {
            options->no_summary = 1;
            continue;
        }
        if (strcmp(arg, "--json") == 0) {
            options->want_json = 1;
            continue;
        }
        if (strncmp(arg, "--json=", 7) == 0) {
            options->want_json = 1;
            options->json_path = arg + 7;
            continue;
        }
        if (strcmp(arg, "--csv") == 0) {
            options->want_csv = 1;
            continue;
        }
        if (strncmp(arg, "--csv=", 6) == 0) {
            options->want_csv = 1;
            options->csv_path = arg + 6;
            continue;
        }
        if (arg[0] == '-' && arg[1] != '\0') {
            fprintf(stderr, "%s: unknown option '%s'\n", argv[0], arg);
            print_usage(argv[0]);
            return -1;
        }

        if (options->capture_path) {
            fprintf(stderr, "%s: more than one capture given ('%s' and '%s')\n",
                    argv[0], options->capture_path, arg);
            return -1;
        }
        options->capture_path = arg;
    }

    if (!options->capture_path) {
        fprintf(stderr, "%s: no capture file given\n", argv[0]);
        print_usage(argv[0]);
        return -1;
    }

    /* Two structured formats interleaved on one stream parse as neither. */
    if (options->want_json && options->want_csv
            && !options->json_path && !options->csv_path) {
        fprintf(stderr, "%s: --json and --csv cannot both write to stdout; "
                        "give a path to at least one\n", argv[0]);
        return -1;
    }

    /*
     * A structured document on stdout has to be the only thing on stdout.
     * Leaving the packet walk switched on would emit something that parses as
     * neither JSON nor CSV, so asking for one implies the quiet flags rather
     * than requiring the caller to remember them.
     */
    if ((options->want_json && !options->json_path)
            || (options->want_csv && !options->csv_path)) {
        options->quiet      = 1;
        options->no_summary = 1;
    }

    return 0;
}

/* ── temporarily silencing the per-packet walk ───────────────────────────── */

/*
 * The parsers print as they go, which is the point of the tool but useless
 * when the caller wants only the summary or a JSON document. Rather than
 * threading a verbosity flag through every parser, stdout's file descriptor is
 * pointed at the null device for the duration of the capture loop and restored
 * afterwards, so the summaries still land on the real stdout.
 *
 * Diagnostics go to stderr and are deliberately left alone: a malformed packet
 * should still be reported even in quiet mode.
 */
typedef struct {
    int   saved_fd;
    FILE* null_stream;
    int   active;
} StdoutSilencer;

static void stdout_silence(StdoutSilencer* silencer) {
    memset(silencer, 0, sizeof(*silencer));
    silencer->saved_fd = -1;

    fflush(stdout);
    silencer->saved_fd = os_dup(os_fileno(stdout));
    if (silencer->saved_fd < 0)
        return;

    silencer->null_stream = fopen(OS_NULL_DEVICE, "wb");
    if (!silencer->null_stream) {
        os_close(silencer->saved_fd);
        silencer->saved_fd = -1;
        return;
    }

    if (os_dup2(os_fileno(silencer->null_stream), os_fileno(stdout)) < 0) {
        fclose(silencer->null_stream);
        silencer->null_stream = NULL;
        os_close(silencer->saved_fd);
        silencer->saved_fd = -1;
        return;
    }
    silencer->active = 1;
}

static void stdout_restore(StdoutSilencer* silencer) {
    if (!silencer->active)
        return;

    fflush(stdout);
    os_dup2(silencer->saved_fd, os_fileno(stdout));
    os_close(silencer->saved_fd);
    fclose(silencer->null_stream);
    silencer->active = 0;
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(int argc, char* argv[]) {
    Options        options;
    PcapReader*    reader;
    uint8_t*       buf;
    StackContext*  stack;
    StdoutSilencer silencer;
    PcapPacketHeader pkt_hdr;
    size_t pkt_count = 0;
    int    status = EXIT_SUCCESS;
    int    parsed = parse_options(argc, argv, &options);

    if (parsed != 0)
        return parsed > 0 ? EXIT_SUCCESS : EXIT_FAILURE;

    /* Silence stdout before anything can write to it. pcap_open announces the
       file it opened, and that banner would sit in front of a JSON document. */
    if (options.quiet)
        stdout_silence(&silencer);
    else
        memset(&silencer, 0, sizeof(silencer));

    reader = pcap_open(options.capture_path);
    if (!reader) {
        stdout_restore(&silencer);
        return EXIT_FAILURE;
    }

    buf = (uint8_t*)malloc(PKT_BUF_SIZE);
    if (!buf) {
        stdout_restore(&silencer);
        fprintf(stderr, "Out of memory\n");
        pcap_close(reader);
        return EXIT_FAILURE;
    }

    stack = stack_create();
    if (!stack) {
        stdout_restore(&silencer);
        fprintf(stderr, "Out of memory\n");
        free(buf);
        pcap_close(reader);
        return EXIT_FAILURE;
    }

    printf("\n");

    while (1) {
        size_t pkt_len = pcap_next(reader, &pkt_hdr, buf, PKT_BUF_SIZE);
        if (pkt_len == 0) break;

        pkt_count++;
        uint64_t timestamp_usec =
            ((uint64_t)pkt_hdr.ts_sec * 1000000u) + pkt_hdr.ts_usec;
        stack_expire_idle(stack, timestamp_usec);
        printf("══ Packet #%zu  (%u bytes on-wire  @  %u.%06u s) ══\n",
               pkt_count,
               pkt_hdr.orig_len,
               pkt_hdr.ts_sec,
               pkt_hdr.ts_usec);

        if (reader->global.network != LINKTYPE_ETHERNET) {
            printf("  [skip] Non-Ethernet link type %u\n",
                   reader->global.network);
            printf("\n");
            continue;
        }

        stack_dispatch_frame(stack, buf, pkt_len, timestamp_usec);
        printf("\n");
    }

    stdout_restore(&silencer);

    if (!options.no_summary) {
        printf("── Done. Parsed %zu packet(s). ──\n", pkt_count);
        stack_print_summary(stack);
    }

    if (options.want_json
            && report_write_json(stack, options.json_path, pkt_count) != 0) {
        fprintf(stderr, "Cannot write JSON report to %s\n",
                options.json_path ? options.json_path : "stdout");
        status = EXIT_FAILURE;
    }
    if (options.want_csv
            && report_write_csv(stack, options.csv_path, pkt_count) != 0) {
        fprintf(stderr, "Cannot write CSV report to %s\n",
                options.csv_path ? options.csv_path : "stdout");
        status = EXIT_FAILURE;
    }

    stack_destroy(stack);
    free(buf);
    pcap_close(reader);
    return status;
}
