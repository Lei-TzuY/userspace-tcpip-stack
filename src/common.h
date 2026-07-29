#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

/* ─────────────────────────────────────────────────
   Portable byte-order helpers
   ───────────────────────────────────────────────── */
#ifdef _WIN32
#  include <winsock2.h>   /* ntohs / ntohl */
#  ifdef _MSC_VER
#    pragma comment(lib, "Ws2_32.lib")
#  endif
#else
#  include <arpa/inet.h>
#endif

/* Suppress unused-parameter warnings in stubs */
#define UNUSED(x) ((void)(x))

#endif /* COMMON_H */
