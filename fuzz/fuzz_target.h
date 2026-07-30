#ifndef FUZZ_TARGET_H
#define FUZZ_TARGET_H

/*
 * fuzz_target.h — shared plumbing for the fuzz targets
 *
 * Every target in this directory defines LLVMFuzzerTestOneInput(). Two drivers
 * can call it:
 *
 *   libFuzzer      — coverage-guided mutation, used when the project is built
 *                    with -DTCPIP_FUZZ=ON under clang.
 *   standalone_main.c — replays the files and directories named on the command
 *                    line. This works with any compiler, including MSVC, and
 *                    is what CTest uses to replay the checked-in corpus.
 *
 * The parsers print what they find. During fuzzing that output is worthless
 * and slow, so the drivers call fuzz_silence_stdout() first. Anything a driver
 * needs the user to see goes to stderr instead.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

/*
 * The libFuzzer entry point. Returns 0; any other value is reserved by
 * libFuzzer for future use.
 */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

/*
 * Redirect stdout to the platform null device. Safe to call more than once.
 * Errors are ignored: losing the redirect costs speed, not correctness.
 */
void fuzz_silence_stdout(void);

/*
 * Write size bytes to a new temporary file whose path is stored in path_out.
 * Returns 0 on success, -1 on failure. The caller must pass the path to
 * fuzz_temp_file_remove() when finished.
 *
 * The pcap reader opens captures by path rather than by stream, so a target
 * that wants to fuzz it has to materialise the input on disk.
 */
int fuzz_temp_file_write(const uint8_t* data, size_t size,
                         char* path_out, size_t path_cap);

/* Delete a file created by fuzz_temp_file_write(). */
void fuzz_temp_file_remove(const char* path);

#endif /* FUZZ_TARGET_H */
