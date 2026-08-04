/*
 * test_support.c — make a failed assertion behave like a failed test
 *
 * Every test in this directory checks things with assert(). On Windows that is
 * not enough on its own: the debug CRT answers a failed assertion with a modal
 * dialog box, so the process sits waiting for a click that a CTest run will
 * never provide. What should be an immediate failure becomes a hang until
 * whatever timeout is furthest out gives up, with none of the assertion text
 * anywhere in the log.
 *
 * Routing the CRT's assertion and error reports to stderr instead restores the
 * usual behaviour: the message is printed, the process aborts, CTest records a
 * failure, and the log says which assertion it was.
 *
 * This file is linked into every test target rather than being called from
 * each main(), because a test that forgets the call is exactly the test whose
 * failure would go unnoticed.
 */

#if defined(_WIN32) && defined(_DEBUG)

#include <crtdbg.h>

static int test_support_quiet_assertions(void) {
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
    _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDERR);
    return 0;
}

/*
 * Run it before main(). The CRT walks the .CRT$XCU section during start-up and
 * calls every function pointer it finds there, which is the documented way to
 * get C code to run ahead of main() with MSVC.
 */
#pragma section(".CRT$XCU", read)
__declspec(allocate(".CRT$XCU"))
static int (*test_support_init)(void) = test_support_quiet_assertions;

#else

/*
 * Nothing to do elsewhere: assert() writes to stderr and calls abort(), which
 * is already what a test failure should look like. ISO C forbids an empty
 * translation unit, so leave something behind.
 */
typedef int test_support_translation_unit_is_not_empty;

#endif
