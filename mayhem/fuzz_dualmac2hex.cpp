// In-process libFuzzer harness for tcpreplay common/mac.c:dualmac2hex().
//
// dualmac2hex() parses a comma-delimited pair of MAC addresses ("aa:bb:cc:dd:ee:ff,11:22:...")
// into two 6-byte buffers. We feed the fuzz bytes straight in as the comma-delimited string so the
// fuzzer drives the strtok_r split + the per-token mac2hex() hex parser. Output buffers are the
// fixed 6-byte MAC width (mac2hex writes exactly 6 octets when len>=6), so the harness itself never
// over-reads/over-writes. `len` is the string length — matching the real callers
// (tcpedit/plugins/dlt_en10mb/en10mb.c passes `strlen(OPT_ARG(ENET_DMAC))`); dualmac2hex early-
// returns for len<=1, so this reproduces production semantics rather than a hardcoded width. No heap
// is retained (no leak).
#include <cstring>
#include <stddef.h>
#include <stdint.h>
#include <string>

#include <fuzzer/FuzzedDataProvider.h>

typedef unsigned char u_char;
extern "C" int dualmac2hex(const char *dualmac, u_char *first, u_char *second, int len);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string dualmac = provider.ConsumeRandomLengthString();

    // Real callers pass strlen(arg) as len (a C string — no embedded NULs), so measure the
    // NUL-terminated length rather than the std::string size.
    const char *s = dualmac.c_str();
    u_char first[6] = {0};
    u_char second[6] = {0};
    dualmac2hex(s, first, second, (int)strlen(s));

    return 0;
}
