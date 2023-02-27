#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" int dualmac2hex(const char *dualmac, u_char *first, u_char *second, int len);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 20) {
        return 0;
    }
    FuzzedDataProvider provider(data, size);
    std::string mac = provider.ConsumeRemainingBytesAsString();
    u_char* buf = (u_char*) malloc(6);
    u_char* buf2 = (u_char*) malloc(6);
    provider.ConsumeData(buf, 6);
    provider.ConsumeData(buf2, 6);

    dualmac2hex(mac.c_str(), buf, buf2, 6);

    free(buf);
    free(buf2);

    return 0;
}
