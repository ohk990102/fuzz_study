#include <stdint.h>
#include <stddef.h>

void test1(const uint8_t *Data, size_t Size) {
    if (Size >= 4) {
        if (Data[0] == 'A' && Data[1] == 'B' && Data[2] == 'C') {
            int c = Data[0] / (Data[3] - 'A'+10);
        }
    }
}

void test2(const uint8_t *Data, size_t Size) {
    if (Size >= 4) {
        if (Data[0] == 'A' && Data[1] == 'B' && Data[2] == 'C') {
            int c = Data[0] / (Data[3] - Data[0]+10);
        }
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    test1(Data, Size);
    return 0;
}