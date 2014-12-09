#include "base64.h"

int test_base64() {
    unsigned char buf[4096];
    unsigned char b64[4096];
    unsigned int n, b64_n;

    n = read(0, buf, sizeof(buf));
    b64_n = base64_encoded_len(n);
    base64_encode(b64, buf, n, base64_std_table);

    write(1, buf, n);
    write(1, "\n", 1);

    write(1, b64, b64_n);
    write(1, "\n", 1);

    return 0;
}
