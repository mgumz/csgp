#include "platform.h"
#include "djb/str.h"
#include <stdlib.h>

void osexit(int c, const char* msg) {
    if (msg) {
        posix_write(2, msg, str_len(msg));
        posix_write(2, "\n", 1);
    }
    exit(c);
}

