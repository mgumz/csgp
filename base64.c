/*------------------------------------------------------------------*\

       file: base64.c
      about: implements base64-encoding
     author: m. gumz <mg@2hoch5.com>
    license: see LICENSE.txt

\*------------------------------------------------------------------*/

#include "base64.h"

const unsigned char base64_std_table[65] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/=";


int base64_encoded_len(unsigned int n) {
    return ((n + 2)/3)*4;
}

int base64_encode(unsigned char* out, unsigned char* in, unsigned int n, unsigned const char table[65]) {

    union { unsigned char val[4]; unsigned int all; } b64;

    // take the next 3 bytes, spread 6bits of each over
    // the 4byte b64.val, then lookup the replacement
    // char in the table and do some padding if needed
    //
    for (b64.all = 0; ; n = n - 3, in += 3, out += 4) {

        switch(n) {
        default:
            b64.val[3] = in[2] & 0x3f;
            b64.val[2] = in[2] >> 6;
        case 2:
            b64.val[2] |= (in[1] << 2) & 0x3f;
            b64.val[1] = in[1] >> 4;
        case 1:
            b64.val[1] |= (in[0] << 4) & 0x3f;
            b64.val[0] = in[0] >> 2;
            break;
        }

        b64.val[0] = table[b64.val[0]];
        b64.val[1] = table[b64.val[1]];
        b64.val[2] = table[b64.val[2]];
        b64.val[3] = table[b64.val[3]];

        *((unsigned int*)out) = b64.all;
        b64.all = 0;

        if (n < 3) { // padding
            out[3] = table[64];
            if (n < 2) {
                out[2] = table[64];
            }
            // we use 'n' to count, it will wrap
            // around on negative numbers. so, this
            // is the loop-termination
            break;
        }
    }

    return 1;
}
