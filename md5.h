#ifndef _MD5_H_
#define _MD5_H_

/*------------------------------------------------------------------*\

       file: md5.h (taken from alock, based on opensd m5d)
      about: implements md5-checksumming
     author: m. gumz <mg@2hoch5.com>
    license: see md5.c

\*------------------------------------------------------------------*/

enum {
    MD5_BLOCK_LENGTH         = 64,
    MD5_DIGEST_LENGTH        = 16,
    MD5_DIGEST_STRING_LENGTH = (MD5_DIGEST_LENGTH * 2 + 1)
};

typedef struct {
    unsigned int state[4];                  /* state */
    unsigned long long count;                /* number of bits, mod 2^64 */
    unsigned char buffer[MD5_BLOCK_LENGTH];  /* input buffer */
} md5Context;

extern void md5_init(md5Context*);
extern void md5_update(md5Context*, const unsigned char[], unsigned int);
extern void md5_pad(md5Context*);
extern void md5_final(unsigned char [MD5_DIGEST_LENGTH], md5Context*);
extern void md5_transform(unsigned int [4], const unsigned char [MD5_BLOCK_LENGTH]);

#endif
