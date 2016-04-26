/*------------------------------------------------------------------*\

       file: main.c
      about: csgp is a commandline tool which derives a password from
             a secret and a domain-name.

             it is a port of supergenpass.com into plain c
     author: m. gumz <mg@2hoch5.com>
    license: see LICENSE.txt

   SUPERGENPASS:

     in_pw:domain
      |
      v
     input -> md5Context.state     (16bytes)
      ^            |
      |            v
      |       md5_final(raw, &ctx) (16bytes)
      |            |
      |            v
      |       base64(out, raw)     (24bytes)
      |            |
      |            v
      +------ is_valid()
                   |
                   v
                  out
   notes:

   - the initial password is stored only once in the working
     buffer. it get's overwritten in the first round already.
   - for the whole process we allocate only 25 bytes: the amount
     of ram needed to base64_encode(16 bytes) == 24 bytes PLUS
     1 extra byte to detect, if the given master password is too
     long (see read_pw()).
   - the 16 bytes for the digest are stored inside the 24 byte buffer
     (like this: [24......[16..............]] ). this works because
     * the master-passwords ends directly as a md5-state in the first round
     * the md5-state is copied over into the 16byte block
     * the 16byte block gets base64-encoded. the b64-encoder chases the
       currently processed byte from the 16byte block but never catches
       up; except for the last round. in that round, any trace of the raw
       md5-state got erased by the base64-version of it:

           +--------+
       [aaaa.......[111.........]]
       [aaaabbbb...[111222......]]
       [aaaabbbbccc[c11222333...]]

     * the 24byte buffer is then transformed into a md5-state and
       the whole process repeats.

   - in addition we need one md5Context and bytes for the
     domain which we get by argv[]
   - all sensitive information gets overwritten as soon
     as it is not needed anymore

\*------------------------------------------------------------------*/

#include "md5.h"
#include "base64.h"
#include "platform.h"

#include "djb/str.h"
#include "djb/scan.h"
#include "djb/byte.h"

/*------------------------------------------------------------------*\
\*------------------------------------------------------------------*/

const char USAGE[]  = "csgp -domain=xyz [-length=10] [-nolock]";
const char PROMPT[] = "password: ";

// special base64-table to replace
// '+' -> 9
// '/' -> 8
// '=' => A (the padding sign)
const unsigned char B64_SGP_TABLE[BASE64_LUT_LEN] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "012345678998A";

enum {
    MIN_PW_LENGTH         = 4,
    DEFAULT_PW_LENGTH     = 10,
    MAX_ROUNDS            = 10,
    B64_MD5_DIGEST_LENGTH = 24, // base_encded_len(MD5_DIGEST_LENGTH)
};


/*------------------------------------------------------------------*\
\*------------------------------------------------------------------*/

struct SGP;
int supergenpass(struct SGP*);
int read_pw(int fd, unsigned char* pw, size_t max_len);
int get_opts(int argc, char* argv[], size_t* len, unsigned char** domain, int* lock);
int is_valid(const unsigned char* pw, size_t len);

/*------------------------------------------------------------------*\
\*------------------------------------------------------------------*/

struct SGP {
    size_t          in_len;   // length of input password
    size_t          out_len;  // length of generated password
    unsigned char   pw[B64_MD5_DIGEST_LENGTH+1]; // see 'notes' above
    md5Context      md5;
    unsigned char*  domain;
    size_t          domain_len;
};

/*------------------------------------------------------------------*\
\*------------------------------------------------------------------*/

int main(int argc, char* argv[]) {

    struct SGP sgp;
    unsigned char* domain = 0;
    int domain_len = 0;
    int lock = 1;

    sgp.out_len = DEFAULT_PW_LENGTH;

    get_opts(argc, argv, &sgp.out_len, &domain, &lock);

    if (!domain) {
        return osexit(1, "usage: csgp -domain=\"example.com\"");
    }

    domain_len = str_len(domain);

    if (lock) {
        if (lock_memory(domain, domain_len) != 0) {
            return osexit(4, "error: can't lock memory");
        }
        if (lock_memory(&sgp, sizeof(sgp)) != 0) {
            return osexit(4, "error: can't lock memory");
        }
    }

    if ((sgp.out_len < MIN_PW_LENGTH) || (sgp.out_len > B64_MD5_DIGEST_LENGTH)) {
        return osexit(1, "error: given -length must be >= 4 and <= 24");
    }

    sgp.domain = domain;
    sgp.domain_len = domain_len;

    sgp.in_len = read_pw(0, sgp.pw, sizeof(sgp.pw));

    supergenpass(&sgp);

    if (posix_isatty(1)) {
        posix_write(1, "\n", 1);
        posix_write(1, sgp.pw, sgp.out_len);
        posix_write(1, "\n", 1);
    } else {
        posix_write(1, sgp.pw, sgp.out_len);
    }
    posix_fsync(1);

    byte_zero(domain, domain_len);
    byte_zero(&sgp, sizeof(sgp));

    if (lock) {
        unlock_memory(&sgp, sizeof(sgp));
        unlock_memory(domain, domain_len);
    }

    return 0;
}


int supergenpass(struct SGP* sgp) {

    md5Context* ctx = &(sgp->md5);
    unsigned char* pw = &(sgp->pw[0]);
    unsigned char* raw = &(sgp->pw[B64_MD5_DIGEST_LENGTH-MD5_DIGEST_LENGTH]);
    int round;
    md5_init(ctx);

    // the initial round
    md5_update(ctx, pw, sgp->in_len);
    md5_update(ctx, (unsigned char*)":", 1);
    md5_update(ctx, sgp->domain, sgp->domain_len);
    md5_final(raw, ctx);
    base64_encode(pw, raw, MD5_DIGEST_LENGTH, B64_SGP_TABLE);

    // the other MAX_ROUNDS - 1
    for (round = 1; round < MAX_ROUNDS; round++) {
        md5_init(ctx);
        md5_update(ctx, pw, B64_MD5_DIGEST_LENGTH);
        md5_final(raw, ctx);
        base64_encode(pw, raw, MD5_DIGEST_LENGTH, B64_SGP_TABLE);
    }

    // continue until the pw is valid
    for (; is_valid(pw, sgp->out_len) == 0; ) {
        md5_init(ctx);
        md5_update(ctx, pw, B64_MD5_DIGEST_LENGTH);
        md5_final(raw, ctx);
        base64_encode(pw, raw, MD5_DIGEST_LENGTH, B64_SGP_TABLE);
    }

    // cleanup: md5_final() sets all elements of ctx to 0.
    // the user is interested only in the first sgp->out_len bytes
    // of sgp->pw anyway: 0 the rest.
    byte_zero(pw + sgp->out_len, sizeof(sgp->pw) - sgp->out_len);
    return 1;
}

/*------------------------------------------------------------------*\
\*------------------------------------------------------------------*/

int get_opts(int argc, char* argv[], size_t* len, unsigned char** domain, int* lock) {

    const char opt_help[]   = "-h";
    const char opt_length[] = "-length=";
    const char opt_domain[] = "-domain=";
    const char opt_nolock[] = "-nolock";

    int i;
    for (i = 1; i < argc; i++) {
        if (str_diffn(argv[i], opt_help, sizeof(opt_help)-1) == 0) {
            return osexit(0, USAGE);
        } else if (str_diffn(argv[i], opt_nolock, sizeof(opt_nolock)-1) == 0) {
            *lock = 0;
        } else if (str_diffn(argv[i], opt_length, sizeof(opt_length)-1) == 0) {
            unsigned long l = 0;
            if (str_len(argv[i]) <= sizeof(opt_length)-1) {
                return osexit(1, "error: missing argument for -length");
            }
            if (scan_ulong(&argv[i][sizeof(opt_length)-1], &l) == 0) {
                return osexit(1, "error: can't parse given -length");
            }
            *len = (size_t)l;
        } else if (str_diffn(argv[i], opt_domain, sizeof(opt_domain)-1) == 0) {
            if (str_len(argv[i]) <= sizeof(opt_domain)-1) {
                return osexit(1, "error: missing argument for -domain");
            }
            *domain = (unsigned char*)&argv[i][sizeof(opt_domain)-1];
        }
    }
    return 0;
}

int read_pw(int fd, unsigned char* pw, size_t max_len) {

    int n;

    if (posix_isatty(fd)) {
        posix_write(2, PROMPT, sizeof(PROMPT)-1);
        posix_fsync(2);
        tty_echo(fd, 0);
    }

    n = (int)posix_read(fd, pw, max_len);

    if (posix_isatty(fd)) {
        tty_echo(fd, 1);
    }

    if (n == -1) {
        return osexit(2, "error: reading pw");
    }

    // scan backward for lf/cr aka 'the enter'
    for(; n > 0; n--) {
        if (!(pw[n-1] == '\n' || pw[n-1] == '\r')) {
            break;
        }
    }

    if (n == 0) {
        return osexit(2, "error: pw empty");
    }

    // the given buffer is essentially one byte larger
    // than the maximum allowed passphrase length.
    // if we were able to read max_len bytes, the
    // passphrase exceeds the maximum passphrase length.
    // a) due to the limit of the design of csgp we won't
    //    be able to handle more bytes
    // b) we don't want to write the superflouse bytes to
    //    stdout where they would become part of the next
    //    command and thus leak information.
    // thus, we flush stdin, zero the already read password
    // and exit with an error
    if (n == max_len) {
        if (posix_isatty(fd)) {
            discard_fd(1);
        }
        byte_zero(pw, max_len);
        return osexit(2, "the passphrase is longer than 24 bytes.");
    }

    return n;
}

// checks the first 'length' bytes of 'pw' if they
// are valid under the rules of supergenpass.com:
//
// 1. first char is a lowercase letter [a-z]
// 2. there is at least one uppercase letter [A-Z]
// 3. there is at least one digit [0-9]
int is_valid(const unsigned char* pw, size_t len) {
    unsigned int mask = 0;
    if (!(*pw >= 'a' && *pw <= 'z')) {
        return 0;
    }
    for (; len > 0; pw++, len--) {
        if ((*pw >= 'A') && (*pw <= 'Z')) {
            mask |= 1;
        } else if ((*pw >= '0') && (*pw <= '9')) {
            mask |= 2;
        }
        if (mask == 3) {
            return 1;
        }
    }
    return 0;
}

