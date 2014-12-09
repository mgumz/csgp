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
   - for the whole process we allocate only 16+24 bytes:
     16: bytes needed for md5_final()
     24: bytes needed for base64_encode(16 bytes)
   - in addition we need one md5Context and bytes for the
     domain which we get by argv[]
   - all sensitive informatio gets overwritten as soon
     as it is not needed anymore

\*------------------------------------------------------------------*/

#include "md5.h"
#include "base64.h"

#include "djb/str.h"
#include "djb/scan.h"
#include "djb/byte.h"

#include <stdlib.h>

/*------------------------------------------------------------------*\
\*------------------------------------------------------------------*/

const char USAGE[]  = "csgp -domain=xyz [-length=10]";
const char PROMPT[] = "password: ";

// special base64-table to replace
// '+' -> 9
// '/' -> 8
// '=' => A (the padding sign)
const unsigned char B64_SGP_TABLE[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "012345678998A";

enum {
    MIN_PW_LENGTH         = 4,
    DEFAULT_PW_LENGTH     = 10,
    MAX_ROUNDS            = 10,
    B64_MD5_DIGEST_LENGTH = 24, // base_encded_len(MD5_DIGEST_LENGTH)
    PW_BUF_SIZE           = B64_MD5_DIGEST_LENGTH + MD5_DIGEST_LENGTH
};


/*------------------------------------------------------------------*\
\*------------------------------------------------------------------*/

struct SGP;
int supergenpass(struct SGP*);
void osexit(int code, const char* msg);
int read_pw(int fd, unsigned char* pw, int max_length);
int get_opts(int argc, char* argv[], int* length, unsigned char** domain);
int is_valid(unsigned char* in, unsigned int length);

// platform-wrappers
unsigned int posix_write(int fd, const void* buf, unsigned int n);
unsigned int posix_read(int fd, void* buf, unsigned int n);
int posix_fsync(int fd);
int posix_isatty(int fd);
int tty_echo(int fd, int on);

/*------------------------------------------------------------------*\
\*------------------------------------------------------------------*/

struct SGP {
    int             in_len;   // length of input password
    int             out_len;  // length of generated password
    unsigned char   pw[PW_BUF_SIZE]; // see NOTES above
    md5Context      md5;
    unsigned char*  domain;
    int             domain_len;
};

/*------------------------------------------------------------------*\
\*------------------------------------------------------------------*/

int main(int argc, char* argv[]) {

    struct SGP sgp;
    sgp.domain = 0;
    sgp.out_len = DEFAULT_PW_LENGTH;

    get_opts(argc, argv, &sgp.out_len, &sgp.domain);

    if (!sgp.domain) {
        osexit(1, "error: missing argument -domain");
    }
    if ((sgp.out_len < MIN_PW_LENGTH) || (sgp.out_len > B64_MD5_DIGEST_LENGTH)) {
        osexit(1, "error: given -length must be >= 4 and <= 24");
    }

    sgp.domain_len = str_len(sgp.domain);
    sgp.in_len = read_pw(0, sgp.pw, sizeof(sgp.pw));

    supergenpass(&sgp);

    posix_write(1, "\n", 1);
    posix_write(1, sgp.pw, sgp.out_len);
    posix_write(1, "\n", 1);
    posix_fsync(1);

    byte_zero(sgp.domain, sgp.domain_len);
    byte_zero(&sgp, sizeof(sgp));

    return 0;
}


int supergenpass(struct SGP* sgp) {

    md5Context* ctx = &sgp->md5;
    unsigned char* pw = &(sgp->pw[0]);
    unsigned char* raw = &(sgp->pw[B64_MD5_DIGEST_LENGTH]);
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

    // md5_final() sets all elements of ctx to 0
    return 1;
}

/*------------------------------------------------------------------*\
\*------------------------------------------------------------------*/

int get_opts(int argc, char* argv[], int* length, unsigned char** domain) {

    const char opt_help[]   = "-h";
    const char opt_length[] = "-length=";
    const char opt_domain[] = "-domain=";

    int i;
    for (i = 1; i < argc; i++) {
        if (str_diffn(argv[i], opt_help, sizeof(opt_help)-1) == 0) {
            osexit(0, USAGE);
        }
        else if (str_diffn(argv[i], opt_length, sizeof(opt_length)-1) == 0) {
            unsigned long l = 0;
            if (str_len(argv[i]) <= sizeof(opt_length)-1) {
                osexit(1, "error: missing argument for -length");
            }
            if (scan_ulong(&argv[i][sizeof(opt_length)-1], &l) == 0) {
                osexit(1, "error: can't parse given -length");
            }
            *length = (int)l;
        } else if (str_diffn(argv[i], opt_domain, sizeof(opt_domain)-1) == 0) {
            if (str_len(argv[i]) <= sizeof(opt_domain)-1) {
                osexit(1, "error: missing argument for -domain");
            }
            *domain = (unsigned char*)&argv[i][sizeof(opt_domain)-1];
        }
    }
    return 0;
}

int read_pw(int fd, unsigned char* pw, int max_length) {

    int n;


    if (posix_isatty(fd)) {
        posix_write(1, PROMPT, sizeof(PROMPT));
        posix_fsync(1);
        tty_echo(fd, 0);
    }

    n = (int)posix_read(fd, pw, max_length);

    if (posix_isatty(fd)) {
        tty_echo(fd, 1);
    }

    if (n == -1) {
        osexit(2, "error: reading pw");
    }

    // scan backward for lf/cr aka 'the enter'
    for(; n > 0; n--) {
        if (!(pw[n-1] == '\n' || pw[n-1] == '\r')) {
            break;
        }
    }

    if (n == 0) {
        osexit(2, "error: pw empty");
    }

    return n;
}

// checks the first 'length' bytes of 'in' if they
// are valid under the rules of supergenpass.com:
//
// 1. first char is a lowercase letter [a-z]
// 2. there is at least one uppercase letter [A-Z]
// 3. there is at least one digit [0-9]
int is_valid(unsigned char* in, unsigned int length) {
    unsigned int mask = 0;
    if (!(*in >= 'a' && *in <= 'z')) {
        return 0;
    }
    for (; length > 0; in++, length--) {
        if ((*in >= 'A') && (*in <= 'Z')) {
            mask |= 1;
        } else if ((*in >= '0') && (*in <= '9')) {
            mask |= 2;
        }
        if (mask == 3) {
            return 1;
        }
    }
    return 0;
}


void osexit(int c, const char* msg) {
    if (msg) {
        posix_write(2, msg, str_len(msg));
        posix_write(2, "\n", 1);
    }
    exit(c);
}

#ifndef _WIN32
#include <unistd.h>
#include <termios.h>
unsigned int posix_write(int fd, const void* buf, unsigned int n) {
    return write(fd, buf, n);
}
unsigned int posix_read(int fd, void* buf, unsigned int n) {
    return read(fd, buf, n);
}
int posix_fsync(int fd) {
    return fsync(fd);
}
int posix_isatty(int fd) {
    return isatty(fd);
}

int tty_echo(int fd, int on) {

    struct termios tty;
    tcgetattr(fd, &tty);
    if (!on) {
        tty.c_lflag &= ~ECHO;
    } else {
        tty.c_lflag |= ECHO;
    }

    if (tcsetattr(fd, TCSANOW, &tty) != 0) {
        osexit(3, "error: disable echo failed");
    }
    return 1;
}

#else

#define WIN32LEAN_AND_MEAN
#include <windows.h>
#include <io.h>
unsigned int posix_write(int fd, const void* buf, unsigned int n) {
    return _write(fd, buf, n);
}
unsigned int posix_read(int fd, void* buf, unsigned int n) {
    return _read(fd, buf, n);
}
int posix_fsync(int fd) {

    HANDLE h = (HANDLE)_get_osfhandle(fd);
    if (!FlushFileBuffers(h)) {
        return -1;
    }
    return 0;
}
int posix_isatty(int fd) {
    return _isatty(fd);
}

int tty_echo(int fd, int on) {
    HANDLE h = (HANDLE)_get_osfhandle(fd);
    DWORD mode;
    GetConsoleMode(h, &mode);
    if (!on) {
        mode &= ~ENABLE_ECHO_INPUT;
    }
    else {
        mode |= ENABLE_ECHO_INPUT;
    }
    SetConsoleMode(h, mode);
    return 0;
}

#endif
