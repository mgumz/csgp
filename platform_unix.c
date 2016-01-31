/*------------------------------------------------------------------*\

       file: platform_unix.c
      about: implement platform-functions on unix (Linux,*BSD,etc)
     author: m. gumz <mg@2hoch5.com>
    license: see LICENSE.txt

\*------------------------------------------------------------------*/

#include "platform.h"

#include <unistd.h>
#include <sys/mman.h> // mlock() etc; FreeBSD/MacOSX needs it
#include <termios.h>

int posix_write(int fd, const void* buf, size_t n) {
    return write(fd, buf, n);
}
int posix_read(int fd, void* buf, size_t n) {
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

int lock_memory(void* addr, size_t size) {
    return mlock(addr, (unsigned int)size);
}

int unlock_memory(void* addr, size_t size) {
    return munlock(addr, (unsigned int)size);
}

