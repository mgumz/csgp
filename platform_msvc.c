/*------------------------------------------------------------------*\

       file: platform_msvc.c
      about: implement platform-functions for msvc
     author: m. gumz <mg@2hoch5.com>
    license: see LICENSE.txt

\*------------------------------------------------------------------*/

#include "platform.h"

#define WIN32LEAN_AND_MEAN
#include <windows.h>
#include <io.h>

int posix_write(int fd, const void* buf, unsigned int n) {
    return _write(fd, buf, n);
}

int posix_read(int fd, void* buf, unsigned int n) {
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

int lock_memory(void* addr, unsigned int size) {
    return !VirtualLock(addr, size);
}

int unlock_memory(void* addr, unsigned int size) {
    return !VirtualUnlock(addr, size);
}

