#ifndef _PLATFORM_H_
#define _PLATFORM_H_

/*------------------------------------------------------------------*\

       file: platform.h
      about: provide a small cross-plattform layer for a few
             functions
     author: m. gumz <mg@2hoch5.com>
    license: see LICENSE.txt

\*------------------------------------------------------------------*/

#include <stddef.h>

extern int osexit(int code, const char* msg);

extern int posix_write(int fd, const void* buf, size_t n);
extern int posix_read(int fd, void* buf, size_t n);
extern int posix_fsync(int fd);
extern int posix_isatty(int fd);

extern int tty_echo(int fd, int on);

extern int lock_memory(void* addr, size_t size);
extern int unlock_memory(void* addr, size_t size);

#endif
