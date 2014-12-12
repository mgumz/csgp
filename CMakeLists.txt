project(csgp)

set(csgp_src main.c
    base64.c md5.c
    djb/byte_copy.c djb/byte_zero.c
    djb/error.c
    djb/str_diffn.c djb/str_len.c
    djb/scan_ulong.c
)

if (NOT MSVC)
    set (csgp_src ${csgp_src} platform_unix.c)
else(NOT MSVC)
    set (csgp_src ${csgp_src} platform_msvc.c)
endif(NOT MSVC)

add_executable(csgp ${csgp_src})
