project(csgp)

set(csgp_src main.c
    base64.c md5.c
    djb/byte_copy.c djb/byte_zero.c
    djb/error.c
    djb/str_diffn.c djb/str_len.c
    djb/scan_ulong.c
)

if (!MSVC)
    set (csgp_src ${csgp_src} platform_unix.c)
else()
    set (csgp_src ${csgp_src} platform_msvc.c)
endif(!MSVC)

add_executable(csgp ${csgp_src})
