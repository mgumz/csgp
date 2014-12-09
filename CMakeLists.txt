project(csgp)

add_executable(csgp main.c 
    base64.c md5.c
    djb/byte_copy.c djb/byte_zero.c
    djb/error.c
    djb/str_diffn.c djb/str_len.c
    djb/scan_ulong.c
)
