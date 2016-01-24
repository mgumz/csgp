
SRC = main.c base64.c md5.c \
	platform.c platform_unix.c \
	djb/byte_copy.c djb/byte_zero.c \
	djb/error.c \
	djb/str_diffn.c djb/str_len.c \
	djb/scan_ulong.c

csgp: $(SRC)
	$(CC) -o $@ -Os -Wall $(SRC)

clean:
	rm -v csgp
