CC ?= gcc
CFLAGS ?= -Ofast -std=c11 -Wall -Wextra -Wno-type-limits -DARGON2_NO_THREADS
CPPFLAGS ?= -Ithird_party/argon2/include -Ithird_party/argon2/src -Isrc
LDFLAGS ?= -static

ARGON_SRCS := \
	third_party/argon2/src/argon2.c \
	third_party/argon2/src/core.c \
	third_party/argon2/src/encoding.c \
	third_party/argon2/src/ref.c \
	third_party/argon2/src/blake2/blake2b.c

.PHONY: all clean

all: ruutti genhash

ruutti: src/main.c src/readpass.c src/password.h $(ARGON_SRCS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ src/main.c src/readpass.c $(ARGON_SRCS) $(LDFLAGS)

genhash: tools/genhash.c src/readpass.c $(ARGON_SRCS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ tools/genhash.c src/readpass.c $(ARGON_SRCS) $(LDFLAGS)

clean:
	rm -f ruutti genhash
