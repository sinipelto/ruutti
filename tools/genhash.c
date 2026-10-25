#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "readpass.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "argon2.h"

enum {
    T_COST = 2,
    M_COST = 512000,
    LANES = 4,
    SALT_LEN = 32,
    HASH_LEN = 64
};

static int read_salt(unsigned char salt[SALT_LEN]) {
    int fd = open("/dev/urandom", O_RDONLY);
    size_t got = 0;
    if (fd < 0) {
        return -1;
    }
    while (got < SALT_LEN) {
        ssize_t n = read(fd, salt + got, SALT_LEN - got);
        if (n < 0) {
            close(fd);
            return -1;
        }
        if (n == 0) {
            close(fd);
            return -1;
        }
        got += (size_t)n;
    }
    close(fd);
    return 0;
}

int main(void) {
    char password[129];
    size_t password_len = 0;
    unsigned char salt[SALT_LEN];
    char encoded[256];
    int rc;

    if (read_salt(salt) != 0) {
        explicit_bzero(password, sizeof password);
        fputs("genhash: could not read a salt\n", stderr);
        return 1;
    }

    fputs("Enter the gate password. The Argon2id hash is written to stdout.\n", stderr);
    if (read_password(password, sizeof password, &password_len) != 0) {
        fputs("genhash: could not read a password\n", stderr);
        return 1;
    }
    rc = argon2id_hash_encoded(T_COST, M_COST, LANES, password, password_len, salt, SALT_LEN,
                               HASH_LEN, encoded, sizeof encoded);
    explicit_bzero(password, sizeof password);
    explicit_bzero(salt, sizeof salt);
    if (rc != ARGON2_OK) {
        fprintf(stderr, "genhash: %s\n", argon2_error_message(rc));
        return 1;
    }
    if (printf("%s\n", encoded) < 0) {
        return 1;
    }
    return 0;
}
