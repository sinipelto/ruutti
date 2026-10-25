#ifndef RUUTTI_READPASS_H
#define RUUTTI_READPASS_H

#include <stddef.h>

/* Read one password from stdin. At most 128 bytes are accepted.
   On success, buf is NUL-terminated and *len is the byte length.
   On failure, buf is wiped and the return value is -1. */
int read_password(char *buf, size_t cap, size_t *len);

#endif
