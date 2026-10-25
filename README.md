# ruutti

Static Linux program. It asks for a gate password and, when the Argon2id hash matches, starts a login shell as the requested account.

```text
ruutti [account]
```

No account means UID 0, looked up in the passwd database. An all-digit account is a UID. Any other account is a username.

## Hash

`genhash` reads a password with echo disabled and prints an Argon2id hash (19 MiB, 2 iterations, parallelism 1). Put that line in `src/password.h` as `RUUTTI_PASSWORD_HASH`, then build the runtime image. The plaintext password is not stored in the tree.

```text
docker build --platform linux/amd64 --target genhash -t ruutti-genhash .
docker run --rm -it ruutti-genhash
```

## Build and run

```text
docker build --platform linux/amd64 -t ruutti .
docker run --rm -it ruutti testi
docker run --rm -it ruutti
docker run --rm -it ruutti 0
```

`--it` gives the password prompt and the shell a terminal. The runtime image is Alpine, with `testi` as a normal account, root as UID 0, and `/etc/motd` set. The image installs `ruutti` setuid-root.

## Export

Copy the static binary out of a container:

```text
docker create --name ruutti-export ruutti
docker cp ruutti-export:/usr/local/bin/ruutti ./ruutti
docker rm ruutti-export
```

Or write it with BuildKit:

```text
docker build --platform linux/amd64 --target binary --output type=local,dest=./dist .
```

That creates `./dist/ruutti`, a statically linked `linux/amd64` ELF. It runs on Ubuntu amd64. Install it there as root:

```text
install -m 4755 -o root ruutti /usr/local/bin/ruutti
```

The binary then uses that machine's `/etc/passwd`, `runuser`, and login scripts.

## Build flags

The Docker builder is Alpine, so `gcc` links musl. The Makefile compiles with `-Ofast -static`. Argon2id is integer-only; the memory and iteration parameters are what make guessing expensive.
