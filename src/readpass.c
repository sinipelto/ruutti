#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "readpass.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

static struct termios saved_termios;
static int echo_hidden;

static void restore_echo(void) {
    if (!echo_hidden) {
        return;
    }
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved_termios);
    echo_hidden = 0;
}

static void on_signal(int sig) {
    restore_echo();
    _exit(128 + sig);
}

static void arm_signals(void) {
    struct sigaction action;

    memset(&action, 0, sizeof action);
    action.sa_handler = on_signal;
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGHUP, &action, NULL);
    sigaction(SIGQUIT, &action, NULL);
}

int read_password(char *buf, size_t cap, size_t *len) {
    size_t limit;
    size_t n = 0;
    int too_long = 0;
    int saw_cr = 0;

    if (buf == NULL || len == NULL || cap < 2) {
        return -1;
    }
    explicit_bzero(buf, cap);
    limit = cap - 1;
    if (limit > 128) {
        limit = 128;
    }

    if (isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &saved_termios) == 0) {
        struct termios hidden = saved_termios;
        hidden.c_lflag = (tcflag_t)(hidden.c_lflag & (tcflag_t)~ECHO);
        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) == 0) {
            echo_hidden = 1;
            atexit(restore_echo);
            arm_signals();
        }
    }

    if (write(STDERR_FILENO, "Password: ", 10) != 10) {
        restore_echo();
        explicit_bzero(buf, cap);
        return -1;
    }

    for (;;) {
        char c;
        ssize_t got = read(STDIN_FILENO, &c, 1);
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            restore_echo();
            explicit_bzero(buf, cap);
            return -1;
        }
        if (got == 0) {
            break;
        }
        if (saw_cr) {
            saw_cr = 0;
            if (c == '\n') {
                break;
            }
            if (n >= limit) {
                too_long = 1;
            } else {
                buf[n++] = '\r';
            }
        }
        if (c == '\r') {
            saw_cr = 1;
            continue;
        }
        if (c == '\n') {
            break;
        }
        if (n >= limit) {
            too_long = 1;
            continue;
        }
        buf[n++] = c;
    }

    restore_echo();
    if (write(STDERR_FILENO, "\n", 1) != 1) {
        explicit_bzero(buf, cap);
        return -1;
    }
    if (too_long || n == 0) {
        explicit_bzero(buf, cap);
        return -1;
    }
    buf[n] = '\0';
    *len = n;
    return 0;
}
