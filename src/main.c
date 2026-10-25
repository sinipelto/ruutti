#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "password.h"
#include "readpass.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

extern char **environ;

#include "argon2.h"

enum {
    NAME_MAX_LEN = 32,
    ACCOUNT_NAME = 256,
    ACCOUNT_PATH = 4096,
    GROUP_SLOTS = 64
};

struct account {
    char name[ACCOUNT_NAME];
    char home[ACCOUNT_PATH];
    char shell[ACCOUNT_PATH];
    uid_t uid;
    gid_t gid;
};

static void die_user(void) {
    fputs("unknown user\n", stderr);
    exit(1);
}

static int digits_only(const char *text) {
    const char *cursor;
    if (text[0] == '\0') {
        return 0;
    }
    for (cursor = text; *cursor != '\0'; cursor++) {
        if (*cursor < '0' || *cursor > '9') {
            return 0;
        }
    }
    return 1;
}

static int portable_name(const char *text) {
    size_t length = strlen(text);
    size_t index;
    char first;
    if (length == 0 || length > NAME_MAX_LEN) {
        return 0;
    }
    first = text[0];
    if (!((first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z') || first == '_')) {
        return 0;
    }
    for (index = 1; index < length; index++) {
        char c = text[index];
        int ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                 c == '_' || c == '-' || c == '.';
        if (ok) {
            continue;
        }
        if (c == '$' && index + 1 == length) {
            return 1;
        }
        return 0;
    }
    return 1;
}

static int parse_uid(const char *text, uid_t *uid) {
    char *end = NULL;
    unsigned long value;
    errno = 0;
    value = strtoul(text, &end, 10);
    if (end == text || *end != '\0' || errno == ERANGE) {
        return -1;
    }
    if (value != (unsigned long)(uid_t)value) {
        return -1;
    }
    *uid = (uid_t)value;
    return 0;
}

static int copy_text(char *dest, size_t dest_size, const char *src) {
    size_t length;
    if (src == NULL) {
        return -1;
    }
    length = strlen(src);
    if (length == 0 || length >= dest_size) {
        return -1;
    }
    memcpy(dest, src, length + 1);
    return 0;
}

static int fill_account(struct account *acct, const char *name, uid_t uid, gid_t gid, const char *home,
                        const char *shell) {
    if (name == NULL || name[0] == '\0' || name[0] == '-' || strchr(name, '/') != NULL ||
        strchr(name, ' ') != NULL || strchr(name, '\n') != NULL || strchr(name, '\r') != NULL) {
        return -1;
    }
    if (home == NULL || home[0] == '\0') {
        home = "/";
    }
    if (shell == NULL || shell[0] == '\0') {
        shell = "/bin/sh";
    }
    if (copy_text(acct->name, sizeof acct->name, name) != 0 ||
        copy_text(acct->home, sizeof acct->home, home) != 0 ||
        copy_text(acct->shell, sizeof acct->shell, shell) != 0) {
        return -1;
    }
    acct->uid = uid;
    acct->gid = gid;
    return 0;
}

static int split_passwd(char *line, char *field[7]) {
    int index;
    char *cursor = line;
    for (index = 0; index < 6; index++) {
        char *colon = strchr(cursor, ':');
        if (colon == NULL) {
            return -1;
        }
        *colon = '\0';
        field[index] = cursor;
        cursor = colon + 1;
    }
    field[6] = cursor;
    return 0;
}

static int passwd_id(const char *text, unsigned long *value) {
    char *end = NULL;
    errno = 0;
    *value = strtoul(text, &end, 10);
    if (end == text || *end != '\0' || errno == ERANGE) {
        return -1;
    }
    return 0;
}

static int lookup_file(int by_uid, uid_t uid, const char *name, struct account *acct) {
    FILE *file = fopen("/etc/passwd", "r");
    char line[8192];
    if (file == NULL) {
        return -1;
    }
    while (fgets(line, sizeof line, file) != NULL) {
        char *fields[7];
        unsigned long file_uid;
        unsigned long file_gid;
        size_t length;
        char *shell;
        if (line[0] == '\0' || line[0] == '#' || line[0] == '+' || line[0] == '-') {
            continue;
        }
        length = strlen(line);
        if (length > 0 && line[length - 1] == '\n') {
            line[length - 1] = '\0';
        }
        if (split_passwd(line, fields) != 0 || passwd_id(fields[2], &file_uid) != 0 ||
            passwd_id(fields[3], &file_gid) != 0) {
            continue;
        }
        if (by_uid) {
            if ((uid_t)file_uid != uid || (unsigned long)(uid_t)file_uid != file_uid) {
                continue;
            }
        } else if (strcmp(fields[0], name) != 0) {
            continue;
        }
        shell = fields[6];
        if (shell[0] == '\0') {
            shell = "/bin/sh";
        }
        if (fill_account(acct, fields[0], (uid_t)file_uid, (gid_t)file_gid, fields[5], shell) != 0) {
            fclose(file);
            return -1;
        }
        fclose(file);
        return 0;
    }
    fclose(file);
    return -1;
}

static int lookup_libc(int by_uid, uid_t uid, const char *name, struct account *acct) {
    struct passwd *pw = by_uid ? getpwuid(uid) : getpwnam(name);
    if (pw == NULL) {
        return -1;
    }
    return fill_account(acct, pw->pw_name, pw->pw_uid, pw->pw_gid, pw->pw_dir, pw->pw_shell);
}

static int resolve_account(const char *arg, struct account *acct) {
    int by_uid = 1;
    uid_t uid = 0;
    if (arg != NULL) {
        if (digits_only(arg)) {
            if (parse_uid(arg, &uid) != 0) {
                return -1;
            }
        } else if (!portable_name(arg)) {
            return -1;
        } else {
            by_uid = 0;
        }
    }
    if (lookup_libc(by_uid, uid, arg, acct) == 0 || lookup_file(by_uid, uid, arg, acct) == 0) {
        return 0;
    }
    return -1;
}

static int member_of(const char *list, const char *user) {
    size_t user_len = strlen(user);
    const char *cursor = list;
    if (list == NULL) {
        return 0;
    }
    while (*cursor != '\0') {
        const char *comma = strchr(cursor, ',');
        size_t token = comma == NULL ? strlen(cursor) : (size_t)(comma - cursor);
        if (token == user_len && memcmp(cursor, user, user_len) == 0) {
            return 1;
        }
        if (comma == NULL) {
            break;
        }
        cursor = comma + 1;
    }
    return 0;
}

static int add_group(gid_t *groups, int *count, gid_t gid) {
    int index;
    if (*count >= GROUP_SLOTS) {
        return 0;
    }
    for (index = 0; index < *count; index++) {
        if (groups[index] == gid) {
            return 0;
        }
    }
    groups[*count] = gid;
    *count += 1;
    return 0;
}

static int load_groups(const struct account *acct, gid_t *groups, int *count) {
    FILE *file;
    char line[8192];
    *count = 0;
    add_group(groups, count, acct->gid);
    file = fopen("/etc/group", "r");
    if (file == NULL) {
        return 0;
    }
    while (fgets(line, sizeof line, file) != NULL) {
        char *name_end;
        char *gid_text;
        char *members;
        char *end = NULL;
        unsigned long gid;
        size_t length = strlen(line);
        if (length > 0 && line[length - 1] == '\n') {
            line[length - 1] = '\0';
        }
        name_end = strchr(line, ':');
        if (name_end == NULL) {
            continue;
        }
        gid_text = strchr(name_end + 1, ':');
        if (gid_text == NULL) {
            continue;
        }
        gid_text++;
        members = strchr(gid_text, ':');
        if (members == NULL) {
            continue;
        }
        *members = '\0';
        members++;
        errno = 0;
        gid = strtoul(gid_text, &end, 10);
        if (end == gid_text || *end != '\0' || errno == ERANGE) {
            continue;
        }
        if ((unsigned long)(gid_t)gid == gid && member_of(members, acct->name)) {
            add_group(groups, count, (gid_t)gid);
        }
    }
    fclose(file);
    return 0;
}

static void print_motd_file(const char *path) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    struct stat info;
    char buffer[4096];
    if (fd < 0) {
        return;
    }
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode)) {
        close(fd);
        return;
    }
    for (;;) {
        ssize_t got = read(fd, buffer, sizeof buffer);
        ssize_t wrote = 0;
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (got == 0) {
            break;
        }
        while (wrote < got) {
            ssize_t n = write(STDOUT_FILENO, buffer + wrote, (size_t)(got - wrote));
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                close(fd);
                return;
            }
            wrote += n;
        }
    }
    close(fd);
}

static void print_motd(void) {
    static const char *paths[] = {"/run/motd.dynamic", "/usr/lib/motd", "/etc/motd"};
    size_t index;
    for (index = 0; index < sizeof paths / sizeof paths[0]; index++) {
        print_motd_file(paths[index]);
    }
    fflush(stdout);
}

static int executable_file(const char *path) {
    struct stat info;
    if (stat(path, &info) != 0) {
        return 0;
    }
    return S_ISREG(info.st_mode) && (info.st_mode & 0111) != 0;
}

static const char *find_runuser(void) {
    static const char *paths[] = {"/usr/bin/runuser", "/bin/runuser", "/usr/sbin/runuser", "/sbin/runuser"};
    size_t index;
    for (index = 0; index < sizeof paths / sizeof paths[0]; index++) {
        if (executable_file(paths[index])) {
            return paths[index];
        }
    }
    return NULL;
}

static int format_env(char *dest, size_t dest_size, const char *key, const char *value) {
    int wrote = snprintf(dest, dest_size, "%s=%s", key, value);
    if (wrote < 0 || (size_t)wrote >= dest_size) {
        return -1;
    }
    return 0;
}

static void start_fallback(const struct account *acct) {
    gid_t groups[GROUP_SLOTS];
    int ngroups = 0;
    char home_env[ACCOUNT_PATH + 8];
    char user_env[ACCOUNT_NAME + 8];
    char logname_env[ACCOUNT_NAME + 16];
    char shell_env[ACCOUNT_PATH + 8];
    char mail_path[ACCOUNT_NAME + 16];
    char mail_env[ACCOUNT_NAME + 32];
    char term_env[256];
    char argv0[ACCOUNT_NAME];
    const char *base;
    const char *term;
    char *envp[8];
    int envc = 0;
    char *argv[2];

    load_groups(acct, groups, &ngroups);
    if (setgroups((size_t)ngroups, groups) != 0 || setgid(acct->gid) != 0 || setuid(acct->uid) != 0 ||
        geteuid() != acct->uid) {
        fputs("ruutti: cannot start shell\n", stderr);
        exit(127);
    }
    if (chdir(acct->home) != 0 && chdir("/") != 0) {
        fputs("ruutti: cannot start shell\n", stderr);
        exit(127);
    }

    base = strrchr(acct->shell, '/');
    base = base == NULL ? acct->shell : base + 1;
    if (base[0] == '\0') {
        base = "sh";
    }
    if (strlen(base) + 2 > sizeof argv0) {
        fputs("ruutti: cannot start shell\n", stderr);
        exit(127);
    }
    argv0[0] = '-';
    memcpy(argv0 + 1, base, strlen(base) + 1);

    int mail_wrote = snprintf(mail_path, sizeof mail_path, "/var/mail/%s", acct->name);
    if (mail_wrote < 0 || (size_t)mail_wrote >= sizeof mail_path ||
        format_env(home_env, sizeof home_env, "HOME", acct->home) != 0 ||
        format_env(user_env, sizeof user_env, "USER", acct->name) != 0 ||
        format_env(logname_env, sizeof logname_env, "LOGNAME", acct->name) != 0 ||
        format_env(shell_env, sizeof shell_env, "SHELL", acct->shell) != 0 ||
        format_env(mail_env, sizeof mail_env, "MAIL", mail_path) != 0) {
        fputs("ruutti: cannot start shell\n", stderr);
        exit(127);
    }
    envp[envc++] = home_env;
    envp[envc++] = user_env;
    envp[envc++] = logname_env;
    envp[envc++] = shell_env;
    envp[envc++] = mail_env;
    envp[envc++] = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    term = getenv("TERM");
    if (term != NULL && term[0] != '\0' && strlen(term) < sizeof term_env - 5) {
        snprintf(term_env, sizeof term_env, "TERM=%s", term);
        envp[envc++] = term_env;
    }
    envp[envc] = NULL;
    argv[0] = argv0;
    argv[1] = NULL;
    fflush(NULL);
    execve(acct->shell, argv, envp);
    fputs("ruutti: cannot start shell\n", stderr);
    exit(127);
}

static void start_session(const struct account *acct) {
    const char *runuser = find_runuser();
    if (runuser != NULL) {
        char *argv[] = {"runuser", "--login", "--", (char *)acct->name, NULL};
        fflush(NULL);
        execve(runuser, argv, environ);
    }
    start_fallback(acct);
}

int main(int argc, char **argv) {
    struct account acct;
    char password[129];
    size_t password_len = 0;
    int verified;

    if (argc > 2) {
        fputs("usage: ruutti [account]\n", stderr);
        return 1;
    }
    if (resolve_account(argc == 2 ? argv[1] : NULL, &acct) != 0) {
        die_user();
    }
    if (geteuid() != 0) {
        fputs("ruutti: must be run as root\n", stderr);
        return 1;
    }
    if (read_password(password, sizeof password, &password_len) != 0) {
        explicit_bzero(password, sizeof password);
        fputs("Authentication failure\n", stderr);
        return 1;
    }
    verified = argon2id_verify(RUUTTI_PASSWORD_HASH, password, password_len) == ARGON2_OK;
    explicit_bzero(password, sizeof password);
    if (!verified) {
        fputs("Authentication failure\n", stderr);
        return 1;
    }
    print_motd();
    start_session(&acct);
    return 127;
}
