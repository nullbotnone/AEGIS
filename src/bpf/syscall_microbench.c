#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum bench_mode {
    MODE_OPENAT,
    MODE_READ,
    MODE_WRITE,
    MODE_CONNECT,
    MODE_EXECVE,
};

struct bench_config {
    enum bench_mode mode;
    unsigned long iters;
    size_t size;
    const char *path;
    const char *host;
    int port;
};

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s --mode MODE [--iters N] [--size BYTES] [--path FILE] [--host IP] [--port PORT]\n"
            "Modes: openat, read, write, connect, execve\n",
            prog);
}

static double now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static int ensure_file(const char *path, size_t size)
{
    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
    size_t offset = 0;
    char buf[4096];

    if (fd < 0) {
        perror("open setup file");
        return -1;
    }

    memset(buf, 'A', sizeof(buf));
    while (offset < size) {
        size_t chunk = size - offset;
        ssize_t wrote;

        if (chunk > sizeof(buf))
            chunk = sizeof(buf);

        wrote = write(fd, buf, chunk);
        if (wrote < 0) {
            perror("write setup file");
            close(fd);
            return -1;
        }
        offset += (size_t)wrote;
    }

    if (fsync(fd) != 0)
        perror("fsync setup file");
    close(fd);
    return 0;
}

static int bench_openat(const struct bench_config *cfg)
{
    for (unsigned long i = 0; i < cfg->iters; i++) {
        int fd = openat(AT_FDCWD, cfg->path, O_RDONLY);
        if (fd < 0) {
            perror("openat");
            return 1;
        }
        close(fd);
    }
    return 0;
}

static int bench_read(const struct bench_config *cfg)
{
    char *buf = malloc(cfg->size);
    int fd;

    if (!buf) {
        perror("malloc");
        return 1;
    }

    fd = open(cfg->path, O_RDONLY);
    if (fd < 0) {
        perror("open read path");
        free(buf);
        return 1;
    }

    for (unsigned long i = 0; i < cfg->iters; i++) {
        ssize_t rc;
        if (lseek(fd, 0, SEEK_SET) < 0) {
            perror("lseek");
            close(fd);
            free(buf);
            return 1;
        }
        rc = read(fd, buf, cfg->size);
        if (rc < 0) {
            perror("read");
            close(fd);
            free(buf);
            return 1;
        }
    }

    close(fd);
    free(buf);
    return 0;
}

static int bench_write(const struct bench_config *cfg)
{
    char *buf = malloc(cfg->size);
    int fd;

    if (!buf) {
        perror("malloc");
        return 1;
    }
    memset(buf, 'B', cfg->size);

    fd = open(cfg->path, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open write path");
        free(buf);
        return 1;
    }

    for (unsigned long i = 0; i < cfg->iters; i++) {
        ssize_t rc;
        if (lseek(fd, 0, SEEK_SET) < 0) {
            perror("lseek");
            close(fd);
            free(buf);
            return 1;
        }
        rc = write(fd, buf, cfg->size);
        if (rc < 0) {
            perror("write");
            close(fd);
            free(buf);
            return 1;
        }
    }

    if (fsync(fd) != 0)
        perror("fsync");

    close(fd);
    free(buf);
    return 0;
}

static int bench_connect(const struct bench_config *cfg)
{
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)cfg->port);
    if (inet_pton(AF_INET, cfg->host, &sa.sin_addr) != 1) {
        fprintf(stderr, "invalid IPv4 address: %s\n", cfg->host);
        return 1;
    }

    for (unsigned long i = 0; i < cfg->iters; i++) {
        int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            perror("socket");
            return 1;
        }
        if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
            if (errno != ECONNREFUSED && errno != ETIMEDOUT && errno != EINPROGRESS) {
                perror("connect");
                close(fd);
                return 1;
            }
        }
        close(fd);
    }
    return 0;
}

static int bench_execve(const struct bench_config *cfg)
{
    (void)cfg;
    for (unsigned long i = 0; i < cfg->iters; i++) {
        pid_t pid = fork();
        int status;

        if (pid < 0) {
            perror("fork");
            return 1;
        }
        if (pid == 0) {
            char *const argv[] = {"/bin/true", NULL};
            char *const envp[] = {NULL};
            execve("/bin/true", argv, envp);
            _exit(127);
        }
        if (waitpid(pid, &status, 0) < 0) {
            perror("waitpid");
            return 1;
        }
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "child exited abnormally at iteration %lu\n", i);
            return 1;
        }
    }
    return 0;
}

static int parse_mode(const char *value, enum bench_mode *mode)
{
    if (strcmp(value, "openat") == 0) {
        *mode = MODE_OPENAT;
        return 0;
    }
    if (strcmp(value, "read") == 0) {
        *mode = MODE_READ;
        return 0;
    }
    if (strcmp(value, "write") == 0) {
        *mode = MODE_WRITE;
        return 0;
    }
    if (strcmp(value, "connect") == 0) {
        *mode = MODE_CONNECT;
        return 0;
    }
    if (strcmp(value, "execve") == 0) {
        *mode = MODE_EXECVE;
        return 0;
    }
    return -1;
}

int main(int argc, char **argv)
{
    struct bench_config cfg = {
        .mode = MODE_OPENAT,
        .iters = 200000,
        .size = 4096,
        .path = "/tmp/aegis-microbench.dat",
        .host = "127.0.0.1",
        .port = 9,
    };
    double start;
    double elapsed;
    int rc = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            if (parse_mode(argv[++i], &cfg.mode) != 0) {
                fprintf(stderr, "unknown mode: %s\n", argv[i]);
                usage(argv[0]);
                return 1;
            }
        } else if (strcmp(argv[i], "--iters") == 0 && i + 1 < argc) {
            cfg.iters = strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--size") == 0 && i + 1 < argc) {
            cfg.size = strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--path") == 0 && i + 1 < argc) {
            cfg.path = argv[++i];
        } else if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) {
            cfg.host = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            cfg.port = atoi(argv[++i]);
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    if ((cfg.mode == MODE_OPENAT || cfg.mode == MODE_READ || cfg.mode == MODE_WRITE) &&
        ensure_file(cfg.path, cfg.size) != 0) {
        return 1;
    }

    start = now_sec();
    switch (cfg.mode) {
    case MODE_OPENAT:
        rc = bench_openat(&cfg);
        break;
    case MODE_READ:
        rc = bench_read(&cfg);
        break;
    case MODE_WRITE:
        rc = bench_write(&cfg);
        break;
    case MODE_CONNECT:
        rc = bench_connect(&cfg);
        break;
    case MODE_EXECVE:
        rc = bench_execve(&cfg);
        break;
    }
    elapsed = now_sec() - start;

    if (rc == 0) {
        double rate = elapsed > 0.0 ? (double)cfg.iters / elapsed : 0.0;
        printf("mode=%s iters=%lu elapsed=%.6f ops_per_sec=%.2f\n",
               cfg.mode == MODE_OPENAT ? "openat" :
               cfg.mode == MODE_READ ? "read" :
               cfg.mode == MODE_WRITE ? "write" :
               cfg.mode == MODE_CONNECT ? "connect" : "execve",
               cfg.iters,
               elapsed,
               rate);
    }

    return rc;
}
