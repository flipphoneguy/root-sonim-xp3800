# The Daemon

This document explains how the `su` binary provides persistent root access through a daemon architecture, so the kernel exploit only needs to run once per boot.

---

## Table of Contents

- [Why a Daemon](#why-a-daemon)
- [How It Works](#how-it-works)
  - [First Invocation: Exploit + Daemon Startup](#first-invocation-exploit--daemon-startup)
  - [Subsequent Invocations: Instant Connection](#subsequent-invocations-instant-connection)
- [The Daemon Process](#the-daemon-process)
  - [Mount Namespace Escape](#mount-namespace-escape)
  - [Socket Setup](#socket-setup)
  - [Connection Handling](#connection-handling)
- [The Client Protocol](#the-client-protocol)
  - [Message Format](#message-format)
  - [File Descriptor Passing](#file-descriptor-passing)
  - [Response](#response)
- [Environment Handling](#environment-handling)
- [Denylist](#denylist)
- [Exploit Retry Logic](#exploit-retry-logic)
  - [Why Retrying Is Safe](#why-retrying-is-safe)
  - [Concurrency Serialization](#concurrency-serialization)

---

## Why a Daemon

The CVE-2019-2215 exploit takes about 1.2 seconds to run. It involves race conditions (the clobber primitive retries up to 40 times with microsecond-precision busy-wait timing), multiple forks, kernel memory corruption, and is inherently non-deterministic — it can fail. Running the exploit every time someone types `su` would mean:

- **1.2 second latency** on every root command, even trivial ones like `su -c id`
- **Risk of failure** — the exploit is probabilistic, not guaranteed
- **Risk of kernel panic** — concurrent exploit runs corrupt overlapping slab memory, which can crash the kernel. Even sequential runs add cumulative risk.

The daemon solves all three problems. The exploit runs exactly once to bootstrap a persistent root process. That process listens on a Unix socket. Every subsequent `su` invocation is just a socket connect + message exchange — ~0.13 seconds with zero kernel risk.

---

## How It Works

### First Invocation: Exploit + Daemon Startup

When `su` is called and no daemon is running:

1. `su` tries to connect to the daemon's Unix socket at `/data/local/tmp/.su.sock`. Connection refused — no daemon yet.

2. `su` acquires an exclusive file lock (`flock`) on `/data/local/tmp/.su.lock`. This prevents multiple concurrent `su` invocations from each trying to start the exploit simultaneously (which would panic the kernel).

3. After acquiring the lock, `su` checks the socket again — another process may have started the daemon while we were waiting for the lock.

4. `su` forks a child process. The child runs the exploit (`run_exploit()`), which escalates to root through the full CVE-2019-2215 chain (leak → clobber addr_limit → kernel R/W → overwrite cred → disable seccomp → disable SELinux). If the exploit succeeds, the child calls `daemon_main()` and becomes the persistent daemon. If it fails, the child exits.

5. The parent waits for a readiness signal from the child via a pipe. The child writes `"R"` to the pipe after the daemon's socket is bound and listening. The parent uses `select()` with a 10-second timeout — if no signal arrives, the attempt is considered failed and retried.

6. Once the daemon signals readiness, the parent connects to the socket and sends the actual root request (the command the user wanted to run).

### Subsequent Invocations: Instant Connection

When `su` is called and the daemon is already running:

1. `su` tries to connect to `/data/local/tmp/.su.sock`. Connection succeeds immediately.
2. `su` sends the command, environment, and file descriptors over the socket.
3. The daemon executes the command and sends back the exit code.
4. Total time: ~0.13 seconds.

No exploit, no kernel manipulation, no forks beyond the daemon's own child process for the command.

---

## The Daemon Process

After the exploit escalates privileges, the same process becomes the daemon. It never exits (until the device reboots or the process is killed). The daemon can also be started manually with `su --daemon` if it was killed — this requires an existing root context (e.g., ADB root) and skips the exploit entirely.

### OOM Kill Protection

The very first thing the daemon does is protect itself from Android's low-memory killer:

```c
int oom = open("/proc/self/oom_score_adj", O_WRONLY);
write(oom, "-1000", 5);
close(oom);
```

Setting `oom_score_adj` to `-1000` tells the kernel's OOM killer and Android's `lmkd` to never select this process for killing, regardless of memory pressure. Without this, the daemon could be killed during low-memory conditions, forcing the next `su` invocation to re-run the exploit — each exploit run carries a small risk of kernel panic due to the UAF race condition.

### Mount Namespace Escape

After setting OOM protection, the daemon escapes the app's mount namespace:

```c
int nsfd = open("/proc/1/ns/mnt", O_RDONLY);
setns(nsfd, 0);
close(nsfd);
```

This enters PID 1's (init's) mount namespace, giving the daemon access to the full Android filesystem — `/system`, `/data`, `/vendor`, everything. Without this, the daemon would be trapped in the app's sandboxed view of the filesystem, and commands like `mount -o remount,rw /system` would fail because `/system` wouldn't be visible.

Every child process the daemon forks inherits this mount namespace.

### Socket Setup

The daemon creates a Unix domain socket at `/data/local/tmp/.su.sock`:

```c
unlink(SOCKET_PATH);
int server = socket(AF_UNIX, SOCK_STREAM, 0);
bind(server, ...);
chmod(SOCKET_PATH, 0666);
listen(server, 5);
```

The socket is `chmod 0666` so any process on the device can connect — access control is handled by the denylist, not filesystem permissions.

The daemon calls `setsid()` to become a session leader (detached from any terminal) and redirects stdin/stdout/stderr to `/dev/null`.

### Connection Handling

The daemon's main loop accepts connections and forks a handler for each:

```c
while (1) {
    int client = accept(server, NULL, NULL);
    pid_t handler = fork();
    if (handler == 0) {
        signal(SIGCHLD, SIG_DFL);
        daemon_handle(client);
        _exit(0);
    }
    close(client);
}
```

The main daemon process sets `signal(SIGCHLD, SIG_IGN)` so finished handler processes are automatically reaped without becoming zombies. Each handler child resets this to `SIG_DFL` so it can properly `waitpid()` on the command it spawns — without this, `waitpid()` would fail because the child process would be auto-reaped before the handler could collect its exit status.

Each handler child also calls `setsid()` to create a new session and `ioctl(0, TIOCSCTTY, 0)` to acquire the client's terminal as its controlling terminal (without stealing it from the client's session). When the terminal is not owned by another session (e.g., commands invoked from app processes rather than interactive shells), this gives the child proper job control. When the terminal is already owned (e.g., Termux), the ioctl harmlessly fails and the child runs without a controlling terminal.

---

## The Client Protocol

### Message Format

The client sends a single message containing six required null-separated strings, optionally followed by additional environment variables:

```
shell\0cmd\0cwd\0PATH\0TERM\0HOME\0[KEY=VALUE\0KEY=VALUE\0...]
```

| Field | Example | Purpose |
|---|---|---|
| shell | `/system/bin/sh` | Shell to execute the command with |
| cmd | `mount -o remount,rw /system` | Command to run (empty string for interactive shell) |
| cwd | `/data/data/com.termux/files/home` | Working directory for the command |
| PATH | `/system/bin:/vendor/bin` | PATH environment variable |
| TERM | `xterm-256color` | Terminal type |
| HOME | `/data/data/com.termux/files/home` | Home directory |
| (optional) | `EDITOR=vim`, `LANG=en_US.UTF-8`, ... | Additional env vars (when `--preserve-environment` is used) |

If `cmd` is empty, the daemon spawns an interactive shell (no `-c` flag). If `cmd` is non-empty, the daemon runs `shell -c cmd`.

When `--preserve-environment` (`-p`) is used, the client appends all of the caller's environment variables (except `PATH`, `TERM`, and `HOME`, which are already sent as dedicated fields) as null-separated `KEY=VALUE` pairs after `HOME`. The daemon applies these to the child process with `setenv()` before executing the command.

### File Descriptor Passing

Along with the message, the client passes its stdin (fd 0), stdout (fd 1), and stderr (fd 2) to the daemon using `SCM_RIGHTS` — a Unix domain socket mechanism for sending file descriptors between processes.

The client constructs a `sendmsg()` call with a control message (`cmsg`) containing the three file descriptors. The daemon receives them with `recvmsg()` and uses `dup2()` to wire them into the child process that runs the command. This means the command's I/O goes directly to the caller's terminal — the daemon is transparent.

```c
// Client side: pack fds into cmsg
int fds[3] = {0, 1, 2};  // stdin, stdout, stderr
cmsg->cmsg_level = SOL_SOCKET;
cmsg->cmsg_type = SCM_RIGHTS;
memcpy(CMSG_DATA(cmsg), fds, 3 * sizeof(int));
sendmsg(sock, &msg, 0);
```

```c
// Daemon side: extract fds from cmsg
struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
memcpy(fds, CMSG_DATA(cmsg), 3 * sizeof(int));
// In child process:
dup2(fds[0], 0);  // caller's stdin → child's stdin
dup2(fds[1], 1);  // caller's stdout → child's stdout
dup2(fds[2], 2);  // caller's stderr → child's stderr
```

### Response

After the command finishes, the daemon sends a 4-byte integer back to the client: the command's exit code. The client reads this and exits with the same code, making `su -c cmd` return the same exit status as `cmd` itself.

A special exit code of `-1` indicates the request was denied by the denylist.

---

## Environment Handling

The `su` binary sets up environment variables differently depending on how it's invoked:

| Invocation | Shell | PATH | HOME | Other env vars |
|---|---|---|---|---|
| `su` (interactive) | Caller's `$SHELL` | Caller's `$PATH` | Caller's `$HOME` | Not forwarded |
| `su -c cmd` | `/system/bin/sh` | `/sbin:/system/sbin:/system/bin:/system/xbin:/vendor/bin` | `/` | Not forwarded |
| `su -p -c cmd` | Caller's `$SHELL` | Caller's `$PATH` | Caller's `$HOME` | All forwarded |
| `su -s bash -c cmd` | `bash` | System PATH | `/` | Not forwarded |

The logic: plain `su` (interactive shell) uses the caller's shell, PATH, and HOME so the shell feels familiar, but does not forward the rest of the caller's environment. `su -c` uses Android system defaults so commands like `mount`, `pm`, and `settings` resolve correctly without depending on the caller's PATH. The `--preserve-environment` (`-p`) flag forwards the caller's entire environment through the daemon protocol — use this when commands need env vars like `EDITOR`, `LANG`, or `LD_LIBRARY_PATH`.

When environment forwarding is active, all of the caller's environment variables (except `PATH`, `TERM`, and `HOME`, which have their own dedicated fields) are packed into the daemon message as null-separated `KEY=VALUE` pairs. The daemon child applies them with `setenv()` before executing the command.

The `--mount-master` flag is accepted and silently ignored for compatibility with Termux's `sudo` script. The `--shell` (`-s`) flag overrides the shell regardless of other settings.

---

## Denylist

The daemon checks every incoming request against a denylist before executing the command. The check uses `SO_PEERCRED` to get the caller's UID from the Unix socket:

```c
struct ucred peer;
getsockopt(client, SOL_SOCKET, SO_PEERCRED, &peer, &len);
```

This is unforgeable — the kernel fills in the real UID of the connecting process. The UID is then mapped to a package name by parsing `/data/system/packages.list` (the system's authoritative package-to-UID mapping).

Access rules:

- **UID 0** (root) and **UID 2000** (adb shell) are always allowed.
- **`com.termux`** is always allowed, regardless of the denylist.
- If the caller's package name appears in the denylist file (`/data/data/com.flipphoneguy.root.xp3/files/blacklist.txt`), the request is denied. The denylist supports exact matches and wildcard prefixes (`com.example.*`).
- All other callers are allowed by default.

When a request is denied, the daemon sends exit code `-1` and the client prints `su: denied` to stderr.

---

## Exploit Retry Logic

### Why Retrying Is Safe

The exploit's clobber primitive is a race condition — it needs the `EPOLL_CTL_DEL` to fire within a microsecond-wide timing window. Individual clobber attempts retry up to 40 times with delays from 50us to 830us, but the overall exploit (all four phases) can also fail as a whole.

The `su` binary retries the entire exploit up to 3 times with a 1-second sleep between attempts:

```c
for (int attempt = 0; attempt < 3; attempt++) {
    if (attempt > 0) sleep(1);
    pid_t pid = fork();
    if (pid == 0) {
        run_exploit();
        daemon_main(ready[1]);
        _exit(0);
    }
    // wait for readiness signal...
    if (started) break;
}
```

Each retry forks a fresh child process. This is safe because each attempt opens a new `/dev/binder` file descriptor, gets a fresh `binder_thread` allocation, and creates a new epoll instance. There's no accumulated kernel damage from a failed attempt — the UAF operates on a fresh slab slot each time. The 1-second sleep gives the kernel time to stabilize between attempts.

### Concurrency Serialization

Multiple `su` invocations arriving at the same time (e.g., a shell script running several `su -c` commands in rapid succession) could each try to start the exploit. Concurrent exploit runs corrupt overlapping slab memory and reliably panic the kernel.

The `su` binary prevents this with `flock()`:

```c
int lock_fd = open(LOCK_PATH, O_CREAT | O_RDWR, 0666);
flock(lock_fd, LOCK_EX);
```

The lock file is at `/data/local/tmp/.su.lock`. When multiple `su` processes find no daemon running, they all block on this lock. Only one proceeds to run the exploit. When it finishes and the daemon is up, the remaining processes release the lock, find the daemon running, and connect normally.

The double-check pattern (try socket → acquire lock → try socket again → start exploit) ensures that a process that waited on the lock doesn't redundantly start the exploit after the lock holder already did.
