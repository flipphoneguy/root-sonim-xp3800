# CVE-2019-2215: The ARM32 Port

This document builds on [The Exploit Explained](CVE-2019-2215.md), which covers the vulnerability, every background concept, and the full escalation chain from UAF through root. Read that first.

This document explains what breaks when porting the exploit from ARM64 to ARM32, why it breaks, and how it's fixed.

---

## Table of Contents

- [What Changes on ARM32](#what-changes-on-arm32)
- [The Alignment Problem](#the-alignment-problem)
  - [Why This Crashes](#why-this-crashes)
- [The Fix: NULL Guard on iov\[10\]](#the-fix-null-guard-on-iov10)
- [The Timing Problem the Fix Creates](#the-timing-problem-the-fix-creates)
- [The Pipe Synchronization Trick](#the-pipe-synchronization-trick)
- [Leak Flow on ARM32 (writev)](#leak-flow-on-arm32-writev)
  - [Phase 1: Getting the task_struct Pointer](#phase-1-getting-the-task_struct-pointer)
  - [Phase 2: Reading task_struct Fields with Secondary Clobber](#phase-2-reading-task_struct-fields-with-secondary-clobber)
- [Clobber Flow on ARM32 (readv)](#clobber-flow-on-arm32-readv)
  - [The preUafBytes Alignment Trick](#the-preuafbytes-alignment-trick)
  - [The Signal Pipe and Busy-Wait Timing](#the-signal-pipe-and-busy-wait-timing)
- [The Full Escalation Chain](#the-full-escalation-chain)
- [ARM32-Specific Constants](#arm32-specific-constants)

---

## What Changes on ARM32

The fundamental difference between ARM64 and ARM32 for this exploit comes down to one thing: **pointer size changes iovec size, which changes the alignment of the UAF corruption**.

On ARM64, pointers are 8 bytes, so each `struct iovec` is 16 bytes.
On ARM32, pointers are 4 bytes, so each `struct iovec` is 8 bytes.

This halving of iovec size means the same waitqueue offset inside the binder_thread maps to completely different iovec field types. What was a harmless length corruption on ARM64 becomes a fatal pointer corruption on ARM32.

Additionally, the binder_thread struct is a different size on ARM32 (0x134 = 308 bytes), and the waitqueue is at a different offset (0x50 instead of 0x98). Every kernel structure offset had to be re-derived from scratch — from reverse engineering the kernel binary with radare2, from probing the live device via `/proc/kallsyms` and `/proc/slabinfo`, or from trial-and-error with the leak primitive.

The escalation chain itself (leak → clobber addr_limit → stable R/W → overwrite cred → disable seccomp → disable SELinux → nsenter) is identical. What changes is how the leak and clobber primitives work at the iovec level.

---

## The Alignment Problem

On ARM32, each iovec is 8 bytes and the waitqueue offset is `0x50`.

`0x50 / 8 = 10.0` — **perfectly aligned**. The waitqueue starts exactly at the beginning of iov[10]. No fractional offset, no landing on a length field.

The waitqueue_head is 12 bytes, overlapping iov[10] and the first half of iov[11]:

```
Offset 0x50: spinlock       (4 bytes) → iov[10].iov_base
Offset 0x54: task_list.next (4 bytes) → iov[10].iov_len
Offset 0x58: task_list.prev (4 bytes) → iov[11].iov_base
```

When `EPOLL_CTL_DEL` fires (the same three-step process — spinlock take, list unlink making it self-referential, spinlock release):

- **Spinlock** writes `0x10001` at offset `0x50` → **iov[10].iov_base** — a *pointer* field
- **task_list.next** writes `slab + 0x54` at offset `0x54` → **iov[10].iov_len** — a *length* field (kernel address = very large length)
- **task_list.prev** writes `slab + 0x54` at offset `0x58` → **iov[11].iov_base** — a *pointer* field

Compare this to ARM64 where the spinlock hit iov[9].iov_len (a length). Here it hits iov[10].iov_base (a pointer).

### Why This Crashes

When the iov_iter reaches iov[10] and sees `iov_base = 0x10001`, the kernel tries to read from (writev) or write to (readv) that address. `0x10001` is not mapped to any physical memory. The kernel takes a page fault in kernel mode with no handler registered for that address. On a production Android kernel, this is an unrecoverable fault — the kernel prints an oops, the system panics, and the device reboots.

On ARM64, the spinlock corruption was invisible to the exploit — it just made a length slightly wrong. On ARM32, the spinlock corruption is lethal.

---

## The Fix: NULL Guard on iov[10]

The solution is to make iov[10] invisible to the iov_iter *before* the UAF fires:

```c
iovec_array[IOVEC_INDX_FOR_WQ].iov_base = NULL;
iovec_array[IOVEC_INDX_FOR_WQ].iov_len = 0;
```

When the iov_iter encounters an entry with `iov_base = NULL` and `iov_len = 0`, it **skips** it entirely — no memory access, no processing, just advance the index and move on. This happens in effectively zero time.

After the UAF fires, iov[10] gets corrupted — `iov_base` becomes `0x10001`, `iov_len` becomes `slab + 0x54`. But the iov_iter already moved past iov[10]. The corruption is write-only — nobody reads those values again.

The **useful** corruption is at `iov[11].iov_base` (offset `0x58`), which gets overwritten with `task_list.prev` — the self-referential pointer `slab + 0x54`. This is a valid kernel address pointing into the slab. When the iov_iter processes iov[11], it dereferences this pointer — reading from it (writev/leak) or writing to it (readv/clobber).

---

## The Timing Problem the Fix Creates

The NULL guard solves the crash but introduces a strict timing requirement that didn't exist on ARM64.

On ARM64, timing was relaxed. The spinlock only corrupted a length field, so it didn't matter whether the UAF fired before, during, or after the iov_iter processed the overlapping entry. The operation survived regardless.

On ARM32, the exploit **only works if the UAF fires after the iov_iter has already passed iov[10]**. Consider what happens if the UAF fires too early:

1. iov_iter is still processing iov[8] or iov[9]
2. EPOLL_CTL_DEL fires — spinlock writes `0x10001` to iov[10].iov_base, task_list.next writes a huge kernel address to iov[10].iov_len
3. iov_iter reaches iov[10] — it's no longer `{NULL, 0}`. It's `{0x10001, huge_number}`
4. Kernel tries to access address `0x10001` → crash

The exploit also fails if the UAF fires too *late* — after the iov_iter has already finished iov[11] and beyond. In that case, iov[11].iov_base gets corrupted to a kernel address, but the iov_iter already processed it with the original userspace address. The corruption has no effect. The exploit reads/writes normal userspace data instead of kernel memory.

The exploit needs the UAF to fire in a **narrow window**: after iov[10] is skipped, but while the iov_iter is still processing (ideally blocked right before) iov[11].

---

## The Pipe Synchronization Trick

Random timing won't work — the window is microseconds wide. The exploit needs a way to **freeze** the parent process at exactly the right iovec entry, guarantee the iov_iter has passed iov[10], then trigger the UAF while the parent is sleeping.

Pipes provide this for the leak direction. The pipe capacity is forced to exactly two pages (8192 bytes) via `F_SETPIPE_SZ`. The exploit carefully sizes the iovec entries before iov[10] so their total data exactly fills the pipe. When the iov_iter reaches iov[11] and tries to continue, the pipe is at capacity (for writev) or empty (for readv), and the parent **blocks** in `pipe_wait()`.

At this point:
- iov[10] has already been skipped (it was `{NULL, 0}`)
- The iov_iter is frozen, waiting for the pipe to become available for iov[11]
- The parent is asleep in kernel mode

The child process now has all the time it needs to call `EPOLL_CTL_DEL`. The UAF fires safely — iov[10] gets corrupted (harmless, already passed), iov[11].iov_base gets a kernel slab pointer (this is what we want). Then the child manipulates the pipe (drains it or fills it) to wake the parent. The parent resumes processing iov[11] with the corrupted kernel pointer.

For the clobber direction, a different timing mechanism is used — see [The Signal Pipe and Busy-Wait Timing](#the-signal-pipe-and-busy-wait-timing).

---

## Leak Flow on ARM32 (writev)

The ARM32 exploit uses a two-phase leak, unlike the ARM64 version which does it in one step. This is needed because of a chicken-and-egg problem: to clobber addr_limit, we need the thread_info (= stack) pointer; to read the stack pointer from the task_struct, we need kernel R/W (which requires addr_limit). The ARM32 exploit solves this with a trick: `binder_thread+0x130` contains a task_struct pointer that **survives the iovec reclaim**.

### Phase 1: Getting the task_struct Pointer

The iov array is `BINDER_THREAD_SZ / 8 = 38` entries, totaling `38 × 8 = 304 = 0x130` bytes. But `binder_thread` is `0x134` bytes. The last 4 bytes at offset `0x130` are **not overwritten** by the iovec copy — they survive from the freed binder_thread. On this kernel, `binder_get_thread` stores the task_struct pointer at offset `0x130` (confirmed by r2 disassembly: `str r3, [r4, 0x130]`). This gives us the task_struct pointer for free from the initial leak.

The parent calls `writev(pipe_write_fd, iovec_array, ...)`:

1. **iov[8] and iov[9]** contain padding buffers totaling `pipeCapacity - 1 = 8191` bytes. writev reads from these buffers and writes the data into the pipe. The pipe now has 8191 bytes — one byte short of full.

2. **iov[10]** is `{NULL, 0}`. The iov_iter skips it instantly.

3. **iov[11]** has a userspace buffer of length `1 + minimumLeak` bytes. writev writes 1 byte into the pipe (filling it to 8192 = capacity), then **blocks** in `pipe_wait()` because the pipe is full.

4. The parent is now frozen at exactly the right position — iov[10] is behind us, and we're partway through iov[11].

5. The **child process** wakes up after a 500ms delay and calls `EPOLL_CTL_DEL`. The UAF fires:
   - Spinlock writes `0x10001` → iov[10].iov_base (harmless — already skipped)
   - `task_list.next` writes `slab + 0x54` → iov[10].iov_len (harmless — already skipped)
   - `task_list.prev` writes `slab + 0x54` → **iov[11].iov_base** (this is the exploit)

6. The child **drains the pipe** by reading all the data out. The parent wakes up.

7. The parent resumes iov[11]. The iov_base has been changed to `slab + 0x54`. The iov_iter already consumed 1 byte (the pre-UAF byte), so it reads from `slab + 0x55` onward. writev reads `minimumLeak` bytes from that kernel address and writes them into the pipe.

8. The child reads the pipe and extracts two values:
   - At offset 3 in the leaked data (= slab offset `0x58`): the self-referential `task_list.prev` pointer (`slab + 0x54`). Subtracting `0x54` gives the slab base address.
   - At offset `0xDB` in the leaked data (= slab offset `0x130`): the **task_struct pointer**, surviving from the freed binder_thread's last 4 bytes.

### Phase 2: Reading task_struct Fields with Secondary Clobber

Now we have the task_struct pointer but need to read two fields from it: `stack` (at offset `0x004`) and `cred` (at offset `0x39C`). We can't do a simple kernel read because we don't have addr_limit bypass yet. Instead, phase 2 does a second writev UAF with a large iov[11] to keep the parent busy writing, while the child uses a separate clobber UAF to modify iov[12] and iov[13] in the parent's slab.

1. The parent's iov[11] is made very large (`minimumLeak + 4 × pipeCapacity`). This gives the parent lots of slab data to write into the pipe, keeping it busy for a long time.

2. The child fires the UAF and reads the initial slab data to extract `slab_addr` (same as phase 1).

3. The child calls `clobber_with_retry(slab_addr + 0x60, new_iovecs, 16)` — this is a **separate, complete clobber UAF** (with its own binder_fd, epoll, fork, etc.). It writes 16 bytes to `slab + 0x60`, which is exactly where iov[12] sits in the parent's slab. The payload replaces iov[12] and iov[13] with:
   - iov[12] = `{task_struct_ptr + 0x004, 4}` — reads the `stack` field
   - iov[13] = `{task_struct_ptr + 0x39C, 4}` — reads the `cred` pointer

4. The child drains the remaining iov[11] data from the pipe.

5. When the parent's writev reaches the modified iov[12] and iov[13], it reads from the task_struct fields and writes those values into the pipe.

6. The child reads 4 bytes (stack pointer) and 4 bytes (cred pointer) from the pipe.

After phase 2, we have: `stack_ptr` (which on kernel 3.x is also the `thread_info` pointer), and `cred_ptr` — both are valid kernel addresses.

---

## Clobber Flow on ARM32 (readv)

The clobber direction writes attacker-controlled data to a chosen kernel address. The parent calls `readv(pipe_read_fd, iovec_array, ...)`.

The flow is conceptually similar to the leak but reversed — the pipe provides data to write instead of receiving data to read. However, the ARM32 clobber uses a fundamentally different timing mechanism from the leak: instead of blocking on a full/empty pipe, it uses a **signal pipe + busy-wait delay** to hit the right timing window.

### The preUafBytes Alignment Trick

The clobber needs to overwrite iov[12] and iov[13] with attacker-chosen `{address, length}` pairs. This is done through iov[11]: after the UAF, iov[11].iov_base points to `slab + 0x54`, and readv writes pipe data there. But not all of that data should go to the slab — some was consumed before the UAF fired.

The exploit sets `preUafBytes = 12`, meaning iov[11] is 28 bytes long (`12 + 16`). The first 12 bytes are consumed into the original userspace dummyBuffer before the UAF fires. After the UAF changes iov[11].iov_base to `slab + 0x54`, the iov_iter has already advanced 12 bytes into iov[11]. The remaining 16 bytes are written to `slab + 0x54 + 12 = slab + 0x60` — which is exactly where iov[12] starts.

Those 16 bytes are the attacker's clobber data: two new iovec entries that replace iov[12] and iov[13]:

```
Bytes  0- 3: payloadAddress    → new iov[12].iov_base
Bytes  4- 7: payloadLength     → new iov[12].iov_len
Bytes  8-11: &testDatum        → new iov[13].iov_base
Bytes 12-15: 4                 → new iov[13].iov_len
```

readv then continues:
- **New iov[12]** `{payloadAddress, payloadLength}`: reads `payloadLength` bytes from the pipe and writes them to `payloadAddress` — the **arbitrary kernel write**.
- **New iov[13]** `{&testDatum, 4}`: reads 4 bytes from the pipe into the local variable `testDatum`.

After readv returns, the exploit checks `testDatum == 0xABCD5678` (the known value placed in the pipe). If it matches, the entire chain worked and `payloadAddress` was written to successfully. If not, the timing was wrong and the exploit retries.

### The Signal Pipe and Busy-Wait Timing

Unlike the leak (which uses pipe blocking for deterministic synchronization), the clobber is a genuine race condition. The timing is controlled through two mechanisms:

1. **Signal pipe**: The parent writes `"X"` to a signal pipe immediately before starting `readv`. The child blocks on reading this pipe, so it knows the exact moment the parent begins the readv operation.

2. **Busy-wait delay**: After receiving the signal, the child calls `busy_wait_ns(delay_ns)` — a tight loop using `clock_gettime(CLOCK_MONOTONIC)` that spins for a precise number of nanoseconds. Then it fires `EPOLL_CTL_DEL`.

3. **Retry loop**: `clobber_with_retry()` runs up to 40 attempts with increasing delays from 50µs to 830µs. Each attempt uses a fresh binder_fd and epoll instance. The test canary (`testDatum == 0xABCD5678`) determines success.

4. **Helper process**: A separate helper process writes `3 × pipeCapacity` bytes into the pipe in one big `write()` call. The data is laid out so that after the padding (consumed by iov[8]+[9]), the clobber data, payload, and test value appear in the right order for iov[11], [12], and [13] to consume.

The helper process and the clobber child run on different CPUs (`pin_cpu(0)` for the helper and parent, `pin_cpu(1)` for the clobber child) to avoid cache contention.

---

## The Full Escalation Chain

With the two-phase leak and the clobber primitive working, the exploit chains them into four phases:

**Phase 1 — Leak task_struct.** `leak_phase1()` uses a writev UAF to read slab memory. The binder_thread+0x130 field (which survives the iovec reclaim because the iov array is only 0x130 bytes) contains the task_struct pointer. The self-referential list_head pointer at slab+0x58 gives the slab base address.

**Phase 2 — Read stack and cred.** `leak_phase2()` uses a second writev UAF with a secondary clobber. While the parent's writev is processing a large iov[11], the child clobbers iov[12] and iov[13] to point to `task_struct+0x004` (stack) and `task_struct+0x39C` (cred). When the parent's writev reaches those entries, it reads the stack and cred pointers from the task_struct.

**Phase 3 — Clobber addr_limit.** `clobber_with_retry(thread_info + 0x008, 0xFFFFFFFF, 4)` writes `0xFFFFFFFF` to the addr_limit field in thread_info (which on kernel 3.x lives at the base of the kernel stack). After this, the kernel no longer validates buffer addresses in syscalls.

**Phase 4 — Escalate privileges.** With addr_limit smashed, a simple pipe pair becomes arbitrary kernel R/W. The exploit:
- Zeroes all 8 uid/gid fields in the cred struct (uid, gid, suid, sgid, euid, egid, fsuid, fsgid)
- Clears securebits
- Sets all 5 capability sets to `{0xFFFFFFFF, 0xFFFFFFFF}` (all capabilities)
- Clears thread_info flags (disables seccomp)
- Writes 0 to `selinux_enforcing` (disables SELinux enforcement)
- Enters PID 1's mount namespace via `setns()` (escapes the app's sandboxed filesystem — see [The Daemon](daemon.md) for how this is used)

---

## ARM32-Specific Constants

Every constant in the exploit was determined empirically for this specific device and kernel build — from reverse engineering the kernel binary with radare2, from probing the live device via `/proc/kallsyms` and `/proc/slabinfo`, or from trial-and-error with the leak primitive:

| Constant | Value | Meaning |
|---|---|---|
| `BINDER_THREAD_SZ` | `0x134` (308) | Size of `binder_thread` on this kernel |
| `IOVEC_ARRAY_SZ` | 38 | `0x134 / 8` — number of iovecs to fill kmalloc-512 |
| `WAITQUEUE_OFFSET` | `0x50` | Offset of the waitqueue inside `binder_thread` |
| `IOVEC_INDX_FOR_WQ` | 10 | `0x50 / 8` — which iovec the waitqueue overlaps |
| `SELINUX_ENFORCING` | `0xc1310ae8` | Address of `selinux_enforcing` global |
| `OFFSET__task_struct__stack` | `0x004` | Stack pointer field in task_struct |
| `OFFSET__task_struct__cred` | `0x39C` | Cred pointer field in task_struct |
| `OFFSET__thread_info__addr_limit` | `0x008` | addr_limit field in thread_info |
| `OFFSET__cred__uid` | `0x004` | UID field offset within struct cred |
| `OFFSET__cred__securebits` | `0x024` | Securebits field within struct cred |
| `OFFSET__cred__cap_inheritable` | `0x028` | Inheritable capabilities within struct cred |
| `OFFSET__cred__cap_permitted` | `0x030` | Permitted capabilities within struct cred |
| `OFFSET__cred__cap_effective` | `0x038` | Effective capabilities within struct cred |
| `OFFSET__cred__cap_bset` | `0x040` | Bounding set within struct cred |
| `OFFSET__cred__cap_ambient` | `0x048` | Ambient capabilities within struct cred |

The 32-bit port is not a recompile of the 64-bit exploit. It required solving a fundamentally different alignment problem (pointer corruption vs. length corruption), engineering a precise timing mechanism that the 64-bit version didn't need, inventing a two-phase leak to break a circular dependency (task_struct pointer embedded at the end of the binder_thread surviving the iov reclaim), and deriving every kernel structure offset from scratch through reverse engineering.
