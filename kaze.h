#ifndef _kaze_h_
#define _kaze_h_

/* clang-format off */
#ifndef KZ_NS_BEGIN
# ifdef __cplusplus
#   define KZ_NS_BEGIN extern "C" {
#   define KZ_NS_END   }
# else
#   define KZ_NS_BEGIN
#   define KZ_NS_END
# endif
#endif /* KZ_NS_BEGIN */

#ifndef KZ_STATIC
# if __GNUC__
#   define KZ_STATIC static __attribute((unused))
# else
#   define KZ_STATIC static
# endif
#endif /* KZ_STATIC */

#ifdef KZ_STATIC_API
# ifndef KZ_IMPLEMENTATION
#   define KZ_IMPLEMENTATION
# endif
# define KZ_API KZ_STATIC
#endif /* KZ_STATIC_API */

#if !defined(KZ_API) && defined(_WIN32)
# ifdef KZ_IMPLEMENTATION
#   define KZ_API __declspec(dllexport)
# else
#   define KZ_API __declspec(dllimport)
# endif
#endif /* KZ_API */

#ifndef KZ_API
# define KZ_API extern
#endif /* KZ_API */

#if (defined(__SUNPRO_C) && __SUNPRO_C >= 0x570) \
        || (defined(_MSC_VER) && _MSC_VER >= 1600) \
        || (defined(__STDC__) && __STDC__ \
            && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L) \
        || (defined (__WATCOMC__) \
            && (defined (_STDINT_H_INCLUDED) || __WATCOMC__ >= 1250)) \
        || (defined(__GNUC__) && (__GNUC__ > 3 || defined(_STDINT_H) \
                || defined(_STDINT_H_) || defined(__UINT_FAST64_TYPE__)))
# include <stdint.h>
#elif defined(__SUNPRO_C) && __SUNPRO_C >= 0x420
# include <sys/inttypes.h>
#else
    typedef unsigned int uint32_t;
    typedef signed int   int32_t;
# if defined(S_SPLINT_S)
    typedef long long int64_t;
    typedef unsigned long long uint64_t;
# elif defined(__GNUC__) && !defined(vxWorks)
    __extension__ typedef long long int64_t;
    __extension__ typedef unsigned long long uint64_t;
# elif defined(__MWERKS__) || defined (__SUNPRO_C) || defined (__SUNPRO_CC) \
       || defined (__APPLE_CC__) || defined (_LONG_LONG) || defined (_CRAYC) \
       || defined (S_SPLINT_S)
    typedef long long int64_t;
    typedef unsigned long long uint64_t;
# elif (defined(__WATCOMC__) && defined(__WATCOM_INT64__)) \
       || (defined(_MSC_VER) && _INTEGRAL_MAX_BITS >= 64) \
       || (defined (__BORLANDC__) && __BORLANDC__ > 0x460) \
       || defined (__alpha) || defined (__DECC)
    typedef __int64 int64_t;
    typedef unsigned __int64 uint64_t;
# else
#   error "No 64-bit integer type available"
# endif
#endif

#include <stddef.h>

#define KZ_OK      (0)
#define KZ_INVALID (-1) /* argument invalid */
#define KZ_FAIL    (-2) /* operation failed (see errno for real error) */
#define KZ_CLOSED  (-3) /* ring buffer is closed */
#define KZ_TOOBIG  (-4) /* enqueue data is too big */
#define KZ_AGAIN   (-5) /* no data available or no enough space */
#define KZ_BUSY    (-6) /* another reading/writing operation is in progress */
#define KZ_TIMEOUT (-7) /* operation timed out */

#define KZ_CREATE (1 << 0)
#define KZ_EXCL   (1 << 1)
#define KZ_RESET  (1 << 2)

#define KZ_READ  (1 << 0)
#define KZ_WRITE (1 << 1)
#define KZ_BOTH  (KZ_READ | KZ_WRITE)

#define KZ_MAX_SIZE ((size_t)0xFFFFFFFFU)

KZ_NS_BEGIN


/* global operations */

KZ_API size_t kz_aligned(size_t bufsize, size_t pagesize);
KZ_API int    kz_exists(const char *name, int *powner, int *puser);
KZ_API int    kz_unlink(const char *name);

KZ_API const char *kz_failerror(void);
KZ_API void        kz_freefailerror(const char *s);

/* object daclarations */

typedef struct kz_State   kz_State;
typedef struct kz_Context kz_Context;

/* queue creation/destruction */

KZ_API kz_State *kz_open(const char *name, int flags, size_t bufsize);
KZ_API void      kz_close(kz_State *S);

KZ_API int kz_shutdown(kz_State *S, int mode);

/* queue info */

KZ_API const char *kz_name(const kz_State *S);
KZ_API size_t      kz_size(const kz_State *S);

KZ_API int kz_pid(const kz_State *S);
KZ_API int kz_isowner(const kz_State *S);
KZ_API int kz_isclosed(const kz_State *S);

/* read/write */

KZ_API int kz_read(kz_State *S, kz_Context *ctx);
KZ_API int kz_write(kz_State *S, kz_Context *ctx, size_t len);

KZ_API int   kz_isread(const kz_Context *ctx);
KZ_API char *kz_buffer(kz_Context *ctx, size_t *plen);
KZ_API int   kz_commit(kz_Context *ctx, size_t len);
KZ_API void  kz_cancel(kz_Context *ctx);

/* sync waiting */

#define kz_wouldblock(ctx) ((ctx)->result == KZ_AGAIN)

KZ_API int kz_wait(kz_State *S, size_t len, int millis);
KZ_API int kz_waitcontext(kz_Context *ctx, int millis);

/* object definitions */

struct kz_Context {
    /* all fields below are private to the implementation */
    void   *state;  /* pointer to the queue state */
    size_t  pos;    /* position in the data */
    size_t  len;    /* length of the data */
    int32_t result; /* result of the operation */
};


KZ_NS_END

#endif    /* _kaze_h_ clang-format on */

#if defined(KZ_IMPLEMENTATION) && !defined(kz_implemented)
#define kz_implemented

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32 /* clang-format off */
# define WIN32_LEAN_AND_MEAN 1
# include <Windows.h>
# include <intrin.h>
# include <strsafe.h>
#else
# ifdef __linux__
#   include <linux/futex.h> /* Definition of FUTEX_* constants */
#   include <sys/syscall.h> /* Definition of SYS_* constants */
#   include <time.h>        /* Definition of CLOCK_* constants */
#   include <unistd.h>
# endif
# include <fcntl.h>  /* for O_* macros */
# include <limits.h> /* for INT_MAX */
# include <signal.h> /* for kill() */
# include <sys/mman.h>
# include <sys/stat.h>
# include <unistd.h>
#endif

#define KZ_ALIGN sizeof(uint32_t)
#define KZ_MARK  ((uint32_t)KZ_MAX_SIZE)

KZ_NS_BEGIN

typedef struct kzQ_ShmInfo {
    /* clang-format on */
    uint32_t size;    /* Size of the queue. */
    uint32_t used;    /* Number of bytes used in the queue (-1 == closed). */
    uint32_t reading; /* Whether the queue is being read. */
    uint32_t head;    /* Head of the queue. */
    uint32_t seq;     /* operation sequence index, used by `kz_wait()`. */
    uint32_t padding1[11];
    uint32_t need;    /* Number of bytes needed to write to the queue. */
    uint32_t writing; /* Whether the queue is being written to. */
    uint32_t tail;    /* Tail of the queue. */
    uint32_t waiters; /* Number of `kz_wait()` waiters on the queue. */
    uint32_t padding2[12];
} kzQ_ShmInfo;

typedef struct kz_ShmHdr {
    uint32_t size;      /* Size of the shared memory. 4GB max. */
    uint32_t _offset;   /* Offset of the second queue buffer. */
    uint32_t owner_pid; /* Owner process id. */
    uint32_t user_pid;  /* User process id. */

    /* for owner, queues[0] is the sending queue,
     * queues[1] is the receiving queue.
     * for user, queues[0] is the receiving queue,
     * queues[1] is the sending queue */
    kzQ_ShmInfo queues[2];
} kz_ShmHdr;

#define KZ_STATIC_ASSERT(cond) \
    typedef char __kz_static_assert_##__LINE__[(cond) ? 1 : -1]

KZ_STATIC_ASSERT(sizeof(kz_ShmHdr) == 256 + 16);

typedef struct kzQ_State {
    kz_State    *S;    /* Pointer to kz_State that owns this state */
    kzQ_ShmInfo *info; /* Pointer to queue state in shm */
    char        *data; /* Pointer to data start */
#ifdef _WIN32
    HANDLE can_push;
    HANDLE can_pop;
#endif
} kzQ_State;

struct kz_State {
#ifdef _WIN32
    DWORD  self_pid;
    HANDLE shm_fd;
#else
    int self_pid;
    int shm_fd;
#endif
    size_t     shm_size;
    kz_ShmHdr *hdr;
    kzQ_State  write;
    kzQ_State  read;
    size_t     name_len;
    char       name_buf[1];
};

/* utils */

static int kz_is_aligned_to(size_t size, size_t align) {
    assert((align & (align - 1)) == 0);
    return (size & (align - 1)) == 0;
}

static size_t kz_get_aligned_size(size_t size, size_t align) {
    assert((align & (align - 1)) == 0);
    return (size + align - 1) & ~(align - 1);
}

static uint32_t kz_read_u32le(const char *data) {
    uint32_t n;
#ifdef __BIG_ENDIAN__
    memcpy(&n, data, sizeof(n));
    n = __builtin_bswap32(n);
#else
    memcpy(&n, data, sizeof(n));
#endif
    return n;
}

static void kz_write_u32le(char *data, uint32_t n) {
#ifdef __BIG_ENDIAN__
    n = __builtin_bswap32(n);
#endif
    memcpy(data, &n, sizeof(n));
}

static int kz_initqueues(kz_State *S);
static int kz_resetqueues(kz_State *S);

static int kzQ_isclosed(const kzQ_State *QS);
static int kzQ_checkclosed(const kzQ_State *QS, uint32_t *state);
static int kzQ_push(kz_Context *ctx);
static int kzQ_pop(kz_Context *ctx);

/* platform relate routines */

#ifndef _WIN32

/* atomic operations */

/* clang-format off */
static uint32_t kzA_load(uint32_t *ptr)
{ return __atomic_load_n(ptr, __ATOMIC_RELAXED); }

static uint32_t kzA_load_acq(uint32_t *ptr)
{ return __atomic_load_n(ptr, __ATOMIC_ACQUIRE); }

static void kzA_store(uint32_t *ptr, uint32_t val)
{ __atomic_store_n(ptr, val, __ATOMIC_RELAXED); }

static uint32_t kzA_fetchadd(uint32_t *ptr, uint32_t delta)
{ return __atomic_fetch_add(ptr, delta, __ATOMIC_RELAXED); }

static uint32_t kzA_fetchadd_rel(uint32_t *ptr, uint32_t delta)
{ return __atomic_fetch_add(ptr, delta, __ATOMIC_RELEASE); }

static uint32_t kzA_subfetch(uint32_t *ptr, uint32_t delta)
{ return __atomic_sub_fetch(ptr, delta, __ATOMIC_RELAXED); }

static int kzA_cmpandswap(uint32_t *state, uint32_t expected, uint32_t desired) {
    return __atomic_compare_exchange_n(
            state, &expected, desired, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED);
}
/* clang-format on */

/* waiting operations */

#if defined(__APPLE__)
/* see <bsd/sys/ulock.h>, this is not public API */
#define UL_COMPARE_AND_WAIT_SHARED 3
#define ULF_WAKE_ALL               0x00000100

__attribute__((weak_import)) extern int __ulock_wait(
        uint32_t operation, void *addr, uint64_t value,
        uint32_t timeout); /* timeout is microseconds */
__attribute__((weak_import)) extern int __ulock_wake(
        uint32_t operation, void *addr, uint64_t wake_value);

#define USE_OS_SYNC_WAIT_ON_ADDRESS 1
/* #include <os/os_sync_wait_on_address.h>, this is public API but only
 * since macOS 14.4 */
#define OS_CLOCK_MACH_ABSOLUTE_TIME    32
#define OS_SYNC_WAIT_ON_ADDRESS_SHARED 1
#define OS_SYNC_WAKE_BY_ADDRESS_SHARED 1
__attribute__((weak_import)) extern int os_sync_wait_on_address(
        void *addr, uint64_t value, size_t size, uint32_t flags);
__attribute__((weak_import)) extern int os_sync_wait_on_address_with_timeout(
        void *addr, uint64_t value, size_t size, uint32_t flags,
        uint32_t clockid, uint64_t timeout_ns);
__attribute__((weak_import)) extern int os_sync_wake_by_address_any(
        void *addr, size_t size, uint32_t flags);
__attribute__((weak_import)) extern int os_sync_wake_by_address_all(
        void *addr, size_t size, uint32_t flags);

#elif defined(__linux__) && defined(SYS_futex_waitv)

static int kz_has_futex_waitv;

static void kz_check_waitv(void) {
    if (__atomic_load_n(&kz_has_futex_waitv, __ATOMIC_RELAXED) == 0) {
        int ret = syscall(SYS_futex_waitv, NULL, 0, 0, NULL, 0);
        int expected = 0, desired = (ret == -1 && errno == ENOSYS) ? -1 : 1;
        __atomic_compare_exchange_n(
                &kz_has_futex_waitv, &expected, desired, 0, __ATOMIC_RELAXED,
                __ATOMIC_RELAXED);
    }
}

static int kz_futex_waitv(struct futex_waitv *waiters, int count, int millis) {
    struct timespec ts;
    int             ret;

    /* specifying NULL would prevent the call from being interruptible
     * cf. https://outerproduct.net/futex-dictionary.html#linux */
    if (millis <= 0) millis = INT_MAX; /* a long time */

    /* setting absolute timeout for futex2 */
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) return KZ_FAIL;

    ts.tv_sec += millis / 1000;
    ts.tv_nsec += (millis % 1000) * 1000000;
    if (ts.tv_nsec >= 1000000000) ts.tv_nsec -= 1000000000, ts.tv_sec += 1;
    ret = syscall(
            SYS_futex_waitv, (void *)waiters, count, 0, &ts, CLOCK_MONOTONIC);

    if (ret >= 0) return KZ_OK;
    if (errno == ETIMEDOUT) return KZ_TIMEOUT;
    if (errno == EAGAIN) return KZ_OK; /* ifValue did not match */
    if (errno == ENOSYS) errno = ENOTSUP;
    return KZ_FAIL;
}

#endif

static int kz_futex_wait(void *addr, uint32_t ifValue, int millis) {
#if defined(__APPLE__)
    int ret;
    if (os_sync_wait_on_address_with_timeout && USE_OS_SYNC_WAIT_ON_ADDRESS) {
        if (millis <= 0)
            ret = os_sync_wait_on_address(
                    (void *)addr, (uint64_t)ifValue, 4,
                    OS_SYNC_WAIT_ON_ADDRESS_SHARED);
        else
            ret = os_sync_wait_on_address_with_timeout(
                    (void *)addr, (uint64_t)ifValue, 4,
                    OS_SYNC_WAIT_ON_ADDRESS_SHARED, OS_CLOCK_MACH_ABSOLUTE_TIME,
                    millis * 1000 * 1000);
    } else if (__ulock_wait)
        ret = __ulock_wait(
                UL_COMPARE_AND_WAIT_SHARED, (void *)addr, (uint64_t)ifValue,
                millis * 1000);
    else
        return (errno = ENOTSUP), KZ_FAIL;

    if (ret >= 0) return KZ_OK;
    if (ret == -ETIMEDOUT || errno == ETIMEDOUT) return KZ_TIMEOUT;

    /* not observed on macOS; just in case ifValue did not match */
    if (errno == EAGAIN) return KZ_OK;
    return KZ_FAIL;

#elif defined(__linux__)
    struct timespec ts;
    int             ret;

    /* specifying NULL would prevent the call from being interruptible
     * cf. https://outerproduct.net/futex-dictionary.html#linux */
    if (millis <= 0) millis = INT_MAX; /* a long time */

    ts.tv_sec = millis / 1000;
    ts.tv_nsec = (millis % 1000) * 1000000;
    ret = syscall(SYS_futex, (void *)addr, FUTEX_WAIT, ifValue, &ts, NULL, 0);

    if (ret >= 0) return KZ_OK;
    if (errno == ETIMEDOUT) return KZ_TIMEOUT;
    if (errno == EAGAIN) return KZ_OK; /* ifValue did not match */
    if (errno == ENOSYS) errno = ENOTSUP;
    return KZ_FAIL;

#else
    errno = ENOTSUP;
    return KZ_FAIL;
#endif
}

static int kz_futex_wake(void *addr, int wakeAll) {
#if defined(__APPLE__)
    int ret;
redo:
    if (wakeAll) {
        if (os_sync_wake_by_address_all && USE_OS_SYNC_WAIT_ON_ADDRESS)
            ret = os_sync_wake_by_address_all(
                    addr, 4, OS_SYNC_WAKE_BY_ADDRESS_SHARED);
        else if (__ulock_wake)
            ret = __ulock_wake(
                    UL_COMPARE_AND_WAIT_SHARED | ULF_WAKE_ALL, addr, 0);
        else
            return (errno = ENOTSUP), KZ_FAIL;
    } else {
        if (os_sync_wake_by_address_any && USE_OS_SYNC_WAIT_ON_ADDRESS)
            ret = os_sync_wake_by_address_any(
                    (void *)addr, 4, OS_SYNC_WAKE_BY_ADDRESS_SHARED);
        else if (__ulock_wake)
            ret = __ulock_wake(UL_COMPARE_AND_WAIT_SHARED, (void *)addr, 0);
        else
            return (errno = ENOTSUP), KZ_FAIL;
    }

    if (ret >= 0 || errno == ENOENT) return KZ_OK;
    if (errno == EINTR) goto redo;
    return KZ_FAIL;

#elif defined(__linux__)
    long ret = syscall(
            SYS_futex, (void *)addr, FUTEX_WAKE, (wakeAll ? INT_MAX : 1), NULL,
            NULL, 0);
    if (ret >= 0) return KZ_OK;
    if (errno == ENOSYS) errno = ENOTSUP;
    return KZ_FAIL;

#else
    (void)addr, (void)wakeAll;
    errno = ENOTSUP;
    return KZ_FAIL;
#endif
}

static int kzQ_waitpush(kzQ_State *QS, size_t old_need, int millis) {
    if (millis != 0) {
        size_t need = kzA_load(&QS->info->need);
        int    ret;
        if (need == 0) need = old_need;
        ret = kz_futex_wait(&QS->info->need, (uint32_t)need, millis);
        if (kzQ_checkclosed(QS, &QS->info->writing)) return KZ_CLOSED;
        if (ret != KZ_OK && ret != KZ_TIMEOUT) return ret;
    }
    return KZ_OK;
}

static int kzQ_waitpop(kzQ_State *QS, int millis) {
    if (millis != 0) {
        int ret = kz_futex_wait(&QS->info->used, 0, millis);
        if (kzQ_checkclosed(QS, &QS->info->reading)) return KZ_CLOSED;
        if (ret != KZ_OK && ret != KZ_TIMEOUT) return ret;
    }
    return KZ_OK;
}

static void kzQ_setneed(kzQ_State *QS, size_t need) {
    kzA_store(&QS->info->need, (uint32_t)need);
}

static int kzQ_wakepush(kzQ_State *QS, size_t new_used) {
    int r = KZ_OK, waked = 0;
    if (kzA_load(&QS->info->writing)) {
        size_t need = kzA_load(&QS->info->need);
        if (need > 0 && need < QS->info->size - new_used) {
            kzQ_setneed(QS, 0);
            r = kz_futex_wake(&QS->info->need, 0);
            waked = 1;
        }
    }
#ifdef SYS_futex_waitv
    if (kz_has_futex_waitv == 1) {
        if (!waked) r = kz_futex_wake(&QS->info->need, 0);
    } else
#endif
    {
        uint32_t *waiters = &QS->S->read.info->waiters;
        uint32_t *seq = &QS->S->read.info->seq;
        kzA_fetchadd(&QS->S->read.info->seq, 1);
        if ((int32_t)kzA_load(waiters) > 0) r = kz_futex_wake(seq, 0);
    }
    (void)waked;
    return r;
}

static int kzQ_wakepop(kzQ_State *QS, size_t old_used) {
    int r = KZ_OK, waked = 0;
    if (kzA_load(&QS->info->reading) && old_used == 0) {
        r = kz_futex_wake(&QS->info->used, 0);
        waked = 1;
    }
#ifdef SYS_futex_waitv
    if (kz_has_futex_waitv == 1) {
        if (!waked) r = kz_futex_wake(&QS->info->used, 0);
    } else
#endif
    {
        uint32_t *waiters = &QS->S->read.info->waiters;
        uint32_t *seq = &QS->S->read.info->seq;
        kzA_fetchadd(&QS->S->read.info->seq, 1);
        if ((int32_t)kzA_load(waiters) > 0) r = kz_futex_wake(seq, 0);
    }
    (void)waked;
    return r;
}

static int kzQ_waitmux(kz_State *S, uint32_t old_seq, size_t need, int millis) {
    uint32_t *waiters = &S->write.info->waiters;
    uint32_t *seq = &S->write.info->seq;
    int       r;
    (void)need;
    kzA_fetchadd(waiters, 1);
#ifdef SYS_futex_waitv
    if (kz_has_futex_waitv == 1) {
        struct futex_waitv waiters[2];
#ifdef FUTEX_SIZE_U32
        int flags = FUTEX_SIZE_U32;
#else
        int flags = FUTEX_32;
#endif
        memset(waiters, 0, sizeof(waiters));
        waiters[0].uaddr = (uintptr_t)&S->read.info->used;
        waiters[0].val = 0;
        waiters[0].flags = flags;
        waiters[1].uaddr = (uintptr_t)&S->write.info->need;
        waiters[1].val = need;
        waiters[1].flags = flags;
        r = kz_futex_waitv(waiters, 2, millis);
    } else
#endif
        r = kz_futex_wait(seq, old_seq, millis);
    kzA_subfetch(waiters, 1);
    return r;
}

/* creation/cleanup operations */

/* clang-format off */
KZ_API const char *kz_failerror(void) { return strerror(errno); }
KZ_API void        kz_freefailerror(const char *s) { (void)s; }

KZ_API int kz_unlink(const char *name)
{ return shm_unlink(name) == 0 || errno == ENOENT ? KZ_OK : KZ_FAIL; }
/* clang-format on */

static int kz_initfail(kz_State *S) {
    int err = errno;
    if (S->hdr != NULL) munmap(S->hdr, S->shm_size);
    close(S->shm_fd);
    free(S);
    errno = err;
    return KZ_FAIL;
}

static int kz_pidexists(int pid) {
    int r = kill(pid, 0);
    return r == 0 || (r == -1 && errno == EPERM);
}

static int kz_mapshm(kz_State *S) {
    struct stat statbuf;

    if (fstat(S->shm_fd, &statbuf) == -1) return KZ_FAIL;
    if (statbuf.st_size == 0) return (errno = ENOENT), KZ_FAIL;

    S->shm_size = statbuf.st_size;
    S->hdr = (kz_ShmHdr *)mmap(
            NULL, S->shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, S->shm_fd,
            0);
    return S->hdr == MAP_FAILED ? KZ_FAIL : KZ_OK;
}

static int kz_createshm(kz_State *S, int flags) {
    int oflags = O_CREAT | O_RDWR;
    int created = 0;

    /* create a new shared memory object */
    if ((flags & KZ_EXCL)) oflags |= O_EXCL;
    S->shm_fd = shm_open(S->name_buf, oflags, 0666);
    if (S->shm_fd == -1) return kz_initfail(S);

    /* check if the file already exists */
    {
        struct stat statbuf;
        if (fstat(S->shm_fd, &statbuf) == -1) return kz_initfail(S);
        if ((flags & KZ_EXCL) && statbuf.st_size != 0)
            return errno = EEXIST, kz_initfail(S);
        created = (statbuf.st_size == 0);
    }

    /* set the size of the shared memory object */
    if (created && ftruncate(S->shm_fd, S->shm_size) == -1)
        return kz_initfail(S);
    if ((flags & KZ_RESET)) created = 1;

    if (kz_mapshm(S) != KZ_OK) return kz_initfail(S);
    if (created) {
        memset(S->hdr, 0, sizeof(kz_ShmHdr));
        S->hdr->size = S->shm_size;
    }

    if (S->hdr->owner_pid != 0 && (int)S->hdr->owner_pid != S->self_pid
        && kz_pidexists(S->hdr->owner_pid))
        return errno = EACCES, kz_initfail(S);
    S->hdr->owner_pid = S->self_pid;
    return created ? kz_initqueues(S) : kz_resetqueues(S);
}

static int kz_openshm(kz_State *S) {
    S->shm_fd = shm_open(S->name_buf, O_RDWR, 0666);
    if (S->shm_fd == -1) return kz_initfail(S);
    if (kz_mapshm(S) != KZ_OK) return kz_initfail(S);
    if (S->shm_size != S->hdr->size) return errno = EBADF, kz_initfail(S);
    if (S->hdr->user_pid != 0 && (int)S->hdr->user_pid != S->self_pid
        && kz_pidexists(S->hdr->user_pid))
        return errno = EACCES, kz_initfail(S);
    return kz_resetqueues(S);
}

KZ_API int kz_exists(const char *name, int *powner, int *puser) {
    kz_State S;
    S.shm_fd = shm_open(name, O_RDWR, 0666);
    S.hdr = NULL;
    if (S.shm_fd < 0) return errno == ENOENT ? 0 : KZ_FAIL;
    if (kz_mapshm(&S) != KZ_OK) return close(S.shm_fd), KZ_FAIL;
    if (powner) *powner = S.hdr->owner_pid;
    if (puser) *puser = S.hdr->user_pid;
    return close(S.shm_fd), 1;
}

KZ_API int kz_shutdown(kz_State *S, int mode) {
    int waked = 0;
    if ((mode & KZ_READ)) {
        kzA_store(&S->read.info->used, KZ_MARK);
        kzQ_setneed(&S->read, 0);
        if (kzA_load(&S->read.info->writing))
            waked = 1, kz_futex_wake(&S->read.info->need, 1);
        if (kzA_load(&S->read.info->reading))
            kz_futex_wake(&S->read.info->used, 1);
    }
    if ((mode & KZ_WRITE)) {
        kzA_store(&S->write.info->used, KZ_MARK);
        kzQ_setneed(&S->write, 0);
        if (kzA_load(&S->write.info->reading))
            waked = 1, kz_futex_wake(&S->write.info->used, 1);
        if (kzA_load(&S->write.info->writing))
            kz_futex_wake(&S->write.info->need, 1);
    }
    if (mode != 0 && (int32_t)kzA_load(&S->read.info->waiters) > 0) {
#ifdef SYS_futex_waitv
        if (kz_has_futex_waitv == 1) {
            if (waked) kz_futex_wake(&S->write.info->used, 1);
        } else
#endif
            (void)waked, kz_futex_wake(&S->read.info->seq, 1);
    }
    return KZ_OK;
}

KZ_API void kz_close(kz_State *S) {
    if (S == NULL) return;
    kz_shutdown(S, KZ_BOTH);
    munmap(S->hdr, S->shm_size);
    close(S->shm_fd);
    free(S);
}

#else

/* atomic operations */

/* clang-format off */
typedef struct { uint32_t nonatomic; } kzA_atomic32_t;

static uint32_t kzA_load(uint32_t *ptr)
{ return _InterlockedCompareExchange((volatile LONG *)ptr, 0, 0); }

static uint32_t kzA_load_acq(uint32_t *ptr)
{ return _InterlockedCompareExchange((volatile LONG *)ptr, 0, 0); }

static void kzA_store(uint32_t *ptr, uint32_t val)
{ _InterlockedExchange((volatile LONG *)ptr, val); }

static uint32_t kzA_fetchadd(uint32_t *ptr, uint32_t delta)
{ return _InterlockedExchangeAdd((volatile LONG *)ptr, delta); }

static uint32_t kzA_fetchadd_rel(uint32_t *ptr, uint32_t delta)
{ return _InterlockedExchangeAdd((volatile LONG *)ptr, delta); }

static uint32_t kzA_subfetch(uint32_t *ptr, uint32_t delta)
{ return _InterlockedExchangeAdd((volatile LONG *)ptr, ~delta + 1) - delta; }

static int kzA_cmpandswap(uint32_t *state, uint32_t expected, uint32_t desired) {
    return _InterlockedCompareExchange((volatile LONG *)state,
            desired, expected) == expected;
}
/* clang-format on */

/* waiting operations */

static int kzQ_waitpush(kzQ_State *QS, size_t old_need, int millis) {
    if (millis != 0) {
        DWORD dwWaitRet = WaitForSingleObject(QS->can_push, millis);
        if (kzQ_checkclosed(QS, &QS->info->writing)) return KZ_CLOSED;
        if (dwWaitRet != WAIT_OBJECT_0 && dwWaitRet != WAIT_TIMEOUT)
            return KZ_FAIL;
    }
    return KZ_OK;
}

static int kzQ_waitpop(kzQ_State *QS, int millis) {
    if (millis != 0) {
        DWORD dwWaitRet = WaitForSingleObject(QS->can_pop, millis);
        if (kzQ_checkclosed(QS, &QS->info->reading)) return KZ_CLOSED;
        if (dwWaitRet != WAIT_OBJECT_0 && dwWaitRet != WAIT_TIMEOUT)
            return KZ_FAIL;
    }
    return KZ_OK;
}

static void kzQ_setneed(kzQ_State *QS, size_t need) {
    kzA_store(&QS->info->need, (uint32_t)need);
    if (need == 0)
        SetEvent(QS->can_push);
    else
        ResetEvent(QS->can_push);
}

static int kzQ_wakepush(kzQ_State *QS, size_t new_used) {
    size_t need = kzA_load(&QS->info->need);
    if (need > 0 && need < QS->info->size - new_used) kzQ_setneed(QS, 0);
    if (new_used == 0) ResetEvent(QS->can_pop);
    return KZ_OK;
}

static int kzQ_wakepop(kzQ_State *QS, size_t old_used) {
    if (old_used == 0) SetEvent(QS->can_pop);
    return KZ_OK;
}

static int kzQ_waitmux(kz_State *S, uint32_t seq, size_t need, int millis) {
    uint32_t *waiters = &S->write.info->waiters;
    HANDLE    aHandles[2] = {0};
    DWORD     dwRet;
    (void)need, (void)seq;
    aHandles[0] = S->read.can_pop;
    aHandles[1] = S->write.can_push;
    kzA_fetchadd(waiters, 1);
    dwRet = WaitForMultipleObjects(
            2,        /* object count */
            aHandles, /* handles */
            FALSE,    /* wait all */
            millis);  /* wait timeout */
    kzA_subfetch(waiters, 1);
    return dwRet == WAIT_FAILED ? KZ_FAIL : KZ_OK;
}

/* creation/cleanup operations */

KZ_API int  kz_unlink(const char *name) { return (void)name, KZ_OK; }
KZ_API void kz_freefailerror(const char *s) { LocalFree((HLOCAL)s); }

static void kz_cleanup(kz_State *S) {
    if (S->hdr != NULL) UnmapViewOfFile(S->hdr);
    if (S->shm_fd != NULL) CloseHandle(S->shm_fd);
    if (S->write.can_push != NULL) CloseHandle(S->write.can_push);
    if (S->write.can_pop != NULL) CloseHandle(S->write.can_pop);
    if (S->read.can_push != NULL) CloseHandle(S->read.can_push);
    if (S->read.can_pop != NULL) CloseHandle(S->read.can_pop);
}

static int kz_initfail(kz_State *S) {
    DWORD dwError = GetLastError();
    kz_cleanup(S);
    free(S);
    SetLastError(dwError);
    return KZ_FAIL;
}

static int kz_pidexists(DWORD pid) {
    DWORD  exitCode;
    int    isRunning = 0;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProcess == NULL) return 0;
    if (GetExitCodeProcess(hProcess, &exitCode))
        isRunning = (exitCode == STILL_ACTIVE);
    CloseHandle(hProcess);
    return isRunning;
}

static HANDLE kz_openevent(const char *name, const char *suffix, int flags) {
    char buf[MAX_PATH];
    StringCbPrintfA(buf, MAX_PATH, "%s-%s", name, suffix);
    if ((flags & KZ_CREATE))
        return CreateEventA(
                NULL,                    /* default security */
                TRUE,                    /* manual reset */
                (flags & KZ_RESET) == 0, /* initial state */
                buf);                    /* name of event object */
    return OpenEventA(
            SYNCHRONIZE | EVENT_MODIFY_STATE, /* Desired access */
            FALSE,                            /* Inherit handle */
            buf);                             /* name of event object */
}

static int kz_initevents(kz_State *S, kzQ_State *q0, kzQ_State *q1, int cr) {
    int flags = cr ? KZ_CREATE : 0;
    q0->can_push = kz_openevent(S->name_buf, "-0-can-push", flags);
    if (q0->can_push == NULL) return 0;
    q0->can_pop = kz_openevent(S->name_buf, "-0-can-pop", flags | KZ_RESET);
    if (q0->can_pop == NULL) return 0;
    q1->can_push = kz_openevent(S->name_buf, "-1-can-push", flags);
    if (q1->can_push == NULL) return 0;
    q1->can_pop = kz_openevent(S->name_buf, "-1-can-pop", flags | KZ_RESET);
    if (q1->can_pop == NULL) return 0;
    return 1;
}

static int kz_createshm(kz_State *S, int flags) {
    int created = 0;

    /* create a new shared memory object */
    S->shm_fd = CreateFileMappingA(
            INVALID_HANDLE_VALUE, /* use paging file */
            NULL,                 /* default security */
            PAGE_READWRITE,       /* read/write access */
            0,                    /* maximum object size (high-order DWORD) */
            (DWORD)S->shm_size,   /* maximum object size (low-order DWORD) */
            S->name_buf);         /* name of mapping object */

    if ((flags & KZ_EXCL) && GetLastError() == ERROR_ALREADY_EXISTS)
        return kz_initfail(S);

    if (S->shm_fd == NULL) return kz_initfail(S);

    /* init the shared memory object */
    S->hdr = (kz_ShmHdr *)MapViewOfFile(
            S->shm_fd,            /* handle to map object */
            FILE_MAP_ALL_ACCESS,  /* read/write permission */
            0,                    /* file offset (high-order DWORD) */
            0,                    /* file offset (low-order DWORD) */
            (SIZE_T)S->shm_size); /* mapping size */
    if (S->hdr == NULL) return kz_initfail(S);
    created = (flags & KZ_RESET) || S->hdr->size != S->shm_size;
    if (created) {
        memset(S->hdr, 0, sizeof(kz_ShmHdr));
        S->hdr->size = (uint32_t)S->shm_size;
    }

    if (S->hdr->owner_pid != 0 && S->hdr->owner_pid != (uint32_t)S->self_pid
        && kz_pidexists(S->hdr->owner_pid))
        return SetLastError(ERROR_ACCESS_DENIED), kz_initfail(S);
    if (!kz_initevents(S, &S->write, &S->read, 1)) return kz_initfail(S);
    return created ? kz_initqueues(S) : kz_resetqueues(S);
}

static int kz_openshm(kz_State *S) {
    S->shm_fd = OpenFileMappingA(
            FILE_MAP_ALL_ACCESS, /* read/write access */
            FALSE,               /* do not inherit the name */
            S->name_buf);        /* name of mapping object */
    if (S->shm_fd == INVALID_HANDLE_VALUE) return kz_initfail(S);

    /* init the shared memory object */
    S->hdr = (kz_ShmHdr *)MapViewOfFile(
            S->shm_fd,           /* handle to map object */
            FILE_MAP_ALL_ACCESS, /* read/write permission */
            0,                   /* file offset (high-order DWORD) */
            0,                   /* file offset (low-order DWORD) */
            0);                  /* mapping size */
    if (S->hdr == NULL) return kz_initfail(S);

    /* retrieve the size of shm */
    S->shm_size = S->hdr->size;

    if (S->hdr->user_pid != 0 && S->hdr->user_pid != (uint32_t)S->self_pid
        && kz_pidexists(S->hdr->user_pid))
        return SetLastError(ERROR_ACCESS_DENIED), kz_initfail(S);
    if (!kz_initevents(S, &S->read, &S->write, 0)) return kz_initfail(S);
    return kz_resetqueues(S);
}

KZ_API const char *kz_failerror(void) {
    DWORD dwErrCode = GetLastError(); /* Get the last error code */
    LPSTR lpBuf = NULL;
    DWORD dwBufSize = 0;
    DWORD dwFormatFlags = FORMAT_MESSAGE_ALLOCATE_BUFFER
                        | FORMAT_MESSAGE_FROM_SYSTEM
                        | FORMAT_MESSAGE_IGNORE_INSERTS;

    /* Let FormatMessage allocate the lpBuf for us */
    dwBufSize = FormatMessageA(
            dwFormatFlags, NULL, /* No message source needed */
            dwErrCode,           /* The error code */
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), /* Default language */
            (LPSTR)&lpBuf, /* Output lpBuf pointer address */
            0,             /* Minimum allocation size, 0 means necessary size */
            NULL           /* No arguments array needed */
    );

    if (dwBufSize == 0) { /* If FormatMessage failed */
        /* Try to allocate memory for a default message */
        lpBuf = (LPSTR)LocalAlloc(LMEM_ZEROINIT, 64);
        if (lpBuf)
            StringCbPrintfA(lpBuf, 64, "Unknown error (0x%lx)", dwErrCode);
        return lpBuf;
    }

    /* Remove trailing CRLF (FormatMessage typically adds newlines) */
    if (dwBufSize >= 2) {
        DWORD i;
        /* Find and remove any trailing CR or LF characters */
        for (i = dwBufSize - 2; i < dwBufSize; i++)
            if (lpBuf[i] == '\r' || lpBuf[i] == '\n') lpBuf[i] = '\0';
    }

    return lpBuf;
}

KZ_API int kz_exists(const char *name, int *powner, int *puser) {
    HANDLE shm_fd = OpenFileMappingA(
            FILE_MAP_ALL_ACCESS, /* read/write access */
            FALSE,               /* do not inherit the name */
            name);               /* name of mapping object */
    if (shm_fd == NULL)
        return GetLastError() == ERROR_FILE_NOT_FOUND ? 0 : KZ_FAIL;
    if (powner || puser) {
        /* init the shared memory object */
        kz_ShmHdr *hdr = (kz_ShmHdr *)MapViewOfFile(
                shm_fd,              /* handle to map object */
                FILE_MAP_ALL_ACCESS, /* read/write permission */
                0,                   /* file offset (high-order DWORD) */
                0,                   /* file offset (low-order DWORD) */
                0);                  /* mapping size */
        if (hdr == NULL) {
            if (powner) *powner = 0;
            if (puser) *puser = 0;
        } else {
            if (powner) *powner = hdr->owner_pid;
            if (puser) *puser = hdr->user_pid;
            UnmapViewOfFile(hdr);
        }
    }
    return (void)CloseHandle(shm_fd), 1;
}

KZ_API int kz_shutdown(kz_State *S, int mode) {
    if ((mode & KZ_READ)) {
        kzA_store(&S->read.info->used, KZ_MARK);
        kzQ_setneed(&S->read, 0);
    }
    if ((mode & KZ_WRITE)) {
        kzA_store(&S->write.info->used, KZ_MARK);
        kzQ_setneed(&S->read, 0);
        SetEvent(S->write.can_pop);
    }
    return KZ_OK;
}

KZ_API void kz_close(kz_State *S) {
    if (S == NULL) return;
    kz_shutdown(S, KZ_BOTH);
    kz_cleanup(S);
    free(S);
}

#endif

/* queue operations */

/* clang-format off */
static int kzQ_isclosed(const kzQ_State *QS)
{ return kzA_load(&QS->info->used) == KZ_MARK; }

static int kzQ_checkclosed(const kzQ_State *QS, uint32_t *state)
{ return kzQ_isclosed(QS) ? (kzA_store(state, 0), 1) : 0; }
/* clang-format on */

static size_t kzQ_freesize(const kzQ_State *QS) {
    size_t used = kzA_load(&QS->info->used);
    return used == KZ_MARK ? 0 : QS->info->size - used;
}

static size_t kzQ_calcneed(const kzQ_State *QS, size_t size) {
    size_t need_size = kz_get_aligned_size(size + sizeof(uint32_t), KZ_ALIGN);
    size_t remain = (size_t)QS->info->size - QS->info->tail;
    if (need_size > remain) need_size += remain;
    return need_size;
}

static int kzQ_push(kz_Context *ctx) {
    kzQ_State *QS = (kzQ_State *)ctx->state;

    /* check if there is enough space */
    size_t remain = (size_t)QS->info->size - QS->info->tail;
    size_t free_size = kzQ_freesize(QS);
    if (free_size < ctx->len) return KZ_AGAIN;

    /* write the offset and the size */
    assert(QS->info->tail < QS->info->size);
    if (ctx->len > remain) {
        kz_write_u32le(QS->data + QS->info->tail, KZ_MARK);
        ctx->pos = 0;
        ctx->len = free_size - remain;
    } else {
        ctx->pos = QS->info->tail;
        ctx->len = remain;
    }
    return KZ_OK;
}

static int kzQ_commitpush(kz_Context *ctx, size_t len) {
    kzQ_State *QS = (kzQ_State *)ctx->state;
    int        r;
    size_t     old_used, size;
    if (kzQ_checkclosed(QS, &QS->info->writing)) return KZ_CLOSED;

    size = kz_get_aligned_size(len + sizeof(uint32_t), KZ_ALIGN);
    if (size > ctx->len) return KZ_INVALID;
    kz_write_u32le(QS->data + ctx->pos, (uint32_t)len);
    QS->info->tail = (uint32_t)((ctx->pos + size) % QS->info->size);
    assert(kz_is_aligned_to(QS->info->tail, KZ_ALIGN));

    if ((old_used = kzA_fetchadd_rel(&QS->info->used, (uint32_t)size)) == KZ_MARK)
        kzA_store(&QS->info->used, KZ_MARK);
    r = kzQ_wakepop(QS, old_used);
    kzA_store(&QS->info->writing, 0);
    return r;
}

static int kzQ_pop(kz_Context *ctx) {
    kzQ_State *QS = (kzQ_State *)ctx->state;

    /* check if there is enough data */
    size_t used_size = kzA_load_acq(&QS->info->used);
    if (used_size == 0) return KZ_AGAIN;
    assert(used_size >= sizeof(uint32_t));

    /* read the size of the data */
    assert(QS->info->head < QS->info->size);
    ctx->pos = QS->info->head;
    ctx->len = kz_read_u32le(QS->data + ctx->pos);
    if (ctx->len == KZ_MARK) {
        ctx->pos = 0;
        ctx->len = kz_read_u32le(QS->data + ctx->pos);
    }
    ctx->len += sizeof(uint32_t);
    return KZ_OK;
}

static int kzQ_commitpop(kz_Context *ctx) {
    kzQ_State *QS = (kzQ_State *)ctx->state;
    int        r;
    size_t     new_used, size;
    if (kzQ_checkclosed(QS, &QS->info->reading)) return KZ_CLOSED;

    size = kz_get_aligned_size(ctx->len, KZ_ALIGN);
    QS->info->head = (uint32_t)((ctx->pos + size) % QS->info->size);
    assert(kz_is_aligned_to(QS->info->head, KZ_ALIGN));

    if ((new_used = kzA_subfetch(&QS->info->used, (uint32_t)size))
        == KZ_MARK - (uint32_t)size)
        kzA_store(&QS->info->used, KZ_MARK);
    r = kzQ_wakepush(QS, new_used);
    kzA_store(&QS->info->reading, 0);
    return r;
}

static kz_State *kz_newstate(const char *name) {
    kz_State *S = (kz_State *)malloc(sizeof(kz_State) + strlen(name));
    if (S == NULL) return NULL;
    memset(S, 0, sizeof(kz_State));
    memcpy(S->name_buf, name, strlen(name) + 1);
    S->name_len = strlen(name);
#ifdef _WIN32
    S->self_pid = GetCurrentProcessId();
#else
    S->self_pid = getpid();
#endif
    return S;
}

static void kz_setowner(kz_State *S, int isowner) {
    int write = 0, read = 1;
    if (isowner)
        S->hdr->owner_pid = S->self_pid;
    else {
        S->hdr->user_pid = S->self_pid;
        write = 1, read = 0;
    }
    S->write.S = S;
    S->write.info = &S->hdr->queues[write];
    S->write.data = (char *)(S->hdr + 1) + S->hdr->queues[0].size * write;
    S->read.S = S;
    S->read.info = &S->hdr->queues[read];
    S->read.data = (char *)(S->hdr + 1) + S->hdr->queues[0].size * read;
}

static int kz_initqueues(kz_State *S) {
    kz_ShmHdr *hdr = S->hdr;
    size_t     total_size = hdr->size - sizeof(kz_ShmHdr);
    size_t queue_size, aligned_size = kz_get_aligned_size(total_size, KZ_ALIGN);
    if (aligned_size > total_size) aligned_size -= KZ_ALIGN;
    assert(aligned_size <= total_size);
    queue_size = aligned_size / 2;
    hdr->queues[0].size = (uint32_t)queue_size;
    hdr->queues[1].size = (uint32_t)queue_size;
    kz_setowner(S, 1);
    return KZ_OK;
}

static int kz_resetqueues(kz_State *S) {
    assert(S->hdr->queues[0].size != 0);
    kz_setowner(S, 0);
    kzA_store(&S->read.info->reading, 0);
    kzA_store(&S->write.info->writing, 0);
    if (kzA_load(&S->read.info->used) == KZ_MARK) {
        S->read.info->head = S->read.info->tail = 0;
        kzA_store(&S->read.info->used, 0);
        kzQ_setneed(&S->read, 0);
    }
    if (kzA_load(&S->write.info->used) == KZ_MARK) {
        S->write.info->head = S->write.info->tail = 0;
        kzA_store(&S->write.info->used, 0);
        kzQ_setneed(&S->write, 0);
    }
    return KZ_OK;
}

/* API */

/* clang-format off */
KZ_API const char *kz_name(const kz_State *S) { return S->name_buf; }
KZ_API int         kz_pid(const kz_State *S) { return S->self_pid; }

KZ_API size_t kz_size(const kz_State *S)
{ return S->hdr ? S->hdr->queues[0].size : 0; }
/* clang-format on */

KZ_API size_t kz_aligned(size_t bufsize, size_t pagesize) {
    size_t required_size = kz_get_aligned_size(
            sizeof(kz_ShmHdr) + bufsize * 2, pagesize);
    if (!kz_is_aligned_to(required_size, KZ_ALIGN))
        required_size &= ~(KZ_ALIGN - 1); /* LCOV_EXCL_LINE */
    return required_size - sizeof(kz_ShmHdr);
}

KZ_API int kz_isowner(const kz_State *S) {
    if (S->hdr == NULL) return KZ_INVALID;
    if (S->hdr->owner_pid == S->hdr->user_pid)
        return S->write.info == S->hdr->queues;
    return (uint32_t)S->self_pid == S->hdr->owner_pid;
}

KZ_API int kz_isclosed(const kz_State *S) {
    if (S->hdr == NULL) return KZ_BOTH;
    return (kzQ_isclosed(&S->write) << 1) | kzQ_isclosed(&S->read);
}

KZ_API int kz_read(kz_State *S, kz_Context *ctx) {
    if (S->hdr == NULL) return KZ_CLOSED;
    if (kzQ_isclosed(&S->read)) return KZ_CLOSED;

    memset(ctx, 0, sizeof(kz_Context));
    ctx->state = &S->read;
    if (kzA_cmpandswap(&S->read.info->reading, 0, 1)) {
        ctx->result = kzQ_pop(ctx);
        assert(ctx->result == KZ_OK || ctx->result == KZ_AGAIN);
        return ctx->result;
    }
    return ctx->result = KZ_BUSY;
}

KZ_API int kz_write(kz_State *S, kz_Context *ctx, size_t len) {
    size_t need;
    if (S->hdr == NULL) return KZ_CLOSED;

    need = kzQ_calcneed(&S->write, len);
    if (need > S->write.info->size) return KZ_TOOBIG;
    if (kzQ_isclosed(&S->write)) return KZ_CLOSED;

    memset(ctx, 0, sizeof(kz_Context));
    ctx->state = &S->write;
    ctx->len = need;
    if (kzA_cmpandswap(&S->write.info->writing, 0, 1)) {
        if ((ctx->result = kzQ_push(ctx)) == KZ_AGAIN) {
            ctx->pos = 0, ctx->len = need;
            kzQ_setneed(&S->write, need);
        }
        assert(ctx->result == KZ_OK || ctx->result == KZ_AGAIN);
        return ctx->result;
    }
    return ctx->result = KZ_BUSY;
}

KZ_API char *kz_buffer(kz_Context *ctx, size_t *plen) {
    kzQ_State *QS = (kzQ_State *)ctx->state;
    assert(QS != NULL);
    if (ctx->result != KZ_OK) return NULL;
    if (plen) *plen = ctx->len - sizeof(uint32_t);
    return QS->data + ctx->pos + sizeof(uint32_t);
}

KZ_API int kz_isread(const kz_Context *ctx) {
    const kzQ_State *QS = (const kzQ_State *)ctx->state;
    assert(QS != NULL);
    return QS == &QS->S->read;
}

KZ_API void kz_cancel(kz_Context *ctx) {
    kzQ_State *QS = (kzQ_State *)ctx->state;
    assert(QS != NULL);
    if (kz_isread(ctx))
        kzA_store(&QS->info->reading, 0);
    else if (kzA_cmpandswap(&QS->info->writing, 1, 0))
        kzQ_setneed(QS, 0);
}

KZ_API int kz_commit(kz_Context *ctx, size_t len) {
    kzQ_State *QS = (kzQ_State *)ctx->state;
    assert(QS != NULL);
    if (ctx->result != KZ_OK) return KZ_INVALID;
    return kz_isread(ctx) ? kzQ_commitpop(ctx) : kzQ_commitpush(ctx, len);
}

KZ_API int kz_waitcontext(kz_Context *ctx, int millis) {
    kzQ_State *QS = (kzQ_State *)ctx->state;
    assert(QS != NULL);
    if ((int)ctx->result != KZ_AGAIN) return ctx->result;
    for (;;) {
        int isread = kz_isread(ctx);
        int r = isread ? kzQ_waitpop(QS, millis)
                       : kzQ_waitpush(QS, ctx->len, millis);
        if (r != KZ_OK) return ctx->result = r;
        r = isread ? kzQ_pop(ctx) : kzQ_push(ctx);
        ctx->result = (r == KZ_AGAIN) ? KZ_TIMEOUT : r;
        if (millis >= 0 || ctx->result != KZ_TIMEOUT) return ctx->result;
    }
}

KZ_API int kz_wait(kz_State *S, size_t len, int millis) {
    int    canread = KZ_OK, canwrite = KZ_OK;
    size_t need;
    if (S->hdr == NULL) return KZ_CLOSED;
    if (kzQ_isclosed(&S->read) || kzQ_isclosed(&S->write)) return KZ_CLOSED;

    need = kzQ_calcneed(&S->write, len);
    if (need > S->write.info->size) return KZ_TOOBIG;
    for (;;) {
        uint32_t seq = kzA_load(&S->write.info->seq);
        canread = (kzA_load(&S->read.info->used) != 0);
        canwrite = (kzQ_freesize(&S->write) >= need);
        if (millis != 0 && !canread && !canwrite) {
            int r;
            kzQ_setneed(&S->write, need);
            if ((r = kzQ_waitmux(S, seq, need, millis)) != KZ_OK) return r;
            if (kzQ_isclosed(&S->read) || kzQ_isclosed(&S->write))
                return KZ_CLOSED;
            canread = (kzA_load(&S->read.info->used) != 0);
            canwrite = (kzQ_freesize(&S->write) >= need);
        }
        if (canread && canwrite) return KZ_BOTH;
        if (canwrite) return KZ_WRITE;
        if (canread) return KZ_READ;
        if (millis >= 0) return KZ_TIMEOUT;
    }
}

KZ_API kz_State *kz_open(const char *name, int flags, size_t bufsize) {
    kz_State *S = kz_newstate(name);
    size_t    queue_size;
    int       ret;
    if (S == NULL) return NULL;
    S->hdr = NULL;

#ifdef SYS_futex_waitv
    kz_check_waitv();
#endif

    /* calculate the size of the shared memory object */
    S->shm_size = kz_get_aligned_size(sizeof(kz_ShmHdr) + bufsize, KZ_ALIGN);
    queue_size = (S->shm_size - sizeof(kz_ShmHdr)) / 2;

    /* check the size of the ring buffer */
    if ((flags & KZ_CREATE)
        && (queue_size < sizeof(uint32_t) * 2 || S->shm_size >= KZ_MAX_SIZE)) {
#ifdef _WIN32
        SetLastError(ERROR_INVALID_PARAMETER);
#else
        errno = EINVAL;
#endif
        return (void)kz_initfail(S), NULL;
    }

    ret = flags & KZ_CREATE ? kz_createshm(S, flags) : kz_openshm(S);
    return ret == KZ_OK ? S : NULL;
}

KZ_NS_END

#endif /* KZ_IMPLEMENTATION */

/* cc: cc='gcc' flags+='-Wall -Wextra -pedantic -std=c99 -O3' input='kaze.c'
 * unixcc: flags+='-shared' output='kaze.so'
 * win32cc: flags+='-mdll' output='kaze.dll'
 */
