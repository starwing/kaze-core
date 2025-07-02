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
#   define KZ_STATIC static __attribute__ ((unused))
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
#define KZ_CLOSED  (-3) /* channel is closed */
#define KZ_TOOBIG  (-4) /* data to written is too big */
#define KZ_AGAIN   (-5) /* no data available or no enough space */
#define KZ_BUSY    (-6) /* another operation is in progress */
#define KZ_TIMEOUT (-7) /* operation timed out */

#define KZ_CREATE (1 << 16)
#define KZ_EXCL   (1 << 17)
#define KZ_RESET  (1 << 18)

#define KZ_READ  (1 << 0)
#define KZ_WRITE (1 << 1)
#define KZ_BOTH  (KZ_READ | KZ_WRITE)

#define KZ_MAX_SIZE ((uint32_t)0xFFFFFFFFU)

KZ_NS_BEGIN


/* global operations */

KZ_API size_t kz_aligned (size_t bufsize, size_t pagesize);
KZ_API int    kz_exists  (const char *name, int *powner, int *puser);
KZ_API int    kz_unlink  (const char *name);

KZ_API const char *kz_failerror     (void);
KZ_API void        kz_freefailerror (const char *s);

/* object declarations */

typedef struct kz_State   kz_State;
typedef struct kz_Context kz_Context;

/* queue creation/destruction */

KZ_API kz_State *kz_open  (const char *name, int flags, size_t bufsize);
KZ_API void      kz_close (kz_State *S);

KZ_API int kz_shutdown (kz_State *S, int mode);

/* queue info */

KZ_API const char *kz_name (const kz_State *S);
KZ_API size_t      kz_size (const kz_State *S);

KZ_API int kz_pid      (const kz_State *S);
KZ_API int kz_isowner  (const kz_State *S);
KZ_API int kz_isclosed (const kz_State *S);

/* read/write */

#define kz_setnotify(ctx,v) ((ctx)->notify = (v))

KZ_API int kz_read  (kz_State *S, kz_Context *ctx);
KZ_API int kz_write (kz_State *S, kz_Context *ctx, size_t len);

KZ_API int   kz_isread (const kz_Context *ctx);
KZ_API char *kz_buffer (kz_Context *ctx, size_t *plen);
KZ_API int   kz_commit (kz_Context *ctx, size_t len);
KZ_API void  kz_cancel (kz_Context *ctx);

/* sync waiting */

#define kz_wouldblock(ctx) ((ctx)->result == KZ_AGAIN)

KZ_API int kz_wait        (kz_State *S, size_t len, int millis);
KZ_API int kz_waitcontext (kz_Context *ctx, int millis);

/* object definitions */

struct kz_Context {
    /* all fields below are private, only used by the implementation */
    void   *state;  /* pointer to the queue state */
    size_t  pos;    /* position in the data */
    size_t  len;    /* length of the data */
    int32_t result; /* result of the operation */
    int32_t notify; /* whether notify opposite */
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

KZ_NS_BEGIN

/* clang-format on */
#define KZ_ALIGN       sizeof(uint32_t)
#define KZ_CLOSE_MASK  ((uint32_t)0x80000000U)
#define KZ_REWIND_MARK ((uint32_t)0xFFFFFFFFU)
#define KZ_CACHE_LINE  (64 / sizeof(uint32_t))

/* The reading/writing fields in kz_ShmQueue below used as signals of current
 * queue reading/writing status.
 * If the value is 0, no operation is in progress.
 * If the value is `KZ_NOWAIT`, a reading/writing operation is in progress.
 * Otherwise, a reading/writing operation is blocking from lacking data/space.
 */
#define KZ_NOWAIT   (~(uint32_t)0)
#define KZ_WAITREAD (1)
#define KZ_WAITBOTH (2)

typedef struct kz_ShmQueue {
    uint32_t writing;  /* Whether the queue is being written to. */
    uint32_t tail;     /* Tail of the queue. */
    uint32_t can_push; /* Windows only, Whether the queue can push no wait. */
    uint32_t padding1[KZ_CACHE_LINE - 3];

    uint32_t reading; /* Whether the queue is being read. */
    uint32_t head;    /* Head of the queue. */
    uint32_t can_pop; /* Windows only, Whether the queue can pop no wait. */
    uint32_t padding2[KZ_CACHE_LINE - 3];

    uint32_t used; /* Number of bytes used in the queue (-1 == closed). */
    uint32_t padding3[KZ_CACHE_LINE - 1];
} kz_ShmQueue;

typedef struct kz_ShmHdr {
    uint32_t size;       /* Size of the shared memory. 4GB max. */
    uint32_t queue_size; /* Size of a single queue. */
    uint32_t owner_pid;  /* Owner process id. */
    uint32_t user_pid;   /* User process id. */

    /* for owner, queues[0] is the sending queue,
     * queues[1] is the receiving queue.
     * for user, queues[0] is the receiving queue,
     * queues[1] is the sending queue */
    kz_ShmQueue queues[2];
} kz_ShmHdr;

#define KZ_STATIC_ASSERT(cond) \
    typedef char __kz_static_assert_##__LINE__[(cond) ? 1 : -1]

KZ_STATIC_ASSERT(sizeof(kz_ShmHdr) == 192 * 2 + 16);

typedef struct kz_Queue {
    kz_State    *S;    /* Pointer to kz_State that owns this state */
    kz_ShmQueue *info; /* Pointer to queue state in shm */
    char        *data; /* Pointer to data start */
    uint32_t     size; /* size of queue in bytes */
#ifdef _WIN32
    HANDLE hCanPushEvent;
    HANDLE hCanPopEvent;
#endif
} kz_Queue;

typedef struct kz_Mux {
    uint32_t wused;
    uint32_t rused;
    uint32_t need;
    int      mode;
} kz_Mux;

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
    kz_Queue   write;
    kz_Queue   read;
    size_t     name_len;
    char       name_buf[1];
};

/* utils */

static int kz_pidexists(int pid);
static int kzS_initqueues(kz_State *S, int isowner, int created);

/* clang-format off */
static kz_Queue *kzC_state(kz_Context *ctx)
{ return ctx ? (kz_Queue *)ctx->state : NULL; }

static int kzS_checkpid(kz_State *S, uint32_t *pid)
{ return *pid == 0 || *pid == (uint32_t)S->self_pid || !kz_pidexists(*pid); }

static int kz_is_aligned_to(size_t size, size_t align)
{ assert(!(align & (align - 1))); return (size & (align - 1)) == 0; }

static size_t kz_get_aligned_size(size_t size, size_t align)
{ assert(!(align & (align - 1))); return (size + align - 1) & ~(align - 1); }
/* clang-format on */

static int kzS_checksize(kz_State *S) {
    size_t queue_size = (S->shm_size - sizeof(kz_ShmHdr)) / 2;
    return queue_size >= sizeof(uint32_t) * 2 && queue_size < KZ_CLOSE_MASK;
}

static uint32_t kzQ_calcneed(const kz_Queue *Q, size_t size) {
    uint32_t need_size = (uint32_t)kz_get_aligned_size(
            size + sizeof(uint32_t), KZ_ALIGN);
    uint32_t remain = Q->size - Q->info->tail;
    if (need_size > remain) need_size += remain;
    return need_size;
}

static uint32_t kz_read_u32le(const char *data) {
    return (uint32_t)(data[0] & 0xFF) /* clang-format off */
        | (uint32_t)(data[1] & 0xFF) << 8
        | (uint32_t)(data[2] & 0xFF) << 16
        | (uint32_t)(data[3] & 0xFF) << 24; /* clang-format on */
}

static void kz_write_u32le(char *data, uint32_t n) {
    data[0] = n & 0xFF;
    data[1] = (n >> 8) & 0xFF;
    data[2] = (n >> 16) & 0xFF;
    data[3] = (n >> 24) & 0xFF;
}

/* platform relate routines */

#ifndef _WIN32

/* atomic operations */

/* clang-format off */
static uint32_t kzA_load(uint32_t *ptr)
{ return __atomic_load_n(ptr, __ATOMIC_ACQUIRE); }

static uint32_t kzA_loadR(uint32_t *ptr)
{ return __atomic_load_n(ptr, __ATOMIC_RELAXED); }

static void kzA_storeR(uint32_t *ptr, uint32_t val)
{ __atomic_store_n(ptr, val, __ATOMIC_RELAXED); }

static uint32_t kzA_fetchadd(uint32_t *ptr, uint32_t delta)
{ return __atomic_fetch_add(ptr, delta, __ATOMIC_RELEASE); }

static uint32_t kzA_subfetch(uint32_t *ptr, uint32_t delta)
{ return __atomic_sub_fetch(ptr, delta, __ATOMIC_RELEASE); }

static int kzA_cmpandswapR(uint32_t *state, uint32_t expected, uint32_t desired) {
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
#endif

static int kz_futex_wait(void *addr, uint32_t ifValue, int millis) {
#if defined(__APPLE__)
    int r;
    if (os_sync_wait_on_address_with_timeout && USE_OS_SYNC_WAIT_ON_ADDRESS) {
        if (millis < 0)
            r = os_sync_wait_on_address(
                    (void *)addr, (uint64_t)ifValue, 4,
                    OS_SYNC_WAIT_ON_ADDRESS_SHARED);
        else
            r = os_sync_wait_on_address_with_timeout(
                    (void *)addr, (uint64_t)ifValue, 4,
                    OS_SYNC_WAIT_ON_ADDRESS_SHARED, OS_CLOCK_MACH_ABSOLUTE_TIME,
                    millis * 1000 * 1000);
    } else if (__ulock_wait)
        r = __ulock_wait(
                UL_COMPARE_AND_WAIT_SHARED, (void *)addr, (uint64_t)ifValue,
                millis * 1000);
    else
        return (errno = ENOTSUP), KZ_FAIL;

    if (r >= 0) return KZ_OK;
    if (r == -ETIMEDOUT || errno == ETIMEDOUT) return KZ_TIMEOUT;

    /* not observed on macOS; just in case ifValue did not match */
    if (errno == EAGAIN) return KZ_OK;
    return KZ_FAIL;

#elif defined(__linux__)
    int r;

    /* specifying NULL would prevent the call from being interruptible
     * cf. https://outerproduct.net/futex-dictionary.html#linux */
    if (millis < 0) millis = INT_MAX; /* a long time */

    {
        struct timespec ts;
        ts.tv_sec = millis / 1000;
        ts.tv_nsec = (millis % 1000) * 1000000;
        r = syscall(SYS_futex, (void *)addr, FUTEX_WAIT, ifValue, &ts, NULL, 0);
    }

    if (r >= 0) return KZ_OK;
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
    int r;
redo:
    if (wakeAll) {
        if (os_sync_wake_by_address_all && USE_OS_SYNC_WAIT_ON_ADDRESS)
            r = os_sync_wake_by_address_all(
                    addr, 4, OS_SYNC_WAKE_BY_ADDRESS_SHARED);
        else if (__ulock_wake)
            r = __ulock_wake(
                    UL_COMPARE_AND_WAIT_SHARED | ULF_WAKE_ALL, addr, 0);
        else
            return (errno = ENOTSUP), KZ_FAIL;
    } else {
        if (os_sync_wake_by_address_any && USE_OS_SYNC_WAIT_ON_ADDRESS)
            r = os_sync_wake_by_address_any(
                    (void *)addr, 4, OS_SYNC_WAKE_BY_ADDRESS_SHARED);
        else if (__ulock_wake)
            r = __ulock_wake(UL_COMPARE_AND_WAIT_SHARED, (void *)addr, 0);
        else
            return (errno = ENOTSUP), KZ_FAIL;
    }

    if (r >= 0 || errno == ENOENT) return KZ_OK;
    if (errno == EINTR) goto redo;
    return KZ_FAIL;

#elif defined(__linux__)
    long r = syscall(
            SYS_futex, (void *)addr, FUTEX_WAKE, (wakeAll ? INT_MAX : 1), NULL,
            NULL, 0);
    if (r >= 0) return KZ_OK;
    if (errno == ENOSYS) errno = ENOTSUP;
    return KZ_FAIL;

#else
    (void)addr, (void)wakeAll;
    errno = ENOTSUP;
    return KZ_FAIL;
#endif
}

static int kzQ_waitpush(kz_Queue *Q, uint32_t writing, int millis) {
    int r = kz_futex_wait(&Q->info->writing, writing, millis);
    return (r != KZ_OK && r != KZ_TIMEOUT) ? r : KZ_AGAIN;
}

static int kzQ_waitpop(kz_Queue *Q, uint32_t reading, int millis) {
    int r = kz_futex_wait(&Q->info->reading, reading, millis);
    return (r != KZ_OK && r != KZ_TIMEOUT) ? r : KZ_AGAIN;
}

static int kzS_waitmux(kz_State *S, const kz_Mux *m, int millis) {
    int r;
    if (m->mode == KZ_WRITE)
        r = kz_futex_wait(&S->write.info->writing, m->need, millis);
    else {
        uint32_t reading = m->mode == KZ_BOTH ? KZ_WAITBOTH : KZ_WAITREAD;
        r = kz_futex_wait(&S->read.info->reading, reading, millis);
    }
    return (r != KZ_OK && r != KZ_TIMEOUT) ? r : 0;
}

static int kzQ_wakepush(kz_Queue *Q, uint32_t new_used) {
    uint32_t *writing = &Q->info->writing;
    uint32_t  need = kzA_loadR(writing);

    int r1 = KZ_OK, r2 = KZ_OK;
    if (need > 0 && need <= Q->size - new_used) {
        uint32_t *reading = &Q->S->write.info->reading;
        if (kzA_cmpandswapR(reading, KZ_WAITBOTH, KZ_NOWAIT))
            r1 = kz_futex_wake(reading, 0);
        if (kzA_cmpandswapR(writing, need, KZ_NOWAIT))
            r2 = kz_futex_wake(writing, 0);
    }
    return r1 == KZ_OK ? r2 : r1;
}

static int kzQ_wakepop(kz_Queue *Q) {
    uint32_t *reading = &Q->info->reading;
    uint32_t  state = kzA_loadR(reading);
    if (state == KZ_WAITBOTH || state == KZ_WAITREAD) {
        if (kzA_cmpandswapR(reading, state, KZ_NOWAIT))
            return kz_futex_wake(reading, 0);
    }
    return KZ_OK;
}

/* creation/cleanup operations */

KZ_API const char *kz_failerror(void) { return strerror(errno); }
KZ_API void        kz_freefailerror(const char *s) { (void)s; }

/* clang-format off */
static int kz_pidexists(int pid)
{ int r = kill(pid, 0); return r == 0 || (r == -1 && errno == EPERM); }

KZ_API int kz_unlink(const char *name)
{ return shm_unlink(name) == 0 || errno == ENOENT ? KZ_OK : KZ_FAIL; }
/* clang-format on */

static int kzS_initfail(kz_State *S) {
    int err = errno;
    if (S->hdr != NULL) munmap(S->hdr, S->shm_size);
    close(S->shm_fd);
    free(S);
    errno = err;
    return KZ_FAIL;
}

static int kzS_mapshm(kz_State *S) {
    struct stat statbuf;
    if (fstat(S->shm_fd, &statbuf) == -1) return KZ_FAIL;
    if (statbuf.st_size == 0) return (errno = ENOENT), KZ_FAIL;

    S->shm_size = statbuf.st_size;
    S->hdr = (kz_ShmHdr *)mmap(
            NULL, S->shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, S->shm_fd,
            0);
    return S->hdr == MAP_FAILED ? KZ_FAIL : KZ_OK;
}

static int kzS_createshm(kz_State *S, int flags) {
    struct stat statbuf;

    int oflags = O_CREAT | O_RDWR;
    int created = 0;
    if (!kzS_checksize(S)) return errno = EINVAL, KZ_FAIL;

    /* create a new shared memory object */
    if ((flags & KZ_EXCL)) oflags |= O_EXCL;
    S->shm_fd = shm_open(S->name_buf, oflags, flags & 0x1FF);
    if (S->shm_fd == -1) return KZ_FAIL;

    /* check if the file already exists */
    if (fstat(S->shm_fd, &statbuf) == -1) return KZ_FAIL;
    if ((flags & KZ_EXCL) && statbuf.st_size != 0)
        return errno = EEXIST, KZ_FAIL;
    created = (statbuf.st_size == 0);

    /* set the size of the shared memory object */
    if (created && ftruncate(S->shm_fd, S->shm_size) == -1) return KZ_FAIL;
    if ((flags & KZ_RESET)) created = 1;

    if (kzS_mapshm(S) != KZ_OK) return KZ_FAIL;
    if (created) {
        memset(S->hdr, 0, sizeof(kz_ShmHdr));
        S->hdr->size = S->shm_size;
    }

    if (!kzS_checkpid(S, &S->hdr->owner_pid)) return errno = EACCES, KZ_FAIL;
    return kzS_initqueues(S, 1, created);
}

static int kzS_openshm(kz_State *S) {
    S->shm_fd = shm_open(S->name_buf, O_RDWR, 0666);
    if (S->shm_fd == -1) return KZ_FAIL;
    if (kzS_mapshm(S) != KZ_OK) return KZ_FAIL;
    if (S->shm_size != S->hdr->size) return errno = EBADF, KZ_FAIL;
    if (!kzS_checkpid(S, &S->hdr->user_pid)) return errno = EACCES, KZ_FAIL;
    return kzS_initqueues(S, 0, 0);
}

KZ_API int kz_exists(const char *name, int *powner, int *puser) {
    kz_State S;
    S.shm_fd = shm_open(name, O_RDWR, 0);
    S.hdr = NULL;
    if (S.shm_fd < 0) return errno == ENOENT ? 0 : KZ_FAIL;
    if (kzS_mapshm(&S) != KZ_OK) return close(S.shm_fd), KZ_FAIL;
    if (powner) *powner = S.hdr->owner_pid;
    if (puser) *puser = S.hdr->user_pid;
    return close(S.shm_fd), 1;
}

KZ_API int kz_shutdown(kz_State *S, int mode) {
    uint32_t *reading, state;
    int       r1 = KZ_OK, r2 = KZ_OK;
    if (!S || mode == 0) return KZ_OK;
    if ((mode & KZ_READ)) {
        uint32_t *writing = &S->read.info->writing;
        uint32_t  need = kzA_loadR(writing);
        kzA_fetchadd(&S->read.info->used, KZ_CLOSE_MASK);
        if (kzA_cmpandswapR(writing, need, KZ_NOWAIT))
            r1 = kz_futex_wake(writing, 1);
    }
    reading = &S->write.info->reading;
    state = kzA_loadR(reading);
    kzA_fetchadd(&S->write.info->used, KZ_CLOSE_MASK);
    if (kzA_cmpandswapR(reading, state, KZ_NOWAIT))
        r2 = kz_futex_wake(reading, 1);
    return r1 == KZ_OK ? r2 : r1;
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

#define kzA_loadR kzA_load

/* clang-format off */
static uint32_t kzA_load(uint32_t *ptr)
{ return _InterlockedCompareExchange((volatile LONG *)ptr, 0, 0); }

static void kzA_storeR(uint32_t *ptr, uint32_t val)
{ _InterlockedExchange((volatile LONG *)ptr, val); }

static uint32_t kzA_fetchadd(uint32_t *ptr, uint32_t delta)
{ return _InterlockedExchangeAdd((volatile LONG *)ptr, delta); }

static uint32_t kzA_subfetch(uint32_t *ptr, uint32_t delta)
{ return _InterlockedExchangeAdd((volatile LONG *)ptr, ~delta + 1) - delta; }

static int kzA_cmpandswapR(uint32_t *state, uint32_t expected, uint32_t desired) {
    return _InterlockedCompareExchange((volatile LONG *)state,
            desired, expected) == (LONG)expected;
}
/* clang-format on */

/* waiting operations */

static int kzQ_waitpush(kz_Queue *Q, uint32_t used, int millis) {
    DWORD dwRet = WaitForSingleObject(Q->hCanPushEvent, millis);
    if (dwRet != WAIT_OBJECT_0 && dwRet != WAIT_TIMEOUT) return KZ_FAIL;
    return (void)used, KZ_AGAIN;
}

static int kzQ_waitpop(kz_Queue *Q, uint32_t used, int millis) {
    DWORD dwRet = WaitForSingleObject(Q->hCanPopEvent, millis);
    if (dwRet != WAIT_OBJECT_0 && dwRet != WAIT_TIMEOUT) return KZ_FAIL;
    return (void)used, KZ_AGAIN;
}

static int kzS_waitmux(kz_State *S, const kz_Mux *m, int millis) {
    HANDLE aHandles[2] = {0};
    DWORD  dwRet;
    int    i = 0;
    if ((m->mode & KZ_WRITE)) aHandles[i++] = S->write.hCanPushEvent;
    if ((m->mode & KZ_READ)) aHandles[i++] = S->read.hCanPopEvent;
    dwRet = WaitForMultipleObjects(
            i,        /* object count */
            aHandles, /* handles */
            FALSE,    /* wait all */
            millis);  /* wait timeout */
    return dwRet == WAIT_FAILED ? KZ_FAIL : 0;
}

static int kzQ_wakepush(kz_Queue *Q, uint32_t new_used) {
    uint32_t need = kzA_loadR(&Q->info->writing);
    int      ok = need > 0 && need < Q->size - new_used;
    if (ok && kzA_cmpandswapR(&Q->info->can_push, 0, 1))
        SetEvent(Q->hCanPushEvent);
    if (kzA_cmpandswapR(&Q->info->can_pop, 1, 0)) ResetEvent(Q->hCanPopEvent);
    return KZ_OK;
}

static int kzQ_wakepop(kz_Queue *Q) {
    uint32_t reading = kzA_loadR(&Q->info->reading);
    if (reading > 0 && kzA_cmpandswapR(&Q->info->can_pop, 0, 1))
        SetEvent(Q->hCanPopEvent);
    if (kzA_cmpandswapR(&Q->info->can_push, 1, 0)) ResetEvent(Q->hCanPushEvent);
    return KZ_OK;
}

/* creation/cleanup operations */

KZ_API int  kz_unlink(const char *name) { return (void)name, KZ_OK; }
KZ_API void kz_freefailerror(const char *s) { LocalFree((HLOCAL)s); }

static void kz_cleanup(kz_State *S) {
    if (S->hdr != NULL) UnmapViewOfFile(S->hdr);
    if (S->shm_fd != NULL) CloseHandle(S->shm_fd);
    if (S->write.hCanPushEvent != NULL) CloseHandle(S->write.hCanPushEvent);
    if (S->write.hCanPopEvent != NULL) CloseHandle(S->write.hCanPopEvent);
    if (S->read.hCanPushEvent != NULL) CloseHandle(S->read.hCanPushEvent);
    if (S->read.hCanPopEvent != NULL) CloseHandle(S->read.hCanPopEvent);
}

static int kzS_initfail(kz_State *S) {
    DWORD dwError = GetLastError();
    kz_cleanup(S);
    free(S);
    SetLastError(dwError);
    return KZ_FAIL;
}

static int kz_pidexists(int pid) {
    DWORD  exitCode;
    int    isRunning = 0;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pid);
    if (hProcess == NULL) return 0;
    if (GetExitCodeProcess(hProcess, &exitCode))
        isRunning = (exitCode == STILL_ACTIVE);
    CloseHandle(hProcess);
    return isRunning;
}

static HANDLE kz_openevent(const char *name, const char *suffix, int cr) {
    char buf[MAX_PATH];
    StringCbPrintfA(buf, MAX_PATH, "%s-%s", name, suffix);
    if (cr)
        return CreateEventA(
                NULL,  /* default security */
                TRUE,  /* manual reset */
                FALSE, /* initial state */
                buf);  /* name of event object */
    return OpenEventA(
            SYNCHRONIZE | EVENT_MODIFY_STATE, /* Desired access */
            FALSE,                            /* Inherit handle */
            buf);                             /* name of event object */
}

static int kzS_initevents(kz_State *S, kz_Queue *q0, kz_Queue *q1, int cr) {
    int flags = cr ? KZ_CREATE : 0;
    q0->hCanPushEvent = kz_openevent(S->name_buf, "-0-can-push", flags);
    if (q0->hCanPushEvent == NULL) return 0;
    q0->hCanPopEvent = kz_openevent(S->name_buf, "-0-can-pop", flags);
    if (q0->hCanPopEvent == NULL) return 0;
    q1->hCanPushEvent = kz_openevent(S->name_buf, "-1-can-push", flags);
    if (q1->hCanPushEvent == NULL) return 0;
    q1->hCanPopEvent = kz_openevent(S->name_buf, "-1-can-pop", flags);
    if (q1->hCanPopEvent == NULL) return 0;
    if (cr) {
        kzA_storeR(&q0->info->can_push, 0), ResetEvent(q0->hCanPushEvent);
        kzA_storeR(&q0->info->can_pop, 0), ResetEvent(q0->hCanPopEvent);
        kzA_storeR(&q1->info->can_push, 0), ResetEvent(q1->hCanPushEvent);
        kzA_storeR(&q1->info->can_pop, 0), ResetEvent(q1->hCanPopEvent);
    }
    return 1;
}

static int kzS_createshm(kz_State *S, int flags) {
    int created = 0;
    if (!kzS_checksize(S))
        return SetLastError(ERROR_INVALID_PARAMETER), KZ_FAIL;

    /* create a new shared memory object */
    S->shm_fd = CreateFileMappingA(
            INVALID_HANDLE_VALUE, /* use paging file */
            NULL,                 /* default security */
            PAGE_READWRITE,       /* read/write access */
            0,                    /* maximum object size (high-order DWORD) */
            (DWORD)S->shm_size,   /* maximum object size (low-order DWORD) */
            S->name_buf);         /* name of mapping object */
    if ((flags & KZ_EXCL) && GetLastError() == ERROR_ALREADY_EXISTS)
        return KZ_FAIL;
    if (S->shm_fd == NULL) return KZ_FAIL;

    /* init the shared memory object */
    S->hdr = (kz_ShmHdr *)MapViewOfFile(
            S->shm_fd,            /* handle to map object */
            FILE_MAP_ALL_ACCESS,  /* read/write permission */
            0,                    /* file offset (high-order DWORD) */
            0,                    /* file offset (low-order DWORD) */
            (SIZE_T)S->shm_size); /* mapping size */
    if (S->hdr == NULL) return KZ_FAIL;
    created = (flags & KZ_RESET) || S->hdr->size != S->shm_size;
    if (created) {
        memset(S->hdr, 0, sizeof(kz_ShmHdr));
        S->hdr->size = (uint32_t)S->shm_size;
    }

    if (!kzS_checkpid(S, &S->hdr->owner_pid))
        return SetLastError(ERROR_ACCESS_DENIED), KZ_FAIL;
    if (kzS_initqueues(S, 1, created) != KZ_OK) return KZ_FAIL;
    if (!kzS_initevents(S, &S->write, &S->read, created)) return KZ_FAIL;
    return KZ_OK;
}

static int kzS_openshm(kz_State *S) {
    S->shm_fd = OpenFileMappingA(
            FILE_MAP_ALL_ACCESS, /* read/write access */
            FALSE,               /* do not inherit the name */
            S->name_buf);        /* name of mapping object */
    if (S->shm_fd == NULL) return KZ_FAIL;

    /* init the shared memory object */
    S->hdr = (kz_ShmHdr *)MapViewOfFile(
            S->shm_fd,           /* handle to map object */
            FILE_MAP_ALL_ACCESS, /* read/write permission */
            0,                   /* file offset (high-order DWORD) */
            0,                   /* file offset (low-order DWORD) */
            0);                  /* mapping size */
    if (S->hdr == NULL) return KZ_FAIL;

    /* retrieve the size of shm */
    S->shm_size = S->hdr->size;

    if (!kzS_checkpid(S, &S->hdr->user_pid))
        return SetLastError(ERROR_ACCESS_DENIED), KZ_FAIL;
    if (kzS_initqueues(S, 0, 0) != KZ_OK) return KZ_FAIL;
    if (!kzS_initevents(S, &S->read, &S->write, 0)) return KZ_FAIL;
    return KZ_OK;
}

KZ_API const char *kz_failerror(void) {
    DWORD i, dwErrCode = GetLastError();
    DWORD dwFormatFlags = FORMAT_MESSAGE_ALLOCATE_BUFFER
                        | FORMAT_MESSAGE_FROM_SYSTEM
                        | FORMAT_MESSAGE_IGNORE_INSERTS;
    LPSTR lpBuf = NULL; /* Let FormatMessage allocate the lpBuf for us */
    DWORD dwBufSize = FormatMessageA(
            dwFormatFlags, NULL, /* No message source needed */
            dwErrCode,           /* The error code */
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), /* Default language */
            (LPSTR)&lpBuf, /* Output lpBuf pointer address */
            0,             /* Minimum allocation size, 0 means necessary size */
            NULL);         /* No arguments array needed */
    if (dwBufSize == 0) {  /* If FormatMessage failed */
        /* Try to allocate memory for a default message */
        lpBuf = (LPSTR)LocalAlloc(LMEM_ZEROINIT, 64);
        if (lpBuf)
            StringCbPrintfA(lpBuf, 64, "Unknown error (0x%lx)", dwErrCode);
    }
    /* Remove trailing CRLF (FormatMessage typically adds newlines) */
    if (dwBufSize >= 2)
        for (i = dwBufSize - 2; i > 0 && (lpBuf[i] == '\r' || lpBuf[i] == '\n');
             i--)
            lpBuf[i] = '\0';
    return lpBuf;
}

KZ_API int kz_exists(const char *name, int *powner, int *puser) {
    HANDLE shm_fd = OpenFileMappingA(
            FILE_MAP_ALL_ACCESS, /* read/write access */
            FALSE,               /* do not inherit the name */
            name);               /* name of mapping object */
    if (shm_fd == NULL)
        return GetLastError() == ERROR_FILE_NOT_FOUND ? 0 : KZ_FAIL;
    if (powner || puser) { /* init the shared memory object */
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
    if (S && (mode & KZ_READ)) {
        kzA_fetchadd(&S->read.info->used, KZ_CLOSE_MASK);
        SetEvent(S->read.hCanPushEvent);
    }
    if (S && (mode & KZ_WRITE)) {
        kzA_fetchadd(&S->write.info->used, KZ_CLOSE_MASK);
        SetEvent(S->write.hCanPopEvent);
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

/* Context operations */

#define kzQ_isread(Q) ((Q) == &(Q)->S->read)

KZ_API char *kz_buffer(kz_Context *ctx, size_t *plen) {
    kz_Queue *Q = kzC_state(ctx);
    if (Q == NULL || ctx->result != KZ_OK) return NULL;
    if (plen) *plen = ctx->len - sizeof(uint32_t);
    return Q->data + ctx->pos + sizeof(uint32_t);
}

KZ_API int kz_isread(const kz_Context *ctx) {
    const kz_Queue *Q = kzC_state((kz_Context *)ctx);
    if (Q == NULL) return KZ_INVALID;
    return kzQ_isread(Q);
}

KZ_API void kz_cancel(kz_Context *ctx) {
    kz_Queue *Q = kzC_state(ctx);
    if (Q == NULL) return;
    ctx->result = KZ_CLOSED;
    kzA_storeR(kz_isread(ctx) ? &Q->info->reading : &Q->info->writing, 0);
}

static int kzC_push(kz_Context *ctx, uint32_t used) {
    kz_Queue *Q = (kz_Queue *)ctx->state;

    /* check if there is enough space */
    uint32_t remain = Q->size - Q->info->tail;
    uint32_t free_size = Q->size - used;
    if (free_size < ctx->len) return KZ_AGAIN;

    /* write the offset and the size */
    assert(Q->info->tail < Q->size);
    if (ctx->len > remain) {
        kz_write_u32le(Q->data + Q->info->tail, KZ_REWIND_MARK);
        ctx->pos = 0;
        ctx->len = free_size - remain;
    } else {
        ctx->pos = Q->info->tail;
        ctx->len = remain;
    }
    return KZ_OK;
}

static int kzC_pop(kz_Context *ctx, uint32_t used) {
    kz_Queue *Q = (kz_Queue *)ctx->state;

    /* check if there is enough data */
    if (used == 0) return KZ_AGAIN;
    assert(used >= sizeof(uint32_t));

    /* read the size of the data */
    assert(Q->info->head < Q->size);
    ctx->pos = Q->info->head;
    ctx->len = kz_read_u32le(Q->data + ctx->pos);
    if (ctx->len == KZ_REWIND_MARK) {
        ctx->pos = 0;
        ctx->len = kz_read_u32le(Q->data + ctx->pos);
    }
    ctx->len += sizeof(uint32_t);
    return KZ_OK;
}

static int kzQ_checkclosed(kz_Queue *Q, uint32_t used) {
    if ((used & KZ_CLOSE_MASK)) {
        uint32_t *state;
        state = kzQ_isread(Q) ? &Q->info->reading : &Q->info->writing;
        return kzA_storeR(state, 0), 1;
    }
    return 0;
}

static int kzC_waitcontext(kz_Context *ctx, int rd, int millis) {
    kz_Queue *Q = (kz_Queue *)ctx->state;
    uint32_t *state = rd ? &Q->info->reading : &Q->info->writing;
    uint32_t  used, waiting = (uint32_t)ctx->len;
    int (*check)(kz_Context *, uint32_t) = rd ? kzC_pop : kzC_push;
    int (*wait)(kz_Queue *, uint32_t, int) = rd ? kzQ_waitpop : kzQ_waitpush;
    int r = KZ_AGAIN;

    if (kzA_loadR(state) != KZ_NOWAIT) return KZ_INVALID;
    while (r == KZ_AGAIN) {
        kzA_storeR(state, waiting);
        used = kzA_load(&Q->info->used);
        if (kzQ_checkclosed(Q, used)) return KZ_CLOSED;
        if ((r = check(ctx, used)) == KZ_AGAIN) r = wait(Q, waiting, millis);
        if (millis > 0 && r == KZ_AGAIN) r = KZ_TIMEOUT;
    }
    kzA_storeR(state, KZ_NOWAIT);
    return r == KZ_OK ? (ctx->result = r) : r;
}

KZ_API int kz_waitcontext(kz_Context *ctx, int millis) {
    kz_Queue *Q = kzC_state(ctx);
    if (Q == NULL) return KZ_INVALID;
    if (ctx->result != KZ_AGAIN) return ctx->result;
    if (millis == 0) {
        uint32_t used = kzA_load(&Q->info->used);
        if (kzQ_checkclosed(Q, used)) return KZ_CLOSED;
        return (kzQ_isread(Q) ? kzC_pop : kzC_push)(ctx, used);
    }
    return kzC_waitcontext(ctx, kzQ_isread(Q), millis);
}

static int kzC_commitpush(kz_Context *ctx, size_t len) {
    kz_Queue *Q = (kz_Queue *)ctx->state;
    uint32_t  size;

    size = (uint32_t)kz_get_aligned_size(len + sizeof(uint32_t), KZ_ALIGN);
    if (size > ctx->len) return KZ_INVALID;
    kz_write_u32le(Q->data + ctx->pos, (uint32_t)len);
    Q->info->tail = (uint32_t)((ctx->pos + size) % Q->size);
    assert(kz_is_aligned_to(Q->info->tail, KZ_ALIGN));

    kzA_fetchadd(&Q->info->used, (uint32_t)size);
    kzA_storeR(&Q->info->writing, 0);
    return ctx->notify ? kzQ_wakepop(Q) : KZ_OK;
}

static int kzC_commitpop(kz_Context *ctx) {
    kz_Queue *Q = (kz_Queue *)ctx->state;
    uint32_t  size, new_used;

    size = (uint32_t)kz_get_aligned_size(ctx->len, KZ_ALIGN);
    Q->info->head = (uint32_t)((ctx->pos + size) % Q->size);
    assert(kz_is_aligned_to(Q->info->head, KZ_ALIGN));

    new_used = kzA_subfetch(&Q->info->used, (uint32_t)size);
    kzA_storeR(&Q->info->reading, 0);
    return ctx->notify ? kzQ_wakepush(Q, new_used) : KZ_OK;
}

KZ_API int kz_commit(kz_Context *ctx, size_t len) {
    kz_Queue *Q = kzC_state(ctx);
    if (Q == NULL || ctx->result != KZ_OK) return KZ_INVALID;
    if (kzQ_checkclosed(Q, kzA_load(&Q->info->used))) return KZ_CLOSED;
    ctx->result = KZ_CLOSED;
    return kz_isread(ctx) ? kzC_commitpop(ctx) : kzC_commitpush(ctx, len);
}

/* API */

KZ_API const char *kz_name(const kz_State *S) { return S ? S->name_buf : NULL; }
KZ_API int         kz_pid(const kz_State *S) { return S ? S->self_pid : 0; }
KZ_API size_t      kz_size(const kz_State *S) { return S ? S->write.size : 0; }

KZ_API size_t kz_aligned(size_t bufsize, size_t pagesize) {
    size_t required_size;
    if (!kz_is_aligned_to(pagesize, KZ_ALIGN)) return 0;
    required_size = kz_get_aligned_size(
            sizeof(kz_ShmHdr) + bufsize * 2, pagesize);
    assert(kz_is_aligned_to(required_size, KZ_ALIGN));
    return required_size - sizeof(kz_ShmHdr);
}

KZ_API int kz_isowner(const kz_State *S) {
    if (S == NULL || S->hdr == NULL) return KZ_INVALID;
    if (S->hdr->owner_pid == S->hdr->user_pid)
        return S->write.info == S->hdr->queues;
    return (uint32_t)S->self_pid == S->hdr->owner_pid;
}

KZ_API int kz_isclosed(const kz_State *S) {
    uint32_t wused, rused;
    if (S == NULL || S->hdr == NULL) return KZ_BOTH;
    wused = kzA_load(&S->write.info->used);
    rused = kzA_load(&S->read.info->used);
    return (!!(wused & KZ_CLOSE_MASK) << 1) | !!(rused & KZ_CLOSE_MASK);
}

KZ_API int kz_read(kz_State *S, kz_Context *ctx) {
    uint32_t used;
    if (S == NULL || S->hdr == NULL) return KZ_CLOSED;

    used = kzA_load(&S->read.info->used);
    if ((used & KZ_CLOSE_MASK)) return KZ_CLOSED;

    ctx->state = &S->read;
    ctx->pos = 0, ctx->len = KZ_WAITREAD;
    ctx->notify = 1;
    if (!kzA_cmpandswapR(&S->read.info->reading, 0, KZ_NOWAIT))
        return ctx->result = KZ_BUSY;
    ctx->result = kzC_pop(ctx, used);
    if (ctx->result == KZ_AGAIN) assert(ctx->len == KZ_WAITREAD);
    assert(ctx->result == KZ_OK || ctx->result == KZ_AGAIN);
    return ctx->result;
}

KZ_API int kz_write(kz_State *S, kz_Context *ctx, size_t len) {
    uint32_t used, need;
    if (S == NULL || S->hdr == NULL) return KZ_CLOSED;

    used = kzA_load(&S->write.info->used);
    need = kzQ_calcneed(&S->write, len);
    if (need > S->write.size) return KZ_TOOBIG;
    if (used & KZ_CLOSE_MASK) return KZ_CLOSED;

    ctx->state = &S->write;
    ctx->pos = 0, ctx->len = need;
    ctx->notify = 1;
    if (kzA_cmpandswapR(&S->write.info->writing, 0, KZ_NOWAIT)) {
        ctx->result = kzC_push(ctx, used);
        assert(ctx->result == KZ_OK || ctx->result == KZ_AGAIN);
        return ctx->result;
    }
    return ctx->result = KZ_BUSY;
}

static int kzS_checkmux(kz_State *S, kz_Mux *m) {
    int can_write, can_read;
    m->wused = kzA_load(&S->write.info->used);
    m->rused = kzA_load(&S->read.info->used);
    if (m->wused & KZ_CLOSE_MASK || m->rused & KZ_CLOSE_MASK) return KZ_CLOSED;
    can_write = (S->write.size - m->wused >= m->need);
    can_read = (m->rused != 0);
    return (can_write << 1) | can_read;
}

static int kzS_calcmode(kz_State *S, uint32_t need, int *pw, int *pr) {
    uint32_t *writing = &S->write.info->writing;
    uint32_t *reading = &S->read.info->reading;
    if (!*pw) *pw = kzA_cmpandswapR(writing, 0, KZ_NOWAIT);
    if (*pw) kzA_storeR(writing, need);
    if (!*pr) *pr = kzA_cmpandswapR(reading, 0, KZ_NOWAIT);
    if (*pr) kzA_storeR(reading, *pw ? KZ_WAITBOTH : KZ_WAITREAD);
    return (*pw != 0) << 1 | (*pr != 0);
}

KZ_API int kz_wait(kz_State *S, size_t len, int millis) {
    int    r = 0, can_read = 0, can_write = 0;
    kz_Mux m;

    m.need = kzQ_calcneed(&S->write, len);
    if (m.need > S->write.size) return KZ_TOOBIG;
    if ((r = kzS_checkmux(S, &m)) != 0 || millis == 0) return r;

    while (r == 0) {
        m.mode = kzS_calcmode(S, m.need, &can_write, &can_read);
        if (m.mode == 0) return KZ_BUSY;
        if ((r = kzS_checkmux(S, &m)) == 0) r = kzS_waitmux(S, &m, millis);
        if (millis > 0 && r == 0) r = KZ_TIMEOUT;
    }
    if (can_write) kzA_storeR(&S->write.info->writing, 0);
    if (can_read) kzA_storeR(&S->read.info->reading, 0);
    return r;
}

static kz_State *kzS_new(const char *name) {
    size_t    name_len = strlen(name);
    kz_State *S = (kz_State *)malloc(sizeof(kz_State) + name_len);
    if (S == NULL) return NULL;
    memset(S, 0, sizeof(kz_State));
    memcpy(S->name_buf, name, name_len + 1);
    S->name_len = name_len;
#ifdef _WIN32
    S->self_pid = GetCurrentProcessId();
#else
    S->self_pid = getpid();
#endif
    return S;
}

static void kzS_setowner(kz_State *S, int isowner) {
    int write = 0, read = 1;
    if (isowner)
        S->hdr->owner_pid = S->self_pid;
    else {
        S->hdr->user_pid = S->self_pid;
        write = 1, read = 0;
    }
    S->write.S = S;
    S->write.info = &S->hdr->queues[write];
    S->write.data = (char *)(S->hdr + 1) + S->hdr->queue_size * write;
    S->write.size = S->hdr->queue_size;
    S->read.S = S;
    S->read.info = &S->hdr->queues[read];
    S->read.data = (char *)(S->hdr + 1) + S->hdr->queue_size * read;
    S->read.size = S->hdr->queue_size;
}

static void kzS_resetqueues(kz_State *S, int isowner) {
    uint32_t rused, wused;
    kzS_setowner(S, isowner);
    kzA_storeR(&S->read.info->reading, 0);
    kzA_storeR(&S->write.info->writing, 0);
    if ((rused = kzA_load(&S->read.info->used)) & KZ_CLOSE_MASK)
        kzA_cmpandswapR(&S->read.info->used, rused, rused & ~KZ_CLOSE_MASK);
    if ((wused = kzA_load(&S->write.info->used)) & KZ_CLOSE_MASK)
        kzA_cmpandswapR(&S->write.info->used, wused, wused & ~KZ_CLOSE_MASK);
}

static int kzS_initqueues(kz_State *S, int isowner, int created) {
    if (!created)
        kzS_resetqueues(S, isowner);
    else {
        size_t total_size = S->hdr->size - sizeof(kz_ShmHdr);
        size_t aligned_size = kz_get_aligned_size(total_size, KZ_ALIGN);
        if (aligned_size > total_size) aligned_size -= KZ_ALIGN;
        assert(aligned_size <= total_size && aligned_size / 2 < KZ_MAX_SIZE);
        S->hdr->queue_size = (uint32_t)(aligned_size / 2);
        kzS_setowner(S, isowner);
    }
    return KZ_OK;
}

KZ_API kz_State *kz_open(const char *name, int flags, size_t bufsize) {
    kz_State *S = kzS_new(name);
    int       r;
    if (S == NULL) return NULL;
    S->hdr = NULL;

    S->shm_size = kz_get_aligned_size(sizeof(kz_ShmHdr) + bufsize, KZ_ALIGN);
    r = flags & KZ_CREATE ? kzS_createshm(S, flags) : kzS_openshm(S);
    if (r != KZ_OK) return kzS_initfail(S), NULL;
    return S;
}

KZ_NS_END

#endif /* KZ_IMPLEMENTATION */

/* cc: cc='gcc' flags+='-Wall -Wextra -pedantic -std=c99 -O3' input='kaze.c'
 * maccc: flags+='-undefined dynamic_lookup' output='kaze.so'
 * unixcc: flags+='-shared' output='kaze.so'
 * win32cc: flags+='-mdll' output='kaze.dll'
 */
