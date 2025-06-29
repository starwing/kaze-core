#ifdef __linux__
#define _GNU_SOURCE
#include <sched.h>
#endif

#if defined(_MSC_VER)
#include <intrin.h> // For _mm_pause, YieldProcessor
#endif

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

static uint64_t get_time(void);

#define KZ_STATIC_API
#include "kaze.h"

#define BUF_SIZE 16384
static char data[100];

#define MAX_BACKOFF 1000

static void bind_cpu(int cpu_id) {
#ifdef __linux__
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(cpu_id, &mask);
    if (sched_setaffinity(0, sizeof(mask), &mask) < 0)
        perror("sched_getaffinity");
#elif defined(_WIN32)
    SetThreadIdealProcessor(GetCurrentThread(), (DWORD)cpu_id);
#endif
    (void)cpu_id;
}

inline void cpu_relax() {
#if defined(_MSC_VER)
    YieldProcessor();
#elif defined(__GNUC__) || defined(__clang__)
    // GCC or Clang
    #if defined(__x86_64__) || defined(__i386__)
        __asm__ __volatile__("pause");
    #elif defined(__aarch64__) || defined(__arm__)
        __asm__ __volatile__("yield");
    #else
    #endif
#else
#endif
}

static uint64_t get_time(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts) < 0)
        return 0;
    return (uint64_t)ts.tv_sec*1000000000+ts.tv_nsec;
}

typedef struct kz_Balancer {
    int cur, lower, upper;
    int i, wc;
} kz_Balancer;

static void kz_initbalancer(kz_Balancer *b) { memset(b, 0, sizeof(*b)); }
static void kz_markwait(kz_Balancer *b) { b->wc++; }

static void kz_balance(kz_Balancer *b) {
    int i;
    for (i = 0; i < b->cur; i++) cpu_relax();
    b->i++;
}

static void kz_stepbalancer(kz_Balancer *b) {
    int lower = b->i*10/1000;
    int upper = b->i*30/1000;
    if (b->i < 10000) return;
    if (b->wc > upper) {
        if (b->cur == b->upper) {
            b->cur = b->cur ? b->cur << 1 : 1;
            b->upper = b->cur;
        } else {
            b->lower = b->cur;
            b->cur = b->lower + ((b->upper - b->lower + 1) >> 1);
        }
    } else if (b->wc < lower) {
        if (b->cur == b->lower) {
            b->cur = b->cur >> 1;
            b->lower = b->cur;
        } else {
            b->upper = b->cur;
            b->cur = b->lower + ((b->upper - b->lower) >> 1);
        }
    }
    b->i = 0, b->wc = 0;
}

static int flood_server(const char *shm) {
    kz_State *S = kz_open(shm, KZ_CREATE|KZ_RESET|0666, BUF_SIZE);
    kz_Balancer b;
    uint64_t before = 0, after, i = 0, wc = 0, wt = 0;
    int r;
    if (S == NULL) perror("kz_open");
    bind_cpu(0);
    kz_initbalancer(&b);
    printf("start flood server ...\n");
    for (i = 0; !kz_isclosed(S); ++i) {
        kz_Context ctx;
        size_t len = 0;
        char *s;
        r = kz_read(S, &ctx);
        if (r == KZ_AGAIN) {
            uint64_t wb, wa;
            wb = get_time();
            if (r == KZ_AGAIN) r = kz_waitcontext(&ctx, -1);
            if (r == KZ_CLOSED) break;
            wa = get_time();
            wc++, wt += (wa - wb);
            kz_markwait(&b);
        }
        if (r == KZ_CLOSED) break;
        if (r != KZ_OK) return perror("kz_read"), 1;
        if (before == 0) before = get_time();
        s = kz_buffer(&ctx, &len);
        if (len != sizeof(data)) return printf("len error\n"), 1;
        r = memcmp(s, data, sizeof(data));
        if (r != 0) return printf("data error\n"), 1;
        r = kz_commit(&ctx, 0);
        if (r == KZ_CLOSED) break;
        if (r != KZ_OK) return perror("kz_commit"), 1;

        kz_balance(&b);
        if (i > 0 && (i % 5000000) == 0) {
            after = get_time();
            printf("wait count=%lld %.3f%% time=%.3f s balance=%d\n",
                    (long long)wc, wc*100.0/i, wt/1.0e9, b.cur);
            printf("Elapsed time: %.3f s/%lld op, %.2f op/s, %lld ns/op\n",
                    (double)(after - before) / 1.0e9, (long long)i,
                    i * 1e9 / (after - before),
                    (long long)((after - before) / i));
            kz_stepbalancer(&b);
        }
    }
    kz_close(S);
    printf("stop flood server ...\n");
    return 0;
}

static int flood_client(const char *shm, uint64_t N) {
    kz_State *S = kz_open(shm, 0, 0);
    kz_Balancer b;
    uint64_t i, wc = 0;
    uint64_t before, after, wt = 0;
    if (S == NULL) return perror("kz_open"), 1;
    bind_cpu(1);

    kz_initbalancer(&b);
    printf("start flood ...\n");
    before = get_time();
    for (i = 0; i < N; ++i) {
        kz_Context ctx;
        int r = kz_write(S, &ctx, sizeof(data));
        if (r == KZ_AGAIN) {
            uint64_t wb, wa;
            wb = get_time();
            r = kz_waitcontext(&ctx, -1), ++wc;
            wa = get_time();
            wt += (wa - wb);
            kz_markwait(&b);
        }
        if (r == KZ_CLOSED) break;
        if (r != KZ_OK) return perror("kz_write"), 1;
        memcpy(kz_buffer(&ctx, NULL), data, sizeof(data));
        /* notify per 75 commit */
        kz_setnotify(&ctx, i % 75 == 0);
        r = kz_commit(&ctx, sizeof(data));
        if (r == KZ_CLOSED) break;
        if (r != KZ_OK) return perror("kz_commit"), 1;

        kz_balance(&b);
        if (i > 0 && (i % 5000000) == 0) {
            after = get_time();
            printf("wait count=%lld %.3f%% time=%.3f s balance=%d\n",
                    (long long)wc, wc*100.0/i, wt/1.0e9, b.cur);
            printf("Elapsed time: %.3f s/%lld op, %.2f op/s, %lld ns/op\n",
                    (double)(after - before) / 1.0e9, (long long)i,
                    i * 1e9 / (after - before),
                    (long long)((after - before) / i));
            kz_stepbalancer(&b);
        }
    }
    after = get_time();
    printf("wait count=%lld %.3f%% time=%.3f s\n",
            (long long)wc, wc*100.0/N, wt/1.0e9);
    printf("Elapsed time: %.3f s/%lld op, %.2f op/s, %lld ns/op\n",
           (double)(after - before) / 1.0e9, (long long)N,
           N * 1e9 / (after - before),
           (long long)((after - before) / N));
    kz_close(S);
    return 0;
}

static int echo_server(const char *shm) {
    kz_State *S = kz_open(shm, KZ_CREATE|KZ_RESET|0666, BUF_SIZE);
    kz_Balancer b;
    uint64_t before = 0, after, i = 0, wc = 0, wt = 0;
    int r;
    if (S == NULL) perror("kz_open");
    bind_cpu(0);
    kz_initbalancer(&b);
    printf("start echo server ...\n");
    for (i = 0; !kz_isclosed(S); ++i) {
        kz_Context rctx, wctx;
        size_t len = 0, blen = 0;
        char *s, *d;
        r = kz_read(S, &rctx);
        if (r == KZ_AGAIN) {
            uint64_t wb, wa;
            wb = get_time();
            if (r == KZ_AGAIN) r = kz_waitcontext(&rctx, -1);
            if (r == KZ_CLOSED) break;
            wa = get_time();
            wc++, wt += (wa - wb);
            kz_markwait(&b);
        }
        if (r == KZ_CLOSED) break;
        if (r != KZ_OK) return perror("kz_read"), 1;
        if (before == 0) before = get_time();
        s = kz_buffer(&rctx, &len);
        r = kz_write(S, &wctx, len);
        if (r == KZ_AGAIN) {
            uint64_t wb, wa;
            wb = get_time();
            if (r == KZ_AGAIN) r = kz_waitcontext(&rctx, -1);
            if (r == KZ_CLOSED) break;
            wa = get_time();
            wc++, wt += (wa - wb);
            kz_markwait(&b);
        }
        if (r == KZ_CLOSED) break;
        if (r != KZ_OK) return perror("kz_write"), 1;
        d = kz_buffer(&wctx, &blen);
        if (blen < len) return printf("len error\n"), 1;
        memcpy(d, s, len);
        r = kz_commit(&wctx, len);
        if (r == KZ_CLOSED) break;
        if (r != KZ_OK) return perror("kz_commit write"), 1;
        r = kz_commit(&rctx, 0);
        if (r == KZ_CLOSED) break;
        if (r != KZ_OK) return perror("kz_commit read"), 1;

        kz_balance(&b);
        if (i > 0 && (i % 5000000) == 0) {
            after = get_time();
            printf("wait count=%lld %.3f%% time=%.3f s balance=%d\n",
                    (long long)wc, wc*100.0/i, wt/1.0e9, b.cur);
            printf("Elapsed time: %.3f s/%lld op, %.2f op/s, %lld ns/op\n",
                    (double)(after - before) / 1.0e9, (long long)i,
                    i * 1e9 / (after - before),
                    (long long)((after - before) / i));
            kz_stepbalancer(&b);
        }
    }
    kz_close(S);
    printf("stop flood server ...\n");
    return 0;
}

static int echo_client(const char *shm, uint64_t N) {
    kz_State *S = kz_open(shm, 0, 0);
    uint64_t before, after, i = 0, wt = 0, wc = 0;
    uint64_t rcnt = 0, wcnt = 0;
    if (S == NULL) return perror("kz_open"), 1;

    bind_cpu(1);
    printf("start echo ...\n");
    before = get_time();
    for (;;) {
        kz_Context ctx;
        int r = kz_wait(S, sizeof(data), 0);
        if (r == 0) {
            uint64_t wb = get_time(), wa;
            r = kz_wait(S, sizeof(data), -1);
            wa = get_time();
            wt += (wa - wb), wc++;
        }
        if (r == KZ_CLOSED) break;
        assert(r != 0);
        if ((r & KZ_READ) && rcnt < N) {
            size_t len = 0;
            r = kz_read(S, &ctx);
            if (r == KZ_CLOSED) break;
            if (r != KZ_OK) return perror("kz_read"), 1;
            r = memcmp(kz_buffer(&ctx, &len), data, sizeof(data));
            if (r != 0) return printf("data error\n"), 1;
            if (len != sizeof(data)) return printf("len error\n"), 1;
            r = kz_commit(&ctx, sizeof(data));
            if (r == KZ_CLOSED) break;
            if (r != KZ_OK) return perror("kz_commit read"), 1;
            rcnt++;
        }
        if ((r & KZ_WRITE) && wcnt < N) {
            r = kz_write(S, &ctx, sizeof(data));
            if (r == KZ_CLOSED) break;
            if (r != KZ_OK) return perror("kz_write"), 1;
            memcpy(kz_buffer(&ctx, NULL), data, sizeof(data));
            r = kz_commit(&ctx, sizeof(data));
            if (r == KZ_CLOSED) break;
            if (r != KZ_OK) return perror("kz_commit write"), 1;
            wcnt++;
        }
        if (rcnt > 0 && (rcnt % 5000000) == 0) {
            after = get_time();
            printf("wait count=%lld %.3f%% time=%.3f s\n",
                    (long long)wc, wc*100.0/i, wt/1.0e9);
            printf("Elapsed time: %.3f s\n"
                    "\tRead count=%lld op Write count=%lld op\n"
                    "\t%.2f op/s, %lld ns/op\n",
                    (double)(after - before) / 1.0e9,
                    (long long)rcnt, (long long)wcnt,
                    i * 1e9 / (after - before),
                    (long long)((after - before) / i));
        }
        i++;
    }
    after = get_time();
    printf("wait count=%lld %.3f%% time=%.3f s\n",
            (long long)wc, wc*100.0/N, wt/1.0e9);
    printf("Elapsed time: %.3f s/%lld op, %.2f op/s, %lld ns/op\n",
           (double)(after - before) / 1.0e9, (long long)N,
           N * 1e9 / (after - before),
           (long long)((after - before) / N));
    kz_close(S);
    return 0;
}

static int usage(const char *progname) {
    fprintf(stderr,
            "Usage: %s (f[lood]|e[cho]) "
            "(c[lient]|s[erver]) [name] [count]\n",
            progname);
    return 1;
}

int main(int argc, char **argv) {
    const char *shmname = "kaze-test";
    int64_t test_count = 10000000;
    if (argc <= 2) return usage(argv[0]);
    if (argc > 3) shmname = argv[3];
    if (argc > 4) test_count = strtoll(argv[4], NULL, 10);
    if (*argv[1] == 'f') {
        if (argc > 2 && *argv[2] == 's') {
            kz_unlink(shmname);
            return flood_server(shmname);
        } else
            return flood_client(shmname, test_count);
    } else if (*argv[1] == 'e') {
        if (argc > 2 && *argv[2] == 's') {
            kz_unlink(argv[2]);
            return echo_server(shmname);
        } else
            return echo_client(shmname, test_count);
    }
    return usage(argv[0]);
}

/* cc: flags+='-g -ggdb -O3' */
