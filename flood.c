#define _GNU_SOURCE
#include <sched.h>

#define KZ_STATIC_API
#include "kaze.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

static char data[100];

static void bind_cpu(int cpu_id) {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(cpu_id, &mask);
    if (sched_setaffinity(0, sizeof(mask), &mask) < 0)
        perror("sched_getaffinity");
}

static uint64_t get_time(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts) < 0)
        return 0;
    return (uint64_t)ts.tv_sec*1000000000+ts.tv_nsec;
}

static int server(const char *shm) {
    kz_State *S = kz_open(shm, KZ_CREATE|KZ_RESET, 8192);
    if (S == NULL) perror("kz_open");
    bind_cpu(0);
    printf("start flood server ...\n");
    while (!kz_isclosed(S)) {
        kz_Context ctx;
        size_t len = 0;
        char *s;
        int r = kz_read(S, &ctx);
        if (r == KZ_AGAIN) r = kz_waitcontext(&ctx, -1);
        if (r == KZ_CLOSED) break;
        if (r != KZ_OK) return perror("kz_read"), 1;
        s = kz_buffer(&ctx, &len);
        if (len != 100) return printf("len error\n"), 1;
        r = memcmp(s, data, 100);
        if (r != 0) return printf("data error\n"), 1;
        r = kz_commit(&ctx, 0);
        if (r == KZ_CLOSED) break;
        if (r != KZ_OK) return perror("kz_commit"), 1;
    }
    kz_close(S);
    printf("stop flood server ...\n");
    return 0;
}

static int client(const char *shm) {
    kz_State *S = kz_open(shm, 0, 0);
    int i, N = 10000000, wc = 0;
    uint64_t before, after, wt = 0;
    if (S == NULL) return perror("kz_open"), 1;
    bind_cpu(1);

    printf("start flood ...\n");
    before = get_time();
    for (i = 0; i < N; ++i) {
        kz_Context ctx;
        int r = kz_write(S, &ctx, 100);
        if (r == KZ_AGAIN) {
            uint64_t wb, wa;
            wb = get_time();
            r = kz_waitcontext(&ctx, -1), ++wc;
            wa = get_time();
            wt += (wa - wb);
        }
        if (r == KZ_CLOSED) break;
        if (r != KZ_OK) return perror("kz_write"), 1;
        memcpy(kz_buffer(&ctx, NULL), data, 100);
        r = kz_commit(&ctx, 100);
        if (r == KZ_CLOSED) break;
        if (r != KZ_OK) return perror("kz_commit"), 1;
    }
    after = get_time();

    printf("wait count=%d %.3f%% time=%.3f s\n", wc, wc*100.0/N, wt/1.0e9);
    printf("Elapsed time: %.3f s/%lld op, %lld op/s, %lld ns/op\n",
           (double)(after - before) / 1.0e9, (long long)N,
           ((long long)N * 1000 * 1000 * 1000 / (after - before)),
           (long long)((after - before) / N));
    kz_close(S);
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 2) {
        if (strcmp(argv[1], "flood") == 0)
            return server(argv[2]);
        if (strcmp(argv[1], "bench-flood") == 0)
            return client(argv[2]);
    }
    return 1;
}

/* cc: flags+='-g -ggdb -O3' */
