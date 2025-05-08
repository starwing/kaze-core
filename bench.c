#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>

#define KZ_STATIC_API
#include "kz_threads.h"

void *thread_drop(void *arg) {
    kz_State  *S = (kz_State *)arg;
    kz_Context ctx;

    printf("thread_drop: %d\n", kz_pid(S));
    while (!kz_isclosed(S)) {
        if (kzA_load(&S->read.info->used) < 1) continue;
        int r = kz_read(S, &ctx);
        if (r == KZ_AGAIN) r = kz_waitcontext(&ctx, -1);
        if (r == KZ_CLOSED) break;
        assert(r == KZ_OK);
        r = kz_commit(&ctx, 0);
        if (r == KZ_CLOSED) break;
        assert(r == KZ_OK);
    }
    kz_close(S);
    return NULL;
}

int main(void) {
    kz_State  *Suser, *S;
    kz_Thread  t;
    kz_Context ctx;
    uint64_t   before, after;
    uint64_t   i;

    const uint64_t N = 3000000ULL;
    int            r = kz_unlink("bench_drop");
    assert(r == 0);

    S = kz_open("bench_drop", KZ_CREATE | KZ_RESET, kz_aligned(N / 4, 4096));
    printf("queue_size = %zu\n", kz_size(S));

    assert(S != NULL);
    Suser = kz_open("bench_drop", 0, 0);
    assert(Suser != NULL);

    r = kzT_spawn(&t, &thread_drop, Suser);
    assert(r == 0);

    printf("start write ...\n");
    before = kzT_time();
    for (i = 0; i < N; i++) {
        int r = kz_write(S, &ctx, 10);
        if (r == KZ_AGAIN) r = kz_waitcontext(&ctx, -1);
        assert(r == KZ_OK);
        r = kz_commit(&ctx, 0);
        assert(r == KZ_OK);
    }
    after = kzT_time();
    kz_shutdown(S, KZ_WRITE);

    // Wait for the thread to finish
    printf("wait exit ...\n");
    kzT_join(t, NULL);

    printf("Elapsed time: %.3f s/%lld op, %lld op/s, %lld ns/op\n",
           (double)(after - before) / 1.0e9, (long long)N,
           (long long)(N * 1000 * 1000 * 1000 / (after - before)),
           (long long)((after - before) / N));

    // Clean up
    kz_close(S);
    return 0;
}