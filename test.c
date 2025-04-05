#include <stdio.h>

#define KZ_STATIC_API
#include "kaze.h"
#include "kz_threads.h"

static void *echo_thread(void *ud) {
    kz_State *S = kz_open("test", 0, 0);
    if (S == NULL) perror("kz_open");
    assert(S != NULL);
    assert(!kz_isowner(S));
    (void)ud;
    while (!kz_isclosed(S)) {
        kz_Context ctx;
        char data[1024], *buf;
        size_t len, buflen;
        int r = kz_read(S, &ctx);
        if (r == KZ_AGAIN) r = kz_waitcontext(&ctx, -1);
        if (r == KZ_CLOSED) break;
        assert(r == KZ_OK);
        buf = kz_buffer(&ctx, &len);
        assert(len < 1024);
        memcpy(data, buf, len);
        r = kz_commit(&ctx, len);
        assert(r == KZ_OK);
        r = kz_write(S, &ctx, len);
        if (r == KZ_AGAIN) r = kz_waitcontext(&ctx, -1);
        if (r == KZ_CLOSED) break;
        assert(r == KZ_OK);
        buf = kz_buffer(&ctx, &buflen);
        assert(buflen >= len);
        memcpy(buf, data, len);
        r = kz_commit(&ctx, len);
        assert(r == KZ_OK);
    }
    kz_close(S);
    printf("echo thread exit\n");
    return NULL;
}

static void test_echo(void) {
    kz_State *S;
    kz_Thread t;
    char *buf;
    size_t buflen;
    int r, readcount = 0, writecount = 0;
    int count;
    printf("--- test echo ---\n");
    assert(kz_aligned(1024, 4096) == 3824);
    assert(!kz_exists("test"));
    assert(kz_open("test", KZ_CREATE, 0) == NULL);
    if (sizeof(size_t) > 4)
        assert(kz_open("test", KZ_CREATE,
                       KZ_MAX_SIZE * 2 + sizeof(kz_ShmHdr)) == NULL);
    S = kz_open("test", KZ_CREATE, 1024);
    assert(S != NULL);
    assert(kz_exists("test"));
    assert(strcmp(kz_name(S), "test") == 0);
    assert(kz_isowner(S));
    assert(kz_size(S) > 0);
    assert(kz_pid(S) > 0);
    assert(kz_open("test", KZ_CREATE | KZ_EXCL, 1024) == NULL);
    count = (int)kz_size(S) / 10 * 2;
    r = kzT_spawn(&t, &echo_thread, NULL);
    assert(r == 0);
    printf("test count = %d\n", count);
    while (readcount < count || writecount < count) {
        kz_Context ctx;
        r = kz_wait(S, 10, -1);
        assert(r > 0);
        if ((r & KZ_READ) && readcount < count) {
            r = kz_read(S, &ctx);
            buf = kz_buffer(&ctx, &buflen);
            assert(buflen == 10);
            assert(memcmp(buf, "helloworld", buflen) == 0);
            kz_commit(&ctx, buflen);
            readcount++;
            printf("read count=%d\n", readcount);
        }
        if ((r & KZ_WRITE) && writecount < count) {
            r = kz_write(S, &ctx, 10);
            assert(r == KZ_OK);
            buf = kz_buffer(&ctx, &buflen);
            assert(buflen >= 10);
            memcpy(buf, "helloworld", 10);
            kz_commit(&ctx, 10);
            writecount++;
            printf("write count=%d\n", writecount);
        }
    }
    printf("readcount=%d writecount=%d\n", readcount, writecount);
    printf("before shutdown\n");
    kz_shutdown(S, KZ_BOTH);
    printf("after shutdown\n");
    kzT_join(t, NULL);
    printf("after join\n");
    kz_close(S);
    printf("--- test echo ---\n");
}

static kz_State *kz_shadow(kz_State *S) {
    kz_State *S1 = kz_newstate(kz_name(S));
    assert(kz_isowner(S1));
    *S1 = *S;
    kz_setowner(S1, 0);
    return S1;
}

static void test_unsplit(void) {
    kz_State *S = kz_open("test", KZ_CREATE | KZ_RESET, 1024);
    kz_State *S1 = kz_shadow(S);
    kz_Context ctx;
    size_t buflen, len;
    int r;

    printf("--- test unsplit ---\n");
    len = kz_size(S);
    assert(len > 0);
    r = kz_write(S, &ctx, len - 10);
    assert(r == KZ_OK);
    kz_commit(&ctx, len - 10);

    r = kz_read(S1, &ctx);
    assert(r == KZ_OK);
    kz_buffer(&ctx, &buflen);
    assert(buflen == len - 10);
    kz_commit(&ctx, len - 10);

    r = kz_write(S, &ctx, 10);
    assert(r == KZ_OK);
    kz_commit(&ctx, 10);

    r = kz_read(S1, &ctx);
    assert(r == KZ_OK);
    kz_buffer(&ctx, &buflen);
    assert(buflen == 10);
    kz_commit(&ctx, 10);

    kz_close(S);
    free(S1);
    printf("--- test unsplit ---\n");
}

static void test_timeout(void) {
    kz_State *S = kz_open("test", KZ_CREATE | KZ_RESET, 1024);
    kz_Context ctx;
    const char *data = "1234567890123";
    int r;

    printf("--- test timeout ---\n");
    assert(S != NULL);

    r = kz_read(S, &ctx);
    assert(r == KZ_AGAIN);
    r = kz_waitcontext(&ctx, 100);
    assert(r == KZ_TIMEOUT);
    kz_cancel(&ctx);

    for (;;) {
        r = kz_write(S, &ctx, sizeof(data) - 1);
        if (r == KZ_AGAIN) {
            kz_cancel(&ctx);
            break;
        }
        assert(r == KZ_OK);
        memcpy(kz_buffer(&ctx, NULL), data, sizeof(data) - 1);
        r = kz_commit(&ctx, sizeof(data) - 1);
        assert(r == KZ_OK);
    }
    r = kz_write(S, &ctx, sizeof(data) - 1);
    assert(r == KZ_AGAIN);
    r = kz_waitcontext(&ctx, 100);
    assert(r == KZ_TIMEOUT);
    kz_cancel(&ctx);

    r = kz_wait(S, sizeof(data) - 1, 100);
    assert(r == KZ_TIMEOUT);
    kz_close(S);
    printf("--- test timeout ---\n");
}

void bench_n(kz_State *S, size_t count) {
    size_t readcount = 0, writecount = 0;
    char data[] = "1234567890123";
    size_t datalen = sizeof(data) - 1;
    while (readcount < count || writecount < count) {
        kz_Context ctx;
        int r = kz_wait(S, datalen, -1);
        assert(r > 0);
        if ((r & KZ_READ) && readcount < count) {
            r = kz_read(S, &ctx);
            assert(r == KZ_OK);
            r = kz_commit(&ctx, 0);
            assert(r == KZ_OK);
            readcount++;
        }
        if ((r & KZ_WRITE) && writecount < count) {
            size_t buflen;
            char *buf;
            int r = kz_write(S, &ctx, datalen);
            assert(r == KZ_OK);
            buf = kz_buffer(&ctx, &buflen);
            assert(buflen >= datalen);
            memcpy(buf, data, datalen);
            r = kz_commit(&ctx, datalen);
            assert(r == KZ_OK);
            writecount++;
        }
    }
}

void bench_echo(void) {
    kz_State *S = kz_open("test", KZ_CREATE | KZ_RESET, 1024);
    kz_Thread t;
    int r = kzT_spawn(&t, &echo_thread, NULL);
    uint64_t N = 1000000;
    uint64_t before, after;
    printf("--- bench echo ---\n");
    assert(S != NULL);
    assert(r == 0);
    before = kzT_time();
    bench_n(S, N);
    after = kzT_time();
    printf("Elapsed time: %.3f s/1000000 op, %llu op/s, %llu us/op\n",
           (double)(after - before) / 1000000000.0,
           (uint64_t)(N * 1000 * 1000 * 1000 / (after - before)),
           (uint64_t)((after - before) / N));
    printf("--- bench echo ---\n");
    kz_close(S);
    kzT_join(t, NULL);
}

int main(void) {
    kz_unlink("test");
    test_echo();
    test_unsplit();
    test_timeout();
    bench_echo();
    kz_unlink("test");
}

/* cc: flags+='-Wall -Wextra -O3 --coverage -ggdb' */
