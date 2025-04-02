#include <stdio.h>

#define KZ_IMPLEMENTATION
#include "kaze.h"

/* kz_thread - Cross-platform thread support */
#include <stdio.h>
#include <stdlib.h>

/* Platform detection */
#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

/* Thread type definition */
#ifdef _WIN32
typedef struct {
    HANDLE handle;
    DWORD id;
} kz_Thread;
#else
typedef pthread_t kz_Thread;
#endif

/* Thread function type definition */
typedef void* (*kzT_thread_func)(void*);

#ifdef _WIN32
/* Windows thread start function wrapper */
typedef struct {
    kzT_thread_func func;
    void* arg;
} kzT_thread_params;

static DWORD WINAPI win32_thread_func(LPVOID lpParam) {
    kzT_thread_params* params = (kzT_thread_params*)lpParam;
    kzT_thread_func func = params->func;
    void* arg = params->arg;
    void* result;
    
    /* Free parameter structure */
    free(params);
    
    /* Call the actual thread function */
    result = func(arg);
    return (DWORD)(size_t)result; /* May truncate on 64-bit systems */
}
#endif

/* Create a new thread */
static int kzT_spawn(kz_Thread* thread, kzT_thread_func func, void* arg) {
#ifdef _WIN32
    kzT_thread_params* params;
    
    params = (kzT_thread_params*)malloc(sizeof(kzT_thread_params));
    if (!params) {
        return -1; /* Memory allocation failed */
    }
    
    params->func = func;
    params->arg = arg;
    
    thread->handle = CreateThread(
        NULL,                   /* Default security attributes */
        0,                      /* Default stack size */
        win32_thread_func,      /* Thread function */
        params,                 /* Thread function parameters */
        0,                      /* Run thread immediately */
        &thread->id             /* Receive thread ID */
    );
    
    if (thread->handle == NULL) {
        free(params);
        return -1;
    }
    
    return 0; /* Success */
#else
    return pthread_create(thread, NULL, func, arg);
#endif
}

/* Wait for thread completion */
static int kzT_join(kz_Thread thread, void** result) {
#ifdef _WIN32
    DWORD wait_result;
    DWORD exit_code = 0;
    
    wait_result = WaitForSingleObject(thread.handle, INFINITE);
    
    if (wait_result == WAIT_FAILED) {
        return -1;
    }
    
    if (result != NULL) {
        if (!GetExitCodeThread(thread.handle, &exit_code)) {
            CloseHandle(thread.handle);
            return -1;
        }
        *result = (void*)(size_t)exit_code;
    }
    
    CloseHandle(thread.handle);
    return 0;
#else
    return pthread_join(thread, result);
#endif
}

static void *echo_thread(void *ud) {
    kz_State *S = kz_open("test", 0, 0);
    if (S == NULL) perror("kz_open");
    assert(S != NULL);
    (void)ud;
    while (!kz_isclosed(S)) {
        kz_Context ctx;
        char data[1024], *buf;
        size_t len, buflen;
        int r;
        printf("read closing %p (%u) write closing %p (%u)\n",
                (void*)&S->hdr->queues[0].used,
                S->hdr->queues[0].used,
                (void*)&S->hdr->queues[1].used,
                S->hdr->queues[1].used);
        r = kz_read(S, &ctx);
        if (r == KZ_AGAIN) r = kz_waitcontext(&ctx, -1);
        if (r == KZ_CLOSED) break;
        assert(r == KZ_OK);
        buf = kz_buffer(&ctx, &len);
        assert(len < 1024);
        memcpy(data, buf, len);
        kz_commit(&ctx, len);
        r = kz_write(S, &ctx, len);
        if (r == KZ_AGAIN) r = kz_waitcontext(&ctx, -1);
        if (r == KZ_CLOSED) break;
        assert(r == KZ_OK);
        buf = kz_buffer(&ctx, &buflen);
        assert(buflen >= len);
        memcpy(buf, data, len);
        kz_commit(&ctx, len);
    }
    kz_close(S);
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
    kz_unlink("test");
    assert(!kz_exists("test"));
    assert(kz_open("test", KZ_CREATE, 0) == NULL);
    if (sizeof(size_t) > 4)
        assert(kz_open("test", KZ_CREATE, KZ_MAX_SIZE*2+sizeof(kz_ShmHdr)) == NULL);
    S = kz_open("test", KZ_CREATE, 1024);
    assert(S != NULL);
    assert(kz_exists("test"));
    assert(strcmp(kz_name(S), "test") == 0);
    assert(kz_size(S) > 0);
    assert(kz_pid(S) > 0);
    assert(kz_open("test", KZ_CREATE|KZ_EXCL, 1024) == NULL);
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
    kz_State *S = kz_open("test", KZ_CREATE|KZ_RESET, 1024);
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

int main(void) {
    test_echo();
    test_unsplit();
}

/* cc: flags+='-Wall -Wextra -O3 --coverage -ggdb' */
