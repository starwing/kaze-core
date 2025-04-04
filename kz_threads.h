#ifndef kz_threads_h
# define kz_thread_h 1

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

KZ_STATIC DWORD WINAPI win32_thread_func(LPVOID lpParam) {
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
KZ_STATIC int kzT_spawn(kz_Thread* thread, kzT_thread_func func, void* arg) {
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
KZ_STATIC int kzT_join(kz_Thread thread, void** result) {
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

KZ_STATIC uint64_t kzT_time(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
        return 0;
    return (uint64_t)ts.tv_sec*1000000000+ts.tv_nsec;
}


#endif /* kz_thread_h */

