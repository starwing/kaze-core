# kaze-core

`kaze-core` is the foundational component of the [kaze project](https://github.com/starwing/kaze), designed for high-performance, low-latency inter-process communication (IPC) bi-directional channel using shared memory.

## Features

* **Cross-Platform**: Supports Linux, macOS, and Windows.
* **High Performance**:
    * Utilizes futex (on Linux/macOS) or named Events (on Windows) for synchronization, minimizing overhead.
    * Achieves zero-syscall communication in the best-case scenario when queues are not contended and data/space is readily available.
    * On an M4 Mac mini, `kaze-core` demonstrates exceptional performance:
        * **Flood benchmark**: 15.18 million QPS with 65ns per operation
        * **Echo benchmark**: 6.01 million QPS server throughput (166ns latency), 12.02 million QPS client throughput (83ns average read/write)
* **Multiple Implementations**:
    * **C**: A pure C89 implementation (`kaze.h`) providing the core logic.
    * **Go**: A Go package (`kaze/kaze`) that provides a native Go version (without cgo) with a compatible shared memory layout.
    * **Lua**: A Lua binding (`kaze.c`) provides IPC and host implementation capabilities for the Lua language.

## The Shared Memory Layout

`kaze-core` uses a shared memory segment meticulously structured for efficient communication between two processes (an "owner" and a "user"). The layout is defined by `kz_ShmHdr` in C and mirrored by `shmHdr` in Go.

The shared memory segment is organized as:
1. **Header**: `kz_ShmHdr` (400 bytes) containing metadata for the two communication queues.
2. **Queue 0 Data Buffer**: Immediately follows the header. Its size is `kz_ShmHdr.queues[0].size`.
3. **Queue 1 Data Buffer**: Immediately follows Queue 0's data buffer. Its size is `kz_ShmHdr.queues[1].size`.

For owner process, the Queue 0 is the write queue, and the Queue 1 is the read queue. For user process, it's the opposite. The channel offer a `kz_wait()` API to wait whether the queue can read or write. For both processes, `kz_wait()` waits on the `reading` variable of their read queue, and when they need to wake up the other process, they do so through the `reading` variable of their own write queue.

### The Header Layout

```mermaid
---
title: "Shared Memory Layout (kz_ShmHdr)"
---
packet-beta
0-3: "size"
4-7: "queue_size"
8-11: "owner_pid"
12-15: "user_pid"
16-19: "Queue[0].writing"
20-23: "Queue[0].tail"
24-27: "Queue[0].can_push"
28-79: "Queue[0].padding1"
80-83: "Queue[0].reading"
84-87: "Queue[0].head"
88-91: "Queue[0].can_pop"
92-143: "Queue[0].padding2"
144-147: "Queue[0].used"
148-207: "Queue[0].padding3"
208-211: "Queue[1].writing"
212-215: "Queue[1].tail"
216-219: "Queue[1].can_push"
220-271: "Queue[1].padding1"
272-275: "Queue[1].reading"
276-279: "Queue[1].head"
280-283: "Queue[1].can_pop"
284-335: "Queue[1].padding2"
336-339: "Queue[1].used"
340-399: "Queue[1].padding3"
```

The header across 6 cacheline, to split atomic variables of each queue to separate cachelines.

### Field Descriptions

| Field Name | Description                                          |
| ---------- | ---------------------------------------------------- |
| size       | Total size of the shared memory segment. Maximum 4GB |
| queue_size | Size of a single queue.                              |
| owner_pid  | Process ID of the owner process                      |
| user_pid   | Process ID of the user process                       |

### Queue Info Structure (128 bytes each)

| Field    | Size | Description                                     |
| -------- | ---- | ----------------------------------------------- |
| writing  | 4    | Writing status signal (0/KZ_NOWAIT/blocking)    |
| tail     | 4    | Tail position in queue                          |
| can_push | 4    | Windows only: Whether queue can push no wait    |
| padding1 | 52   | Padding (12 uint32_t) - cache line alignment    |
| reading  | 4    | Reading status signal (0/KZ_NOWAIT/KZ_WAITREAD) |
| head     | 4    | Head position in queue                          |
| can_pop  | 4    | Windows only: Whether queue can pop no wait     |
| padding2 | 52   | Padding (13 uint32_t) - cache line alignment    |
| used     | 4    | Number of bytes used (-1 == closed)             |
| padding3 | 60   | Padding (15 uint32_t) - cache line alignment    |

### The state of control variables in queue info

| Control variable | Value              | State         | Description                                                                               |
| ---------------- | ------------------ | ------------- | ----------------------------------------------------------------------------------------- |
| `reading`        | 0                  | No operations | Reader is not reading now.                                                                |
| `reading`        | `KZ_NOWAIT`(-1)    | In reading    | Reader is in `kz_read` oepration, but not waiting for data.                               |
| `reading`        | `KZ_WAITREAD`(1)   | In waiting    | Reader is in `kz_waitcontext` to wait data available.                                     |
| `reading`        | `KZ_WAITBOTH`(2)   | In waiting    | Reader is in `kz_wait` to wait data or space to write.                                    |
| `writing`        | 0                  | No operations | Writer is not writing now.                                                                |
| `writing`        | `KZ_NOWAIT`(-1)    | In writing    | Writer is in `kz_write` operation, but not waiting for space.                             |
| `writing`        | `> 0`              | In waiting    | Writer is in `kz_wait` or `kz_waitcontext`, waitting `writing` bytes space to write data. |
| `used`           | `< KZ_CLOSE_MASK`  | Normal        | there are `used` bytes data in the queue.                                                 |
| `used`           | `>= KZ_CLOSE_MASK` | Closed        | the queue is closed.                                                                      |

## C API (`kaze.h`)

### Example

```c
// for echo server process
int main(void) {
    // create a channel (as owner)
    kz_State *S = kz_open("test", KZ_CREATE | KZ_RESET | 0666, 8192);
    if (S == NULL) perror("kz_open");

    // start echo event loop
    while (!kz_isclosed(S)) {
        kz_Context rctx, wctx;
        char    *rbuf, *wbuf;
        size_t  rlen = 0, wlen = 0;
        int     r;

        // start a read operation
        r = kz_read(S, &rctx);
        // wait if necessary
        if (r == KZ_AGAIN) r = kz_waitcontext(&rctx, -1);
        // exit when the channel is closed
        if (r == KZ_CLOSED) break;
        assert(r == KZ_OK);
        // retrieve the result buffer of read operation
        rbuf = kz_buffer(&rctx, &rlen);

        // start a write operation (overlaps the read operation)
        r = kz_write(S, &wctx, rlen);
        if (r == KZ_AGAIN) r = kz_waitcontext(&wctx, -1);
        if (r == KZ_CLOSED) break;
        assert(r == KZ_OK);
        // retrieve the data buffer of write operation
        wbuf = kz_buffer(&wctx, &wlen);
        assert(wlen >= rlen);
        // write readed result into write buffer
        memcpy(wbuf, rbuf, rlen);
        // commit both operation
        r = kz_commit(&rctx, rlen);
        assert(r == KZ_OK);
        r = kz_commit(&wctx, rlen);
        assert(r == KZ_OK);
    }
    kz_close(S);
    printf("echo thread exit\n");
    return 0;
}

// for echo client process
int main(void) {
    kz_State *S;
    kz_Thread t;
    int readcount = 0, writecount = 0, count = 100;
    int r;

    // open a channel as user, created by server process
    S = kz_open("test", 0, 0);
    assert(S != NULL);

    // start send echo requests
    while (readcount < count || writecount < count) {
        kz_Context ctx;
        size_t buflen;
        char *buf;

        // wait for read or write (-1 means wait forever)
        // 10 means if S can write, it must at least can write 10 bytes
        r = kz_wait(S, 10, -1);
        assert(r > 0);

        // if can read
        if ((r & KZ_READ) && readcount < count) {
            r = kz_read(S, &ctx);
            buf = kz_buffer(&ctx, &buflen);
            assert(buflen == 10);
            assert(memcmp(buf, "helloworld", buflen) == 0);
            kz_commit(&ctx, buflen);
            readcount++;
        }

        // if can write
        if ((r & KZ_WRITE) && writecount < count) {
            r = kz_write(S, &ctx, 10);
            assert(r == KZ_OK);
            buf = kz_buffer(&ctx, &buflen);
            assert(buflen >= 10);
            memcpy(buf, "helloworld", 10);
            kz_commit(&ctx, 10);
            writecount++;
        }
    }
    printf("readcount=%d writecount=%d\n", readcount, writecount);
    // shutdown the channel, makes echo process exit.
    kz_shutdown(S, KZ_BOTH);
    // close the channel.
    kz_close(S);
    return 0;
}
```

The C API provides functions to manage and use these shared memory queues. Key data types:

* `kz_State`: An opaque structure representing the state of a kaze channel.
* `kz_Context`: An opaque structure representing the context of an ongoing read or write operation.

### Global Operations

* `KZ_API size_t kz_aligned(size_t bufsize, size_t pagesize);`
    * Calculates the system page-aligned `bufsize` for a given single direction queue size.
* `KZ_API int kz_exists(const char *name, int *powner, int *puser);`
    * Checks if a named queue exists. If it does, `*powner` and `*puser` are filled with the PIDs of the owner and user processes, respectively.
    * Returns `KZ_OK` if exists, `KZ_FAIL` otherwise.
* `KZ_API int kz_unlink(const char *name);`
    * Removes (unlinks) a named shared memory queue.
    * Returns `KZ_OK` on success or if not found, `KZ_FAIL` on error.
* `KZ_API const char *kz_failerror(void);`
    * Returns a string description of the last platform-specific error (e.g., from `errno` or `GetLastError()`).
* `KZ_API void kz_freefailerror(const char *s);`
    * Frees the error string returned by `kz_failerror`. (Platform-dependent: no-op on POSIX, `LocalFree` on Windows).

### Queue Creation/Destruction

* `KZ_API kz_State *kz_open(const char *name, int flags, size_t bufsize);`
    * Opens an existing queue or creates a new one.
    * `name`: A unique name for the shared memory queue.
    * `flags`: Combination of:
        * `KZ_CREATE`: Create the queue if it doesn't exist.
        * `KZ_EXCL`: With `KZ_CREATE`, fail if the queue already exists.
        * `KZ_RESET`: If creating, or if opening an existing queue and the current process is the owner, reset the queue state.
        * 9bit of permission bits, using 0666 for allow read/write for everyone.
    * `bufsize`: The desired capacity for each of the two internal ring buffers. This size will be aligned. you can use `kz_aligned()` to calculate a buffer size for desired queue size. 
    * Returns a pointer to `kz_State` on success, `NULL` on failure.
* `KZ_API void kz_close(kz_State *S);`
    * Closes the kaze queue connection. Releases resources associated with `S`.
* `KZ_API int kz_shutdown(kz_State *S, int mode);`
    * Gracefully shuts down one or both directions of communication. Marks the respective queue(s) as closed and wakes up any waiting processes.
    * `mode`: `KZ_READ` (shutdown receiving), `KZ_WRITE` (shutdown sending), or `KZ_BOTH`.
    * Returns `KZ_OK` on success.

### Queue Info

* `KZ_API const char *kz_name(const kz_State *S);`
    * Returns the name of the queue.
* `KZ_API size_t kz_size(const kz_State *S);`
    * Returns the configured capacity of a single ring buffer in the queue pair.
* `KZ_API int kz_pid(const kz_State *S);`
    * Returns the PID of the current process as associated with this `kz_State`.
* `KZ_API int kz_isowner(const kz_State *S);`
    * Returns non-zero if the current process is the owner of the queue, 0 otherwise.
* `KZ_API int kz_isclosed(const kz_State *S);`
    * Returns non-zero if both directions of the queue are closed, 0 otherwise.

### Read/Write Operations

These functions use a `kz_Context` to manage multi-step, potentially non-blocking operations.

* `KZ_API int kz_read(kz_State *S, kz_Context *ctx);`
    * Initiates a read operation. Prepares `ctx` for reading.
    * Returns `KZ_OK` if data is immediately available, `KZ_AGAIN` if no data, `KZ_CLOSED` if closed, or other error codes.
* `KZ_API int kz_write(kz_State *S, kz_Context *ctx, size_t len);`
    * Initiates a write operation for `len` bytes. Prepares `ctx` for writing.
    * `len`: The number of bytes intended to be written.
    * Returns `KZ_OK` if space for `len` bytes is immediately available, `KZ_AGAIN` if not enough space, `KZ_TOOBIG` if `len` exceeds queue capacity, `KZ_CLOSED` if closed, or other error codes.
* `KZ_API int kz_isread(const kz_Context *ctx);`
    * Returns non-zero if `ctx` was initiated by `kz_read`, 0 if by `kz_write`.
* `KZ_API char *kz_buffer(kz_Context *ctx, size_t *plen);`
    * Gets a pointer to the internal buffer for reading data from or writing data into.
    * `*plen`: On entry for write, it's the requested write size. On exit, it's updated with the actual contiguous space available (for write) or data length available (for read).
    * Returns `NULL` if the context is invalid or the operation was not successful (e.g. `KZ_AGAIN`).
* `KZ_API int kz_commit(kz_Context *ctx, size_t len);`
    * Commits the read or write operation.
    * `len`: For read, unused value (can pass 0). For write, the number of bytes actually written to the buffer.
    * Updates queue pointers and wakes waiters if necessary.
    * Returns `KZ_OK` on success.
* `KZ_API void kz_cancel(kz_Context *ctx);`
    * Cancels an in-progress read/write operation initiated on `ctx`. Releases any internal locks/flags.

### Synchronization and Waiting

* `#define kz_wouldblock(ctx) ((ctx)->result == KZ_AGAIN)`
    * A macro to check if the last operation on `ctx` (e.g., `kz_read`, `kz_write`) returned `KZ_AGAIN`, indicating it would block if it were a blocking call.
* `KZ_API int kz_wait(kz_State *S, size_t len, int millis);`
    * Waits until either `len` bytes can be written to the send queue OR any data is available in the receive queue.
    * `millis`: Timeout in milliseconds. `<0` for infinite, `0` for non-blocking check.
    * Returns `KZ_READ`, `KZ_WRITE` or `KZ_BOTH` (all positive) if condition met, `KZ_TIMEOUT`, `KZ_CLOSED`, or `KZ_FAIL` (all negative) if any error occurs.
* `KZ_API int kz_waitcontext(kz_Context *ctx, int millis);`
    * Waits for the specific operation previously initiated on `ctx` (either read or write) to become possible.
    * `millis`: Timeout in milliseconds.
    * Returns `KZ_OK` if the operation can proceed, `KZ_TIMEOUT`, `KZ_CLOSED`, or `KZ_FAIL` otherwise. After `KZ_OK`, you typically retry the `kz_buffer` / `kz_commit` sequence.

Return codes like `KZ_OK`, `KZ_AGAIN`, `KZ_CLOSED`, `KZ_TIMEOUT`, `KZ_FAIL`, `KZ_TOOBIG`, `KZ_BUSY`, `KZ_INVALID` are used throughout the API to indicate operation status.

## Lua API

### Example

Unlike the C example which splits into two processes, the Lua API example shows a simpler echo server:

```lua
local kaze = require "kaze"

-- cleanup old channel if exists
kaze.unlink "test"

-- create a channel with 1024 bytes buffer size
local k <close> = assert(kaze.create("test", 1024, "r"))
print("test created")

-- event loop: read message and write it back
while not k:isclosed "rw" do
    local msg = k:read()
    if not msg then break end
    print("received: ", msg)
    k:write(msg)
end
print("exited ...")
```

### Module Functions

* `kaze.aligned(bufsize [, pagesize])`: Aligns buffer size to system page size (default 4096).
* `kaze.exists(name)`: Returns `exists, owner_pid, user_pid` for a named channel.
* `kaze.unlink(name)`: Removes a named channel.
* `kaze.create(name, bufsize [, flags[, perm]])`: Creates a new channel.
     * `flags`: String containing 'c' (create), 'e' (exclusive), 'r' (reset).
     * `perm`: shm file permission, default `0666`.
* `kaze.open(name [, flags [, bufsize]])`: Opens an existing channel.
     * Similar to `create` but doesn't require buffer size.
* `kaze.context()`: create a new reading/writing context (lower interface).

### State Methods

A kaze state object (returned by `create`/`open`) provides:

* `state:close()`: Closes the channel.
* `state:shutdown([mode])`: Shuts down channel direction(s).
     * `mode`: String containing 'r' (read) and/or 'w' (write).
* `state:name()`: Returns channel name.
* `state:size()`: Returns buffer size.
* `state:pid()`: Returns current process PID.
* `state:isowner()`: Returns true if current process is owner.
* `state:isclosed([mode])`: Returns true if channel is closed.
     * `mode`: String containing 'r' (read) and/or 'w' (write).
* `state:wait(request[, timeout])`: Waits for read/write availability.
     * `request`: Number of bytes needed for writing.
     * Returns `can_read, can_write` booleans.

### Context Operations

Low-level API for non-blocking operations:

* `context:read(state)`: Start read operation on context.
     * Returns `context, err`, if err is not `nil` or `"AGAIN"`, context is nil.
* `context:write(state, size)`: Start write operation on context.
     * Returns `context, err`, if err is not `nil` or `"AGAIN"`, context is nil.
* `context:isread()`: Returns true if context is for reading.
* `context:wouldblock()`: Returns true if operation would block.
* `context:readbuffer()`: Reads data from read context.
* `context:writebuffer(data)`: Writes data to write context.
* `context:wait([timeout])`: Waits for context operation to complete.
* `context:cancel()`: Cancels context operation.

After call `context:cancel()` or `context:(read|write)buffer()`, the context could be reused to
start next `read` or `write` operation.

### High-level Operations

Simpler blocking API (internally uses contexts):

* `state:read([timeout])`: Reads data from channel.
* `state:write(data [, timeout])`: Writes data to channel.

All timeout values are in milliseconds, negative means infinite wait， 0 means only check.

## Platform Support

| Platform | Supported | Synchronization | Notes |
|----------|-----------|----------------|--------|
| Linux    | ✅        | futex          | Full support |
| macOS    | ✅        | os_sync_*      | Requires macOS 10.12+ |  
| Windows  | ✅        | Named Events   | Full support |

### Platform-specific Notes

**macOS:** Currently uses `os_sync_wait_on_address` family functions. Fallback to `ulock_*` APIs planned for older systems.

**Windows:** Uses named Events for synchronization. Performance may vary compared to futex-based systems.

**Linux:** Optimal performance with modern kernel (3.2+) for futex support.

## Troubleshooting

### Common Issues

1. **Permission denied**: Ensure proper permissions on shared memory object.
   ```bash
   # Check existing objects
   ls -la /dev/shm/  # Linux
   ls -la /tmp/      # macOS (implementation dependent)
   ```

2. **Channel already exists**: Use `kz_unlink()` to cleanup before creating.
   ```c
   kz_unlink("channel_name");
   ```

3. **Process not found errors**: Ensure both processes are running and accessible.

4. **Operation would block (KZ_AGAIN/ErrAgain)**: 
   - Use `kz_wait()` / `Wait()` to wait for channel readiness
   - Check if the other process is still alive
   - Verify buffer sizes are appropriate for your data

5. **Channel closed unexpectedly**: 
   - Check if the other process terminated
   - Verify proper shutdown sequence using `kz_shutdown()` / `Shutdown()`

### Debugging

**C API Debug:**
```c
#define KZ_DEBUG  // Enable debug output (if implemented)
#include "kaze.h"

// Check error details
if (result == KZ_FAIL) {
    const char *error = kz_failerror();
    printf("Error: %s\n", error);
    kz_freefailerror(error);
}
```

**Go API Debug:**
```bash
# Enable race detection
go test -race ./kaze

# Run with verbose output
go test -v ./kaze

# Enable detailed logging
export GODEBUG=gctrace=1
```

**Lua API Debug:**
```lua
-- Check channel state
local exists, owner_pid, user_pid = kaze.exists("channel_name")
print("Channel exists:", exists)
print("Owner PID:", owner_pid)
print("User PID:", user_pid)
```

### Performance Debugging

1. **Monitor queue usage:**
   ```c
   // Check if queues are full/empty frequently
   size_t queue_size = kz_size(state);
   // Adjust buffer size if needed
   ```

2. **Profile your application:**
   - Use system profilers (perf, Instruments, etc.)
   - Check for unnecessary data copying
   - Verify proper alignment and cache usage

3. **Benchmark different scenarios:**
   ```bash
   # Run built-in benchmarks
   go test -bench=. ./kaze
   ```

### Memory and Resource Leaks

1. **Cleanup shared memory:**
   ```bash
   # Linux: Remove orphaned shared memory
   sudo rm /dev/shm/your_channel_name
   
   # macOS: Implementation dependent, may be in /tmp
   # Windows: Handled automatically by OS
   ```

2. **Check for leaked file descriptors:**
   ```bash
   # Linux/macOS
   lsof -p <your_process_id>
   ```

3. **Verify proper cleanup in code:**
   ```c
   // Always cleanup
   kz_close(state);
   kz_unlink("channel_name");  // For owner process
   ```
   
   ```go
   defer channel.CloseAndUnlink()  // For owner
   defer channel.Close()           // For user
   ```
