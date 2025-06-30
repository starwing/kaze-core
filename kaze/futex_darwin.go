package kaze

import (
	"sync/atomic"
	"unsafe"

	"syscall"
)

/*
#include <sys/syscall.h>
#include <unistd.h>

// fetch the syscall numbers for ulock_wait and ulock_wake
int get_ulock_wait_syscall() {
#ifdef SYS_ulock_wait
    return SYS_ulock_wait;
#else
    return -1;
#endif
}
int get_ulock_wake_syscall() {
#ifdef SYS_ulock_wake
    return SYS_ulock_wake;
#else
    return -1;
#endif
}
*/
import "C"

const (
	UL_COMPARE_AND_WAIT_SHARED = 3
	ULF_WAKE_ALL               = 0x00000100
)

var (
	ulockWaitSyscallNum = int(C.get_ulock_wait_syscall())
	ulockWakeSyscallNum = int(C.get_ulock_wake_syscall())
)

// futex_wait waits until the value at addr changes from ifValue or timeout occurs.
// timeoutMillis <= 0 means wait indefinitely.
// Returns:
// - nil on success
// - ErrTimeout if timeout expired
// - syscall.Errno on other errors
func futex_wait(addr *atomic.Uint32, ifValue uint32, millis int64) error {
	if ulockWaitSyscallNum == -1 {
		panic("No suitable implementation found")
	}

	// Convert timeout to microseconds for ulock API
	timeoutMicros := uint32(millis * 1000)

	ret, _, errno := syscall.Syscall6(
		uintptr(ulockWaitSyscallNum),
		uintptr(UL_COMPARE_AND_WAIT_SHARED),
		uintptr(unsafe.Pointer(addr)),
		uintptr(ifValue),
		uintptr(timeoutMicros),
		0, 0)
	if int32(ret) >= 0 {
		return nil
	}
	if errno == syscall.ETIMEDOUT {
		return ErrTimeout
	}

	if errno == syscall.EAGAIN {
		return nil // Value didn't match, which is fine
	}

	// ocurrs in macOS and don't known why
	if errno == syscall.EINTR || errno == syscall.ENOENT || errno == syscall.Errno(260) {
		return ErrTimeout
	}

	return errno
}

// futex_wake wakes threads waiting on addr.
// If wakeAll is true, wakes all waiting threads, otherwise wakes just one.
// Returns:
// - nil on success
// - syscall.Errno on failure
func futex_wake(addr *atomic.Uint32, wakeAll bool) error {
	if ulockWakeSyscallNum == -1 {
		panic("No suitable implementation found")
	}

	operation := UL_COMPARE_AND_WAIT_SHARED
	if wakeAll {
		operation |= ULF_WAKE_ALL
	}
	for {
		ret, _, errno := syscall.Syscall(
			uintptr(ulockWakeSyscallNum),
			uintptr(operation),
			uintptr(unsafe.Pointer(addr)),
			uintptr(0))

		if int32(ret) >= 0 {
			return nil
		}

		// Handle special error cases
		if errno == syscall.ENOENT {
			// No threads to wake, not really an error
			return nil
		}

		// occurs in macOS but don't known why
		if errno == syscall.Errno(0) || errno == syscall.Errno(316) {
			return nil
		}

		if errno == syscall.EINTR || errno == syscall.ETIMEDOUT ||
			errno == syscall.Errno(260) {
			continue
		}

		return errno
	}
}
