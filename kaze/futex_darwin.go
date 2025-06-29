// Package kaze the double-ended shm queue.
package kaze

import (
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
)

// Constants for os_sync API
const (
	OS_CLOCK_MACH_ABSOLUTE_TIME    uint32 = 32
	OS_SYNC_WAIT_ON_ADDRESS_SHARED uint32 = 1
	OS_SYNC_WAKE_BY_ADDRESS_SHARED uint32 = 1
)

// Constants for ulock API
const (
	UL_COMPARE_AND_WAIT_SHARED uint32 = 3
	ULF_WAKE_ALL               uint32 = 0x00000100
)

var (
	// Sync functions for os_sync API
	osSyncWaitOnAddress            uintptr
	osSyncWaitOnAddressWithTimeout uintptr
	osSyncWakeByAddressAny         uintptr
	osSyncWakeByAddressAll         uintptr

	// Sync functions for ulock API
	ulockWait uintptr
	ulockWake uintptr
)

// ensureInitialized dynamically loads symbol addresses from libSystem
func init() {
	// Try to load os_sync functions (may not be available on older macOS)
	registerWeakLibFunc(&osSyncWaitOnAddress, "os_sync_wait_on_address")
	registerWeakLibFunc(&osSyncWaitOnAddressWithTimeout, "os_sync_wait_on_address_with_timeout")
	registerWeakLibFunc(&osSyncWakeByAddressAny, "os_sync_wake_by_address_any")
	registerWeakLibFunc(&osSyncWakeByAddressAll, "os_sync_wake_by_address_all")

	// Try to load ulock functions (also may not be available)
	registerWeakLibFunc(&ulockWait, "__ulock_wait")
	registerWeakLibFunc(&ulockWake, "__ulock_wake")

	if (osSyncWaitOnAddress == 0 || osSyncWakeByAddressAny == 0) &&
		(ulockWait == 0 || ulockWake == 0) {
		panic("neither os_sync nor ulock functions available")
	}
}

func registerWeakLibFunc(fptr *uintptr, name string) {
	*fptr, _ = purego.Dlsym(purego.RTLD_DEFAULT, name)
}

// futex_wait waits until the value at addr changes from ifValue or timeout occurs.
// timeoutMillis <= 0 means wait indefinitely.
// Returns:
// - nil on success
// - ErrTimeout if timeout expired
// - syscall.Errno on other errors
func futex_wait(addr *atomic.Uint32, ifValue uint32, millis int64) error {
	// First try os_sync API (newer, public API in macOS 14.4+)
	if osSyncWaitOnAddress != 0 && osSyncWaitOnAddressWithTimeout != 0 {
		var ret uintptr

		if millis < 0 {
			// Wait indefinitely
			ret, _, _ = purego.SyscallN(osSyncWaitOnAddress,
				uintptr(unsafe.Pointer(addr)),
				uintptr(ifValue),
				4, // size in bytes (uint32_t)
				uintptr(OS_SYNC_WAIT_ON_ADDRESS_SHARED),
			)
		} else {
			// Wait with timeout
			timeoutNs := uint64(millis) * uint64(time.Millisecond/time.Nanosecond)
			ret, _, _ = purego.SyscallN(osSyncWaitOnAddressWithTimeout,
				uintptr(unsafe.Pointer(addr)),
				uintptr(ifValue),
				4, // size in bytes (uint32_t)
				uintptr(OS_SYNC_WAIT_ON_ADDRESS_SHARED),
				uintptr(OS_CLOCK_MACH_ABSOLUTE_TIME),
				uintptr(timeoutNs),
			)
		}

		return checkWaitErr(ret)
	}

	// Fall back to __ulock API (older, private API)
	if ulockWait != 0 {
		// Convert timeout to microseconds for ulock API
		timeoutMicros := uint32(millis * 1000)

		ret, _, _ := purego.SyscallN(ulockWait,
			uintptr(UL_COMPARE_AND_WAIT_SHARED),
			uintptr(unsafe.Pointer(addr)),
			uintptr(ifValue),
			uintptr(timeoutMicros),
		)

		return checkWaitErr(ret)
	}

	panic("No suitable implementation found")
}

func checkWaitErr(ret uintptr) error {
	if int32(ret) >= 0 {
		return nil
	}

	// Handle special error cases
	err := errno()
	if err == unix.ETIMEDOUT {
		return ErrTimeout
	}

	if err == unix.EAGAIN {
		return nil // Value didn't match, which is fine
	}

	// ocurrs in macOS and don't known why
	if err == unix.EINTR || err == unix.ENOENT || err == unix.Errno(260) {
		return ErrTimeout
	}

	return err
}

// futex_wake wakes threads waiting on addr.
// If wakeAll is true, wakes all waiting threads, otherwise wakes just one.
// Returns:
// - nil on success
// - syscall.Errno on failure
func futex_wake(addr *atomic.Uint32, wakeAll bool) error {
	// First try os_sync API (newer, public API in macOS 14.4+)
	if (osSyncWakeByAddressAny != 0 && !wakeAll) ||
		(osSyncWakeByAddressAll != 0 && wakeAll) {
		var ret uintptr

		for {
			if wakeAll {
				ret, _, _ = purego.SyscallN(osSyncWakeByAddressAll,
					uintptr(unsafe.Pointer(addr)),
					4, // size in bytes (uint32_t)
					uintptr(OS_SYNC_WAKE_BY_ADDRESS_SHARED),
				)
			} else {
				ret, _, _ = purego.SyscallN(osSyncWakeByAddressAny,
					uintptr(unsafe.Pointer(addr)),
					4, // size in bytes (uint32_t)
					uintptr(OS_SYNC_WAKE_BY_ADDRESS_SHARED),
				)
			}

			retry, err := checkWakeErr(ret)
			if !retry {
				return err
			}
		}
	}

	// Fall back to __ulock API (older, private API)
	if ulockWake != 0 {
		operation := UL_COMPARE_AND_WAIT_SHARED
		if wakeAll {
			operation |= ULF_WAKE_ALL
		}

		for {
			ret, _, _ := purego.SyscallN(ulockWake,
				uintptr(operation),
				uintptr(unsafe.Pointer(addr)),
				0, // wake_value
			)
			retry, err := checkWakeErr(ret)
			if !retry {
				return err
			}
		}
	}
	panic("No suitable implementation found")
}

func checkWakeErr(ret uintptr) (retry bool, err error) {
	if int32(ret) >= 0 {
		return false, nil
	}

	// Handle special error cases
	err = errno()
	if err == unix.ENOENT {
		// No threads to wake, not really an error
		return false, nil
	}

	// occurs in macOS but don't known why
	if err == unix.Errno(0) || err == unix.Errno(316) {
		return false, nil
	}

	if err == unix.EINTR || err == unix.ETIMEDOUT || err == unix.Errno(260) {
		retry = true
		return
	}

	return false, err
}
