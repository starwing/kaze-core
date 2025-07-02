package kaze

import (
	"sync/atomic"
	"unsafe"

	"syscall"
)

// futex_wait waits until the value at addr changes from ifValue or timeout occurs.
// timeoutMillis <= 0 means wait indefinitely.
// Returns:
// - nil on success
// - ErrTimeout if timeout expired
// - syscall.Errno on other errors
func futex_wait(addr *atomic.Uint32, ifValue uint32, millis int64) error {
	var errno error
	ret := 0
	if millis < 0 {
		// Use the libc implementation for indefinite wait
		ret, errno = OsSyncWaitOnAddress(
			unsafe.Pointer(addr),
			uint64(ifValue),
			unsafe.Sizeof(*addr),
			OS_SYNC_WAIT_ON_ADDRESS_SHARED)
	} else {
		// Use the libc implementation for timed wait
		ret, errno = OsSyncWaitOnAddressWithTimeout(
			unsafe.Pointer(addr),
			uint64(ifValue),
			unsafe.Sizeof(*addr),
			OS_SYNC_WAIT_ON_ADDRESS_SHARED,
			OS_CLOCK_MACH_ABSOLUTE_TIME,
			uint64(millis)*1e6) // Convert millis to nanoseconds
	}

	if int32(ret) >= 0 {
		return nil
	}
	if errno == syscall.ETIMEDOUT {
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
	for {
		var errno error
		ret := 0
		if wakeAll {
			ret, errno = OsSyncWakeByAddressAll(
				unsafe.Pointer(addr),
				unsafe.Sizeof(*addr),
				OS_SYNC_WAKE_BY_ADDRESS_SHARED)
		} else {
			ret, errno = OsSyncWakeByAddressAny(
				unsafe.Pointer(addr),
				unsafe.Sizeof(*addr),
				OS_SYNC_WAKE_BY_ADDRESS_SHARED)
		}

		if int32(ret) >= 0 {
			return nil
		}

		// Handle special error cases
		if errno == syscall.ENOENT {
			// No threads to wake, not really an error
			return nil
		}

		if errno == syscall.EINTR {
			continue
		}

		return errno
	}
}

// Imported functions from libc, TODO: use ulock* routines before macOS 14.4
const (
	OS_CLOCK_MACH_ABSOLUTE_TIME    = 32
	OS_SYNC_WAIT_ON_ADDRESS_SHARED = 1
	OS_SYNC_WAKE_BY_ADDRESS_SHARED = 1
)

//go:linkname syscall_rawSyscall syscall.rawSyscall
func syscall_rawSyscall(fn, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno)

//go:linkname syscall_syscall6 syscall.syscall6
func syscall_syscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)

//go:cgo_import_dynamic libc_os_sync_wait_on_address os_sync_wait_on_address "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_os_sync_wait_on_address_with_timeout os_sync_wait_on_address_with_timeout "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_os_sync_wake_by_address_any os_sync_wake_by_address_any "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_os_sync_wake_by_address_all os_sync_wake_by_address_all "/usr/lib/libSystem.B.dylib"

var libc_os_sync_wait_on_address_trampoline_addr uintptr
var libc_os_sync_wait_on_address_with_timeout_trampoline_addr uintptr
var libc_os_sync_wake_by_address_any_trampoline_addr uintptr
var libc_os_sync_wake_by_address_all_trampoline_addr uintptr

func OsSyncWaitOnAddress(addr unsafe.Pointer, value uint64, size uintptr,
	flags uint32) (int, syscall.Errno) {
	r0, _, e1 := syscall_syscall6(
		libc_os_sync_wait_on_address_trampoline_addr,
		uintptr(addr),
		uintptr(value),
		size,
		uintptr(flags),
		0, 0,
	)
	return int(r0), e1
}

func OsSyncWaitOnAddressWithTimeout(addr unsafe.Pointer, value uint64,
	size uintptr, flags uint32, clockid uint32, timeout_ns uint64) (int, syscall.Errno) {
	r0, _, e1 := syscall_syscall6(
		libc_os_sync_wait_on_address_with_timeout_trampoline_addr,
		uintptr(addr),
		uintptr(value),
		size,
		uintptr(flags),
		uintptr(clockid),
		uintptr(timeout_ns),
	)
	return int(r0), e1
}

func OsSyncWakeByAddressAny(addr unsafe.Pointer, size uintptr, flags uint32) (int, syscall.Errno) {
	r0, _, e1 := syscall_rawSyscall(
		libc_os_sync_wake_by_address_any_trampoline_addr,
		uintptr(addr),
		size,
		uintptr(flags),
	)
	return int(r0), e1
}

func OsSyncWakeByAddressAll(addr unsafe.Pointer, size uintptr, flags uint32) (int, syscall.Errno) {
	r0, _, e1 := syscall_rawSyscall(
		libc_os_sync_wake_by_address_all_trampoline_addr,
		uintptr(addr),
		size,
		uintptr(flags),
	)
	return int(r0), e1
}
