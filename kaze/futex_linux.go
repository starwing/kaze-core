package kaze

import (
	"math"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	FUTEX_WAIT uintptr = 0
	FUTEX_WAKE uintptr = 1
)

func init() {
	_, _, err := unix.Syscall6(unix.SYS_FUTEX_WAITV,
		0, 0, 0, 0, 0, 0)
	if err != unix.ENOSYS {
		support_futex_waitv = true
	}
}

func futex_waitv(waiters []futex_waiter, millis int) error {
	if millis <= 0 {
		// specifying NULL would prevent the call from being interruptable
		// cf. https://outerproduct.net/futex-dictionary.html#linux
		millis = math.MaxInt32 // a long time
	}

	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return err
	}

	ts.Sec += int64(millis / 1e3)
	ts.Nsec += int64(millis%1e3) * 1e6
	if ts.Nsec >= 1e9 {
		ts.Sec++
		ts.Nsec -= 1e9
	}
	r, _, err := unix.Syscall6(unix.SYS_FUTEX_WAITV,
		uintptr(unsafe.Pointer(&waiters[0])),
		uintptr(len(waiters)),
		0,
		uintptr(unsafe.Pointer(&ts)),
		unix.CLOCK_MONOTONIC,
		0)
	if int32(r) >= 0 {
		return nil
	}
	if err == unix.ETIMEDOUT {
		return ErrTimeout
	}
	if err == unix.EAGAIN {
		return nil
	}
	return err
}

func futex_wait(addr *atomic.Uint32, if_value uint32, millis int) error {
	if millis <= 0 {
		// specifying NULL would prevent the call from being interruptable
		// cf. https://outerproduct.net/futex-dictionary.html#linux
		millis = math.MaxInt32 // a long time
	}

	var ts unix.Timespec
	ts.Sec = int64(millis) / 1e3
	ts.Nsec = int64(millis) % 1e3 * 1e6
	r, _, err := unix.Syscall6(unix.SYS_FUTEX,
		uintptr(unsafe.Pointer(addr)),
		FUTEX_WAIT,
		uintptr(if_value),
		uintptr(unsafe.Pointer(&ts)),
		0,
		0)
	if int32(r) >= 0 {
		return nil
	}
	if err == unix.ETIMEDOUT {
		return ErrTimeout
	}
	if err == unix.EAGAIN {
		return nil
	}
	return err
}

func futex_wake(addr *atomic.Uint32, wakeAll bool) error {
	wake := uintptr(0)
	if wakeAll {
		wake = uintptr(1)
	}
	r, _, err := unix.Syscall(unix.SYS_FUTEX,
		uintptr(unsafe.Pointer(addr)),
		FUTEX_WAKE,
		wake)
	if int32(r) >= 0 || err == unix.ENOENT {
		return nil
	}
	return err
}
