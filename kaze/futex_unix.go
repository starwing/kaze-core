//go:build !windows
// +build !windows

package kaze

import (
	"sync/atomic"
	"unsafe"
)

var support_futex_waitv = false

type futex_waiter struct {
	val        uint64
	uaddr      uint64
	flags      uint32
	__reserved uint32
}

func new_waiter(uaddr *atomic.Uint32, if_value uint32) futex_waiter { //nolint:unusedfunc
	const FUTEX2_SIZE_U32 uint32 = 3
	return futex_waiter{
		val:        uint64(if_value),
		uaddr:      uint64(uintptr(unsafe.Pointer(uaddr))),
		flags:      FUTEX2_SIZE_U32,
		__reserved: 0,
	}
}
