package kaze

import (
	"os"
	"syscall"
	"unsafe"
)

// Unlink removes the shared memory object with the given name.
func Unlink(name string) error {
	namePtr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return os.ErrInvalid
	}

	_, _, errno := syscall.RawSyscall(
		syscall.SYS_SHM_UNLINK,
		uintptr(unsafe.Pointer(namePtr)),
		0, 0)

	if errno == 0 {
		return nil
	}
	return errno
}

func shm_open(name string, mode int, perm uint32) (int, error) {
	namePtr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return -1, os.ErrInvalid
	}

	fd, _, errno := syscall.RawSyscall(
		syscall.SYS_SHM_OPEN,
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(mode),
		uintptr(perm))

	if int32(fd) < 0 {
		return 0, errno
	}
	return int(fd), nil
}
