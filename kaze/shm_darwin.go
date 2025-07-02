package kaze

import (
	"os"
	"syscall"
	"unsafe"
)

func shm_open(name string, mode int, perm uint32) (int, error) {
	namePtr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return -1, err
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

// Exists checks if a shared memory object with the given name exists.
func Exists(name string) (bool, error) {
	shm_fd, err := shm_open(name, syscall.O_RDWR, 0)
	if err == syscall.ENOENT {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	syscall.Close(shm_fd)
	return true, nil
}

// Unlink removes the shared memory object with the given name.
func Unlink(name string) error {
	namePtr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}

	_, _, errno := syscall.RawSyscall(
		syscall.SYS_SHM_UNLINK,
		uintptr(unsafe.Pointer(namePtr)),
		0, 0)

	if errno == 0 {
		return nil
	}
	if errno == syscall.ENOENT {
		// If the file does not exist, we return standard error
		return os.ErrNotExist
	}
	return errno
}
