package kaze

import (
	"fmt"
	"unsafe"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
)

/*
#include <sys/mman.h>

int shm_open2(const char *name, int oflag, int mode) {
  return shm_open(name, oflag, mode);
}
*/
import "C"

var (
	fnShmUnlink func(string) int32

	// use cgo
	// fnShmOpen uintptr

	fnError uintptr
)

func init() {
	// purego.RegisterLibFunc(&fnShmOpen, purego.RTLD_DEFAULT, "shm_open")
	purego.RegisterLibFunc(&fnShmUnlink, purego.RTLD_DEFAULT, "shm_unlink")
	fnError, _ = purego.Dlsym(purego.RTLD_DEFAULT, "__error")
	if fnError == 0 {
		panic("errno(__error) not found")
	}
}

func errno() unix.Errno {
	r, _, _ := purego.SyscallN(fnError)
	return unix.Errno(**(**uint32)(unsafe.Pointer(&r)))
}

func shm_open(name string, mode int, perm int32) (int, error) {
	// fd := fnShmOpen(name, int32(mode), perm)

	// can not use shm_open because it's a variadic function :-(
	fd := C.shm_open2(C.CString(name), C.int(mode), C.int(perm))
	fmt.Printf("fd=%d errno=%d\n", int(fd), uintptr(errno()))
	if int32(fd) < 0 {
		return 0, errno()
	}
	return int(fd), nil
}

func Exists(name string) (bool, error) {
	shm_fd, err := shm_open(name, unix.O_RDWR, default_perm)
	if err == unix.ENOENT {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	unix.Close(shm_fd)
	return true, nil
}

func Unlink(name string) error {
	// open shm file
	r := fnShmUnlink(name)
	fmt.Printf("shm_unlink: r=%d\n", int(r))

	if int32(r) < 0 {
		return errno()
	}

	return nil
}
