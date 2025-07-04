//go:build unix
// +build unix

package kaze

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

type shmHandle = int

// Exists checks if a shared memory object with the given name exists.
func Exists(name string) (ExistInfo, error) {
	shm_fd, err := shm_open(name, syscall.O_RDWR, 0)
	if err != nil {
		if err == syscall.ENOENT {
			return ExistInfo{}, nil
		}
		return ExistInfo{}, err
	}
	defer syscall.Close(shm_fd)
	hdr_buf, err := mapShm(shm_fd)
	if err != nil {
		return ExistInfo{Exists: true}, err
	}
	hdr := (*shmHdr)(unsafe.Pointer(&hdr_buf[0]))
	return ExistInfo{
		Exists:   true,
		OwnerPid: int(hdr.owner_pid),
		UserPid:  int(hdr.user_pid),
	}, nil
}

// Close closes the channel and releases all resources.
func (k *Channel) Close() {
	k.Shutdown(Both)
	if k.hdr != nil {
		_ = unix.Munmap(unsafe.Slice((*byte)((unsafe.Pointer(k.hdr))), k.shm_size))
		k.hdr = nil
	}
	if k.shm_fd >= 0 {
		_ = unix.Close(k.shm_fd)
		k.shm_fd = -1
	}
}

// Shutdown close the channel and wake up all waiting goroutines.
// The mode parameter specifies the shutdown mode, which can be read, write, or
// both.
// If mode.CanRead() is true, it closes the read queue and sets the used mark.
// If mode.CanWrite() is true, it closes the write queue and sets the used mark.
// It will signal the opposite queue to wake up any waiting operations.
// If the channel is already closed, it does nothing.
// This method is idempotent, meaning it can be called multiple times without side effects.
// It is safe to call this method from multiple goroutines concurrently.
// The method does not return an error, as it is designed to be robust against multiple calls.
func (k *Channel) Shutdown(mode State) {
	if k.hdr == nil || mode.NotReady() {
		return
	}
	if mode.CanWrite() {
		k.write.info.used.Add(closeMask)
	}
	reading := &k.write.info.reading
	state := reading.Load()
	if (state == waitBoth || (mode.CanWrite() && state == waitRead)) &&
		reading.CompareAndSwap(state, noWait) {
		_ = futex_wake(reading, true)
	}
	if mode.CanRead() {
		k.read.info.used.Add(closeMask)
		writing := &k.read.info.writing
		need := writing.Load()
		if int32(need) > 0 && writing.CompareAndSwap(need, noWait) {
			_ = futex_wake(writing, true)
		}
	}
}

func (k *Channel) init() {
	k.shm_fd = -1
	k.self_pid = unix.Getpid()
}

func (k *Channel) waitMux(m mux, millis int64) (err error) {
	if m.mode == Write {
		err = futex_wait(&k.write.info.writing, m.need, millis)
	} else {
		reading := &k.read.info.reading
		state := waitRead
		if m.mode.CanReadAndWrite() {
			state = waitBoth
		}
		err = futex_wait(reading, state, millis)
	}
	if err == ErrTimeout {
		err = nil
	}
	return
}

func (k *Channel) createShm(excl bool, reset bool, perm uint32) error {
	mode := unix.O_CREAT | unix.O_RDWR
	if excl {
		mode = mode | unix.O_EXCL
	}
	fd, err := shm_open(k.name, mode, perm)
	if err != nil {
		return fmt.Errorf("failed to shm_open err:%w", err)
	}
	k.shm_fd = fd

	// check if the file already exists
	var statbuf unix.Stat_t
	if err := unix.Fstat(k.shm_fd, &statbuf); err != nil {
		return fmt.Errorf("failed to fstat err:%w", err)
	}

	if (mode&unix.O_EXCL) != 0 && statbuf.Size != 0 {
		return os.ErrExist
	}

	created := (statbuf.Size == 0) || reset

	// set the size of the shared memory object
	if created {
		if err := unix.Ftruncate(k.shm_fd, int64(k.shm_size)); err != nil {
			return fmt.Errorf("failed to ftruncate err:%w", err)
		}
	}

	hdr_buf, err := mapShm(k.shm_fd)
	if err != nil {
		return fmt.Errorf("failed to mmap shared memory err:%w", err)
	}
	// macOS shared memory size may larger than requested size,
	// use the real size retrieved from map
	k.shm_size = len(hdr_buf)
	k.hdr = (*shmHdr)(unsafe.Pointer(&hdr_buf[0]))
	if created {
		*k.hdr = shmHdr{}
	}
	k.hdr.size = uint32(len(hdr_buf))

	if k.hdr.owner_pid != 0 && int(k.hdr.owner_pid) != k.self_pid &&
		pidExists(int(k.hdr.owner_pid)) {
		return os.ErrPermission
	}

	if created {
		k.initQueues()
	} else {
		k.resetQueues(true)
	}
	return nil
}

func (k *Channel) openShm() error {
	fd, err := shm_open(k.name, unix.O_RDWR, default_perm)
	if err != nil {
		return fmt.Errorf("failed to shm_open err:%w", err)
	}

	k.shm_fd = fd

	hdr_buf, err := mapShm(fd)
	if err != nil {
		return fmt.Errorf("failed to mmap shared memory err:%w", err)
	}

	k.shm_size = len(hdr_buf)
	k.hdr = (*shmHdr)(unsafe.Pointer(&hdr_buf[0]))
	if k.shm_size != int(k.hdr.size) {
		return os.ErrInvalid
	}

	if k.hdr.user_pid != 0 && int(k.hdr.user_pid) != k.self_pid &&
		pidExists(int(k.hdr.user_pid)) {
		return os.ErrPermission
	}

	k.resetQueues(false)
	return nil
}

func mapShm(fd shmHandle) ([]byte, error) {
	var statbuf unix.Stat_t
	if err := unix.Fstat(fd, &statbuf); err != nil {
		return nil, fmt.Errorf("failed to fstat err:%w", err)
	}
	if statbuf.Size == 0 {
		return nil, os.ErrNotExist
	}
	hdr_buf, err := unix.Mmap(fd, 0, int(statbuf.Size),
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("failed to mmap shared memory: %w", err)
	}
	return hdr_buf, nil
}

func pidExists(pid int) bool {
	err := unix.Kill(pid, 0)
	return err == nil || err == unix.EPERM
}
