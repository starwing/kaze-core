//go:build unix
// +build unix

package kaze

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const default_perm = 0o666

// Channel represents a shared memory channel.
// It provides methods to create, open, and manage the shared memory object.
// It also provides methods to close the channel and release all resources.
// The channel is used for inter-process communication (IPC) using shared memory.
type Channel struct {
	self_pid int
	shm_fd   int
	shm_size int
	hdr      *shmHdr
	write    queueState
	read     queueState
	name     string
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
	if mode.CanRead() && k.read.info != nil {
		writing := &k.read.info.writing
		need := writing.Load()
		k.read.info.used.Store(closedMark)
		if writing.CompareAndSwap(need, noWait) {
			_ = futex_wake(writing, true)
		}
	}
	reading := &k.write.info.reading
	state := reading.Load()
	if mode.CanReadAndWrite() && state == waitBoth ||
		mode.CanWrite() && state == waitRead {
		k.write.info.used.Store(closedMark)
		if reading.CompareAndSwap(state, noWait) {
			_ = futex_wake(reading, true)
		}
	}
}

func (k *Channel) init() {
	k.shm_fd = -1
	k.self_pid = unix.Getpid()
}

func (k *Channel) waitMux(m mux, millis int64) (err error) {
	if m.mode.CanWrite() {
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

func (k *Channel) createShm(excl bool, reset bool) error {
	mode := unix.O_CREAT | unix.O_RDWR
	if excl {
		mode = mode | unix.O_EXCL
	}
	fd, err := shm_open(k.name, mode, default_perm)
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

	// macOS: the size of the shared memory object may not same as ftruncate
	if err := unix.Fstat(k.shm_fd, &statbuf); err != nil {
		return fmt.Errorf("failed to fstat again err:%w", err)
	}
	k.shm_size = int(statbuf.Size)

	// init the shared memory object
	hdr_buf, err := unix.Mmap(k.shm_fd, 0, int(k.shm_size),
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return err
	}
	if created {
		for i := range hdr_buf {
			hdr_buf[i] = 0
		}
	}
	k.hdr = (*shmHdr)(unsafe.Pointer(&hdr_buf[0]))
	k.hdr.size = uint32(k.shm_size)

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

	var statbuf unix.Stat_t
	if err := unix.Fstat(fd, &statbuf); err != nil {
		return fmt.Errorf("failed to fstat err:%w", err)
	}

	if statbuf.Size == 0 {
		return os.ErrNotExist
	}

	k.shm_size = int(statbuf.Size)
	hdr_buf, err := unix.Mmap(k.shm_fd, 0, int(k.shm_size),
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return fmt.Errorf("failed to mmap err:%w", err)
	}

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

func pidExists(pid int) bool {
	err := unix.Kill(pid, 0)
	return err == nil || err == unix.EPERM
}
