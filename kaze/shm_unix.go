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

type Channel struct {
	self_pid int
	shm_fd   int
	shm_size int
	hdr      *shmHdr
	write    queueState
	read     queueState
	name     string
}

func (k *Channel) init() {
	k.shm_fd = -1
	k.self_pid = unix.Getpid()
}

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

func (k *Channel) Shutdown(mode Mode) {
	waked := false
	if mode.CanRead() {
		k.read.info.used.Store(mark)
		k.read.info.need.Store(0)
		if k.read.info.writing.Load() > 0 {
			waked = true
			_ = futex_wake(&k.read.info.need, true)
		}
	}
	if mode.CanWrite() {
		k.write.info.used.Store(mark)
		k.write.info.need.Store(0)
		if k.write.info.reading.Load() > 0 {
			waked = true
			_ = futex_wake(&k.write.info.used, true)
		}
	}
	waiters := &k.read.info.waiters
	if (mode.CanRead() || mode.CanWrite()) && int32(waiters.Load()) > 0 {
		if support_futex_waitv {
			if !waked {
				_ = futex_wake(&k.write.info.used, true)
			}
		} else {
			_ = futex_wake(&k.read.info.seq, true)
		}
	}
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
		k.resetQueues()
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

	k.resetQueues()
	return nil
}

func (k *Channel) waitMux(old_seq uint32, need, millis int) (err error) {
	waiters := &k.write.info.waiters
	waiters.Add(1)
	if support_futex_waitv {
		waiters := []futex_waiter{
			new_waiter(&k.read.info.used, 0),
			new_waiter(&k.write.info.need, uint32(need)),
		}
		err = futex_waitv(waiters, millis)
	} else {
		err = futex_wait(&k.write.info.seq, old_seq, millis)
	}
	waiters.Add(^uint32(1) + 1)
	return
}

func pidExists(pid int) bool {
	err := unix.Kill(pid, 0)
	return err == nil || err == unix.EPERM
}
