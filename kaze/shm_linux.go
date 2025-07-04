package kaze

import (
	"path"

	"golang.org/x/sys/unix"
)

const shmPrefix = "/dev/shm/"

// Unlink removes the shared memory object with the given name.
func Unlink(name string) error {
	return unix.Unlink(path.Join(shmPrefix, name))
}

func shm_open(name string, mode int, perm uint32) (int, error) {
	return unix.Open(path.Join(shmPrefix, name), mode, perm)
}
