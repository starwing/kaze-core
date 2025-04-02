package kaze

import (
	"errors"
	"io/fs"
	"os"
	"path"

	"golang.org/x/sys/unix"
)

const shmPrefix = "/dev/shm/"

func shm_open(name string, mode int, perm uint32) (int, error) {
	return unix.Open(path.Join(shmPrefix, name), mode, perm)
}

func Exists(name string) (bool, error) {
	_, err := os.Stat(path.Join(shmPrefix, name))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func Unlink(name string) error {
	return unix.Unlink(path.Join(shmPrefix, name))
}
