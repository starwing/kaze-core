package kaze

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestShmOpen(t *testing.T) {
	shmName := "test-double-open"

	err := Unlink(shmName)
	if err == unix.ENOENT {
		err = nil
	}
	assert.NoError(t, err)

	r, err := Exists(shmName)
	assert.NoError(t, err)
	assert.False(t, r)

	fd, err := shm_open(shmName, unix.O_CREAT|unix.O_RDWR, 0o666)
	assert.NoError(t, err)
	assert.True(t, fd >= 0)
	defer unix.Close(fd)
	defer func() {
		_ = Unlink(shmName)
	}()

	fd2, err := shm_open(shmName, unix.O_RDWR, 0x666)
	assert.NoError(t, err)
	assert.True(t, fd2 >= 0)
	defer unix.Close(fd2)
}
