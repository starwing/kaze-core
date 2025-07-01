//go:build unix
// +build unix

package kaze

import (
	"sync/atomic"
	"testing"
	"time"
	_ "unsafe"

	"github.com/stretchr/testify/assert"
)

func TestFutex(t *testing.T) {
	var flag atomic.Uint32
	go func() {
		time.Sleep(10 * time.Millisecond)
		flag.Store(1)
		err := futex_wake(&flag, false)
		assert.NoError(t, err)
	}()
	err := futex_wait(&flag, 0, -1)
	assert.NoError(t, err)

	assert.Equal(t, 1, 1)
}
