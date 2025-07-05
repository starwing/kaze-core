package kaze

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStructAlignment(t *testing.T) {
	// Verify shmHdr matches kz_ShmHdr
	hdr := shmHdr{} //nolint:staticcheck
	assert.Equal(t, 16, int(unsafe.Sizeof(hdr.size)+unsafe.Sizeof(hdr.queue_size)+
		unsafe.Sizeof(hdr.owner_pid)+unsafe.Sizeof(hdr.user_pid)))

	// Each queue should be cache-line aligned
	queue := shmQueue{} //nolint:staticcheck
	queueSize := int(unsafe.Sizeof(queue))
	expectedSize := 3 * 64 // 3 cache lines * 64 bytes
	assert.Equal(t, expectedSize, queueSize,
		"shmQueue size should match C kz_ShmQueue")
}

func TestNormal(t *testing.T) {
	fmt.Println("TestNormal start")
	shmName := "test-normal"
	_ = Unlink(shmName)
	err := Unlink(shmName)
	assert.True(t, errors.Is(err, os.ErrNotExist))
	info, err := Exists(shmName)
	assert.NoError(t, err)
	assert.False(t, info.Exists)

	owner, err := Create(shmName, 1024, OptPerm(0600))
	assert.NoError(t, err)
	assert.Equal(t, shmName, owner.Name())
	assert.True(t, owner.IsOwner())
	assert.NotZero(t, owner.Pid())

	info, err = Exists(shmName)
	assert.NoError(t, err)
	assert.True(t, info.Exists)

	data := []byte("1234567890123") // 13+4 = 17, need 20 bytes
	count := (owner.Size() / len(data)) * 3

	var closed atomic.Bool

	fmt.Printf("before echo\n")
	t.Run("echo", func(t *testing.T) {
		user, err := Open(shmName)
		assert.NoError(t, err)
		defer user.Close()

		assert.Equal(t, shmName, user.Name())
		assert.False(t, user.IsOwner())

		t.Parallel()
		fmt.Printf("[echo] here to wait\n")
		var buf bytes.Buffer
		trans := 0
		for user.IsClosed().NotReady() {
			buf.Reset()
			fmt.Printf("[echo] before wait read trans=%d\n", trans)
			err := user.Read(&buf)
			fmt.Printf("[echo] after read\n")
			if err == os.ErrClosed {
				break
			}
			assert.NoError(t, err)
			if err != nil {
				break
			}
			assert.Equal(t, len(data), len(buf.Bytes()))
			if len(data) != len(buf.Bytes()) {
				break
			}
			err = user.Write(buf.Bytes())
			if err == os.ErrClosed {
				break
			}
			assert.NoError(t, err)
			if err != nil {
				break
			}
			trans++
		}
		fmt.Printf("[echo] trans=%d\n", trans)
		assert.Equal(t, count, trans)
		closed.Store(true)
	})

	fmt.Printf("after echo, before send\n")
	t.Run("send", func(t *testing.T) {
		defer owner.CloseAndUnlink()
		t.Parallel()

		readCount, writeCount := 0, 0
		var buf bytes.Buffer
		for readCount < count || writeCount < count {
			if closed.Load() {
				fmt.Printf("do exit")
				break
			}
			fmt.Printf("[send] before wait rc=%d wc=%d count=%d\n",
				readCount, writeCount, count)
			r, err := owner.Wait(len(data))
			assert.NoError(t, err)
			if err != nil {
				break
			}

			assert.False(t, r.NotReady())
			fmt.Printf("[send] wait result=%s\n", r.String())
			if r.CanRead() && readCount < count {
				buf.Reset()
				err := owner.Read(&buf)
				fmt.Printf("[send] after read, err=%s\n", err)
				assert.NoError(t, err)
				assert.Equal(t, data, buf.Bytes())
				readCount++
				fmt.Printf("[send] after read count=%d\n", readCount)
			}
			if r.CanWrite() && writeCount < count {
				err := owner.Write(data)
				fmt.Printf("[send] after write, err=%s\n", err)
				assert.NoError(t, err)
				writeCount++
				fmt.Printf("[send] after write count=%d\n", writeCount)
			}
		}
	})
	fmt.Printf("after send\n")
}

func TestErrors(t *testing.T) {
	shmName := "test-normal"
	_ = Unlink(shmName)

	_, err := Open(shmName)
	assert.True(t, errors.Is(err, os.ErrNotExist))

	_, err = Open("test\x00invalid")
	assert.True(t, errors.Is(err, os.ErrInvalid))

	_, err = Create(shmName, 0)
	assert.Error(t, err)

	_, err = Create(shmName, MaxQueueSize)
	assert.Error(t, err)

	owner, err := Create(shmName, 1024, OptReset(), OptExclude())
	assert.NoError(t, err)
	defer owner.CloseAndUnlink()

	user, err := Open(shmName)
	assert.NoError(t, err)
	user.Close()

	_, err = owner.WriteContext(MaxQueueSize)
	assert.Equal(t, os.ErrClosed, err)

	user, err = Open(shmName)
	assert.NoError(t, err)
	defer user.Close()

	ctx, err := owner.ReadContext()
	assert.Equal(t, ErrAgain, err)
	assert.Equal(t, ErrAgain, ctx.Result())
	assert.Equal(t, ErrAgain, ctx.Commit(0))

	_, err = owner.WriteContext(MaxQueueSize)
	assert.Equal(t, ErrTooBig, err)
	ctx, err = owner.WriteContext(0)
	assert.NoError(t, err)
	assert.Equal(t, ErrTooBig, ctx.Commit(MaxQueueSize))
	owner.Close()
	assert.Equal(t, os.ErrClosed, ctx.Commit(0))

	owner.Close()
	assert.False(t, owner.IsOwner())

	_, err = Create(shmName, 1024, OptReset(), OptExclude())
	assert.Error(t, err)
}

func TestMemoryBarriers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Memory barrier test not implemented for windows")
	}
	shmName := "test-barriers"

	owner, err := Create(shmName, 1024)
	require.NoError(t, err)
	defer owner.CloseAndUnlink()

	user, err := Open(shmName)
	require.NoError(t, err)
	defer user.Close()

	// Test that writes are visible across processes
	const iterations = 1000
	var readCount, writeCount int64

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		var buf bytes.Buffer
		for atomic.LoadInt64(&readCount) < iterations && ctx.Err() == nil {
			buf.Reset()
			if err := user.Read(&buf); err == nil {
				atomic.AddInt64(&readCount, 1)
			}
		}
	}()

	for atomic.LoadInt64(&writeCount) < iterations && ctx.Err() == nil {
		msg := []byte(fmt.Sprintf("msg_%d", writeCount))
		if err := owner.Write(msg); err == nil {
			atomic.AddInt64(&writeCount, 1)
		}
	}

	// Allow some time for final reads
	time.Sleep(100 * time.Millisecond)

	assert.Equal(t, int64(iterations), atomic.LoadInt64(&writeCount))
	assert.Equal(t, int64(iterations), atomic.LoadInt64(&readCount))
}

func TestTimeout(t *testing.T) {
	shmName := "test-timeout"
	owner, err := Create(shmName, 1024)
	assert.NoError(t, err)
	if err != nil {
		return
	}
	defer owner.CloseAndUnlink()

	ctx, err := owner.ReadContext()
	assert.Equal(t, ErrAgain, err)
	err = ctx.WaitUtil(100 * time.Millisecond)
	assert.Equal(t, ErrTimeout, err)
	ctx.Cancel()

	data := []byte("1234567890123")
	for {
		ctx, err := owner.WriteContext(len(data))
		if err == ErrAgain {
			ctx.Cancel()
			break
		}
		assert.NoError(t, err)
		copy(ctx.Buffer(), data)
		assert.NoError(t, ctx.Commit(len(data)))
	}
	ctx, err = owner.WriteContext(len(data))
	assert.Equal(t, ErrAgain, err)
	err = ctx.WaitUtil(100 * time.Millisecond)
	assert.Equal(t, ErrTimeout, err)
	ctx.Cancel()

	r, err := owner.WaitUtil(len(data), 100*time.Millisecond)
	assert.Equal(t, ErrTimeout, err)
	assert.True(t, r.NotReady())
}

func BenchmarkEcho(b *testing.B) {
	shmName := "bench-echo"
	_ = Unlink(shmName)

	owner, err := Create(shmName, 1024)
	if err != nil {
		assert.NoError(b, err)
		return
	}
	defer owner.CloseAndUnlink()

	go func() {
		user, err := Open(shmName)
		if err != nil {
			assert.NoError(b, err)
			owner.Close()
			return
		}
		defer user.Close()

		var buf bytes.Buffer
		readCount, writeCount := 0, 0
		data := []byte("1234567890123") // 13+4 = 17, need 20 bytes
		for readCount < b.N || writeCount < b.N {
			r := Both
			if readCount < b.N && writeCount < b.N {
				r, err = user.Wait(len(data))
				if err != nil {
					assert.NoError(b, err)
					break
				}
			}
			if r.CanRead() && readCount < b.N {
				buf.Reset()
				err := user.Read(&buf)
				if err != nil {
					assert.NoError(b, err)
				}
				readCount++
			}
			if r.CanWrite() && writeCount < b.N {
				err := user.Write(data)
				if err != nil {
					assert.NoError(b, err)
					return
				}
				writeCount++
			}
		}
	}()

	var buf bytes.Buffer
	b.ResetTimer()
	for owner.IsClosed().NotReady() {
		buf.Reset()

		err := owner.Read(&buf)
		if err != nil {
			if err != os.ErrClosed {
				assert.NoError(b, err)
			}
			break
		}
		err = owner.Write(buf.Bytes())
		if err != nil {
			if err != os.ErrClosed {
				assert.NoError(b, err)
			}
			break
		}
	}
}

func BenchmarkFlood(b *testing.B) {
	shmName := "bench-flood"
	_ = Unlink(shmName)

	owner, err := Create(shmName, 1024)
	assert.NoError(b, err)
	defer owner.CloseAndUnlink()

	go func() {
		user, err := Open(shmName)
		assert.NoError(b, err)
		defer user.Close()
		var buf bytes.Buffer
		for user.IsClosed().NotReady() {
			buf.Reset()
			err = user.Read(&buf)
			if err == os.ErrClosed {
				break
			}
			assert.NoError(b, err)
		}
	}()

	data := []byte("1234567890123") // 13+4 = 17, need 20 bytes
	b.ResetTimer()
	for b.Loop() {
		err = owner.Write(data)
		assert.NoError(b, err)
	}
	owner.Shutdown(Both)
}
