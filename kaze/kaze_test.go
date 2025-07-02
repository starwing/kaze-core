package kaze

import (
	"bytes"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNormal(t *testing.T) {
	fmt.Println("TestNormal start")
	shmName := "test-normal"
	_ = Unlink(shmName)
	err := Unlink(shmName)
	assert.Equal(t, os.ErrNotExist, err)
	exists, err := Exists(shmName)
	assert.NoError(t, err)
	assert.False(t, exists)

	owner, err := Create(shmName, 1024, OptPerm(0600))
	assert.NoError(t, err)
	assert.Equal(t, shmName, owner.Name())
	assert.True(t, owner.IsOwner())
	assert.NotZero(t, owner.Pid())

	exists, err = Exists(shmName)
	assert.NoError(t, err)
	assert.True(t, exists)

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
			fmt.Printf("[echo] before wait read\n")
			buf.Reset()
			err := user.Read(&buf)
			fmt.Printf("[echo] after read, err=%s\n", err)
			if err == os.ErrClosed {
				break
			}
			assert.NoError(t, err)
			if err != nil {
				fmt.Printf("[echo] read err:%s\n", err.Error())
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
				fmt.Printf("[echo] write err:%s\n", err.Error())
				break
			}
			trans++
			fmt.Printf("[echo] trans=%d\n", trans)
		}
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
		fmt.Printf("[send] do shutdown\n")
		owner.Shutdown(Both)
	})
	fmt.Printf("after send\n")
}

func TestErrors(t *testing.T) {
	shmName := "test-normal"
	_ = Unlink(shmName)

	_, err := Open(shmName)
	assert.Error(t, err)

	_, err = Create(shmName, 0)
	assert.Error(t, err)

	_, err = Create(shmName, MaxQueueSize)
	assert.Error(t, err)

	owner, err := Create(shmName, 1024, OptReset(), OptExclude())
	assert.NoError(t, err)
	defer owner.CloseAndUnlink()

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
