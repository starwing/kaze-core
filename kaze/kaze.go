package kaze

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"time"
	"unsafe"
)

const (
	NotReady = Mode(0)
	Read     = Mode(1 << 0)
	Write    = Mode(1 << 1)
	Both     = Mode(Read | Write)
)

var (
	ErrBusy    = errors.New("another routine are reading/writing")
	ErrAgain   = errors.New("operations will block")
	ErrTooBig  = errors.New("request size too big")
	ErrTimeout = errors.New("waiting timeout")
)

type config struct {
	create   bool
	excl     bool
	reset    bool
	buf_size int
}

type Opt func(*config)

func OptCreate(bufSize int) Opt {
	return func(c *config) {
		c.create = true
		c.buf_size = bufSize
	}
}
func OptExclude() Opt {
	return func(c *config) {
		c.excl = true
	}
}

func OptReset() Opt {
	return func(c *config) {
		c.reset = true
	}
}

func Create(name string, bufSize int, opts ...Opt) (*Channel, error) {
	return Open(name, append(opts, OptCreate(bufSize))...)
}

func Open(name string, opts ...Opt) (*Channel, error) {
	var cfg config
	for _, f := range opts {
		f(&cfg)
	}

	kaze := &Channel{
		name: name,
	}
	kaze.init()

	if cfg.create {
		sizeOfHdr := int(unsafe.Sizeof(shmHdr{}))
		shmSize := align(sizeOfHdr+cfg.buf_size, queue_align)
		queuSize := (shmSize - sizeOfHdr) / 2
		if queuSize < prefixSize*2 || queuSize >= int(mark) {
			return nil, os.ErrInvalid
		}
		kaze.shm_size = shmSize
		if err := kaze.createShm(cfg.excl, cfg.reset); err != nil {
			kaze.Close()
			return nil, err
		}
	} else {
		if err := kaze.openShm(); err != nil {
			kaze.Close()
			return nil, err
		}
	}

	return kaze, nil
}

func (k Channel) CloseAndUnlink() error {
	name := k.name
	k.Close()
	return Unlink(name)
}

func (k Channel) Name() string {
	return k.name
}

func (k Channel) Size() int {
	return int(k.hdr.queues[0].size)
}

func (k Channel) Pid() int {
	return k.self_pid
}

func (k Channel) IsOwner() bool {
	if k.hdr == nil {
		return false
	}
	if k.hdr.owner_pid == k.hdr.user_pid {
		return k.write.info == &k.hdr.queues[0]
	}
	return k.self_pid == int(k.hdr.owner_pid)
}

func (k Channel) IsClosed() Mode {
	if k.hdr == nil {
		return Both
	}
	return NotReady.SetRead(k.read.isClosed()).SetWrite(k.write.isClosed())
}

type Mode int

func (s Mode) String() string {
	switch {
	case s.CanReadAndWrite():
		return "Mode[Both]"
	case s.CanRead():
		return "Mode[Read]"
	case s.CanWrite():
		return "Mode[Write]"
	default:
		return "Mode[None]"
	}
}

func (s Mode) NotReady() bool {
	return s == 0
}

func (s Mode) CanRead() bool {
	return (s & Read) != 0
}

func (s Mode) CanWrite() bool {
	return (s & Write) != 0
}

func (s Mode) CanReadAndWrite() bool {
	return (s & Both) != 0
}

func (s Mode) SetRead(f ...bool) Mode {
	if len(f) == 0 {
		return s | Read
	}
	if f[0] {
		return s.SetRead()
	}
	return s
}

func (s Mode) SetWrite(f ...bool) Mode {
	if len(f) == 0 {
		return s | Write
	}
	if f[0] {
		return s.SetWrite()
	}
	return s
}

func (k *Channel) Check(requsted int) (Mode, error) {
	return k.WaitUtil(requsted, 0)
}

func (k *Channel) Wait(requsted int) (Mode, error) {
	return k.WaitUtil(requsted, -1)
}

func (k *Channel) WaitUtil(requsted int, timeout time.Duration) (Mode, error) {
	if k.hdr == nil || k.read.isClosed() || k.write.isClosed() {
		return 0, os.ErrClosed
	}

	need := k.write.calcNeed(requsted)
	if need > k.write.size() {
		return 0, ErrTooBig
	}

	canRead := (k.read.used() != 0)
	canWrite := (k.write.free() >= need)
	for {
		if timeout != 0 && !canRead && !canWrite {
			k.write.info.need.Store(uint32(need))
			err := k.waitMux(need, int(timeout.Milliseconds()))
			if err != nil && (timeout > 0 || err != ErrTimeout) {
				return 0, err
			}
			if k.read.isClosed() || k.write.isClosed() {
				return 0, os.ErrClosed
			}
			canRead = (k.read.used() != 0)
			canWrite = (k.write.free() >= need)
		}
		if canRead || canWrite || timeout >= 0 {
			return NotReady.SetRead(canRead).SetWrite(canWrite), nil
		}
	}
}

func (k *Channel) Read(b *bytes.Buffer) error {
	ctx, err := k.ReadContext()
	if err == ErrAgain {
		err = ctx.Wait()
	}
	if err != nil {
		return err
	}
	r := ctx.Buffer()
	rlen := len(r)
	_, _ = b.Write(r)
	err = ctx.Commit(rlen)
	if err != nil && err != os.ErrClosed {
		return err
	}
	return err
}

func (k *Channel) Write(b []byte) error {
	ctx, err := k.WriteContext(len(b))
	if err == ErrAgain {
		err = ctx.Wait()
	}
	if err != nil {
		return err
	}
	copy(ctx.Buffer(), b)
	return ctx.Commit(len(b))
}

func (k *Channel) ReadContext() (Context, error) {
	if k.hdr == nil || k.read.isClosed() {
		return Context{}, os.ErrClosed
	}

	ctx := Context{state: &k.read}
	if k.read.checkReading() {
		return Context{}, ctx.result
	}
	ctx.result = ctx.pop()
	return ctx, ctx.result
}

func (k *Channel) WriteContext(request int) (Context, error) {
	if k.hdr == nil || k.write.isClosed() {
		return Context{}, os.ErrClosed
	}

	need := k.write.calcNeed(request)
	if need > k.write.size() {
		return Context{}, ErrTooBig
	}

	ctx := Context{state: &k.write}
	if k.write.checkWriting() {
		return Context{}, ErrBusy
	}

	if err := ctx.push(need); err != nil {
		if err == ErrAgain {
			ctx.pos = 0
			ctx.len = uint32(need)
			k.write.info.need.Store(uint32(need))
		}
		ctx.result = err
		return ctx, ctx.result
	}
	return ctx, nil
}

type Context struct {
	state  *queueState
	result error
	pos    uint32
	len    uint32
}

func (c Context) Cancel() {
	if c.state.isRead() {
		c.state.info.reading.CompareAndSwap(1, 0)
	} else {
		if c.state.info.writing.CompareAndSwap(1, 0) {
			c.state.info.need.Store(0)
		}
	}
}

func (c Context) Result() error {
	return c.result
}

func (c Context) Buffer() []byte {
	if c.result != nil {
		return nil
	}
	return c.state.data[prefixSize+int(c.pos):][:int(c.len)-prefixSize]
}

func (c Context) Commit(size int) error {
	if c.result != nil {
		return c.result
	}
	if c.state.isRead() {
		return c.commitPop()
	} else {
		return c.commitPush(size)
	}
}

func (c *Context) Wait() error {
	return c.WaitUtil(-1)
}

func (c *Context) WaitUtil(timeout time.Duration) error {
	if c.result != ErrAgain {
		return c.result
	}
	for {
		var err error
		if c.state.isRead() {
			err = c.state.waitPop(int(timeout.Milliseconds()))
			if err == nil {
				err = c.pop()
			}
		} else {
			err = c.state.waitPush(int(c.len), int(timeout.Milliseconds()))
			if err == nil {
				err = c.push(int(c.len))
			}
		}
		if err == ErrAgain {
			err = ErrTimeout
		}
		if timeout >= 0 || err != ErrTimeout {
			c.result = err
			return err
		}
	}
}

func (c *Context) push(need int) error {
	remain := c.state.size() - int(c.state.info.tail)

	// check if there is enough space
	free_size := c.state.free()
	if free_size < need {
		return ErrAgain
	}

	// write the offset and the size
	c.state.info.need.Store(0)
	if need > remain {
		binary.LittleEndian.PutUint32(c.state.data[c.state.info.tail:], mark)
		c.pos = 0
		c.len = uint32(free_size - remain)
	} else {
		c.pos = c.state.info.tail
		c.len = uint32(remain)
	}
	return nil
}

func (c *Context) pop() error {
	// check if there is enough data
	used_size := c.state.used()
	if used_size == 0 {
		return ErrAgain
	}

	// read the size of the data
	c.pos = c.state.info.head
	c.len = binary.LittleEndian.Uint32(c.state.data[c.pos:])
	if c.len == mark {
		c.pos = 0
		c.len = binary.LittleEndian.Uint32(c.state.data[c.pos:])
	}
	c.len += uint32(prefixSize)
	return nil
}

func (c Context) commitPush(len int) error {
	if c.state.isClosed() {
		return os.ErrClosed
	}

	size := align(prefixSize+len, queue_align)
	if size > int(c.len) {
		return ErrTooBig
	}
	binary.LittleEndian.PutUint32(c.state.data[c.pos:], uint32(len))
	c.state.info.tail = (c.pos + uint32(size)) % uint32(c.state.size())

	old_used := c.state.info.used.Add((uint32)(size)) - (uint32)(size)
	err := c.state.wakePop(int(old_used))
	c.state.info.writing.Store(0)
	return err
}

func (c Context) commitPop() error {
	if c.state.isClosed() {
		return os.ErrClosed
	}

	size := align(int(c.len), queue_align)
	c.state.info.head = (c.pos + uint32(size)) % uint32(c.state.size())

	new_used := c.state.info.used.Add((uint32)(-size))
	err := c.state.wakePush(int(new_used))
	c.state.info.reading.Store(0)
	return err
}
