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

	k := &Channel{
		name: name,
	}
	k.init()

	if cfg.create {
		sizeOfHdr := int(unsafe.Sizeof(shmHdr{}))
		shmSize := align(sizeOfHdr+cfg.buf_size, queue_align)
		queuSize := (shmSize - sizeOfHdr) / 2
		if queuSize < prefixSize*2 || queuSize >= int(mark) {
			return nil, os.ErrInvalid
		}
		k.shm_size = shmSize
		if err := k.createShm(cfg.excl, cfg.reset); err != nil {
			k.Close()
			return nil, err
		}
	} else {
		if err := k.openShm(); err != nil {
			k.Close()
			return nil, err
		}
	}

	return k, nil
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
	_, err1 := k.read.used()
	_, err2 := k.write.used()
	return NotReady.SetRead(err1 == os.ErrClosed).SetWrite(err2 == os.ErrClosed)
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
	return (s & Read) == Read
}

func (s Mode) CanWrite() bool {
	return (s & Write) == Write
}

func (s Mode) CanReadAndWrite() bool {
	return (s & Both) == Both
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
	if k == nil || k.hdr == nil {
		return 0, os.ErrClosed
	}
	var m mux
	m.need = k.write.calcNeed(requsted)
	if m.need > k.write.size() {
		return 0, ErrTooBig
	}
	r, err := m.Check(k)
	if err != nil {
		return 0, err
	}
	if timeout == 0 {
		return r, nil
	}
	for r == 0 {
		m.seq = k.write.info.seq.Load()
		k.write.info.need.CompareAndSwap(0, m.need)
		err = k.waitMux(m, int(timeout.Milliseconds()))
		k.write.info.need.CompareAndSwap(m.need, 0)
		if err != nil {
			return 0, err
		}
		r, err = m.Check(k)
		if timeout > 0 && err == nil {
			return 0, ErrTimeout
		}
		if err != nil {
			return 0, err
		}
	}
	return r, err
}

type mux struct {
	wused uint32 // number of bytes used in write queue
	rused uint32 // number of bytes used in read queue
	need  uint32 // number of bytes requested for write
	seq   uint32 // sequence number for wakeup
}

func (m mux) Check(k *Channel) (Mode, error) {
	var err1, err2 error
	m.wused, err1 = k.write.used()
	m.rused, err2 = k.read.used()
	if err1 != nil || err2 != nil {
		return 0, os.ErrClosed
	}
	can_write := (k.write.size()-m.wused >= m.need)
	can_read := (m.rused != 0)
	return NotReady.SetRead(can_read).SetWrite(can_write), nil
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
	if k.hdr == nil {
		return Context{}, os.ErrClosed
	}
	used, err := k.read.used()
	if err != nil {
		return Context{}, err
	}

	ctx := Context{state: &k.read}
	if !k.read.info.reading.CompareAndSwap(0, 1) {
		return Context{}, ErrBusy
	}
	ctx.result = ctx.pop(used)
	return ctx, ctx.result
}

func (k *Channel) WriteContext(request int) (Context, error) {
	if k.hdr == nil {
		return Context{}, os.ErrClosed
	}
	used, err := k.write.used()
	if err != nil {
		return Context{}, err
	}

	need := k.write.calcNeed(request)
	if need > k.write.size() {
		return Context{}, ErrTooBig
	}

	ctx := Context{state: &k.write}
	if !k.write.info.writing.CompareAndSwap(0, 1) {
		return Context{}, ErrBusy
	}

	ctx.len = uint32(need)
	ctx.result = ctx.push(used, need)
	return ctx, ctx.result
}

type Context struct {
	state  *queueState
	result error
	pos    uint32
	len    uint32
	batch  bool
}

func (c Context) Cancel() {
	if c.state.isRead() {
		c.state.info.reading.CompareAndSwap(1, 0)
	} else {
		c.state.info.writing.CompareAndSwap(1, 0)
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

func (c *Context) SetNotify(v bool) {
	c.batch = !v
}

func (c *Context) Wait() error {
	return c.WaitUtil(-1)
}

func (c *Context) WaitUtil(timeout time.Duration) error {
	if c.result != ErrAgain {
		return c.result
	}
	used, err := c.checkWait()
	if timeout == 0 {
		c.result = err
		return err
	}
	for {
		if err == ErrAgain {
			if c.state.isRead() {
				err = c.state.waitPop(used, int(timeout.Milliseconds()))
			} else {
				err = c.state.waitPush(used, c.len, int(timeout.Milliseconds()))
			}
		}
		if err != nil && err != ErrAgain {
			return err
		}
		used, err = c.checkWait()
		if err != ErrAgain {
			break
		}
		if timeout >= 0 {
			c.result = err
			return ErrTimeout
		}
	}
	c.result = err
	return err
}

func (c *Context) checkWait() (uint32, error) {
	used, err := c.state.used()
	if err != nil {
		c.state.cancelOperateion()
		return 0, err
	}
	if c.state.isRead() {
		return used, c.pop(used)
	} else {
		return used, c.push(used, c.len)
	}
}

func (c *Context) push(used, need uint32) error {
	remain := c.state.size() - c.state.info.tail
	free := c.state.size() - used

	// check if there is enough space
	if free < need {
		return ErrAgain
	}

	// write the offset and the size
	if need > remain {
		binary.LittleEndian.PutUint32(c.state.data[c.state.info.tail:], mark)
		c.pos = 0
		c.len = uint32(free - remain)
	} else {
		c.pos = c.state.info.tail
		c.len = uint32(remain)
	}
	return nil
}

func (c *Context) pop(used uint32) error {
	// check if there is enough data
	if used == 0 {
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
	_, err := c.state.used()
	if err != nil {
		c.state.cancelOperateion()
		return err
	}

	size := uint32(align(prefixSize+len, queue_align))
	if size > c.len {
		return ErrTooBig
	}
	binary.LittleEndian.PutUint32(c.state.data[c.pos:], uint32(len))
	c.state.info.tail = (c.pos + size) % c.state.size()

	old_used := c.state.info.used.Add(size) - size
	if old_used == mark {
		c.state.cancelOperateion()
		return os.ErrClosed
	}
	if !c.batch {
		err = c.state.wakePop(old_used)
	}
	c.state.info.writing.Store(0)
	return err
}

func (c Context) commitPop() error {
	_, err := c.state.used()
	if err != nil {
		c.state.cancelOperateion()
		return err
	}

	size := uint32(align(int(c.len), queue_align))
	c.state.info.head = (c.pos + size) % c.state.size()

	new_used := c.state.info.used.Add(-size)
	if new_used+size == mark {
		c.state.cancelOperateion()
		return os.ErrClosed
	}
	if !c.batch {
		err = c.state.wakePush(new_used)
	}
	c.state.info.reading.Store(0)
	return err
}
