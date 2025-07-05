// Package kaze provides a high-performance, cross-platform, shared memory
// queue implementation that allows for efficient inter-process communication
// (IPC) using shared memory.
//
// Basic usage:
//
//	// Process 1 (Owner)
//	owner, err := kaze.Create("my-channel", 8192)
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer owner.CloseAndUnlink()
//
//	// Process 2 (User)
//	user, err := kaze.Open("my-channel")
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer user.Close()
//
//	// Communication
//	err = owner.Write([]byte("Hello"))
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	var buf bytes.Buffer
//	err = user.Read(&buf)
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Printf("Received: %s\n", buf.String())
package kaze

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"time"
	"unsafe"
)

const (
	// NotReady mode indicates that the channel
	// is not ready for any operations.
	NotReady = State(0)

	// Read mode.
	Read = State(1 << 0)

	// Write mode.
	Write = State(1 << 1)

	// Both mode indicates that the channel
	// is ready for both read and write operations.
	Both = State(Read | Write)
)

const (
	// MaxQueueSize is the maximum size of the queue.
	MaxQueueSize = 0xFFFFFFFF // 4 GiB
)

var (
	// ErrBusy returns when multiple routines are trying to read/write.
	ErrBusy = errors.New("another routine are reading/writing")

	// ErrAgain is returned when the operation cannot be
	// completed immediately.
	// you should call Wait() to wait for the channel is ready.
	ErrAgain = errors.New("operations will block")

	// ErrTooBig is returned when the requested space to write
	// is larger than the queue size.
	ErrTooBig = errors.New("request size too big")

	// ErrTimeout is returned when the operation timed out
	ErrTimeout = errors.New("waiting timeout")
)

// Channel represents a shared memory channel.
// It provides methods to create, open, and manage the shared memory object.
// It also provides methods to close the channel and release all resources.
// The channel is used for inter-process communication (IPC) using shared memory.
type Channel struct {
	self_pid int
	shm_fd   shmHandle
	shm_size int
	hdr      *shmHdr
	write    queue
	read     queue
	name     string
}

const default_perm = 0o666

// config holds the configuration options for creating or opening a channel.
type config struct {
	create   bool
	excl     bool
	reset    bool
	buf_size int
	perm     uint32
}

// Opt is a functional option type for configuring the channel.
type Opt func(*config)

// OptCreate is an option to create a new channel
// with a specified buffer.
func OptCreate(bufSize int) Opt {
	return func(c *config) {
		c.create = true
		c.buf_size = bufSize
	}
}

// OptPerm is an option to set the permissions for the shared memory object.
func OptPerm(perm uint32) Opt {
	return func(c *config) {
		c.perm = perm
	}
}

// OptExclude is an option to create a new channel
func OptExclude() Opt {
	return func(c *config) {
		c.excl = true
	}
}

// OptReset is an option to reset the channel.
func OptReset() Opt {
	return func(c *config) {
		c.reset = true
	}
}

// Create creates a new channel with the specified name and buffer size.
func Create(name string, bufSize int, opts ...Opt) (*Channel, error) {
	return Open(name, append(opts, OptCreate(bufSize))...)
}

// Open opens an existing channel with the specified name.
func Open(name string, opts ...Opt) (*Channel, error) {
	cfg := config{perm: default_perm}
	for _, f := range opts {
		f(&cfg)
	}

	k := &Channel{
		name: name,
	}
	k.init()

	if cfg.create {
		sizeOfHdr := int(unsafe.Sizeof(shmHdr{}))
		shmSize := align(sizeOfHdr+cfg.buf_size, queueAlign)
		queueSize := (shmSize - sizeOfHdr) / 2
		if queueSize < prefixSize*2 || queueSize >= int(closeMask) {
			return nil, os.ErrInvalid
		}
		k.shm_size = shmSize
		if err := k.createShm(cfg.excl, cfg.reset, cfg.perm); err != nil {
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

// CloseAndUnlink closes the channel and unlinks the shared memory object.
func (k *Channel) CloseAndUnlink() {
	name := k.name
	k.Close()
	_ = Unlink(name)
}

// Name returns the name of the channel.
func (k Channel) Name() string {
	return k.name
}

// Size returns the size of the channel in bytes.
func (k Channel) Size() int {
	return int(k.hdr.queue_size)
}

// Pid returns the process ID of the channel owner.
func (k Channel) Pid() int {
	return k.self_pid
}

// IsOwner checks if the current process is the owner of the channel.
func (k Channel) IsOwner() bool {
	if k.hdr == nil {
		return false
	}
	if k.hdr.owner_pid == k.hdr.user_pid {
		return k.write.info == &k.hdr.queues[0]
	}
	return k.self_pid == int(k.hdr.owner_pid)
}

// IsClosed checks if the channel is closed.
func (k Channel) IsClosed() State {
	if k.hdr == nil {
		return Both
	}
	_, err1 := k.read.used()
	_, err2 := k.write.used()
	return NotReady.SetRead(err1 == os.ErrClosed).SetWrite(err2 == os.ErrClosed)
}

// State represents the current state of the channel, indicating whether it can
// read, write, or both.
type State int

// String returns a string representation of the channel state.
func (s State) String() string {
	switch {
	case s.CanReadAndWrite():
		return "State[Both]"
	case s.CanRead():
		return "State[Read]"
	case s.CanWrite():
		return "State[Write]"
	default:
		return "State[None]"
	}
}

// NotReady checks if the channel is not ready for any operations.
func (s State) NotReady() bool {
	return s == 0
}

// CanRead checks if the channel can read data.
func (s State) CanRead() bool {
	return (s & Read) == Read
}

// CanWrite checks if the channel can write data.
func (s State) CanWrite() bool {
	return (s & Write) == Write
}

// CanReadAndWrite checks if the channel can both read and write data.
func (s State) CanReadAndWrite() bool {
	return (s & Both) == Both
}

// SetRead sets the read state.
func (s State) SetRead(f ...bool) State {
	if len(f) == 0 {
		return s | Read
	}
	if f[0] {
		return s.SetRead()
	}
	return s
}

// SetWrite sets the write state.
func (s State) SetWrite(f ...bool) State {
	if len(f) == 0 {
		return s | Write
	}
	if f[0] {
		return s.SetWrite()
	}
	return s
}

// Check checks the channel state for the requested number of bytes.
func (k *Channel) Check(requsted int) (State, error) {
	return k.WaitUtil(requsted, 0)
}

// Wait waits until the channel is ready for writing
// the requested number of bytes,
// or the channel is ready for reading.
func (k *Channel) Wait(requsted int) (State, error) {
	return k.WaitUtil(requsted, -1*time.Second)
}

// WaitUtil is same as Wait, but it allows you to specify a timeout.
func (k *Channel) WaitUtil(requsted int, timeout time.Duration) (State, error) {
	if k == nil || k.hdr == nil {
		return 0, os.ErrClosed
	}
	var m mux
	var err error
	m.need, err = k.write.calcNeed(requsted)
	if err != nil {
		return 0, err
	}
	r, err := m.check(k)
	if err != nil || timeout == 0 {
		return r, err
	}
	can_write, can_read := false, false
	for r == 0 {
		if !m.setupMode(k, &can_write, &can_read) {
			return 0, ErrBusy
		}
		r, err = m.check(k)
		if err != nil {
			break
		}
		if r == 0 {
			err = k.waitMux(m, timeout.Milliseconds())
			if timeout > 0 && err == nil {
				err = ErrTimeout
			}
			if err != nil {
				break
			}
		}
	}
	if can_write {
		k.write.info.writing.Store(0)
	}
	if can_read {
		k.read.info.reading.Store(0)
	}
	return r, err
}

// mux represents the state for multiplexed waiting on read/write operations.
// It tracks queue usage and determines which operations are possible.
type mux struct {
	wused uint32 // Bytes used in write queue
	rused uint32 // Bytes used in read queue
	need  uint32 // Bytes needed for write operation
	mode  State  // Current waiting mode (read/write/both)
}

// check examines the current queue state and determines what operations
// are possible (read/write/both/none).
func (m mux) check(k *Channel) (State, error) {
	var err1, err2 error
	m.wused, err1 = k.write.used()
	m.rused, err2 = k.read.used()
	if err1 != nil || err2 != nil {
		return 0, os.ErrClosed
	}
	can_write := (k.write.size-m.wused >= m.need)
	can_read := (m.rused != 0)
	return NotReady.SetRead(can_read).SetWrite(can_write), nil
}

// setupMode attempts to acquire locks for the specified operations
// and sets up the waiting mode accordingly.
func (m *mux) setupMode(k *Channel, can_write *bool, can_read *bool) bool {
	writing := &k.write.info.writing
	if !*can_write {
		*can_write = writing.CompareAndSwap(0, noWait)
	}
	if *can_write {
		writing.Store(m.need)
	}
	reading := &k.read.info.reading
	if !*can_read {
		*can_read = reading.CompareAndSwap(0, noWait)
	}
	if *can_read {
		state := waitRead
		if *can_write {
			state = waitBoth
		}
		reading.Store(state)
	}
	m.mode = NotReady.SetWrite(*can_write).SetRead(*can_read)
	return *can_write || *can_read
}

// Read reads data from the channel into the provided bytes.Buffer.
// It blocks until data is available or an error occurs.
func (k *Channel) Read(b *bytes.Buffer) error {
	ctx, err := k.ReadContext()
	if err == os.ErrClosed {
		return err
	} else if err != nil && err != ErrAgain {
		return fmt.Errorf("failed to get read context: %w", err)
	}
	if err == ErrAgain {
		err = ctx.Wait()
		if err == os.ErrClosed {
			return err
		} else if err != nil {
			return fmt.Errorf("failed to wait for read context: %w", err)
		}
	}
	r := ctx.Buffer()
	rlen := len(r)
	_, _ = b.Write(r)
	err = ctx.Commit(rlen)
	if err != nil && err != os.ErrClosed {
		return fmt.Errorf("failed to commit read context: %w", err)
	}
	return err
}

// Write writes data from the provided byte slice to the channel.
// It blocks until the data is written or an error occurs.
func (k *Channel) Write(b []byte) error {
	ctx, err := k.WriteContext(len(b))
	if err == os.ErrClosed {
		return err
	} else if err != nil && err != ErrAgain {
		return fmt.Errorf("failed to get write context: %w", err)
	}
	if err == ErrAgain {
		err = ctx.Wait()
		if err == os.ErrClosed {
			return err
		} else if err != nil {
			return fmt.Errorf("failed to wait for write context: %w", err)
		}
	}
	copy(ctx.Buffer(), b)
	err = ctx.Commit(len(b))
	if err != nil && err != os.ErrClosed {
		return fmt.Errorf("failed to commit write context: %w", err)
	}
	return err
}

// ReadContext returns a Context for reading from the channel.
func (k *Channel) ReadContext() (Context, error) {
	if k.hdr == nil {
		return Context{}, os.ErrClosed
	}
	used, err := k.read.used()
	if err != nil {
		return Context{}, err
	}

	if !k.read.info.reading.CompareAndSwap(0, 1) {
		return Context{}, ErrBusy
	}
	ctx := Context{state: &k.read, notify: true}
	ctx.len = waitRead
	ctx.result = ctx.pop(used)
	return ctx, ctx.result
}

// WriteContext returns a Context for writing to the channel.
func (k *Channel) WriteContext(request int) (Context, error) {
	if k.hdr == nil {
		return Context{}, os.ErrClosed
	}
	used, err := k.write.used()
	if err != nil {
		return Context{}, err
	}

	need, err := k.write.calcNeed(request)
	if err != nil {
		return Context{}, err
	}

	if !k.write.info.writing.CompareAndSwap(0, 1) {
		return Context{}, ErrBusy
	}

	ctx := Context{state: &k.write, notify: true}
	ctx.len = uint32(need)
	ctx.result = ctx.push(used)
	return ctx, ctx.result
}

// Context represents the context of a read or write operation on the channel.
// It provides methods to commit the operation, cancel it, and retrieve the
// result of the operation.
type Context struct {
	state  *queue
	result error
	pos    uint32
	len    uint32
	notify bool
}

// Cancel cancels the current read or write operation.
func (c Context) Cancel() {
	if c.state.isRead() {
		c.state.info.reading.Store(0)
	} else {
		c.state.info.writing.Store(0)
	}
}

// Result returns the result of the read or write operation.
func (c Context) Result() error {
	return c.result
}

// Buffer returns the buffer containing the data read from the channel.
func (c Context) Buffer() []byte {
	if c.result != nil {
		return nil
	}
	return c.state.data[prefixSize+int(c.pos):][:int(c.len)-prefixSize]
}

// Commit commits the read or write operation.
func (c Context) Commit(size int) error {
	if c.state.k.hdr == nil {
		return os.ErrClosed
	}
	if c.result != nil {
		return c.result
	}
	if c.state.isRead() {
		return c.commitPop()
	} else {
		return c.commitPush(size)
	}
}

// SetNotify sets when calls `Commit`, whether to notify the other side
// that the operation is complete.
// If `v` is true, it will notify the other side that the operation is complete,
// allowing it to proceed with its own operations.
// If `v` is false, it will not notify the other side, and the other side will
// not be able to proceed until the next operation is performed.
// This is useful for batching operations where you want to perform multiple
// operations before notifying the other side.
func (c *Context) SetNotify(v bool) {
	c.notify = v
}

// Wait waits until the channel is ready for the current operation.
func (c *Context) Wait() error {
	return c.WaitUtil(-1 * time.Second)
}

// WaitUtil waits until the channel is ready for the current operation,
// with a specified timeout.
func (c *Context) WaitUtil(timeout time.Duration) error {
	if c.result != ErrAgain {
		return c.result
	}
	if timeout == 0 {
		_, err := c.checkWait()
		return err
	}
	state, wait := &c.state.info.writing, c.state.waitPush
	if c.state.isRead() {
		state, wait = &c.state.info.reading, c.state.waitPop
	}
	err := ErrAgain
	for err == ErrAgain {
		state.Store(c.len)
		_, err = c.checkWait()
		if err != ErrAgain {
			break
		}
		err = wait(c.len, timeout.Milliseconds())
		if timeout > 0 && err == ErrAgain {
			err = ErrTimeout
		}
	}
	state.Store(noWait)
	if err == nil {
		c.result = nil
	}
	return err
}

// checkWait checks if the context operation can proceed without blocking.
// It returns the current queue usage and any error that occurred.
func (c *Context) checkWait() (uint32, error) {
	used, err := c.state.used()
	if err != nil {
		c.state.cancelOperation()
		return 0, err
	}
	if c.state.isRead() {
		return used, c.pop(used)
	} else {
		return used, c.push(used)
	}
}

// push attempts to start a push (write) operation.
// It calculates available space and sets up buffer pointers.
func (c *Context) push(used uint32) error {
	remain := c.state.size - c.state.info.tail
	free := c.state.size - used

	// check if there is enough space
	if free < c.len {
		return ErrAgain
	}

	// write the offset and the size
	if c.len > remain {
		binary.LittleEndian.PutUint32(c.state.data[c.state.info.tail:], rewindMark)
		c.pos = 0
		c.len = uint32(free - remain)
	} else {
		c.pos = c.state.info.tail
		c.len = uint32(remain)
	}
	return nil
}

// pop attempts to start a pop (read) operation.
// It reads the message length and sets up buffer pointers.
func (c *Context) pop(used uint32) error {
	// check if there is enough data
	if used == 0 {
		return ErrAgain
	}

	// read the size of the data
	c.pos = c.state.info.head
	c.len = binary.LittleEndian.Uint32(c.state.data[c.pos:])
	if c.len == rewindMark {
		c.pos = 0
		c.len = binary.LittleEndian.Uint32(c.state.data[c.pos:])
	}
	c.len += uint32(prefixSize)
	return nil
}

// commitPush finalizes a write operation by updating queue pointers
// and optionally notifying waiting readers.
func (c Context) commitPush(len int) error {
	_, err := c.state.used()
	if err != nil {
		c.state.cancelOperation()
		return err
	}

	needSize := align(prefixSize+len, queueAlign)
	if needSize > int(c.len) {
		return ErrTooBig
	}
	size := uint32(needSize)
	binary.LittleEndian.PutUint32(c.state.data[c.pos:], uint32(len))
	c.state.info.tail = (c.pos + size) % c.state.size

	old_used := c.state.info.used.Add(size) - size
	if old_used&closeMask != 0 {
		c.state.cancelOperation()
		return os.ErrClosed
	}
	if c.notify {
		err = c.state.wakePop()
	}
	c.state.info.writing.Store(0)
	return err
}

// commitPop finalizes a read operation by updating queue pointers
// and optionally notifying waiting writers.
func (c Context) commitPop() error {
	_, err := c.state.used()
	if err != nil {
		c.state.cancelOperation()
		return err
	}

	size := uint32(align(int(c.len), queueAlign))
	c.state.info.head = (c.pos + size) % c.state.size

	new_used := c.state.info.used.Add(-size)
	if new_used&closeMask != 0 {
		c.state.cancelOperation()
		return os.ErrClosed
	}
	if c.notify {
		err = c.state.wakePush(new_used)
	}
	c.state.info.reading.Store(0)
	return err
}
