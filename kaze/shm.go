package kaze

import (
	"sync/atomic"
	"unsafe"
)

const (
	queueAlign int = 4

	// closeMask is or-ed to `used` to indicate that the queue is closed.
	closeMask uint32 = 0x80000000

	// rewindMark to indicate that the queue is rewind to the beginning.
	rewindMark uint32 = 0xFFFFFFFF

	// 64 bytes is the cache line size on most modern CPUs
	cacheLineSize int = 64 / 4

	// assigned to `reading` or `writing` to indicate that
	// the queue is waiting for both push and pop operations.
	noWait uint32 = 0xFFFFFFFF // No wait for push/pop operations.

	// assigned to `reading` or to indicate that the
	// queue is waiting for data to be popped.
	waitRead uint32 = 1

	// assigned to `reading` to indicate that the
	// queue is waiting on `Wait()` routine.
	waitBoth uint32 = 2
)

// ExistInfo holds information about the existence of a shared memory object.
type ExistInfo struct {
	Exists   bool // Whether the shared memory object exists.
	OwnerPid int  // Owner process id.
	UserPid  int  // User process id.
}

// shmHdr represents the header structure in shared memory that contains
// metadata for two bidirectional queues. It maps directly to the C
// kz_ShmHdr structure for cross-language compatibility.
type shmHdr struct {
	size       uint32 // Total size of shared memory segment (max 4GiB)
	queue_size uint32 // Size of each individual queue
	owner_pid  uint32 // Process ID of the channel owner
	user_pid   uint32 // Process ID of the channel user

	// for owner, queues[0] is the sending queue,
	// queues[1] is the receiving queue.
	// for user, queues[0] is the receiving queue,
	// queues[1] is the sending queue
	queues [2]shmQueue // Two queue structures for bidirectional communication
}

// shmQueue represents a single queue's metadata in shared memory.
// It contains atomic variables for synchronization and is carefully
// padded to avoid false sharing between cache lines.
type shmQueue struct {
	writing  atomic.Uint32             // Writing operation state
	tail     uint32                    // Write position in queue
	can_push atomic.Uint32             // Windows-only: push availability flag
	padding1 [cacheLineSize - 3]uint32 // Cache line alignment padding

	reading  atomic.Uint32             // Reading operation state
	head     uint32                    // Read position in queue
	can_pop  atomic.Uint32             // Windows-only: pop availability flag
	padding2 [cacheLineSize - 3]uint32 // Cache line alignment padding

	used     atomic.Uint32             // Number of bytes used (or closed indicator)
	padding3 [cacheLineSize - 1]uint32 // Cache line alignment padding
}

func (k *Channel) setOwner(is_owner bool) {
	if is_owner {
		k.hdr.owner_pid = uint32(k.self_pid)
		k.initState(&k.write, 0)
		k.initState(&k.read, 1)
	} else {
		k.hdr.user_pid = uint32(k.self_pid)
		k.initState(&k.read, 0)
		k.initState(&k.write, 1)
	}
}

func (k *Channel) initState(state *queue, idx int) {
	hdr_buf := unsafe.Add(unsafe.Pointer(k.hdr), unsafe.Sizeof(shmHdr{}))
	size := k.hdr.queue_size

	state.k = k
	state.info = &k.hdr.queues[idx]
	state.data = unsafe.Slice((*byte)(unsafe.Add(hdr_buf, int(size)*idx)), size)
	state.size = size
}

func (k *Channel) initQueues() {
	total_size := int(k.hdr.size) - int(unsafe.Sizeof(shmHdr{}))
	aligned_size := align(total_size, queueAlign)
	if aligned_size > total_size {
		aligned_size -= queueAlign
	}
	queue_size := aligned_size / 2
	k.hdr.queue_size = uint32(queue_size)
	k.setOwner(true)
}

func (k *Channel) resetQueues(isOwner bool) {
	k.setOwner(isOwner)
	k.read.info.reading.Store(0)
	k.read.info.can_push.Store(0)
	k.write.info.writing.Store(0)
	k.write.info.can_pop.Store(0)
	if used, err := k.read.used(); err != nil {
		k.read.info.used.CompareAndSwap(used, used&^closeMask)
	}
	if used, err := k.write.used(); err != nil {
		k.write.info.used.CompareAndSwap(used, used&^closeMask)
	}
}

func align(size int, alignment int) int {
	return (size + alignment - 1) & ^(alignment - 1)
}
