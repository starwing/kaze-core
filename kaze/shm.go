package kaze

import (
	"sync/atomic"
	"unsafe"
)

const mark uint32 = 0xFFFFFFFF
const queue_align int = 4

type shmHdr struct {
	size      uint32 // Size of the shared memory. 4GB max.
	offset    uint32 // Offset of the second queue buffer.
	owner_pid uint32 // Owner process id.
	user_pid  uint32 // User process id.

	// for owner, queues[0] is the sending queue,
	// queues[1] is the receiving queue.
	// for user, queues[0] is the receiving queue,
	// queues[1] is the sending queue
	queues [2]shmQueue
}

type shmQueue struct {
	size     uint32        // Size of the queue.
	used     atomic.Uint32 // Number of bytes used in the queue (-1 == closed).
	reading  atomic.Uint32 // Whether the queue is being read.
	head     uint32        // Head of the queue.
	mux      atomic.Uint32 // futex wait the writing queue, wake reading queue.
	padding1 [11]uint32
	need     atomic.Uint32 // Number of bytes needed to read from the queue.
	writing  atomic.Uint32 // Whether the queue is being written to.
	tail     uint32        // Tail of the queue.
	padding2 [13]uint32
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

func (k *Channel) initState(state *queueState, idx int) {
	hdr_buf := unsafe.Add(unsafe.Pointer(k.hdr), unsafe.Sizeof(shmHdr{}))
	size := k.hdr.queues[0].size

	state.k = k
	state.info = &k.hdr.queues[idx]
	state.data = unsafe.Slice((*byte)(unsafe.Add(hdr_buf, int(size)*idx)), size)
}

func (k *Channel) initQueues() {
	total_size := int(k.hdr.size) - int(unsafe.Sizeof(shmHdr{}))
	aligned_size := align(total_size, queue_align)
	if aligned_size > total_size {
		aligned_size -= queue_align
	}
	queue_size := aligned_size / 2
	k.hdr.queues[0].size = (uint32)(queue_size)
	k.hdr.queues[1].size = (uint32)(queue_size)
	k.setOwner(true)
}

func (k *Channel) resetQueues() {
	k.setOwner(false)
	k.read.info.reading.Store(0)
	k.write.info.writing.Store(0)
	if k.read.info.used.Load() == mark {
		k.read.info.head = 0
		k.read.info.tail = 0
		k.read.info.used.Store(0)
		k.read.setNeed(0)
	}
	if k.write.info.used.Load() == mark {
		k.write.info.head = 0
		k.write.info.tail = 0
		k.write.info.used.Store(0)
		k.write.setNeed(0)
	}
}

func align(size int, alignment int) int {
	return (size + alignment - 1) & ^(alignment - 1)
}
