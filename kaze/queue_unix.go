//go:build !windows
// +build !windows

package kaze

// queue represents a single direction queue in the shared memory channel.
// It encapsulates the queue state and provides low-level operations for
// reading and writing data.
type queue struct {
	k    *Channel  // Parent channel
	info *shmQueue // Pointer to queue metadata in shared memory
	data []byte    // Slice of queue data buffer
	size uint32    // Size of the queue in bytes
}

// waitPush waits for space to become available in the queue for writing.
// Returns ErrAgain if the wait completes (successfully or timeout).
func (s *queue) waitPush(writing uint32, millis int64) error {
	err := futex_wait(&s.info.writing, writing, millis)
	if err != nil && err != ErrTimeout {
		return err
	}
	return ErrAgain
}

// waitPop waits for data to become available in the queue for reading.
// Returns ErrAgain if the wait completes (successfully or timeout).
func (s *queue) waitPop(reading uint32, millis int64) error {
	err := futex_wait(&s.info.reading, reading, millis)
	if err != nil && err != ErrTimeout {
		return err
	}
	return ErrAgain
}

// wakePush attempts to wake up writers waiting for queue space.
// Called when space becomes available after a read operation.
func (s *queue) wakePush(new_used uint32) (err error) {
	writing := &s.info.writing
	need := writing.Load()
	if need > 0 && need < s.size-new_used {
		if writing.CompareAndSwap(need, noWait) {
			err = futex_wake(writing, false)
		}
		reading := &s.k.write.info.reading
		if reading.CompareAndSwap(waitBoth, noWait) {
			if err1 := futex_wake(reading, false); err == nil {
				err = err1
			}
		}
	}
	return
}

// wakePop attempts to wake up readers waiting for data.
// Called when data becomes available after a write operation.
func (s *queue) wakePop() (err error) {
	reading := &s.info.reading
	state := reading.Load()
	if state == waitRead || state == waitBoth {
		if reading.CompareAndSwap(state, noWait) {
			err = futex_wake(reading, false)
		}
	}
	return
}
