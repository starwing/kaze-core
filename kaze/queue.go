package kaze

import (
	"os"
	"unsafe"
)

const prefixSize int = int(unsafe.Sizeof(uint32(0)))

// isRead returns true if this queue is used for reading by the current process.
func (s *queue) isRead() bool {
	return s == &s.k.read
}

// calcNeed calculates the aligned space needed for a request of given size.
// It includes the 4-byte prefix and aligns to queue alignment boundaries.
func (s *queue) calcNeed(request int) (uint32, error) {
	need := align(prefixSize+request, queueAlign)
	if need > int(s.size) {
		return 0, ErrTooBig
	}
	return uint32(need), nil
}

// used returns the number of bytes currently used in the queue.
// If the close mask is set, it returns os.ErrClosed.
func (s *queue) used() (used uint32, err error) {
	used = s.info.used.Load()
	if used&closeMask != 0 {
		err = os.ErrClosed
	}
	return
}

// cancelOperation cancels the current read or write operation by
// resetting the appropriate atomic state variable.
func (s *queue) cancelOperation() {
	if s.isRead() {
		s.info.reading.Store(0)
	} else {
		s.info.writing.Store(0)
	}
}
