package kaze

import (
	"unsafe"
)

const prefixSize int = int(unsafe.Sizeof(uint32(0)))

func (s *queueState) isRead() bool {
	return s == &s.k.read
}

func (s *queueState) isClosed() bool {
	return s.info.used.Load() == mark
}

func (s *queueState) calcNeed(request int) int {
	return align(prefixSize+request, queue_align)
}

func (s *queueState) size() int {
	return int(s.info.size)
}

func (s *queueState) used() int {
	return int(s.info.used.Load())
}

func (s *queueState) free() int {
	return s.size() - s.used()
}

func (s *queueState) checkReading() bool {
	return !s.info.reading.CompareAndSwap(0, 1)
}

func (s *queueState) checkWriting() bool {
	return !s.info.writing.CompareAndSwap(0, 1)
}
