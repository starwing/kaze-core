package kaze

import (
	"os"
	"unsafe"
)

const prefixSize int = int(unsafe.Sizeof(uint32(0)))

func (s *queueState) isRead() bool {
	return s == &s.k.read
}

func (s *queueState) calcNeed(request int) uint32 {
	return uint32(align(prefixSize+request, queueAlign))
}

func (s *queueState) used() (used uint32, err error) {
	used = s.info.used.Load()
	if used&closeMask != 0 {
		err = os.ErrClosed
	}
	return
}

func (s *queueState) cancelOperateion() {
	if s.isRead() {
		s.info.reading.Store(0)
	} else {
		s.info.writing.Store(0)
	}
}
