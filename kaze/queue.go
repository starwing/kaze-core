package kaze

import (
	"os"
	"unsafe"
)

const prefixSize int = int(unsafe.Sizeof(uint32(0)))

func (s *queue) isRead() bool {
	return s == &s.k.read
}

func (s *queue) calcNeed(request int) uint32 {
	return uint32(align(prefixSize+request, queueAlign))
}

func (s *queue) used() (used uint32, err error) {
	used = s.info.used.Load()
	if used&closeMask != 0 {
		err = os.ErrClosed
	}
	return
}

func (s *queue) cancelOperateion() {
	if s.isRead() {
		s.info.reading.Store(0)
	} else {
		s.info.writing.Store(0)
	}
}
