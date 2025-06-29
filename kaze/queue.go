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

func (s *queueState) size() uint32 {
	return s.info.size
}

func (s *queueState) used() (uint32, error) {
	used := s.info.used.Load()
	if used == closedMark {
		return 0, os.ErrClosed
	}
	return used, nil
}

func (s *queueState) cancelOperateion() {
	if s.isRead() {
		s.info.reading.Store(0)
	} else {
		s.info.writing.Store(0)
	}
}
