//go:build !windows
// +build !windows

package kaze

import "os"

type queueState struct {
	k    *Channel
	info *shmQueue
	data []byte
}

func (s *queueState) waitPush(old_need, millis int) error {
	if millis != 0 {
		need := s.info.need.Load()
		if need == 0 {
			need = uint32(old_need)
		}
		err := futex_wait(&s.info.need, need, millis)
		if s.isClosed() {
			s.info.writing.Store(0)
			return os.ErrClosed
		}
		if err != nil && err != ErrTimeout {
			return err
		}
	}
	return nil
}
func (s *queueState) waitPop(millis int) error {
	if millis != 0 {
		err := futex_wait(&s.info.used, 0, millis)
		if s.isClosed() {
			s.info.reading.Store(0)
			return os.ErrClosed
		}
		if err != nil && err != ErrTimeout {
			return err
		}
	}
	return nil
}

func (s *queueState) setNeed(new_need int) {
	s.info.need.Store(uint32(new_need))
}

func (s *queueState) wakePush(new_used int) (err error) {
	waked := false
	s.k.read.info.seq.Add(1)
	if s.info.writing.Load() != 0 {
		need := int(s.info.need.Load())
		if need > 0 && need < s.size()-new_used {
			s.setNeed(0)
			err = futex_wake(&s.info.need, false)
			waked = true
		}
	}
	if support_futex_waitv {
		if !waked {
			err = futex_wake(&s.info.need, false)
		}
	} else if int32(s.k.read.info.waiters.Load()) > 0 {
		err = futex_wake(&s.k.read.info.seq, false)
	}
	return
}

func (s *queueState) wakePop(old_used int) (err error) {
	waked := false
	s.k.read.info.seq.Add(1)
	if s.info.reading.Load() != 0 && old_used == 0 {
		err = futex_wake(&s.info.used, false)
		waked = true
	}
	if support_futex_waitv {
		if !waked {
			err = futex_wake(&s.info.used, false)
		}
	} else if int32(s.k.write.info.waiters.Load()) > 0 {
		err = futex_wake(&s.k.write.info.seq, false)
	}
	return err
}
