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

func (s *queueState) wakePush(new_used int) (err error) {
	mux := &s.k.read.info.mux
	waked := false
	if s.info.writing.Load() != 0 {
		need := int(s.info.need.Load())
		if need > 0 && need < s.size()-new_used {
			err = futex_wake(&s.info.need, false)
			waked = true
		}
	}
	if !(waked && support_futex_waitv) && mux.Load() > 0 {
		if support_futex_waitv {
			err = futex_wake(&s.info.need, false)
		} else {
			err = futex_wake(mux, false)
		}
	}
	return
}

func (s *queueState) wakePop(old_used int) (err error) {
	mux := &s.k.read.info.mux
	waked := false
	if s.info.reading.Load() != 0 && old_used == 0 {
		err = futex_wake(&s.info.used, false)
		waked = true
	}
	if !(waked && support_futex_waitv) && mux.Load() > 0 {
		if support_futex_waitv {
			err = futex_wake(&s.info.used, false)
		} else {
			err = futex_wake(mux, false)
		}
	}
	return err
}
