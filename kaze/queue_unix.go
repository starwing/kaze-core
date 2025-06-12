//go:build !windows
// +build !windows

package kaze

import "os"

type queueState struct {
	k    *Channel
	info *shmQueue
	data []byte
}

const waitRead = ^uint32(0)

func (s *queueState) waitPush(need, millis int) error {
	if millis != 0 {
		if !s.info.need.CompareAndSwap(0, uint32(need)) {
			return futex_wake(&s.info.need, false)
		}
		err := futex_wait(&s.info.need, uint32(need), millis)
		if s.isClosed() {
			s.setNeed(0)
			return os.ErrClosed
		}
		s.info.need.CompareAndSwap(uint32(need), 0)
		if err != nil && err != ErrTimeout {
			return err
		}
	}
	return nil
}

func (s *queueState) waitPop(millis int) error {
	if millis != 0 {
		if !s.info.need.CompareAndSwap(0, waitRead) {
			return futex_wake(&s.info.need, false)
		}
		err := futex_wait(&s.info.need, 0, millis)
		if s.isClosed() {
			s.setNeed(0)
			return os.ErrClosed
		}
		s.info.need.CompareAndSwap(waitRead, 0)
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
	need := int(s.info.need.Load())
	waked := false
	if need > 0 && need < s.size()-new_used {
		waked = true
		err = futex_wake(&s.info.need, false)
	}
	return wakeMux(s, waked, err)
}

func (s *queueState) wakePop(old_used int) (err error) {
	waked := false
	if s.info.need.Load() > 0 && old_used == 0 {
		waked = true
		err = futex_wake(&s.info.need, false)
	}
	return wakeMux(s, waked, err)
}

func wakeMux(s *queueState, waked bool, err error) error {
	if support_futex_waitv {
		if !waked && int32(s.k.read.info.waiters.Load()) > 0 {
			err = futex_wake(&s.k.read.info.need, false)
		}
	} else {
		s.k.read.info.seq.Add(1)
		if int32(s.k.read.info.waiters.Load()) > 0 {
			err = futex_wake(&s.k.read.info.seq, false)
		}
	}
	return err
}
