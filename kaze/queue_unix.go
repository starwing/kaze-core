//go:build !windows
// +build !windows

package kaze

type queueState struct {
	k    *Channel
	info *shmQueue
	data []byte
}

const waitRead = ^uint32(0)

func (s *queueState) waitPush(used, need uint32, millis int) error {
	if !s.info.need.CompareAndSwap(0, uint32(need)) {
		return nil
	}
	err := futex_wait(&s.info.used, used, millis)
	s.setNeed(0)
	if _, cerr := s.used(); cerr != nil {
		return cerr
	}
	if err != nil && err != ErrTimeout {
		return err
	}
	return nil
}

func (s *queueState) waitPop(used uint32, millis int) error {
	if !s.info.need.CompareAndSwap(0, waitRead) {
		return nil
	}
	err := futex_wait(&s.info.used, used, millis)
	s.setNeed(0)
	if _, cerr := s.used(); cerr != nil {
		return cerr
	}
	if err != nil && err != ErrTimeout {
		return err
	}
	return nil
}

func (s *queueState) setNeed(new_need uint32) {
	s.info.need.Store(new_need)
}

func (s *queueState) wakePush(new_used uint32) (err error) {
	need := s.info.need.Load()
	waked := false
	if need > 0 && need < s.size()-new_used {
		waked = true
		err = futex_wake(&s.info.used, false)
	}
	return wakeMux(s, waked, err)
}

func (s *queueState) wakePop(_ uint32) (err error) {
	waked := false
	if s.info.need.Load() > 0 {
		waked = true
		err = futex_wake(&s.info.used, false)
	}
	return wakeMux(s, waked, err)
}

func wakeMux(s *queueState, waked bool, err error) error {
	if support_futex_waitv {
		if !waked && int32(s.k.read.info.waiters.Load()) > 0 {
			err = futex_wake(&s.k.read.info.used, false)
		}
	} else {
		s.k.read.info.seq.Add(1)
		if int32(s.k.read.info.waiters.Load()) > 0 {
			err = futex_wake(&s.k.read.info.seq, false)
		}
	}
	return err
}
