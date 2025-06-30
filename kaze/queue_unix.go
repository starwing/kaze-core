//go:build !windows
// +build !windows

package kaze

type queueState struct {
	k    *Channel
	info *shmQueue
	data []byte
	size uint32
}

func (s *queueState) waitPush(writing uint32, millis int64) error {
	err := futex_wait(&s.info.writing, writing, millis)
	if err != nil && err != ErrTimeout {
		return err
	}
	return ErrAgain
}

func (s *queueState) waitPop(reaading uint32, millis int64) error {
	err := futex_wait(&s.info.reading, reaading, millis)
	if err != nil && err != ErrTimeout {
		return err
	}
	return ErrAgain
}

func (s *queueState) wakePush(new_used uint32) (err error) {
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

func (s *queueState) wakePop() (err error) {
	reading := &s.info.reading
	state := reading.Load()
	if state == waitRead || state == waitBoth {
		if reading.CompareAndSwap(state, noWait) {
			err = futex_wake(reading, false)
		}
	}
	return
}
