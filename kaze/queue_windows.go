package kaze

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

type queueState struct {
	k        *Channel
	info     *shmQueue
	data     []byte
	can_push windows.Handle
	can_pop  windows.Handle
}

func (s *queueState) init(name string, index int, created bool) (err error) {
	s.can_push, err = new_or_open_event(fmt.Sprintf("%s-%d-can-push", name, index), created)
	if err != nil {
		return
	}
	s.can_pop, err = new_or_open_event(fmt.Sprintf("%s-%d-can-pop", name, index), created)
	return
}

func new_or_open_event(name string, created bool) (windows.Handle, error) {
	ptr, err := windows.BytePtrFromString(name)
	if err != nil {
		return windows.Handle(0), err
	}
	name_ptr := (*uint16)(unsafe.Pointer(ptr))
	if created {
		return windows.CreateEvent(nil, 1, 0, name_ptr)
	} else {
		return windows.OpenEvent(windows.SYNCHRONIZE|windows.EVENT_MODIFY_STATE,
			false, name_ptr)
	}
}

func (s *queueState) waitPush(_, millis int) error {
	if millis != 0 {
		_, err := windows.WaitForSingleObject(s.can_push, uint32(millis))
		if s.isClosed() {
			s.info.writing.Store(0)
			return os.ErrClosed
		}
		if err == windows.ERROR_TIMEOUT {
			return ErrTimeout
		}
		return err
	}
	return nil
}

func (s *queueState) waitPop(millis int) error {
	if millis != 0 {
		_, err := windows.WaitForSingleObject(s.can_pop, uint32(millis))
		if s.isClosed() {
			s.info.reading.Store(0)
			return os.ErrClosed
		}
		if err == windows.ERROR_TIMEOUT {
			return ErrTimeout
		}
		return err
	}
	return nil
}

func (s *queueState) wakePush(new_used int) (err error) {
	mux := &s.k.read.info.mux
	waked := false
	if s.info.writing.Load() != 0 {
		need := int(s.info.need.Load())
		if need > 0 && need < s.size()-new_used {
			waked = true
		}
	}
	if waked || mux.Load() > 0 {
		err = windows.SetEvent(s.can_push)
		err = windows.ResetEvent(s.can_push)
	}
	return
}

func (s *queueState) wakePop(old_used int) (err error) {
	mux := &s.k.read.info.mux
	waked := false
	if s.info.reading.Load() != 0 && old_used == 0 {
		waked = true
	}
	if waked || mux.Load() > 0 {
		err = windows.SetEvent(s.can_pop)
		err = windows.ResetEvent(s.can_pop)
	}
	return err
}
