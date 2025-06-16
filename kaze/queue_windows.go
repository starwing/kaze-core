package kaze

import (
	"fmt"
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

func (s *queueState) waitPush(_, _ uint32, millis int) error {
	_, err := windows.WaitForSingleObject(s.can_push, uint32(millis))
	if _, cerr := s.used(); cerr != nil {
		return cerr
	}
	if err == windows.ERROR_TIMEOUT {
		return ErrTimeout
	}
	return err
}

func (s *queueState) waitPop(_ uint32, millis int) error {
	_, err := windows.WaitForSingleObject(s.can_pop, uint32(millis))
	if _, cerr := s.used(); cerr != nil {
		return cerr
	}
	if err == windows.ERROR_TIMEOUT {
		return ErrTimeout
	}
	return err
}

func (s *queueState) setNeed(new_need uint32) {
	s.info.need.Store(new_need)
	if new_need == 0 {
		windows.SetEvent(s.can_push)
	} else {
		windows.ResetEvent(s.can_push)
	}
}

func (s *queueState) wakePush(new_used uint32) (err error) {
	need := s.info.need.Load()
	if need > 0 && need < s.size()-new_used {
		s.setNeed(0)
	}
	if new_used == 0 {
		err = windows.ResetEvent(s.can_pop)
	}
	return
}

func (s *queueState) wakePop(old_used uint32) (err error) {
	if old_used == 0 {
		err = windows.SetEvent(s.can_pop)
	}
	return
}
