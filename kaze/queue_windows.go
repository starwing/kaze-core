package kaze

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

type queue struct {
	k            *Channel
	info         *shmQueue
	data         []byte
	size         uint32
	canPushEvent windows.Handle
	canPopEvent  windows.Handle
}

func (s *queue) init(name string, index int, created bool) (err error) {
	s.canPushEvent, err = new_or_open_event(fmt.Sprintf("%s-%d-can-push", name, index), created)
	if err != nil {
		return
	}
	s.canPopEvent, err = new_or_open_event(fmt.Sprintf("%s-%d-can-pop", name, index), created)
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

func (s *queue) waitPush(_ uint32, millis int64) error {
	_, err := windows.WaitForSingleObject(s.canPushEvent, uint32(millis))
	if _, cerr := s.used(); cerr != nil {
		return cerr
	}
	if err == windows.ERROR_TIMEOUT {
		return ErrTimeout
	}
	return ErrAgain
}

func (s *queue) waitPop(_ uint32, millis int64) error {
	_, err := windows.WaitForSingleObject(s.canPopEvent, uint32(millis))
	if _, cerr := s.used(); cerr != nil {
		return cerr
	}
	if err == windows.ERROR_TIMEOUT {
		return ErrTimeout
	}
	return ErrAgain
}

func (s *queue) wakePush(new_used uint32) (err error) {
	need := s.info.writing.Load()
	if need > 0 && need < s.size-new_used {
		if s.info.can_push.CompareAndSwap(0, 1) {
			err = windows.SetEvent(s.canPushEvent)
		}
	}
	if s.info.can_pop.CompareAndSwap(1, 0) {
		err1 := windows.ResetEvent(s.canPopEvent)
		if err == nil {
			err = err1
		}
	}
	return
}

func (s *queue) wakePop() (err error) {
	reading := s.info.reading.Load()
	if reading > 0 && s.info.can_pop.CompareAndSwap(0, 1) {
		err = windows.SetEvent(s.canPopEvent)
	}
	if s.info.can_push.CompareAndSwap(1, 0) {
		err1 := windows.ResetEvent(s.canPushEvent)
		if err == nil {
			err = err1
		}
	}
	return
}
