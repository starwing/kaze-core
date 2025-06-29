package kaze

import (
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Exists checks if a shared memory object with the given name exists.
func Exists(name string) (bool, error) {
	shm_fd, err := openFileMapping(
		windows.FILE_MAP_READ|windows.FILE_MAP_WRITE, /* read/write access */
		0,    /* do not inherit the name */
		name) /* name of mapping object */
	if err == nil {
		windows.CloseHandle(shm_fd)
		return true, nil
	}
	if err == windows.ERROR_FILE_NOT_FOUND {
		return false, nil
	}
	return false, err
}

// Unlink removes the shared memory object with the given name.
// On Windows, this function does not actually unlink the file,
// because the file is automatically deleted when the last handle to it is closed.
// It is provided for compatibility with other platforms.
func Unlink(_ string) error {
	// on Windows, mapping file doesn't need unlink.
	return nil
}

// Channel represents a shared memory channel.
// It provides methods to create, open, and manage the shared memory object.
// It also provides methods to close the channel and release all resources.
// The channel is used for inter-process communication (IPC) using shared memory.
type Channel struct {
	self_pid int
	shm_fd   windows.Handle
	shm_size int
	hdr      *shmHdr
	write    queueState
	read     queueState
	name     string
}

// Close closes the channel and releases all resources.
func (k *Channel) Close() {
	if k.hdr != nil {
		_ = windows.UnmapViewOfFile(uintptr(unsafe.Pointer(k.hdr)))
		k.hdr = nil
	}
	closeHandle(&k.write.canPushEvent)
	closeHandle(&k.write.canPopEvent)
	closeHandle(&k.read.canPushEvent)
	closeHandle(&k.read.canPopEvent)
	closeHandle(&k.shm_fd)
}

// Shutdown closes the channel in state direction.
// If state.CanRead() is true, it closes the read queue and sets the used mark.
// If state.CanWrite() is true, it closes the write queue, sets the used mark.
// It will signals the opposite queue to wake up any waiting operations.
func (k *Channel) Shutdown(state State) {
	if state.CanRead() {
		k.read.info.used.Store(closedMark)
		windows.SetEvent(k.read.canPushEvent)
	}
	if state.CanWrite() {
		k.write.info.used.Store(closedMark)
		windows.SetEvent(k.write.canPopEvent)
	}
}

func closeHandle(handle *windows.Handle) {
	if *handle != windows.Handle(0) {
		_ = windows.CloseHandle(*handle)
		*handle = windows.Handle(0)
	}
}

func (k *Channel) init() {
	k.self_pid = int(windows.GetCurrentProcessId())
}

func (k *Channel) waitMux(m mux, millis int64) (err error) {
	var handles [2]windows.Handle
	cnt := 0
	if m.mode.CanRead() {
		handles[cnt] = k.read.canPopEvent
		cnt++
	}
	if m.mode.CanWrite() {
		handles[cnt] = k.write.canPushEvent
		cnt++
	}
	_, err = windows.WaitForMultipleObjects(handles[:cnt], false, uint32(millis))
	return
}

func (k *Channel) createShm(excl bool, reset bool) (err error) {
	created := false

	/* create a new shared memory object */
	k.shm_fd, err = createFileMapping(
		windows.InvalidHandle,  /* use paging file */
		nil,                    /* default security */
		windows.PAGE_READWRITE, /* read/write access */
		0,                      /* maximum object size (high-order DWORD) */
		uint32(k.shm_size),     /* maximum object size (low-order DWORD) */
		k.name)                 /* name of mapping object */
	if err != nil && (err != windows.ERROR_ALREADY_EXISTS || excl) {
		return
	}

	/* init the shared memory object */
	hdr_rawbuf, err := windows.MapViewOfFile(
		k.shm_fd, /* handle to map object */
		windows.FILE_MAP_READ|windows.FILE_MAP_WRITE, /* read/write permission */
		0,                   /* file offset (high-order DWORD) */
		0,                   /* file offset (low-order DWORD) */
		uintptr(k.shm_size)) /* mapping size */
	if err != nil {
		return
	}
	hdr_buf := toSlice(hdr_rawbuf, k.shm_size)
	k.hdr = (*shmHdr)(unsafe.Pointer(&hdr_buf[0]))

	created = reset || k.hdr.size != uint32(k.shm_size)
	if created {
		for i := range hdr_buf {
			hdr_buf[i] = 0
		}
		k.hdr.size = uint32(k.shm_size)
	}

	if k.hdr.owner_pid != 0 && k.hdr.owner_pid != uint32(k.self_pid) &&
		pidExists(k.hdr.owner_pid) {
		return os.ErrPermission
	}

	k.write.init(k.name, 0, created)
	k.read.init(k.name, 1, created)
	k.setOwner(true)
	if created {
		k.initQueues()
	} else {
		k.resetQueues(true)
	}
	return
}

func (k *Channel) openShm() (err error) {
	k.shm_fd, err = openFileMapping(
		windows.FILE_MAP_READ|windows.FILE_MAP_WRITE, /* read/write access */
		0,      /* do not inherit the name */
		k.name) /* name of mapping object */
	if err != nil {
		return
	}

	/* init the shared memory object */
	hdr_rawbuf, err := windows.MapViewOfFile(
		k.shm_fd, /* handle to map object */
		windows.FILE_MAP_READ|windows.FILE_MAP_WRITE, /* read/write permission */
		0, /* file offset (high-order DWORD) */
		0, /* file offset (low-order DWORD) */
		0) /* mapping size */
	if err != nil {
		return
	}

	/* retrieve the size of shm */
	hdr_buf := toSlice(hdr_rawbuf, k.shm_size)
	k.hdr = (*shmHdr)(unsafe.Pointer(&hdr_buf[0]))
	k.shm_size = int(k.hdr.size)

	if k.hdr.user_pid != 0 && k.hdr.user_pid != uint32(k.self_pid) &&
		pidExists(k.hdr.user_pid) {
		return os.ErrPermission
	}

	k.read.init(k.name, 0, false)
	k.write.init(k.name, 1, false)
	k.setOwner(false)
	k.resetQueues(false)
	return
}

func pidExists(pid uint32) bool {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)

	exitCode := uint32(0)
	if err := windows.GetExitCodeProcess(handle, &exitCode); err != nil {
		return false
	}
	return exitCode == uint32(windows.STATUS_PENDING)
}

// below from: https://github.com/aceofkid/go-ipc/master/internal/sys/windows/syscall_windows.go#L74
var (
	modkernel32           = windows.NewLazyDLL("kernel32.dll")
	procOpenFileMapping   = modkernel32.NewProc("OpenFileMappingW")
	procCreateFileMapping = modkernel32.NewProc("CreateFileMappingW")
)

// openFileMapping is a wraper for windows syscall.
func openFileMapping(access uint32, inheritHandle uint32, name string) (windows.Handle, error) {
	namep, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	nameu := unsafe.Pointer(namep)
	r1, _, err := procOpenFileMapping.Call(uintptr(access), uintptr(inheritHandle), uintptr(nameu))
	if r1 == 0 {
		if err == windows.ERROR_FILE_NOT_FOUND {
			return 0, &os.PathError{Path: name, Op: "CreateFileMapping", Err: err}
		}
		return 0, os.NewSyscallError("OpenFileMapping", err)
	}
	if err == syscall.Errno(0) {
		err = nil
	}
	return windows.Handle(r1), err
}

// createFileMapping is a wraper for windwos syscall.
// We cannot use a call from golang.org/x/sys/windows,
// because it returns nil error, if the syscall returned a valid handle.
// However, createFileMapping may return a valid handle
// along with ERROR_ALREADY_EXISTS, and in this case we cannot find out,
// if the file existed before.
func createFileMapping(fhandle windows.Handle, sa *windows.SecurityAttributes,
	prot uint32, maxSizeHigh uint32, maxSizeLow uint32,
	name string) (handle windows.Handle, err error) {
	var namep *uint16
	if len(name) > 0 {
		namep, err = windows.UTF16PtrFromString(name)
		if err != nil {
			return 0, err
		}
	}
	nameu := unsafe.Pointer(namep)
	sau := unsafe.Pointer(sa)
	r1, _, err := procCreateFileMapping.Call(uintptr(fhandle), uintptr(sau),
		uintptr(prot), uintptr(maxSizeHigh), uintptr(maxSizeLow), uintptr(nameu))
	if r1 == 0 {
		if err == windows.ERROR_ALREADY_EXISTS {
			return 0, &os.PathError{Path: name, Op: "CreateFileMapping", Err: err}
		}
		return 0, os.NewSyscallError("CreateFileMapping", err)
	}
	if err == syscall.Errno(0) {
		err = nil
	}
	return windows.Handle(r1), err
}

func toSlice(p uintptr, size int) []byte {
	addr := *(*unsafe.Pointer)(unsafe.Pointer(&p))
	return unsafe.Slice((*byte)(addr), size)
}
