package event

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// Poll polls (blocking, hence no timeout) for events on the file descriptor and the event
// file descriptor (waiting for a stop / POLLIN event).
func Poll(efd EvtFileDescriptor, fd FileDescriptor, events int16) (bool, unix.Errno) {
	pollEvents := [...]unix.PollFd{
		{
			Fd:     int32(efd),
			Events: unix.POLLIN,
		},
		{
			Fd:     int32(fd),
			Events: events,
		},
	}
	_, errno := pollBlock(&pollEvents[0], len(pollEvents), nil)
	if errno != 0 {
		return pollEvents[0].Revents&unix.POLLIN != 0, errno
	}

	if pollEvents[1].Revents&unix.POLLHUP != 0 || pollEvents[1].Revents&unix.POLLERR != 0 {
		errno = unix.ECONNRESET
	}

	return pollEvents[0].Revents&unix.POLLIN != 0, errno
}

func pollBlock(fds *unix.PollFd, nfds int, timeout *unix.Timespec) (int, unix.Errno) {
	n, _, e := unix.Syscall6(unix.SYS_PPOLL, uintptr(unsafe.Pointer(fds)),
		uintptr(nfds), uintptr(unsafe.Pointer(timeout)), 0, 0, 0)

	return int(n), e
}
