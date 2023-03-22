package event

import (
	"github.com/fako1024/slimcap/capture/afpacket/socket"
	"golang.org/x/sys/unix"
)

// Handler wraps a socket file descriptor and an event file descriptor in a single
// instance. In addition, a (unexported) mock file descriptor allows for mocking
// the entire handler without having to manipulate / distinguish from the caller side
type Handler struct {

	// Efd denotes the event file descriptor of this handler
	Efd EvtFileDescriptor

	// Fd denotes the socket file descriptor of this handler
	Fd socket.FileDescriptor

	mockFd *socket.MockFileDescriptor
}

// Poll polls (blocking, hence no timeout) for events on the file descriptor and the event
// file descriptor (waiting for a POLLIN event).
func (p *Handler) Poll(events int16) (bool, unix.Errno) {
	pollEvents := [...]unix.PollFd{
		{
			Fd:     int32(p.Efd),
			Events: unix.POLLIN,
		},
		{
			Fd:     int32(p.Fd),
			Events: events,
		},
	}

	// Fast path: If this is not a MockHandler, simply return a regular poll
	if p.mockFd.FileDescriptor == 0 {
		return poll(pollEvents)
	}

	// MockHandler logic: Poll, then release the semaphore, indicating data has
	// been consumed
	hasEvent, errno := poll(pollEvents)
	if !hasEvent {
		if errno := p.mockFd.ReleaseSemaphore(); errno != 0 {
			return false, errno
		}
	}

	return hasEvent, errno
}

func (p *Handler) GetSocketStats() (socket.TPacketStats, error) {

	// Fast path: If this is not a MockHandler, simply return a call to GetSocketStats()
	if p.mockFd.FileDescriptor == 0 {
		return p.Fd.GetSocketStats()
	}

	// MockHandler logic: Return the number of packets counted via IncrementPacketCount()
	return p.mockFd.GetSocketStats()
}

/////////////////////////////////////////////////////////////////////////////////////////

func poll(pollEvents [2]unix.PollFd) (bool, unix.Errno) {
	errno := pollBlock(&pollEvents[0], len(pollEvents))
	if errno != 0 {
		return pollEvents[0].Revents&unix.POLLIN != 0, errno
	}

	if pollEvents[1].Revents&unix.POLLHUP != 0 || pollEvents[1].Revents&unix.POLLERR != 0 {
		errno = unix.ECONNRESET
	}

	return pollEvents[0].Revents&unix.POLLIN != 0, errno
}
