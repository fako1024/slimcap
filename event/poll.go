package event

import (
	"fmt"

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
	if p.mockFd == nil {
		return poll(pollEvents)
	}

	// MockHandler logic: Poll, then release the semaphore, indicating data has
	// been consumed
	hasEvent, errno := poll(pollEvents)
	if !hasEvent && errno == 0 {
		if errno := p.mockFd.ReleaseSemaphore(); errno != 0 {
			return false, errno
		}
	}

	return hasEvent, errno
}

// Recvfrom retrieves data directly from the socket
func (p *Handler) Recvfrom(buf []byte, flags int) (int, uint8, error) {

	// Fast path: If this is not a MockHandler, simply return a regular read
	if p.mockFd == nil {
		return p.recvfrom(buf, flags)
	}

	// MockHandler logic: return data from buffer
	pkt := p.mockFd.Get()
	copy(buf, pkt.Payload())

	return pkt.Len(), pkt.Type(), nil
}

func (p *Handler) GetSocketStats() (socket.TPacketStats, error) {

	// Fast path: If this is not a MockHandler, simply return a call to GetSocketStats()
	if p.mockFd == nil {
		return p.Fd.GetSocketStats()
	}

	// MockHandler logic: Return the number of packets counted via IncrementPacketCount()
	return p.mockFd.GetSocketStats()
}

/////////////////////////////////////////////////////////////////////////////////////////

func (p *Handler) recvfrom(buf []byte, flags int) (int, uint8, error) {
	n, sockAddr, err := unix.Recvfrom(int(p.Fd), buf, flags)
	if err != nil {
		return 0, 0, fmt.Errorf("error receiving next packet from socket: %w", err)
	}

	// Determine the packet type (direction)
	var pktType uint8
	if llsa, ok := sockAddr.(*unix.SockaddrLinklayer); ok {
		pktType = llsa.Pkttype
	} else {
		return 0, 0, fmt.Errorf("failed to determine packet type")
	}

	return n, pktType, nil
}

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
