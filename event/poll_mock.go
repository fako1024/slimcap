//go:build linux && !slimcap_nomock
// +build linux,!slimcap_nomock

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

// GetSocketStats returns (and resets) socket / traffic statistics
func (p *Handler) GetSocketStats() (socket.TPacketStats, error) {

	// Fast path: If this is not a MockHandler, simply return a call to GetSocketStats()
	if p.mockFd == nil {
		return p.Fd.GetSocketStats()
	}

	// MockHandler logic: Return the number of packets counted via IncrementPacketCount()
	return p.mockFd.GetSocketStats()
}

// MockHandler wraps a regular Handler to allow defining new methods on top of it
// to facilitate mocking without having to rely on interfaces (and actually provide
// mocking as close to the original implementation as possible)
type MockHandler Handler

// NewMockHandler instantiates a new mock Handler (wrapping a regular one)
func NewMockHandler() (*Handler, *socket.MockFileDescriptor, error) {
	fd, err := socket.NewMock()
	if err != nil {
		return nil, nil, err
	}

	efd, err := New()
	if err != nil {
		return nil, nil, err
	}

	// Here be magic: Since under the hood both a FileDescriptor and a MockFileDescriptor
	// are just integers (socket file descriptors) we simply duplicate the mock FD. That way
	// it is possible to interact normally while being able to provide extented (mock)
	// functionality on top of it
	return &Handler{
		Efd: efd,
		Fd:  fd.FileDescriptor,

		mockFd: &fd,
	}, &fd, nil
}

// ToMockHandler converts an existing Handler pointer variable to an equivalent MockHandler
func ToMockHandler(h *Handler) *MockHandler {
	m := MockHandler(*h)
	return &m
}

// SignalAvailableData sets the semaphore of the underlying event file descriptor,
// indicating that data is available (and releasing the block)
func (m *MockHandler) SignalAvailableData() error {
	return m.write([]byte{1, 0, 0, 0, 0, 0, 0, 0})
}

// HasPackets returns if there are packets in the underlying mock socket
func (m *MockHandler) HasPackets() bool {
	return m.mockFd.HasPackets()
}

//////////////////////////////////////////////////////////////////////////////////////////////////////

func (m *MockHandler) write(data []byte) error {
	n, err := unix.Write(int(m.mockFd.FileDescriptor), data)
	if err != nil {
		return fmt.Errorf("failed to signal new data on mock file descriptor: %w", err)
	}
	if n != 8 {
		return fmt.Errorf("failed to signal new data on mock file descriptor:(unexpected number of bytes read, want 8, have %d)", n)
	}
	return nil
}
