package event

import (
	"fmt"

	"github.com/fako1024/slimcap/capture/afpacket/socket"
	"golang.org/x/sys/unix"
)

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
