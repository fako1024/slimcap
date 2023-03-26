//go:build linux
// +build linux

package socket

import (
	"errors"
	"unsafe"

	"github.com/fako1024/slimcap/capture"
	"golang.org/x/sys/unix"
)

// MockFileDescriptor denotes a mock file descriptor mimicking the behavior of an
// AF_PACKET socket by means of using a simple event file descriptor instead
type MockFileDescriptor struct {
	FileDescriptor

	// NPacketsProcessed: Packet counter to provide GetSocketStats() functionality
	nPacketsProcessed int

	buf       chan capture.Packet
	noRelease bool
}

// NewMock instantiates a new mock file descriptor
func NewMock() (MockFileDescriptor, error) {
	sd, err := unix.Eventfd(0, unix.EFD_SEMAPHORE)
	if err != nil {
		return MockFileDescriptor{
			FileDescriptor: -1,
		}, err
	}

	return MockFileDescriptor{
		FileDescriptor: FileDescriptor(sd),
		buf:            make(chan capture.Packet, 16),
	}, nil
}

// IncrementPacketCount allows for simulation of packet / traffic statistics by means
// of manual counting (to be used during population of a mock data source)
func (m *MockFileDescriptor) IncrementPacketCount(delta int) {
	m.nPacketsProcessed += delta
}

// GetSocketStats returns (and resets) socket / traffic statistics
func (m *MockFileDescriptor) GetSocketStats() (ss TPacketStats, err error) {

	if m.FileDescriptor <= 0 {
		err = errors.New("invalid socket")
		return
	}

	// Retrieve TPacket stats for the socket
	ss = TPacketStats{
		Packets: uint32(m.nPacketsProcessed),
	}
	m.nPacketsProcessed = 0

	return
}

// SetNoRelease disables reading from the eventFD after data has been consumed (thereby
// not releasing the block which has to be handled elsewhere instead)
func (m *MockFileDescriptor) SetNoRelease(enable bool) *MockFileDescriptor {
	m.noRelease = enable
	return m
}

// ReleaseSemaphore consumes from the event fd, releasing the semaphore and indicating
// that the next event can be sent
func (m *MockFileDescriptor) ReleaseSemaphore() (errno unix.Errno) {

	// Skip if noRelease mode is set
	if m.noRelease {
		return 0
	}

	var (
		rVal [8]byte
		n    int
	)
	n, errno = read(int(m.FileDescriptor), rVal[:])
	if errno != 0 {
		return
	}
	if n != len(rVal) {
		panic("failed to release mock semaphore (unexpected number of bytes read)")
	}
	return
}

func (m *MockFileDescriptor) Put(pkt capture.Packet) {
	m.buf <- pkt
}

func (m *MockFileDescriptor) Get() capture.Packet {
	return <-m.buf
}

/////////////////////////////////////////////////////////////////////////////////////////

func read(fd int, p []byte) (int, unix.Errno) {
	r0, _, e1 := unix.Syscall(unix.SYS_READ, uintptr(fd), uintptr(unsafe.Pointer(&p[0])), uintptr(len(p)))
	return int(r0), e1
}
