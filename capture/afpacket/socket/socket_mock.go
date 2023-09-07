//go:build linux && !slimcap_nomock
// +build linux,!slimcap_nomock

package socket

import (
	"errors"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/fako1024/slimcap/capture"
	"golang.org/x/sys/unix"
)

// MockFileDescriptor denotes a mock file descriptor mimicking the behavior of an
// AF_PACKET socket by means of using a simple event file descriptor instead
type MockFileDescriptor struct {
	FileDescriptor

	// nPacketsProcessed: Atomic packet counter to provide GetSocketStats() functionality
	nPacketsProcessed atomic.Uint64

	// lastPoll: Atomic timestamp tracking the last moment of poll on socket
	lastPoll atomic.Int64

	buf       chan capture.Packet
	noRelease atomic.Bool
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
func (m *MockFileDescriptor) IncrementPacketCount(delta uint64) {
	m.nPacketsProcessed.Add(delta)
}

// LastPoll return the timestamp of the last poll on the FileDescriptor
func (m *MockFileDescriptor) LastPoll() int64 {
	return m.lastPoll.Load()
}

// GetSocketStats returns (and resets) socket / traffic statistics
func (m *MockFileDescriptor) GetSocketStats() (ss TPacketStats, err error) {

	if !m.FileDescriptor.IsOpen() {
		err = errors.New("invalid socket")
		return
	}

	// Retrieve TPacket stats for the socket and reset them at the same time using
	// atomic.Swap
	ss = TPacketStats{
		Packets: uint32(m.nPacketsProcessed.Swap(0)),
	}

	return
}

// GetSocketStatsNoReset returns socket / traffic statistics (without resetting the counters)
func (m *MockFileDescriptor) GetSocketStatsNoReset() (ss TPacketStats, err error) {

	if !m.FileDescriptor.IsOpen() {
		err = errors.New("invalid socket")
		return
	}

	// Retrieve TPacket stats for the socket
	ss = TPacketStats{
		Packets: uint32(m.nPacketsProcessed.Load()),
	}

	return
}

// SetNoRelease disables reading from the eventFD after data has been consumed (thereby
// not releasing the block which has to be handled elsewhere instead)
func (m *MockFileDescriptor) SetNoRelease(enable bool) *MockFileDescriptor {
	m.noRelease.Store(enable)
	return m
}

// ReleaseSemaphore consumes from the event fd, releasing the semaphore and indicating
// that the next event can be sent
func (m *MockFileDescriptor) ReleaseSemaphore() (errno unix.Errno) {

	m.lastPoll.Store(time.Now().Unix())

	// Skip if noRelease mode is set
	if m.noRelease.Load() {
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

// Put sends a single packets via the (buffered) mock file descriptor
func (m *MockFileDescriptor) Put(pkt capture.Packet) {
	m.buf <- pkt
}

// Get fetches a single packets from the (buffered) mock file descriptor
func (m *MockFileDescriptor) Get() capture.Packet {
	return <-m.buf
}

// HasPackets returns if there are currently any packets in the mock buffer
func (m *MockFileDescriptor) HasPackets() bool {
	return len(m.buf) > 0
}

/////////////////////////////////////////////////////////////////////////////////////////

func read(fd int, p []byte) (int, unix.Errno) {
	r0, _, e1 := unix.Syscall(unix.SYS_READ, uintptr(fd), uintptr(unsafe.Pointer(&p[0])), uintptr(len(p))) // #nosec:G103
	return int(r0), e1
}
