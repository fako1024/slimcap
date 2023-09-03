//go:build linux
// +build linux

package event

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// EvtFileDescriptor denotes a system-level event file descriptor
type EvtFileDescriptor int

// EvtData denotes the data sent / received during an event
type EvtData [8]byte

var (

	// SignalUnblock ends any ongoing PPOLL syscall  (similar to a timeout)
	SignalUnblock = EvtData{1, 0, 0, 0, 0, 0, 0, 0}

	// SignalStop causes the capture to stop
	SignalStop = EvtData{0, 0, 0, 0, 0, 0, 0, 1}
)

// New instantiates a new non-blocking event file descriptor
func New() (EvtFileDescriptor, error) {
	efd, err := unix.Eventfd(0, unix.EFD_NONBLOCK)
	if err != nil {
		return -1, fmt.Errorf("failed to create event file descriptor: %w", err)
	}

	return EvtFileDescriptor(efd), nil
}

// Signal sends an event via the event file descriptor
func (e EvtFileDescriptor) Signal(data EvtData) error {
	n, err := unix.Write(int(e), data[:])
	if err != nil {
		return fmt.Errorf("failed to send event: %w", err)
	}
	if n != len(data) {
		return fmt.Errorf("failed to send event (unexpected number of bytes written, want %d, have %d)", len(data), n)
	}

	return nil
}

// ReadEvent reads the event data from the event file descriptor
func (e EvtFileDescriptor) ReadEvent() (EvtData, error) {
	var data EvtData
	n, err := unix.Read(int(e), data[:])
	if err != nil {
		return data, fmt.Errorf("failed to read event data: %w", err)
	}
	if n != len(data) {
		return data, fmt.Errorf("failed to read event data (unexpected number of bytes read, want %d, have %d)", len(data), n)
	}

	return data, nil
}
