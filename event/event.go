package event

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// FileDescriptor denotes a generic system level file descriptor (an int)
type FileDescriptor = int

// EvtFileDescriptor denotes a system-level event file descriptor
type EvtFileDescriptor FileDescriptor

var incrementBytes = []byte{1, 0, 0, 0, 0, 0, 0, 0}

// NewEvtFileDescriptor instantiates a new non-blocking event file descriptor
func NewEvtFileDescriptor() (EvtFileDescriptor, error) {
	efd, err := unix.Eventfd(0, unix.EFD_NONBLOCK)
	if err != nil {
		return -1, fmt.Errorf("failed to create event file descriptor: %w", err)
	}

	return EvtFileDescriptor(efd), nil
}

// Stop sends a STOP event via the event file descriptor
func (e EvtFileDescriptor) Stop() error {
	fmt.Println(int(e))
	n, err := unix.Write(int(e), incrementBytes)
	if err != nil {
		return fmt.Errorf("failed to send STOP event: %w", err)
	}
	if n != len(incrementBytes) {
		return fmt.Errorf("failed to send STOP event (unexpected number of bytes written, want %d, have %d)", len(incrementBytes), n)
	}

	return nil
}
