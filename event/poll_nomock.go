//go:build linux && slimcap_nomock
// +build linux,slimcap_nomock

package event

import (
	"github.com/fako1024/slimcap/capture/afpacket/socket"
	"golang.org/x/sys/unix"
)

// Handler wraps a socket file descriptor and an event file descriptor in a single
// instance
type Handler struct {

	// Efd denotes the event file descriptor of this handler
	Efd EvtFileDescriptor

	// Fd denotes the socket file descriptor of this handler
	Fd socket.FileDescriptor
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

	return poll(pollEvents)
}

// Recvfrom retrieves data directly from the socket
func (p *Handler) Recvfrom(buf []byte, flags int) (int, uint8, error) {
	return p.recvfrom(buf, flags)
}

// GetSocketStats returns (and resets) socket / traffic statistics
func (p *Handler) GetSocketStats() (socket.TPacketStats, error) {
	return p.Fd.GetSocketStats()
}
