//go:build linux
// +build linux

package event

import (
	"fmt"

	"golang.org/x/sys/unix"
)

const nPollEvents = 2

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

func poll(pollEvents [nPollEvents]unix.PollFd) (bool, unix.Errno) {
	errno := pollBlock(&pollEvents[0], nPollEvents)
	if errno != 0 {
		return pollEvents[0].Revents&unix.POLLIN != 0, errno
	}

	if pollEvents[1].Revents&unix.POLLHUP != 0 || pollEvents[1].Revents&unix.POLLERR != 0 {
		errno = unix.ECONNRESET
	}

	return pollEvents[0].Revents&unix.POLLIN != 0, errno
}
