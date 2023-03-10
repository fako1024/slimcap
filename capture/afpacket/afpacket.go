//go:build linux
// +build linux

package afpacket

import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/fako1024/slimcap/event"
	"github.com/fako1024/slimcap/link"
	"golang.org/x/sys/unix"
)

const (
	DefaultSnapLen = (1 << 16) // 64 kiB
)

func setupSocket(iface *link.Link) (event.FileDescriptor, error) {

	// Setup socket
	sd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, htons(unix.ETH_P_ALL))
	if err != nil {
		return -1, err
	}

	// Bind to selected interface
	if err := unix.Bind(sd, &unix.SockaddrLinklayer{
		Protocol: uint16(htons(unix.ETH_P_ALL)),
		Ifindex:  iface.Index,
	}); err != nil {
		return -1, err
	}

	return sd, nil
}

func getSocketStats(sd event.FileDescriptor) (ss tPacketStats, err error) {

	if sd <= 0 {
		err = errors.New("invalid socket")
		return
	}

	// Retrieve TPacket stats for the socket
	sockLen := unsafe.Sizeof(ss)
	err = getsockopt(sd, unix.SOL_PACKET, unix.PACKET_STATISTICS, unsafe.Pointer(&ss), uintptr(unsafe.Pointer(&sockLen)))

	return
}

func setSocketOptions(sd event.FileDescriptor, iface *link.Link, snapLen int, promisc bool) error {

	if sd <= 0 {
		return errors.New("invalid socket")
	}

	// Set TPacket version on socket to the configured version
	if err := unix.SetsockoptInt(sd, unix.SOL_PACKET, unix.PACKET_VERSION, tPacketVersion); err != nil {
		return fmt.Errorf("failed to set TPacket version: %w", err)
	}

	// If the source is in promiscuous mode, set the required flag
	if promisc {
		mReq := unix.PacketMreq{
			Ifindex: int32(iface.Index),
			Type:    unix.PACKET_MR_PROMISC,
		}
		reqLen := unsafe.Sizeof(mReq)
		if err := setsockopt(sd, unix.SOL_SOCKET, unix.PACKET_ADD_MEMBERSHIP, unsafe.Pointer(&mReq), uintptr(unsafe.Pointer(&reqLen))); err != nil {
			return fmt.Errorf("failed to set promiscuous mode: %w", err)
		}
	}

	// Set baseline BPF filters to select only packets with a valid IP header and set the correct snaplen
	if bpfFilterFn := iface.LinkType.BPFFilter(); bpfFilterFn != nil {
		var (
			p               unix.SockFprog
			bfpInstructions = bpfFilterFn(snapLen)
		)
		p.Len = uint16(len(bfpInstructions))
		if p.Len != 0 {
			p.Filter = (*unix.SockFilter)(unsafe.Pointer(&bfpInstructions[0]))
			if err := setsockopt(sd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, unsafe.Pointer(&p), unix.SizeofSockFprog); err != nil {
				return fmt.Errorf("failed to set BPF filter: %w", err)
			}
		}
	}

	return nil
}

func setupRingBuffer(sd event.FileDescriptor, tPacketReq tPacketRequest) ([]byte, event.EvtFileDescriptor, error) {

	if sd <= 0 {
		return nil, -1, errors.New("invalid socket")
	}

	// Setup event file descriptor used for stopping the capture (we start with that to avoid
	// having to clean up the ring buffer in case the decriptor can't be created
	eventFD, err := event.NewEvtFileDescriptor()
	if err != nil {
		return nil, -1, fmt.Errorf("failed to setup event file descriptor: %w", err)
	}

	// Set socket option to use PACKET_RX_RING
	if err := setsockopt(sd, unix.SOL_PACKET, unix.PACKET_RX_RING, unsafe.Pointer(&tPacketReq), unsafe.Sizeof(tPacketReq)); err != nil {
		return nil, -1, fmt.Errorf("failed to call ring buffer instruction: %w", err)
	}

	// Setup memory mapping
	buf, err := unix.Mmap(sd, 0, tPacketReq.blockSizeNr(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, -1, fmt.Errorf("failed to set up mmap ring buffer: %w", err)
	}
	if buf == nil {
		return nil, -1, fmt.Errorf("mmap ring buffer is nil (error: %w)", err)
	}

	return buf, eventFD, nil
}

func getsockopt(fd, level, name int, val unsafe.Pointer, vallen uintptr) error {
	if _, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), uintptr(level), uintptr(name), uintptr(val), vallen, 0); errno != 0 {
		return error(errno)
	}

	return nil
}

func setsockopt(fd, level, name int, val unsafe.Pointer, vallen uintptr) error {
	if _, _, errno := unix.Syscall6(unix.SYS_SETSOCKOPT, uintptr(fd), uintptr(level), uintptr(name), uintptr(val), vallen, 0); errno != 0 {
		return error(errno)
	}

	return nil
}

func htons(v uint16) int {
	return int((v << 8) | (v >> 8))
}
