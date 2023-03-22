//go:build linux
// +build linux

package socket

import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/fako1024/slimcap/link"
	"golang.org/x/sys/unix"
)

const (
	TPacketVersion = unix.TPACKET_V3
)

// FileDescriptor denotes a generic system level file descriptor (an int)
type FileDescriptor int

// TPacketStats denotes the V3 tpacket_stats structure, c.f.
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_packet.h
type TPacketStats struct {
	Packets      uint32
	Drops        uint32
	QueueFreezes uint32
}

// New instantiates a new file decriptor
func New(iface *link.Link) (FileDescriptor, error) {

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

	return FileDescriptor(sd), nil
}

// GetSocketStats returns (and resets) socket / traffic statistics
func (sd FileDescriptor) GetSocketStats() (ss TPacketStats, err error) {

	if sd <= 0 {
		err = errors.New("invalid socket")
		return
	}

	// Retrieve TPacket stats for the socket
	sockLen := unsafe.Sizeof(ss)
	err = getsockopt(sd, unix.SOL_PACKET, unix.PACKET_STATISTICS, unsafe.Pointer(&ss), uintptr(unsafe.Pointer(&sockLen)))

	return
}

// SetSocketOptions sets several socket options on the underlying file descriptor required
// to perform AF_PACKET capture and retrieval of socket / traffic statistics
func (sd FileDescriptor) SetSocketOptions(iface *link.Link, snapLen int, promisc bool) error {

	if sd <= 0 {
		return errors.New("invalid socket")
	}

	// Set TPacket version on socket to the configured version
	if err := unix.SetsockoptInt(int(sd), unix.SOL_PACKET, unix.PACKET_VERSION, TPacketVersion); err != nil {
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
	if bpfFilterFn := iface.Type.BPFFilter(); bpfFilterFn != nil {
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

// SetupRingBuffer peforms a call via setsockopt() to prepare a mmmap'ed ring buffer
func (sd FileDescriptor) SetupRingBuffer(val unsafe.Pointer, vallen uintptr) error {
	return setsockopt(sd, unix.SOL_PACKET, unix.PACKET_RX_RING, val, vallen)
}

// Close closes the file descriptor
func (sd FileDescriptor) Close() error {
	return unix.Close(int(sd))
}

/////////////////////////////////////////////////////////////////////////////////////////

func getsockopt(fd FileDescriptor, level, name int, val unsafe.Pointer, vallen uintptr) error {
	if _, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), uintptr(level), uintptr(name), uintptr(val), vallen, 0); errno != 0 {
		return error(errno)
	}

	return nil
}

func setsockopt(fd FileDescriptor, level, name int, val unsafe.Pointer, vallen uintptr) error {
	if _, _, errno := unix.Syscall6(unix.SYS_SETSOCKOPT, uintptr(fd), uintptr(level), uintptr(name), uintptr(val), vallen, 0); errno != 0 {
		return error(errno)
	}

	return nil
}

func htons(v uint16) int {
	return int((v << 8) | (v >> 8))
}
